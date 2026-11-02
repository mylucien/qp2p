//! 引擎：端点生命周期与打洞入口。
//!
//! 外壳（CLI / 桌面 / Android）都只和这一层打交道。
//!
//! 三项提升成功率的能力都在这里：
//! - **并行候选**：一次打洞喂进整组候选地址
//! - **重试前刷新**：每轮重试重建端点、重新 STUN，避免用过期映射
//! - **失败期间保活**：重试间隔里往已知地址发小包，让 NAT 映射不过期

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use quinn::Connection;
use tokio::time::Instant;

use crate::candidate::Candidate;
use crate::peer::{backoff_ms, punch, Role};
use crate::socket;

/// 打洞前给对端的准备时间：双方都要先拿到对端地址。
const ALIGN_DELAY: Duration = Duration::from_millis(300);
/// 失败期间的保活间隔。家用 NAT 的 UDP 映射常见 30s~120s 回收。
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
/// 保活包：3 字节魔数 + 类型，对端 quinn 会当作无效 QUIC 包丢弃。
const KEEPALIVE_MAGIC: &[u8] = b"\x00QP2K";

pub struct Engine {
    endpoint: Option<quinn::Endpoint>,
    bind_addr: SocketAddr,
    local_addr: SocketAddr,
    stun: Vec<String>,
    srflx: Option<SocketAddr>,
    upnp: Option<SocketAddr>,
    candidates: Vec<Candidate>,
    /// 复制自 quinn 的同一个 UDP socket；renw 前必须释放，否则端口一直被占
    keepalive: Option<Arc<std::net::UdpSocket>>,
}

impl Engine {
    /// 绑定端口、STUN、UPnP、创建端点。
    pub async fn bind(bind_addr: SocketAddr, stun_servers: &[String]) -> Result<Self> {
        let bound = socket::bind(bind_addr, stun_servers).await?;
        Ok(Self {
            endpoint: Some(bound.endpoint),
            bind_addr: bound.bind_addr,
            local_addr: bound.local_addr,
            stun: stun_servers.to_vec(),
            srflx: bound.srflx,
            upnp: bound.upnp,
            candidates: bound.candidates,
            keepalive: Some(bound.keepalive),
        })
    }

    pub fn endpoint(&self) -> &quinn::Endpoint {
        self.endpoint.as_ref().expect("endpoint 未初始化")
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn srflx(&self) -> Option<SocketAddr> {
        self.srflx
    }

    pub fn upnp(&self) -> Option<SocketAddr> {
        self.upnp
    }

    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }

    /// 关闭当前端点，在同一个端口上重建，并重新做 STUN / UPnP。
    ///
    /// 用于重试：NAT 映射可能已经变了，拿着旧候选再打只是浪费窗口。
    /// 只应在没有活跃连接时调用。
    pub async fn renew(&mut self) -> Result<()> {
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.close(0u32.into(), b"renew");
            let _ = tokio::time::timeout(Duration::from_millis(500), endpoint.wait_idle()).await;
            drop(endpoint);
        }
        // 关键：先放掉复制出来的保活句柄，否则这个端口一直被占着
        self.keepalive = None;

        let mut last_error = None;
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(120)).await;
            }
            match socket::bind(self.bind_addr, &self.stun).await {
                Ok(bound) => {
                    self.install(bound);
                    return Ok(());
                }
                Err(e) => last_error = Some(e),
            }
        }

        // 原端口一时半会儿释放不了（Windows 常见），换临时端口也比用旧映射强
        let fallback = SocketAddr::new(self.bind_addr.ip(), 0);
        match socket::bind(fallback, &self.stun).await {
            Ok(bound) => {
                tracing::warn!(
                    "[engine] 原端口 {} 不可用，刷新后改用 {}",
                    self.bind_addr,
                    bound.local_addr
                );
                self.install(bound);
                Ok(())
            }
            Err(e) => Err(last_error.unwrap_or(e)),
        }
    }

    fn install(&mut self, bound: socket::Bound) {
        self.endpoint = Some(bound.endpoint);
        self.bind_addr = bound.bind_addr;
        self.local_addr = bound.local_addr;
        self.srflx = bound.srflx;
        self.upnp = bound.upnp;
        self.candidates = bound.candidates;
        self.keepalive = Some(bound.keepalive);
        tracing::info!("[engine] 端点已刷新 addr={}", self.local_addr);
    }

    /// 对一组候选地址打洞。
    pub async fn punch(
        &self,
        peers: &[SocketAddr],
        role: Role,
        window: Duration,
    ) -> Result<Connection, punch::PunchError> {
        let start = Instant::now() + ALIGN_DELAY;
        punch::execute(self.endpoint(), peers, role, start, window).await
    }

    /// 带重试的打洞：每轮开始前刷新自己的映射，并重新取对端候选。
    ///
    /// `peers` 在每轮被调用一次——接上信令面后，这里换成"重新拉对端候选"。
    pub async fn punch_with_retry<F>(
        &mut self,
        role: Role,
        mut peers: F,
        attempts: u8,
    ) -> Result<Connection, punch::PunchError>
    where
        F: FnMut() -> Vec<SocketAddr>,
    {
        let attempts = attempts.max(1);
        let mut last = punch::PunchError::Timeout;

        for attempt in 0..attempts {
            if attempt > 0 {
                let wait = Duration::from_millis(backoff_ms(attempt - 1));
                let known = peers();
                self.sleep_with_keepalive(wait, &known).await;
                if let Err(e) = self.renew().await {
                    tracing::warn!("[engine] 端点刷新失败，继续用旧端点: {e}");
                }
            }

            let known = peers();
            if known.is_empty() {
                last = punch::PunchError::NoCandidates;
                continue;
            }
            tracing::info!(
                "[engine] 第 {} 轮打洞，候选 {} 个",
                attempt + 1,
                known.len()
            );

            match self.punch(&known, role, punch::DEFAULT_WINDOW).await {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    tracing::warn!("[engine] 第 {} 轮失败: {e}", attempt + 1);
                    last = e;
                }
            }
        }

        Err(last)
    }

    /// 等待期间定时发保活包，避免 NAT 映射在重试间隔里被回收。
    async fn sleep_with_keepalive(&self, total: Duration, peers: &[SocketAddr]) {
        let deadline = Instant::now() + total;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return;
            }
            let chunk = (deadline - now).min(KEEPALIVE_INTERVAL);
            tokio::time::sleep(chunk).await;

            for peer in peers {
                match &self.keepalive {
                    Some(socket) => {
                        if let Err(e) = socket.send_to(KEEPALIVE_MAGIC, peer) {
                            tracing::debug!("[engine] 保活失败 {peer}: {e}");
                        }
                    }
                    None => return,
                }
            }
        }
    }

    pub async fn wait_idle(&self) {
        self.endpoint().wait_idle().await;
    }
}
