//! 引擎：端点生命周期与打洞入口。
//!
//! 外壳（CLI / 桌面 / Android）都只和这一层打交道。
//!
//! 三条与成功率相关的策略：
//! - **不依赖启动对齐**：dialer 短超时、listener 长守候，先起后起都能连上
//! - **重试前刷新**：重建端点、重新 STUN，避免拿过期映射硬打
//! - **失败期保活**：重试间隔里往已知地址发小包，防止 NAT 映射被回收

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use quinn::Connection;
use tokio::time::Instant;

use crate::candidate::{normalize, Candidate, CandidateKind};
use crate::identity::{Identity, NodeId};
use crate::peer::{punch, Role};
use crate::socket;
use crate::stun_watch;
use crate::tls::TlsIdentity;
use crate::upnp;

/// dialer 单轮打洞时长：够覆盖对端启动晚几秒的情况。
const DIAL_ATTEMPT: Duration = Duration::from_secs(10);
/// listener 单轮守候时长：先启动的一方要能等到后启动的一方。
const LISTEN_ATTEMPT: Duration = Duration::from_secs(35);
/// 两轮之间的间隔。
const RETRY_DELAY: Duration = Duration::from_secs(5);
/// 失败期间的保活间隔。家用 NAT 的 UDP 映射常见 30s~120s 回收。
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
/// 保活包：3 字节魔数 + 类型，对端 quinn 会当作无效 QUIC 包丢弃。
const KEEPALIVE_MAGIC: &[u8] = b"\x00QP2K";
/// 打洞期间的开孔间隔。
///
/// QUIC 的 Initial 重传是指数退避（1s、2s、4s…），对端 NAT 刚开始收包时
/// 可能正好落在两次重传之间；用同一个五元组额外每 200ms 发一个小包，
/// 把"孔"持续顶开，而且这些包不参与握手，失败也不会拖慢状态机。
const PROBE_INTERVAL: Duration = Duration::from_millis(200);
const PROBE_MAGIC: &[u8] = b"\x00QP2H";

pub struct Engine {
    endpoint: Option<quinn::Endpoint>,
    bind_addr: SocketAddr,
    local_addr: SocketAddr,
    stun: Vec<String>,
    srflx: Option<SocketAddr>,
    upnp: Option<SocketAddr>,
    candidates: Vec<Candidate>,
    keepalive: Option<Arc<std::net::UdpSocket>>,
    /// 本节点身份。打洞成功后的对端认证用它签名。
    identity: Identity,
    /// 期望的对端 node_id；None 表示"验签但不校验具体是谁"。
    expected_peer: Option<NodeId>,
    /// 证书身份：落盘之后指纹在重启间不变，对端才能钉扎
    tls: TlsIdentity,
    /// 钉扎对端证书的指纹；刷新端点后要重新应用
    pin_fp: Option<[u8; 32]>,
    /// UPnP 映射句柄，退出/刷新时负责删除
    mapping: Option<upnp::Mapping>,
    renewer: Option<tokio::task::JoinHandle<()>>,
    /// 周期性 STUN 保活：刷新映射、发现端口变化、持续判定 NAT 行为
    stun_shared: Arc<stun_watch::Shared>,
    stun_task: Option<tokio::task::JoinHandle<()>>,
}

/// 把 `Bound` 里的 STUN 旁路接到保活任务上。
fn start_stun_watch(
    bound: &mut socket::Bound,
    servers: &[String],
    generation: u64,
) -> (Arc<stun_watch::Shared>, Option<tokio::task::JoinHandle<()>>) {
    let shared = stun_watch::Shared::new(bound.srflx, bound.nat, generation);
    let task = bound.stun_rx.take().map(|rx| {
        stun_watch::spawn(
            bound.keepalive.clone(),
            servers.to_vec(),
            bound.stun_targets.clone(),
            rx,
            shared.clone(),
        )
    });
    (shared, task)
}

impl Engine {
    /// 绑定端口、STUN、UPnP、创建端点；身份每次随机（只适合测试）。
    pub async fn bind(bind_addr: SocketAddr, stun_servers: &[String]) -> Result<Self> {
        Self::bind_in(bind_addr, stun_servers, None).await
    }

    /// 同上，但身份与证书落在 `data_dir` 里：重启后 `node_id` 和 `tls_fp` 不变。
    pub async fn bind_in(
        bind_addr: SocketAddr,
        stun_servers: &[String],
        data_dir: Option<&Path>,
    ) -> Result<Self> {
        let identity = crate::identity::Identity::load_or_create(data_dir)?;
        let tls = TlsIdentity::load_or_create(data_dir)?;
        let mut bound = socket::bind(bind_addr, stun_servers, &tls).await?;
        let mapping = bound.mapping.clone();
        let renewer = start_upnp_renewer(mapping.clone());
        let (stun_shared, stun_task) = start_stun_watch(&mut bound, stun_servers, 0);

        Ok(Self {
            endpoint: Some(bound.endpoint),
            bind_addr: bound.bind_addr,
            local_addr: bound.local_addr,
            stun: stun_servers.to_vec(),
            srflx: bound.srflx,
            upnp: bound.upnp,
            candidates: bound.candidates,
            keepalive: Some(bound.keepalive),
            identity,
            expected_peer: None,
            pin_fp: None,
            tls,
            mapping,
            renewer,
            stun_shared,
            stun_task,
        })
    }

    /// 证书指纹（sha256 hex）。稳定之后可以直接钉扎对端。
    pub fn tls_fp(&self) -> String {
        self.tls.fingerprint()
    }

    /// 钉扎对端证书指纹：不符时 QUIC 握手就失败，不进入认证阶段。
    pub fn expect_peer_fp(&mut self, fp: Option<&str>) -> Result<()> {
        let pin = match fp {
            None => None,
            Some(text) => {
                let bytes = hex::decode(text.trim()).context("指纹不是合法十六进制")?;
                let array: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("指纹必须是 32 字节（64 位十六进制）"))?;
                Some(array)
            }
        };
        self.pin_fp = pin;
        let config = crate::tls::client_config(pin)?;
        // quinn 的 set_default_client_config 需要 &mut Endpoint，取出来改再放回
        if let Some(mut endpoint) = self.endpoint.take() {
            endpoint.set_default_client_config(config);
            self.endpoint = Some(endpoint);
        }
        Ok(())
    }

    /// 本节点标识（`hex(sha256(pubkey))[..32]`）。
    pub fn node_id(&self) -> NodeId {
        self.identity.node_id()
    }

    /// 本节点的签名身份。信令请求要用它签名，外壳只借用、不复制。
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// 各角色的单轮打洞时长。外壳自己做重试循环时按这个传超时。
    pub fn attempt_timeout(role: Role) -> Duration {
        match role {
            Role::Dialer => DIAL_ATTEMPT,
            Role::Listener => LISTEN_ATTEMPT,
        }
    }

    /// 本节点的公钥指纹，可用于人工核对。
    pub fn public_key(&self) -> [u8; 32] {
        self.identity.public_key()
    }

    /// 公钥的十六进制形式（64 字符），方便打印和人工比对。
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key())
    }

    /// 要求对端必须是这个 node_id；不设置则只验签、不限身份。
    pub fn expect_peer(&mut self, peer: Option<NodeId>) {
        self.expected_peer = peer;
    }

    pub fn endpoint(&self) -> Option<&quinn::Endpoint> {
        self.endpoint.as_ref()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// 当前公网映射：周期 STUN 观测到的最新值，没有就退回启动时的探测结果。
    pub fn srflx(&self) -> Option<SocketAddr> {
        self.stun_shared.snapshot().mapped.or(self.srflx)
    }

    /// 实时候选地址：启动时的内网 / UPnP 候选 + 最新的 STUN 映射。
    ///
    /// 周期保活发现映射变化后，[`Engine::candidates`] 里的 srflx 就过期了；
    /// 登记到信令用这个。
    pub fn live_candidates(&self) -> Vec<Candidate> {
        let mut list: Vec<Candidate> = self
            .candidates
            .iter()
            .filter(|c| c.kind != CandidateKind::Srflx)
            .cloned()
            .collect();
        if let Some(addr) = self.srflx() {
            list.push(Candidate::new(CandidateKind::Srflx, addr));
        }
        normalize(list)
    }

    /// 周期 STUN 保活开关。外壳在"没有任何直连且没休眠"时打开。
    pub fn stun_set_active(&self, on: bool) {
        self.stun_shared.set_active(on);
    }

    /// 公网映射每变一次加一，用来判断要不要重新登记。
    pub fn stun_generation(&self) -> u64 {
        self.stun_shared.snapshot().generation
    }

    /// 连续多少轮 STUN 保活没有任何服务器回应。
    pub fn stun_misses(&self) -> u32 {
        self.stun_shared.misses()
    }

    /// 调整保活间隔（测试用；默认 25 秒）。
    pub fn stun_set_interval(&self, interval: Duration) {
        self.stun_shared.set_interval(interval);
    }

    /// 本机 NAT 的映射行为。
    pub fn nat_kind(&self) -> crate::stun::NatKind {
        self.stun_shared.snapshot().kind
    }

    pub fn upnp(&self) -> Option<SocketAddr> {
        self.upnp
    }

    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }

    /// 主动收尾：停续租、删掉路由器上的端口映射、关掉端点。
    ///
    /// `Drop` 里做不了这些——运行时可能已经关了，spawn 出去的删除任务根本跑不完，
    /// 路由器上就留一条指向空气的映射。CLI 退出前应当显式调用这个方法。
    pub async fn shutdown(&mut self) {
        if let Some(task) = self.renewer.take() {
            task.abort();
        }
        if let Some(task) = self.stun_task.take() {
            task.abort();
        }
        if let Some(mapping) = self.mapping.take() {
            match tokio::time::timeout(Duration::from_secs(3), mapping.delete()).await {
                Ok(Ok(())) => tracing::info!("[engine] UPnP 映射已删除"),
                Ok(Err(e)) => tracing::debug!("[engine] 删除 UPnP 映射失败: {e}"),
                Err(_) => tracing::debug!("[engine] 删除 UPnP 映射超时"),
            }
        }
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.close(0u32.into(), b"shutdown");
            let _ = tokio::time::timeout(Duration::from_millis(500), endpoint.wait_idle()).await;
        }
        self.keepalive = None;
    }

    /// 关闭当前端点，在同一个端口上重建，并重新做 STUN / UPnP。
    ///
    /// 失败时端点保持关闭并返回错误，调用方下一轮会拿到"端点不可用"，
    /// 不会 panic。只应在没有活跃连接时调用。
    pub async fn renew(&mut self) -> Result<()> {
        // 旧映射先撤掉：换了端口之后它指向的是一个已经没人监听的端口
        if let Some(task) = self.renewer.take() {
            task.abort();
        }
        if let Some(task) = self.stun_task.take() {
            task.abort();
        }
        if let Some(old) = self.mapping.take() {
            // 必须等它删完再重绑：映射是按端口登记的，新映射建好之后
            // 旧的后台任务一删，删掉的就是新映射（同端口）。
            match tokio::time::timeout(Duration::from_secs(3), old.delete()).await {
                Ok(Ok(())) => tracing::debug!("[engine] 旧 UPnP 映射已删除"),
                Ok(Err(e)) => tracing::debug!("[engine] 删除旧 UPnP 映射失败: {e}"),
                Err(_) => tracing::debug!("[engine] 删除旧 UPnP 映射超时"),
            }
        }

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
            match socket::bind(self.bind_addr, &self.stun, &self.tls).await {
                Ok(bound) => {
                    self.install(bound);
                    return Ok(());
                }
                Err(e) => last_error = Some(e),
            }
        }

        // 原端口一时半会儿释放不了（Windows 常见），换临时端口也比用旧映射强
        let fallback = SocketAddr::new(self.bind_addr.ip(), 0);
        match socket::bind(fallback, &self.stun, &self.tls).await {
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

    fn install(&mut self, mut bound: socket::Bound) {
        self.mapping = bound.mapping.clone();
        self.renewer = start_upnp_renewer(self.mapping.clone());
        // generation 沿用并加一：外壳比较它判断"映射变了没"，重置回 0 会和旧值撞车
        let next_generation = self.stun_shared.snapshot().generation + 1;
        let was_active = self.stun_shared.is_active_flag();
        let (shared, task) = start_stun_watch(&mut bound, &self.stun, next_generation);
        shared.set_active(was_active);
        self.stun_shared = shared;
        self.stun_task = task;

        // 新端点的默认客户端配置是"不钉扎"，这里把用户的钉扎重新贴回去
        let mut endpoint = bound.endpoint;
        if self.pin_fp.is_some() {
            if let Ok(config) = crate::tls::client_config(self.pin_fp) {
                endpoint.set_default_client_config(config);
            }
        }
        self.endpoint = Some(endpoint);
        self.bind_addr = bound.bind_addr;
        self.local_addr = bound.local_addr;
        self.srflx = bound.srflx;
        self.upnp = bound.upnp;
        self.candidates = bound.candidates;
        self.keepalive = Some(bound.keepalive);
        tracing::info!("[engine] 端点已刷新 addr={}", self.local_addr);
    }

    /// 对一组候选地址打洞；`timeout` 由角色决定。
    ///
    /// 打洞期间会额外用同一个 socket 每 200ms 往所有候选发一个小包开孔，
    /// 不依赖 QUIC 的指数退避重传。
    pub async fn punch(
        &self,
        peers: &[SocketAddr],
        role: Role,
        timeout: Duration,
    ) -> Result<Connection, punch::PunchError> {
        self.punch_as(peers, role, timeout, self.expected_peer.clone())
            .await
    }

    /// 同 [`Engine::punch`]，但本次调用单独指定"必须是对面这个 node_id"。
    ///
    /// 组网（多对端）时一台机器同时和多个节点打洞，每个连接的对端都不同，
    /// 全局的 `expected_peer` 不够用——所以认证目标要按连接传进来。
    pub async fn punch_as(
        &self,
        peers: &[SocketAddr],
        role: Role,
        timeout: Duration,
        expected: Option<NodeId>,
    ) -> Result<Connection, punch::PunchError> {
        let Some(endpoint) = self.endpoint.as_ref() else {
            return Err(punch::PunchError::Dial("端点不可用".to_string()));
        };

        let handles = punch::AuthHandles {
            identity: self.identity.clone(),
            expected,
        };

        let probe = self.spawn_probe(peers, timeout);
        let result = punch::execute(endpoint, peers, role, timeout, Some(handles)).await;
        if let Some(task) = probe {
            task.abort();
        }
        result
    }

    fn spawn_probe(
        &self,
        peers: &[SocketAddr],
        total: Duration,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let socket = self.keepalive.clone()?;
        let peers = peers.to_vec();
        Some(tokio::spawn(async move {
            let deadline = Instant::now() + total;
            loop {
                for peer in &peers {
                    if let Err(e) = socket.send_to(PROBE_MAGIC, peer) {
                        tracing::debug!("[engine] 开孔包发送失败 {peer}: {e}");
                    }
                }
                if Instant::now() + PROBE_INTERVAL >= deadline {
                    return;
                }
                tokio::time::sleep(PROBE_INTERVAL).await;
            }
        }))
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
        let mut last = punch::PunchError::Timeout(Duration::ZERO);
        let timeout = match role {
            Role::Dialer => DIAL_ATTEMPT,
            Role::Listener => LISTEN_ATTEMPT,
        };

        for attempt in 0..attempts {
            if attempt > 0 {
                let known = peers();
                self.sleep_with_keepalive(RETRY_DELAY, &known).await;
                if let Err(e) = self.renew().await {
                    tracing::warn!("[engine] 端点刷新失败，将放弃后续重试: {e}");
                    return Err(punch::PunchError::Dial(format!("端点刷新失败: {e}")));
                }
            }

            let known = peers();
            if known.is_empty() {
                last = punch::PunchError::NoCandidates;
                continue;
            }
            tracing::info!(
                "[engine] 第 {} 轮打洞，候选 {} 个，最长 {:?}",
                attempt + 1,
                known.len(),
                timeout
            );

            match self.punch(&known, role, timeout).await {
                Ok(conn) => return Ok(conn),
                // 身份不对不是网络问题：刷新端点、换个时刻重试都不会变
                Err(e @ punch::PunchError::Auth(_)) => {
                    tracing::warn!("[engine] 第 {} 轮失败: {e}", attempt + 1);
                    return Err(e);
                }
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

            let Some(socket) = &self.keepalive else {
                return;
            };
            for peer in peers {
                if let Err(e) = socket.send_to(KEEPALIVE_MAGIC, peer) {
                    tracing::debug!("[engine] 保活失败 {peer}: {e}");
                }
            }
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        if let Some(task) = self.renewer.take() {
            task.abort();
        }
        if let Some(task) = self.stun_task.take() {
            task.abort();
        }
        // 兜底：正常退出应当显式调用 shutdown().await，这里只处理被遗忘的情况
        if let Some(mapping) = self.mapping.take() {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    let _ = mapping.delete().await;
                });
            }
        }
    }
}

/// 租约过半就续一次；永久映射（租约 0）不需要。
fn start_upnp_renewer(mapping: Option<upnp::Mapping>) -> Option<tokio::task::JoinHandle<()>> {
    let mapping = mapping?;
    if mapping.lease() == 0 {
        return None;
    }
    let interval = Duration::from_secs(u64::from(mapping.lease() / 2).max(60));

    Some(tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            match mapping.renew().await {
                Ok(()) => tracing::debug!("[engine] UPnP 映射已续租"),
                Err(e) => tracing::warn!("[engine] UPnP 续租失败: {e}"),
            }
        }
    }))
}
