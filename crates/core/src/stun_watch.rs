//! 周期性 STUN 保活与映射变化检测。
//!
//! 为什么需要它：保活包（`KEEPALIVE_MAGIC`）只在打洞重试期间发，
//! QUIC 自带的 keepalive 只在"已有直连"时有。一个**没有任何直连**的空闲节点，
//! NAT 映射没人刷新，家用路由器通常 30~120 秒就回收；而登记到信令的候选地址
//! 最长会过期十分钟，别人打过来打的是死端口。
//!
//! 做法：同一个 socket 上每隔 [`DEFAULT_INTERVAL`] 向（最多）两台 STUN 服务器各发一次请求。
//! 这既刷新映射，又能在端口变化时立刻发现——只在变化时才需要重新登记。
//! 同时用两台**不同 IP** 的服务器的回答，持续判定 NAT 映射行为（cone / symmetric）。
//!
//! 只在"没有任何直连且没休眠"时才发：有直连时 QUIC 的 15 秒 keepalive 已经在刷新映射，
//! 不必让射频多醒一次。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::RngCore;
use tokio::sync::{mpsc, Notify};

use crate::socket::StunReply;
use crate::stun::{self, NatKind};

/// 家用 NAT 的 UDP 映射超时最短约 30 秒，25 秒留一点余量。
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(25);

/// 一轮里等待响应的时间。
const ROUND_WAIT: Duration = Duration::from_secs(2);

/// 当前对公网映射的认知。
#[derive(Debug, Clone, Copy)]
pub struct Snapshot {
    pub mapped: Option<SocketAddr>,
    pub kind: NatKind,
    /// 映射地址每变一次加一；调用方比较它来判断"要不要重新登记"
    pub generation: u64,
}

/// 保活任务与 Engine 共享的状态。
pub struct Shared {
    active: AtomicBool,
    misses: AtomicU32,
    interval_ms: AtomicU64,
    /// 间隔被修改时唤醒正在睡的保活任务，让新间隔立刻生效
    interval_changed: Notify,
    snap: Mutex<Snapshot>,
}

impl Shared {
    pub fn new(mapped: Option<SocketAddr>, kind: NatKind, generation: u64) -> Arc<Self> {
        Arc::new(Self {
            active: AtomicBool::new(false),
            misses: AtomicU32::new(0),
            interval_ms: AtomicU64::new(DEFAULT_INTERVAL.as_millis() as u64),
            interval_changed: Notify::new(),
            snap: Mutex::new(Snapshot {
                mapped,
                kind,
                generation,
            }),
        })
    }

    pub fn snapshot(&self) -> Snapshot {
        *self.snap.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_active(&self, on: bool) {
        self.active.store(on, Ordering::Relaxed);
    }

    fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// 当前开关状态（Engine 重建端点时用来沿用）。
    pub fn is_active_flag(&self) -> bool {
        self.is_active()
    }

    /// 连续多少轮没有任何服务器回应。
    pub fn misses(&self) -> u32 {
        self.misses.load(Ordering::Relaxed)
    }

    pub fn set_interval(&self, interval: Duration) {
        self.interval_ms
            .store(interval.as_millis().max(1) as u64, Ordering::Relaxed);
        self.interval_changed.notify_one();
    }

    fn interval(&self) -> Duration {
        Duration::from_millis(self.interval_ms.load(Ordering::Relaxed))
    }

    /// 把一轮观测合并进当前认知。
    ///
    /// - 空观测：只记一次 miss。
    /// - 当前映射仍被某台服务器确认：保持不变（对称 NAT 下各服务器的端口不同，
    ///   不能因为"第一个回应的"换了就当作映射变化）。
    /// - 否则采用第一条，generation 加一。
    pub fn absorb(&self, observations: &[(IpAddr, SocketAddr)]) {
        if observations.is_empty() {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.misses.store(0, Ordering::Relaxed);

        let mut snap = self.snap.lock().unwrap_or_else(|e| e.into_inner());
        let kind = stun::classify(observations);
        if kind != NatKind::Unknown {
            snap.kind = kind;
        }
        let confirmed = snap
            .mapped
            .is_some_and(|m| observations.iter().any(|(_, o)| *o == m));
        if !confirmed {
            snap.mapped = Some(observations[0].1);
            snap.generation += 1;
        }
    }
}

/// 启动保活任务。`rx` 是旁观 socket 抄出来的 STUN 响应。
pub fn spawn(
    socket: Arc<std::net::UdpSocket>,
    servers: Vec<String>,
    mut targets: Vec<SocketAddr>,
    mut rx: mpsc::UnboundedReceiver<StunReply>,
    shared: Arc<Shared>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(shared.interval()) => {}
                // 间隔变了：按新间隔重新开始睡，而不是睡完旧的那一觉
                _ = shared.interval_changed.notified() => continue,
            }
            // 睡眠期间攒下的旧响应一律丢弃，事务 ID 对不上也不会误用
            while rx.try_recv().is_ok() {}
            if !shared.is_active() {
                continue;
            }

            // 启动时全都没解析到 / 连续没回应：重新解析（DNS 恢复、服务器换 IP）
            if targets.is_empty() || shared.misses() >= 2 {
                let fresh = resolve_all(&servers).await;
                if !fresh.is_empty() {
                    targets = fresh;
                }
            }

            let mut pending: HashMap<[u8; 12], SocketAddr> = HashMap::new();
            for target in &targets {
                let mut txid = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut txid);
                if socket
                    .send_to(&stun::build_binding_request(txid), target)
                    .is_ok()
                {
                    pending.insert(txid, *target);
                }
            }

            let mut observations: Vec<(IpAddr, SocketAddr)> = Vec::new();
            let deadline = tokio::time::Instant::now() + ROUND_WAIT;
            while !pending.is_empty() {
                match tokio::time::timeout_at(deadline, rx.recv()).await {
                    Ok(Some(reply)) => {
                        if pending.get(&reply.txid) == Some(&reply.from) {
                            pending.remove(&reply.txid);
                            observations.push((reply.from.ip(), reply.mapped));
                        }
                    }
                    // 超时或通道关闭
                    _ => break,
                }
            }
            shared.absorb(&observations);
        }
    })
}

/// 每个域名取最多两个 IPv4 地址，总共不超过 4 个目标。
async fn resolve_all(servers: &[String]) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for server in servers {
        if let Ok(addrs) = tokio::net::lookup_host(server.as_str()).await {
            out.extend(addrs.filter(SocketAddr::is_ipv4).take(2));
        }
    }
    out.truncate(4);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn first_observation_sets_mapping_and_bumps_generation() {
        let shared = Shared::new(None, NatKind::Unknown, 0);
        shared.absorb(&[(ip("1.1.1.1"), sa("9.9.9.9:5000"))]);
        let snap = shared.snapshot();
        assert_eq!(snap.mapped, Some(sa("9.9.9.9:5000")));
        assert_eq!(snap.generation, 1);
        assert_eq!(snap.kind, NatKind::Unknown); // 单台服务器不足以分类
    }

    #[test]
    fn unchanged_mapping_does_not_bump_generation() {
        let shared = Shared::new(Some(sa("9.9.9.9:5000")), NatKind::Cone, 7);
        shared.absorb(&[
            (ip("1.1.1.1"), sa("9.9.9.9:5000")),
            (ip("2.2.2.2"), sa("9.9.9.9:5000")),
        ]);
        assert_eq!(shared.snapshot().generation, 7);
    }

    #[test]
    fn changed_mapping_bumps_generation_once() {
        let shared = Shared::new(Some(sa("9.9.9.9:5000")), NatKind::Cone, 0);
        let moved = [
            (ip("1.1.1.1"), sa("9.9.9.9:6000")),
            (ip("2.2.2.2"), sa("9.9.9.9:6000")),
        ];
        shared.absorb(&moved);
        shared.absorb(&moved);
        let snap = shared.snapshot();
        assert_eq!(snap.mapped, Some(sa("9.9.9.9:6000")));
        assert_eq!(snap.generation, 1);
    }

    #[test]
    fn symmetric_nat_does_not_flap_between_servers() {
        // 对称 NAT：两台服务器看到不同端口。只要旧映射仍被确认，就不算变化
        let shared = Shared::new(Some(sa("9.9.9.9:5000")), NatKind::Unknown, 0);
        shared.absorb(&[
            (ip("2.2.2.2"), sa("9.9.9.9:5001")),
            (ip("1.1.1.1"), sa("9.9.9.9:5000")),
        ]);
        let snap = shared.snapshot();
        assert_eq!(snap.kind, NatKind::Symmetric);
        assert_eq!(snap.mapped, Some(sa("9.9.9.9:5000")));
        assert_eq!(snap.generation, 0);
    }

    #[test]
    fn misses_count_up_and_reset_on_answer() {
        let shared = Shared::new(None, NatKind::Unknown, 0);
        shared.absorb(&[]);
        shared.absorb(&[]);
        assert_eq!(shared.misses(), 2);
        shared.absorb(&[(ip("1.1.1.1"), sa("9.9.9.9:1"))]);
        assert_eq!(shared.misses(), 0);
    }
}
