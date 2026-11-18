//! TUN 模式的数据面：把 IP 包按五元组复用到 QUIC 双向流上。
//!
//! 线上格式：流的第一字节是类型 `2`（区别于 TCP 端口映射的 `1`），
//! 之后是 `[len:u16][IP 包]` 的帧序列。这里用「一条流一条流」而不是
//! datagram，是因为 QUIC datagram 受路径 MTU 限制（约 1150），
//! 内层 MTU 会被压得很低，TCP MSS 跟着难看。
//!
//! 代价是单条流内的队头阻塞——但每条 TCP 连接各自一条流，互不影响。
//!
//! 两种接法共用同一套转发逻辑：
//! - [`run`]：只有一个对端（`qp2p tun` 这类直连调试）
//! - [`run_mesh`]：多对端组网（`qp2p up`），按目标虚拟 IP 选连接
//!
//! # 转发模型：主循环不许等网络
//!
//! 早期实现直接在转发循环里 `await` 每一次写流，后果是**一条流卡住、
//! 整条隧道停摆**：QUIC 的流控窗口一旦不动（对端不 ACK、CGNAT 黑洞、
//! 对端应用没在读），`write_all` 会永久挂起，`select!` 也就不再轮询
//! TUN 队列，所有对端所有流一起死。界面还显示"已连接"，因为连接本身没断。
//!
//! 现在拆成两级：
//!
//! - 主循环只做「查表 + `try_send` 入队」，队列满了就丢包（内层 TCP 会重传），
//!   绝不等待网络；只有新建流时需要 `open_bi`，带 [`OPEN_TIMEOUT`] 上限。
//! - 每条流一个 [`FlowWriter`] 任务，负责真正写帧，每帧带 [`WRITE_TIMEOUT`]。
//!   写不动就 `reset` 这条流，不影响别人。
//!
//! 接收方向同理：`to_tun` 用 `try_send`。接收侧一旦反压，QUIC 流控窗口
//! 就不再前进，反压会顺着流控传导到**对端**的发送循环——两个方向一起卡死。
//!
//! # 失效判据（A 方案）
//!
//! 不新增任何探测包，只借真实业务流量观察"排队的包有没有被写出去"：
//! 单帧超时、连续几条流失败、有积压却长时间零进展。三条信号都落在
//! [`PeerHealth`] 上，触发后摘表、关连接、叫会话循环重拨。

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use quinn::{Connection, ReadExactError, RecvStream, SendStream};
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::sync::RwLock;

use crate::route::{flow::FlowKey, flow::FlowTable, ip, TunLink};

/// 流类型：IP 包。
const KIND_IP: u8 = 2;
/// 空闲多久回收一条流。
const FLOW_IDLE: Duration = Duration::from_secs(120);
/// 同时存在的流上限，与 quinn 的 `max_concurrent_bidi_streams` 对齐。
const FLOW_CAPACITY: usize = 200;
const READ_BUF: usize = 4096;

/// 单条流排队待写的包数上限。满了丢包，让内层 TCP 重传。
///
/// 64 帧约 90KB：够吸收一个 RTT 内的突发，又不至于让卡死的流囤积太多。
const FLOW_QUEUE: usize = 64;
/// 一帧写出去的上限。超过说明这条流的发送窗口已经不动了。
const WRITE_TIMEOUT: Duration = Duration::from_secs(3);
/// 新建双向流的上限。正常路径瞬时返回，只有流配额用尽才会等。
const OPEN_TIMEOUT: Duration = Duration::from_secs(3);
/// 有包排队却这么久没写出一帧 → 整条连接的流控停死。
const STALL_TIMEOUT: Duration = Duration::from_secs(30);
/// 同一连接连续这么多条流写失败 → 不再逐条重开，直接换连接。
const BROKEN_STREAK: u32 = 3;
/// 失效扫描周期。
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// 数据面活跃度：收到/发出任何包就打一个时间戳。
///
/// 会话循环靠它决定轮询档位（有流量就勤快点，静默就退到 60 秒一次），
/// 空闲断链也靠它判断"真的没人用了"。
#[derive(Clone)]
struct Activity {
    base: Instant,
    last_ms: Arc<AtomicU64>,
}

impl Activity {
    fn new() -> Self {
        Self {
            base: Instant::now(),
            last_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    fn touch(&self) {
        self.last_ms
            .store(self.base.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    fn idle(&self) -> Duration {
        let last = self.last_ms.load(Ordering::Relaxed);
        if last == 0 {
            return Duration::ZERO;
        }
        self.base
            .elapsed()
            .saturating_sub(Duration::from_millis(last))
    }
}

/// 一个对端的写健康度。
///
/// A 方案的全部判据都在这里，不额外发一个探测包——只看真实流量：
///
/// - 单帧写超过 [`WRITE_TIMEOUT`]：这条流废了；
/// - 连续 [`BROKEN_STREAK`] 条流都写不出去：整条连接废了；
/// - 有包排队却 [`STALL_TIMEOUT`] 一帧都没写出去：流控停死，也废了。
///
/// 时间戳只由**写成功**推进，不被"收到对端数据"刷新。接收正常但发送积压，
/// 恰恰说明对端没在消费，属于要处理的异常，不能拿来掩盖。
struct PeerHealth {
    base: Instant,
    /// 最后一次成功写完一帧
    last_write_ms: AtomicU64,
    /// 已入队、还没写完的帧数
    pending: AtomicU32,
    /// 连续写失败的流数
    fails: AtomicU32,
    /// 已经判定失效（只告一次，避免多条流的 writer 同时触发重建）
    dead: AtomicBool,
}

impl PeerHealth {
    fn new() -> Self {
        Self {
            base: Instant::now(),
            last_write_ms: AtomicU64::new(0),
            pending: AtomicU32::new(0),
            fails: AtomicU32::new(0),
            dead: AtomicBool::new(false),
        }
    }

    fn now_ms(&self) -> u64 {
        self.base.elapsed().as_millis() as u64
    }

    fn note_queued(&self) {
        self.pending.fetch_add(1, Ordering::Relaxed);
    }

    /// 扣回 `n` 个入队名额，防下溢。
    ///
    /// 用 `compare_exchange` 循环而不是 `fetch_update`：后者在新版 Rust 里
    /// 被标成 deprecated（改名 `try_update`），而 `try_update` 在旧版工具链
    /// 上还不存在——两个名字都会踩到一端，CAS 循环两边都兼容。
    fn note_unqueued(&self, n: u32) {
        if n == 0 {
            return;
        }
        let mut cur = self.pending.load(Ordering::Relaxed);
        loop {
            let next = cur.saturating_sub(n);
            if next == cur {
                return;
            }
            match self.pending.compare_exchange_weak(
                cur,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(actual) => cur = actual,
            }
        }
    }

    fn note_write_ok(&self) {
        self.last_write_ms.store(self.now_ms(), Ordering::Relaxed);
        self.note_unqueued(1);
        self.fails.store(0, Ordering::Relaxed);
    }

    /// 收到对端数据：清失败计数，但**不**推进写时间戳。
    fn note_read_ok(&self) {
        self.fails.store(0, Ordering::Relaxed);
    }

    /// 记一次写失败。积压由调用方按实际剩下的帧数清账，这里只管连败计数。
    fn note_fail(&self) {
        self.fails.fetch_add(1, Ordering::Relaxed);
    }

    fn broken(&self) -> bool {
        self.fails.load(Ordering::Relaxed) >= BROKEN_STREAK
    }

    /// 有积压，却超过 [`STALL_TIMEOUT`] 没有成功写出过一帧。
    fn stalled(&self) -> bool {
        self.stalled_after(STALL_TIMEOUT)
    }

    /// 同 [`Self::stalled`]，但可指定阈值（测试用短阈值，免得真等 30 秒）。
    fn stalled_after(&self, limit: Duration) -> bool {
        if self.pending.load(Ordering::Relaxed) == 0 {
            return false;
        }
        self.now_ms()
            .saturating_sub(self.last_write_ms.load(Ordering::Relaxed))
            > limit.as_millis() as u64
    }

    /// 抢占式标记失效：只有第一个调用者拿到 true。
    fn mark_dead(&self) -> bool {
        !self.dead.swap(true, Ordering::AcqRel)
    }

    fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Relaxed)
    }
}

/// 连接表里的一项：连接本身 + 它的写健康度。
#[derive(Clone)]
struct MeshPeer {
    conn: Connection,
    health: Arc<PeerHealth>,
}

/// 用户可见提示的出口（"直连已失效，正在重建"）。
///
/// 包一层 newtype 而不是直接存 trait object：`OnceLock<Arc<dyn Fn(&str) + Send + Sync>>`
/// 会触发 `clippy::type_complexity`，把 trait object 收进结构体就没这问题。
pub struct Notice(Arc<dyn Fn(&str) + Send + Sync>);

impl Notice {
    fn new<F>(f: F) -> Self
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        Self(Arc::new(f))
    }

    fn say(&self, message: &str) {
        (self.0)(message);
    }
}

/// 多对端连接表：目标虚拟地址 → 已建立的直连。
///
/// 组网时一台机器同时和多个节点相连，内核把一个包交给 TUN 之后，
/// 我们只能靠**目标地址**判断该从哪条连接发出去。
pub struct MeshLinks {
    peers: RwLock<HashMap<Ipv4Addr, MeshPeer>>,
    to_tun: mpsc::Sender<Vec<u8>>,
    /// 目标没有直连时，把对端虚拟地址丢进来，让会话循环立刻去打通它
    wake: RwLock<Option<mpsc::Sender<Ipv4Addr>>>,
    activity: Activity,
    /// 上一次唤醒的时间（毫秒）；3 秒冷却，避免持续丢包把信令打成洪水
    started: Instant,
    last_wake_ms: Arc<AtomicU64>,
    /// 允许对端经本机访问的目标（局域网出口）；空 = 拒绝一切端口映射请求
    allowed: Arc<Vec<SocketAddr>>,
    /// 用户可见提示（"直连已失效，正在重建"）。会话层注入，没注入就只写日志。
    notice: OnceLock<Notice>,
}

impl MeshLinks {
    /// `allowed` 非空时，同一条连接上除了 IP 包流，还会处理对端发起的
    /// 端口映射流（`KIND_TCP`）——安卓当局域网出口就是靠它。
    pub fn new(to_tun: mpsc::Sender<Vec<u8>>, allowed: Vec<SocketAddr>) -> Arc<Self> {
        Arc::new(Self {
            peers: RwLock::new(HashMap::new()),
            to_tun,
            wake: RwLock::new(None),
            activity: Activity::new(),
            started: Instant::now(),
            last_wake_ms: Arc::new(AtomicU64::new(0)),
            allowed: Arc::new(allowed),
            notice: OnceLock::new(),
        })
    }

    /// 会话循环启动时挂上唤醒通道。没挂之前丢包就是丢包，行为和以前一致。
    pub async fn set_wake(&self, tx: mpsc::Sender<Ipv4Addr>) {
        *self.wake.write().await = Some(tx);
    }

    /// 挂一条用户可见提示的出口。重复调用只认第一次。
    /// 挂一条用户可见提示的出口。重复调用只认第一次。
    pub fn set_notice<F>(&self, f: F)
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        let _ = self.notice.set(Notice::new(f));
    }

    fn say(&self, message: &str) {
        if let Some(notice) = self.notice.get() {
            notice.say(message);
        }
    }

    /// 收到发往"还没连上"的对端的包：叫会话循环马上打洞。
    ///
    /// `try_send` 而不是 `send`：TUN 不能因为队列满就阻塞，丢几个包
    /// 换来的是打洞立刻开始，重传会补上。
    async fn wake_peer(&self, ip: Ipv4Addr) {
        let now = self.started.elapsed().as_millis() as u64;
        let prev = self.last_wake_ms.load(Ordering::Relaxed);
        if prev != 0 && now.saturating_sub(prev) < 3_000 {
            return;
        }
        self.last_wake_ms.store(now, Ordering::Relaxed);
        let guard = self.wake.read().await;
        if let Some(tx) = guard.as_ref() {
            let _ = tx.try_send(ip);
        }
    }

    /// 明确失效后的唤醒：绕过 3 秒冷却，立刻让会话循环重拨。
    ///
    /// 和 [`Self::wake_peer`] 分开是因为两者语义不同：那个是"还没连上，
    /// 值得试一下"，这个是"刚判定死掉，必须马上重建"。
    async fn force_wake(&self, ip: Ipv4Addr) {
        self.last_wake_ms
            .store(self.started.elapsed().as_millis() as u64, Ordering::Relaxed);
        let guard = self.wake.read().await;
        if let Some(tx) = guard.as_ref() {
            let _ = tx.try_send(ip);
        }
    }

    /// 距上次有任何数据包过去了多久。
    pub fn idle_for(&self) -> Duration {
        self.activity.idle()
    }

    /// 全局空闲超过 `timeout` 就把所有直连断掉，返回断掉几条。
    ///
    /// 移动端省电/省流量的可选行为：断了之后下一次有包会立刻重新打洞。
    pub async fn drop_all_idle(&self, timeout: Duration) -> usize {
        if self.activity.idle() < timeout {
            return 0;
        }
        let mut peers = self.peers.write().await;
        let count = peers.len();
        for (_, peer) in peers.drain() {
            peer.health.mark_dead();
            peer.conn.close(0u32.into(), b"idle");
        }
        count
    }

    /// 挂上一个刚打通的直连：开始接收它的入站包，断开时自动摘除。
    ///
    /// 同一个虚拟 IP 已有旧连接时直接替换（对端重启或 NAT 重新映射都会这样），
    /// 旧连接关掉即可——它的流会在写失败后自然淘汰。
    pub async fn attach(self: &Arc<Self>, ip: Ipv4Addr, conn: Connection) {
        let health = Arc::new(PeerHealth::new());
        let peer = MeshPeer {
            conn: conn.clone(),
            health: health.clone(),
        };
        let old = { self.peers.write().await.insert(ip, peer) };
        if let Some(old) = old {
            if old.conn.stable_id() != conn.stable_id() {
                tracing::debug!("[tun] {ip} 的连接已刷新，关闭旧连接");
                old.health.mark_dead();
                old.conn.close(0u32.into(), b"replaced");
            }
        }

        {
            let conn = conn.clone();
            let to_tun = self.to_tun.clone();
            let activity = self.activity.clone();
            let allowed = self.allowed.clone();
            let health = health.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_inbound(conn, to_tun, allowed, activity, health).await {
                    tracing::debug!("[tun] 接收循环结束: {e:#}");
                }
            });
        }

        // 断开后把表项清掉，否则新包会一直往死连接里塞
        let weak = Arc::downgrade(self);
        let watch = conn.clone();
        tokio::spawn(async move {
            let reason = watch.closed().await;
            let Some(links) = weak.upgrade() else { return };
            let removed = {
                let mut peers = links.peers.write().await;
                // 只删自己：这个 IP 可能已经被更新的连接顶上来了
                if peers.get(&ip).map(|p| p.conn.stable_id()) == Some(watch.stable_id()) {
                    peers.remove(&ip);
                    true
                } else {
                    false
                }
            };
            if removed {
                tracing::info!("[tun] {ip} 的连接已断开: {reason}");
            }
        });
    }

    /// 判定一个对端的直连已失效：摘表、关连接、叫会话循环重拨。
    ///
    /// 只处理**表里当前那一条**连接——同一个 IP 可能已经被更新的连接顶掉了，
    /// 旧连接的 writer 失败时不能误杀新连接。
    async fn mark_dead(&self, ip: Ipv4Addr, conn: &Connection, reason: &str) {
        let removed = {
            let mut peers = self.peers.write().await;
            match peers.get(&ip) {
                Some(p) if p.conn.stable_id() == conn.stable_id() => {
                    peers.remove(&ip);
                    true
                }
                _ => false,
            }
        };
        if !removed {
            return;
        }
        conn.close(0u32.into(), b"stalled");
        tracing::warn!("[tun] 直连 {ip} 已失效（{reason}），准备重建");
        self.say(&format!("· 与 {ip} 的直连已失效，正在重建"));
        self.force_wake(ip).await;
    }

    /// 扫描所有对端：有包排队却长时间写不出去的直接判死。
    ///
    /// 这条是 [`PeerHealth::stalled`] 的落地。它依赖主循环还活着——
    /// 所以必须先有"主循环不许等网络"的改造，否则主循环自己卡住，
    /// 这个扫描再也不会跑。
    pub async fn reap_stalled(&self) {
        let stalled: Vec<(Ipv4Addr, Connection)> = {
            let peers = self.peers.read().await;
            peers
                .iter()
                .filter(|(_, p)| !p.health.is_dead() && p.health.stalled())
                .map(|(ip, p)| (*ip, p.conn.clone()))
                .collect()
        };
        for (ip, conn) in stalled {
            let first = {
                let peers = self.peers.read().await;
                peers.get(&ip).is_some_and(|p| p.health.mark_dead())
            };
            if first {
                self.mark_dead(ip, &conn, "有包排队 30 秒写不出去").await;
            }
        }
    }

    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    pub async fn peer_ips(&self) -> Vec<Ipv4Addr> {
        self.peers.read().await.keys().copied().collect()
    }

    pub async fn contains(&self, ip: Ipv4Addr) -> bool {
        self.peers.read().await.contains_key(&ip)
    }

    async fn conn_for(&self, dst: Ipv4Addr) -> Option<MeshPeer> {
        self.peers.read().await.get(&dst).cloned()
    }
}

/// 单个对端：所有包都走这一条连接，不做地址查表。
pub async fn run(conn: Connection, link: TunLink, local: Ipv4Addr) -> Result<()> {
    let TunLink {
        from_tun,
        to_tun,
        mtu,
    } = link;

    let health = Arc::new(PeerHealth::new());
    let inbound = {
        let conn = conn.clone();
        let to_tun = to_tun.clone();
        let activity = Activity::new();
        // 单对端调试模式不开放端口映射：白名单为空，行为与以前完全一致
        let allowed = Arc::new(Vec::new());
        let health = health.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_inbound(conn, to_tun, allowed, activity, health).await {
                tracing::debug!("[tun] 接收循环结束: {e:#}");
            }
        })
    };

    let route = Route::Single {
        conn,
        health: health.clone(),
    };
    let result = pump(route, from_tun, to_tun, local, mtu).await;
    inbound.abort();
    result
}

/// 多对端组网：按目标虚拟地址选连接。
///
/// `local` 是本机的虚拟地址，用来判断 ICMP echo 要不要就地应答——
/// 远端不开 `ip_forward` 也能 ping 通，这是用户判断"连没连上"的第一反应。
pub async fn run_mesh(
    links: Arc<MeshLinks>,
    from_tun: mpsc::Receiver<Vec<u8>>,
    local: Ipv4Addr,
    mtu: u16,
) -> Result<()> {
    let to_tun = links.to_tun.clone();
    pump(
        Route::Mesh(links),
        from_tun,
        to_tun,
        local,
        usize::from(mtu),
    )
    .await
}

enum Route {
    Single {
        conn: Connection,
        health: Arc<PeerHealth>,
    },
    Mesh(Arc<MeshLinks>),
}

impl Route {
    async fn conn_for(&self, dst: Ipv4Addr) -> Option<MeshPeer> {
        match self {
            Self::Single { conn, health } => Some(MeshPeer {
                conn: conn.clone(),
                health: health.clone(),
            }),
            Self::Mesh(links) => links.conn_for(dst).await,
        }
    }

    /// 连接失效时通知会话层。单对端调试模式没有会话循环，交给调用方自己处理。
    async fn report_dead(&self, ip: Ipv4Addr, peer: &MeshPeer, reason: &str) {
        let Self::Mesh(links) = self else { return };
        if peer.health.mark_dead() {
            links.mark_dead(ip, &peer.conn, reason).await;
        }
    }
}

/// 流表的值：连接、发送队列、这条流所属对端的健康度。
///
/// 队列而不是 `SendStream`：写动作交给 [`FlowWriter`]，主循环只入队。
type FlowValue = (Connection, mpsc::Sender<Vec<u8>>, Arc<PeerHealth>);

async fn pump(
    route: Route,
    mut from_tun: mpsc::Receiver<Vec<u8>>,
    to_tun: mpsc::Sender<Vec<u8>>,
    local: Ipv4Addr,
    mtu: usize,
) -> Result<()> {
    let mut flows: FlowTable<FlowValue> = FlowTable::new(FLOW_IDLE, FLOW_CAPACITY);

    // 用固定 deadline 而不是每轮重建的新 sleep：后者会被源源不断的包
    // 反复取消重建，大流量时扫描永远不跑，空闲流永远回收不掉。
    let mut sweep = tokio::time::interval(SWEEP_INTERVAL);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    sweep.tick().await;

    loop {
        tokio::select! {
            packet = from_tun.recv() => {
                let Some(packet) = packet else { break };
                // 这里不许出现无限等待：入队是 try_send，写帧在独立任务里带超时。
                // 任何一条流卡住都只能拖累它自己，不能停住整个转发循环。
                if let Err(e) = dispatch(&route, &mut flows, &to_tun, local, packet, mtu).await {
                    tracing::debug!("[tun] 转发失败: {e:#}");
                }
            }
            _ = sweep.tick() => {
                for (key, (_, tx, _)) in flows.sweep(Instant::now()) {
                    tracing::trace!("[tun] 回收空闲流 {key:?}");
                    // 关掉队列，writer 收尾时自己 reset
                    drop(tx);
                }
                if let Route::Mesh(links) = &route {
                    links.reap_stalled().await;
                }
            }
        }
    }

    for (_, (_, tx, _)) in flows.drain() {
        drop(tx);
    }
    Ok(())
}

async fn dispatch(
    route: &Route,
    flows: &mut FlowTable<FlowValue>,
    to_tun: &mpsc::Sender<Vec<u8>>,
    local: Ipv4Addr,
    mut packet: Vec<u8>,
    mtu: usize,
) -> Result<()> {
    let Some(parsed) = ip::parse(&packet) else {
        return Ok(());
    };

    // 出站包也算活跃：会话循环据此决定轮询档位和要不要断链
    if let Route::Mesh(links) = route {
        links.activity.touch();
    }

    // `IpPacket` 借着 `packet`，而下面要把 `packet` 移进发送队列，
    // 所以先把用到的字段拷出来（都是 Copy，没有额外开销）。
    let dst = parsed.dst;

    // 1. 打自己的 ping 就地应答，不打扰对端。回包也走 try_send：
    //    为了一个 ICMP 把整条转发循环堵住不值得。
    if dst == local && ip::is_echo_request(&parsed) {
        if let Some(reply) = ip::echo_reply(&parsed) {
            let _ = to_tun.try_send(reply);
        }
        return Ok(());
    }

    if packet.len() > mtu {
        bail!("包比 MTU 大（{} > {mtu}），内核本应分片", packet.len());
    }

    // 2. 已有流：入队即返回，绝不等网络
    let key = FlowKey::new(parsed.proto, parsed.src, dst, parsed.ports);
    let now = Instant::now();
    if flows.contains(&key) {
        let (_, tx, health) = flows.get_mut(&key, now).expect("刚判断过存在");
        health.note_queued();
        match tx.try_send(packet) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Full(_)) => {
                // 队列满说明这条流的写动作跟不上。丢包让内层 TCP 退避重传，
                // 比让主循环等它强得多。
                health.note_unqueued(1);
                tracing::trace!("[tun] {key:?} 发送队列满，丢包");
                return Ok(());
            }
            Err(TrySendError::Closed(back)) => {
                // writer 已经退出了（写超时/出错）。这条流作废，下面重开一条，
                // 把这个包挂在新的流上——不必等 TCP 重传。
                health.note_unqueued(1);
                flows.remove(&key);
                packet = back;
            }
        }
    }

    // 3. 这个目标没有直连：叫会话循环立刻去打通它，这个包先丢（重传会补上）
    let Some(peer) = route.conn_for(dst).await else {
        if let Route::Mesh(links) = route {
            links.wake_peer(dst).await;
        }
        tracing::debug!("[tun] 目标 {} 没有直连，已唤醒打洞", dst);
        return Ok(());
    };

    // 已经判死的连接不再往上写，催一次重建就走
    if peer.health.is_dead() {
        if let Route::Mesh(links) = route {
            links.wake_peer(dst).await;
        }
        return Ok(());
    }

    // 4. 新开一条流。唯一还可能等的地方，用超时兜住：
    //    流配额用尽时 open_bi 会一直挂着，不能让它拖住主循环。
    let (send_stream, mut recv) =
        match tokio::time::timeout(OPEN_TIMEOUT, peer.conn.open_bi()).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => {
                peer.health.note_fail();
                if peer.health.broken() {
                    route.report_dead(dst, &peer, "打开流失败").await;
                }
                return Err(e).with_context(|| format!("向 {} 打开双向流失败", dst));
            }
            Err(_) => {
                peer.health.note_fail();
                if peer.health.broken() {
                    route.report_dead(dst, &peer, "打开流超时").await;
                }
                bail!("向 {} 打开双向流超时", dst);
            }
        };

    // 首字节和首包都交给 writer：主循环只负责建流，不承担任何写阻塞
    let (tx, rx) = mpsc::channel::<Vec<u8>>(FLOW_QUEUE);
    let links = match route {
        Route::Mesh(links) => Some(Arc::downgrade(links)),
        Route::Single { .. } => None,
    };
    tokio::spawn(
        FlowWriter {
            send: send_stream,
            rx,
            health: peer.health.clone(),
            ip: dst,
            conn: peer.conn.clone(),
            links,
        }
        .run(),
    );

    peer.health.note_queued();
    if tx.try_send(packet).is_err() {
        peer.health.note_unqueued(1);
    }

    // 对端可能主动关流：等它，顺便把错误暴露到日志
    tokio::spawn(async move {
        let mut buf = [0u8; 64];
        let _ = recv.read(&mut buf).await;
    });

    if let Some((old, (_, old_tx, _))) = flows.insert(key, (peer.conn, tx, peer.health), now) {
        drop(old_tx);
        tracing::debug!("[tun] 流表满，淘汰 {old:?}");
    }
    Ok(())
}

/// 一条流的写任务：把队列里的帧写进 QUIC 流，写不动就收尾。
///
/// 它跑在独立任务里，所以 `write_all` 挂起时只挂住它自己。写帧超时或出错，
/// 就把这条流 `reset` 掉——内层 TCP 会因为收不到 ACK 重传，主循环下一次
/// `try_send` 会发现队列已关，立刻重开一条新流接上。
struct FlowWriter {
    send: SendStream,
    rx: mpsc::Receiver<Vec<u8>>,
    health: Arc<PeerHealth>,
    ip: Ipv4Addr,
    conn: Connection,
    links: Option<Weak<MeshLinks>>,
}

impl FlowWriter {
    async fn run(mut self) {
        // 首字节声明这是 IP 包流
        let mut failure: Option<&'static str> = None;
        match tokio::time::timeout(WRITE_TIMEOUT, self.send.write_all(&[KIND_IP])).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::debug!("[tun] {} 写流类型失败: {e}", self.ip);
                failure = Some("写流类型失败");
            }
            Err(_) => {
                tracing::debug!("[tun] {} 写流类型超时", self.ip);
                failure = Some("写流类型超时");
            }
        }

        while failure.is_none() {
            let Some(packet) = self.rx.recv().await else {
                break;
            };
            let written =
                tokio::time::timeout(WRITE_TIMEOUT, write_frame(&mut self.send, &packet)).await;
            match written {
                Ok(Ok(())) => self.health.note_write_ok(),
                Ok(Err(e)) => {
                    tracing::debug!("[tun] {} 写帧失败: {e:#}", self.ip);
                    failure = Some("写帧失败");
                }
                Err(_) => {
                    tracing::debug!("[tun] {} 写帧超时（{WRITE_TIMEOUT:?}）", self.ip);
                    failure = Some("写帧超时");
                }
            }
        }

        match failure {
            Some(reason) => self.fail(reason).await,
            None => {
                // 队列被关掉（流空闲回收 / 连接被替换）：安静收尾
                let _ = self.send.reset(0u32.into());
            }
        }
    }

    /// 写不出去：清账、关流，必要时判整个对端失效。
    async fn fail(&mut self, reason: &'static str) {
        // 队列里还没写的 + 当前这一帧，都从积压里扣掉，别让它们继续顶着
        let left = u32::try_from(self.rx.len()).unwrap_or(u32::MAX);
        self.health.note_unqueued(left.saturating_add(1));
        let _ = self.send.reset(0u32.into());
        self.health.note_fail();

        if !self.health.broken() {
            return;
        }
        let Some(links) = self.links.as_ref().and_then(Weak::upgrade) else {
            return;
        };
        if self.health.mark_dead() {
            links.mark_dead(self.ip, &self.conn, reason).await;
        }
    }
}

async fn write_frame(send: &mut SendStream, packet: &[u8]) -> Result<()> {
    let len = u16::try_from(packet.len()).context("单个 IP 包超过 64KB")?;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(packet).await?;
    Ok(())
}

/// 接收方向：对端每开一条流就是一个新 flow。
///
/// 同一条连接上会混着两种流：`KIND_IP`（IP 包，TUN 用）和 `KIND_TCP`
/// （端口映射，本机当局域网出口时用）。分派必须发生在**同一个** accept 循环里，
/// 否则两个循环会互相抢流，抢到不认识的类型只能丢弃。
async fn serve_inbound(
    conn: Connection,
    to_tun: mpsc::Sender<Vec<u8>>,
    allowed: Arc<Vec<SocketAddr>>,
    activity: Activity,
    health: Arc<PeerHealth>,
) -> Result<()> {
    loop {
        let (send, mut recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::debug!("[tun] 不再接受流: {e}");
                return Ok(());
            }
        };
        let to_tun = to_tun.clone();
        let activity = activity.clone();
        let allowed = allowed.clone();
        let health = health.clone();
        tokio::spawn(async move {
            let mut kind = [0u8; 1];
            if let Err(e) = recv.read_exact(&mut kind).await {
                tracing::trace!("[tun] 读流类型失败: {e}");
                return;
            }
            match kind[0] {
                KIND_IP => {
                    if let Err(e) = pump_stream(&mut recv, to_tun, activity, health).await {
                        tracing::trace!("[tun] 流结束: {e:#}");
                    }
                    drop(send);
                }
                super::KIND_TCP => {
                    if let Err(e) =
                        super::handle_tcp_flow(super::KIND_TCP, send, recv, &allowed).await
                    {
                        tracing::debug!("[tun] 端口映射流结束: {e:#}");
                    }
                }
                other => {
                    tracing::debug!("[tun] 未知流类型 {other}，丢弃");
                    drop(send);
                }
            }
        });
    }
}

async fn pump_stream(
    recv: &mut RecvStream,
    to_tun: mpsc::Sender<Vec<u8>>,
    activity: Activity,
    health: Arc<PeerHealth>,
) -> Result<()> {
    loop {
        let mut len = [0u8; 2];
        match recv.read_exact(&mut len).await {
            Ok(()) => {}
            // 读到 0 字节就是正常结束：对端把这条流关了
            Err(ReadExactError::FinishedEarly(0)) => return Ok(()),
            Err(e) => return Err(e).context("读帧长度失败"),
        }
        let len = usize::from(u16::from_be_bytes(len));
        if len == 0 || len > READ_BUF * 16 {
            bail!("帧长度非法：{len}");
        }
        let mut buf = vec![0u8; len];
        recv.read_exact(&mut buf).await.context("读帧失败")?;
        activity.touch();
        health.note_read_ok();
        // 绝不 await：这里的反压会顺着 QUIC 流控传导回对端的发送循环，
        // 两个方向一起卡死。队列满就丢包，内层 TCP 会重传。
        match to_tun.try_send(buf) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                tracing::trace!("[tun] 回程队列满，丢包");
            }
            Err(TrySendError::Closed(_)) => return Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_never_underflows() {
        let h = PeerHealth::new();
        h.note_unqueued(5);
        assert_eq!(h.pending.load(Ordering::Relaxed), 0);

        h.note_queued();
        h.note_write_ok();
        assert_eq!(h.pending.load(Ordering::Relaxed), 0);
        // 多扣几次也不能回到 u32::MAX
        h.note_unqueued(3);
        assert_eq!(h.pending.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn no_pending_means_no_stall() {
        let h = PeerHealth::new();
        // 从建立到现在一帧都没发过，但也没有包排队：不能判死
        std::thread::sleep(Duration::from_millis(5));
        assert!(!h.stalled(), "没积压就不是停滞");
    }

    #[test]
    fn queued_but_never_written_is_stalled() {
        let h = PeerHealth::new();
        h.note_queued();
        std::thread::sleep(Duration::from_millis(2));
        // 有积压、零进展：阈值放到 0 就能立刻观测到
        assert!(h.stalled_after(Duration::ZERO), "有积压且零进展就该判停滞");

        // 写成功一帧后积压清零，即使阈值是 0 也不能再报停滞
        h.note_write_ok();
        assert!(!h.stalled_after(Duration::ZERO));
    }

    #[test]
    fn three_failures_break_the_link() {
        let h = PeerHealth::new();
        h.note_fail();
        assert!(!h.broken());
        h.note_fail();
        assert!(!h.broken());
        h.note_fail();
        assert!(h.broken(), "连续三条流失败就该换连接");
        h.note_read_ok();
        assert!(!h.broken(), "收到对端数据说明链路是通的，计数要清掉");
    }

    #[test]
    fn write_success_clears_failure_streak() {
        let h = PeerHealth::new();
        h.note_fail();
        h.note_fail();
        h.note_queued();
        h.note_write_ok();
        assert!(!h.broken());
        assert_eq!(h.pending.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn dead_is_reported_only_once() {
        let h = PeerHealth::new();
        assert!(h.mark_dead(), "第一个调用者拿到 true");
        assert!(!h.mark_dead(), "后续调用者拿到 false，避免重复重建");
        assert!(h.is_dead());
    }
}
