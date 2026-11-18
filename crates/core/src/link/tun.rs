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
//! # 失效判据（A 方案，第二版）
//!
//! 不新增任何探测包，判据只看 **QUIC 自己的统计**：
//!
//! - 我方还在发（`udp_tx` 在涨），对端却连续 [`PEER_SILENT`] 一个 UDP 包都没回
//!   （`udp_rx` 不动）→ 链路黑洞，摘表、关连接、叫会话循环重拨。
//! - 流级只做"废掉这一条流"，不判连接死活：单帧写超过 [`WRITE_TIMEOUT`] 就
//!   `reset`，主循环换一条新流继续；有积压却 [`STALL_TIMEOUT`] 零进展才兜底判死。
//!
//! 第一版拿"本地写成功"当判据（连败 3 条流就换连接），实测不可靠：一条流被
//! reset 后主循环立刻在同一条连接上开新流，新流自带全新的 1.25MB 流控额度，
//! 前几帧必然"写成功"——而它们可能一帧都没到对端，于是连败计数被反复清零，
//! 黑洞期间一条判据都不触发，全靠 QUIC 默认的 30 秒 idle timeout 收场。
//! 那个判据还会误杀：6 秒抖动就能凑够 3 条超时流，把本来能自愈的连接掐掉。

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
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
/// 同时存在的流上限。
///
/// 刻意低于 `tls.rs` 里给对端的 `max_concurrent_bidi_streams`（256）：
/// 自己先到 200 就开始回收空闲流，把余量留给对端发起的方向。
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
/// 有包排队却这么久没写出一帧 → 整条连接的流控停死（兜底，正常判据是下面那条）。
const STALL_TIMEOUT: Duration = Duration::from_secs(30);
/// 我方还在发，对端却这么久没回任何 UDP 包 → 判死。
///
/// 8 秒：够 QUIC 在丢包重传、路径切换（WiFi↔4G）里缓过来，又能把黑洞的
/// 发现时间压到「8 秒 + 一个扫描周期」。
const PEER_SILENT: Duration = Duration::from_secs(8);
/// 判断"我方还在发"的回看窗口：超过这么久没发过包，就无从判断对端死活。
///
/// 必须**明显小于 keepalive 间隔**（15 秒），否则空闲链路会被误杀：一个
/// keepalive 的 PING/ACK 发生在 t=0，下一次要等到 t=15，中间 8~12 秒里
/// "rx 没动、tx 也没动"看着就像黑洞。取 4 个扫描周期。
///
/// 黑洞期间这个窗口不会关：未确认的数据会被 QUIC 按 RTO 重传（0.3/0.9/2.1/4.5 秒…），
/// `udp_tx` 一直在涨，所以"还在发"始终成立。
const SEND_WINDOW: Duration = Duration::from_secs(6);
/// 失效扫描周期。2 秒比 5 秒多花不了什么，但直接决定判死的滞后长度。
const SWEEP_INTERVAL: Duration = Duration::from_secs(2);

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
/// 判据两层，**连接死活只认"对端有没有回包"**：
///
/// - 连接级（唯一可信信号）：我方还在发，对端连续 [`PEER_SILENT`] 没回任何
///   UDP 包 → 黑洞。数据来自 `conn.stats()` 的 UDP 计数，不额外发探测包。
/// - 流级（只废流，不判连接）：单帧写超过 [`WRITE_TIMEOUT`] 就换一条流；
///   有积压却 [`STALL_TIMEOUT`] 零进展才兜底判死（对端在收但不消费）。
///
/// "写成功"不能当判据：一条流被 reset 后，主循环立刻在同一条连接上开新流，
/// 新流自带全新的流控额度，前几帧必然写成功——哪怕一帧都没出过网卡。
struct PeerHealth {
    base: Instant,
    /// 最后一次成功写完一帧；也用作停滞计时的起点
    last_write_ms: AtomicU64,
    /// 已入队、还没写完的帧数
    pending: AtomicU32,
    /// 对端回包的采样状态（只有扫描线程读写）
    silence: std::sync::Mutex<Silence>,
    /// 已经判定失效（只告一次，避免多条流的 writer 同时触发重建）
    dead: AtomicBool,
}

/// 对端回包的采样状态。
#[derive(Default)]
struct Silence {
    tx: u64,
    rx: u64,
    /// 上一次 `rx` 增长的时刻
    rx_at_ms: u64,
    /// 上一次 `tx` 增长的时刻
    tx_at_ms: u64,
    /// 采过样之后我方至少发过一个包——一个包都没发过就无从判断对端死活
    sent: bool,
    started: bool,
}

impl PeerHealth {
    fn new() -> Self {
        Self {
            base: Instant::now(),
            last_write_ms: AtomicU64::new(0),
            pending: AtomicU32::new(0),
            silence: std::sync::Mutex::new(Silence::default()),
            dead: AtomicBool::new(false),
        }
    }

    fn now_ms(&self) -> u64 {
        self.base.elapsed().as_millis() as u64
    }

    fn note_queued(&self) {
        // 从"零积压"变成"有积压"时重启停滞计时。不重置的话，空闲很久之后
        // 入队的第一个包会拿着几十秒前的旧时间戳，被扫描当成"停滞 30 秒"杀掉。
        if self.pending.fetch_add(1, Ordering::Relaxed) == 0 {
            self.last_write_ms.store(self.now_ms(), Ordering::Relaxed);
        }
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
    }

    /// 采一次 QUIC 的 UDP 计数，判断对端是不是已经不理我们了。
    ///
    /// `tx`/`rx` 是连接建立以来的累计值（`conn.stats()` 的
    /// `udp_tx.datagrams` / `udp_rx.datagrams`）。返回 true = 判定失效。
    fn observe(&self, tx: u64, rx: u64) -> bool {
        self.observe_at(tx, rx, self.now_ms())
    }

    /// 同 [`Self::observe`]，但时间戳由调用方给（单测用假时间，免得真等 8 秒）。
    fn observe_at(&self, tx: u64, rx: u64, now_ms: u64) -> bool {
        let mut s = self.silence.lock().unwrap_or_else(|e| e.into_inner());
        if !s.started {
            *s = Silence {
                tx,
                rx,
                rx_at_ms: now_ms,
                tx_at_ms: now_ms,
                sent: false,
                started: true,
            };
            return false;
        }
        if rx > s.rx {
            s.rx = rx;
            s.rx_at_ms = now_ms;
        }
        if tx > s.tx {
            s.tx = tx;
            s.tx_at_ms = now_ms;
            s.sent = true;
        }
        if !s.sent {
            return false;
        }
        let sending = now_ms.saturating_sub(s.tx_at_ms) <= SEND_WINDOW.as_millis() as u64;
        let silent = now_ms.saturating_sub(s.rx_at_ms) >= PEER_SILENT.as_millis() as u64;
        sending && silent
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
    /// 每个对端上一次被唤醒的时刻（毫秒）；3 秒冷却，避免持续丢包把信令打成洪水。
    /// 按目的地址分开记：冷却不该被别的对端用掉。
    started: Instant,
    last_wake: Arc<std::sync::Mutex<HashMap<Ipv4Addr, u64>>>,
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
            last_wake: Arc::new(std::sync::Mutex::new(HashMap::new())),
            allowed: Arc::new(allowed),
            notice: OnceLock::new(),
        })
    }

    /// 会话循环启动时挂上唤醒通道。没挂之前丢包就是丢包，行为和以前一致。
    pub async fn set_wake(&self, tx: mpsc::Sender<Ipv4Addr>) {
        *self.wake.write().await = Some(tx);
    }

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
        {
            let Ok(mut last) = self.last_wake.lock() else {
                return;
            };
            if let Some(prev) = last.get(&ip) {
                if now.saturating_sub(*prev) < 3_000 {
                    return;
                }
            }
            last.insert(ip, now);
            // 表别无限长：过了冷却期的记录没有意义
            if last.len() > 4096 {
                last.retain(|_, at| now.saturating_sub(*at) < 60_000);
            }
        }
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
        if let Ok(mut last) = self.last_wake.lock() {
            last.insert(ip, self.started.elapsed().as_millis() as u64);
        }
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
            tokio::spawn(async move {
                if let Err(e) = serve_inbound(conn, to_tun, allowed, activity).await {
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

    /// 扫描所有对端：对端不回包、或有积压长时间零进展的，摘表并重拨。
    ///
    /// 依赖主循环还活着——所以必须先有"主循环不许等网络"的改造，否则主循环
    /// 自己卡住，这个扫描再也不会跑。
    pub async fn reap_unhealthy(&self) {
        let unhealthy: Vec<(Ipv4Addr, Connection, &'static str)> = {
            let peers = self.peers.read().await;
            peers
                .iter()
                .filter_map(|(ip, p)| {
                    if p.health.is_dead() {
                        return None;
                    }
                    // 连接级判据：我方在发、对端不回包
                    let stats = p.conn.stats();
                    if p.health
                        .observe(stats.udp_tx.datagrams, stats.udp_rx.datagrams)
                    {
                        return Some((*ip, p.conn.clone(), "对端 8 秒没有回包"));
                    }
                    // 兜底：对端在收包但不消费，流控彻底停死
                    if p.health.stalled() {
                        return Some((*ip, p.conn.clone(), "有包排队 30 秒写不出去"));
                    }
                    None
                })
                .collect()
        };
        for (ip, conn, reason) in unhealthy {
            let first = {
                let peers = self.peers.read().await;
                match peers.get(&ip) {
                    // 必须比对连接身份：快照与这里之间，这个 IP 可能已经被新连接
                    // 顶替，点亮新连接的 dead 标记会让它永远进不了扫描（假"已连接"）
                    Some(p) if p.conn.stable_id() == conn.stable_id() => p.health.mark_dead(),
                    _ => false,
                }
            };
            if first {
                self.mark_dead(ip, &conn, reason).await;
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
        tokio::spawn(async move {
            if let Err(e) = serve_inbound(conn, to_tun, allowed, activity).await {
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
                    links.reap_unhealthy().await;
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

    // 4. 建流也交给 writer：流配额用尽时 `open_bi` 会一直挂着，
    //    留在主循环里就等于把所有对端、所有流一起拖住。
    let (tx, rx) = mpsc::channel::<Vec<u8>>(FLOW_QUEUE);
    tokio::spawn(
        FlowWriter {
            rx,
            health: peer.health.clone(),
            ip: dst,
            conn: peer.conn.clone(),
        }
        .run(),
    );

    peer.health.note_queued();
    if tx.try_send(packet).is_err() {
        peer.health.note_unqueued(1);
    }

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
///
/// 注意它**不判连接死活**：本地写失败说明不了对端还在不在，摘连接是
/// [`MeshLinks::reap_unhealthy`] 按 QUIC 的对端回包计数决定的。
struct FlowWriter {
    rx: mpsc::Receiver<Vec<u8>>,
    health: Arc<PeerHealth>,
    ip: Ipv4Addr,
    conn: Connection,
}

impl FlowWriter {
    async fn run(mut self) {
        // 建流在这里等：配额用尽时只挂住这一条流，主循环照常收包
        let (mut send, mut recv) =
            match tokio::time::timeout(OPEN_TIMEOUT, self.conn.open_bi()).await {
                Ok(Ok(pair)) => pair,
                Ok(Err(e)) => {
                    tracing::debug!("[tun] {} 打开双向流失败: {e}", self.ip);
                    self.fail(None).await;
                    return;
                }
                Err(_) => {
                    tracing::debug!("[tun] {} 打开双向流超时（{OPEN_TIMEOUT:?}）", self.ip);
                    self.fail(None).await;
                    return;
                }
            };

        // 对端可能主动关流：等它，顺便把错误暴露到日志
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let _ = recv.read(&mut buf).await;
        });

        // 首字节声明这是 IP 包流
        let mut broken = false;
        match tokio::time::timeout(WRITE_TIMEOUT, send.write_all(&[KIND_IP])).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::debug!("[tun] {} 写流类型失败: {e}", self.ip);
                broken = true;
            }
            Err(_) => {
                tracing::debug!("[tun] {} 写流类型超时", self.ip);
                broken = true;
            }
        }

        while !broken {
            let Some(packet) = self.rx.recv().await else {
                break;
            };
            let written =
                tokio::time::timeout(WRITE_TIMEOUT, write_frame(&mut send, &packet)).await;
            match written {
                Ok(Ok(())) => self.health.note_write_ok(),
                Ok(Err(e)) => {
                    tracing::debug!("[tun] {} 写帧失败: {e:#}", self.ip);
                    broken = true;
                }
                Err(_) => {
                    tracing::debug!("[tun] {} 写帧超时（{WRITE_TIMEOUT:?}）", self.ip);
                    broken = true;
                }
            }
        }

        if broken {
            self.fail(Some(&mut send)).await;
        } else {
            // 队列被关掉（流空闲回收 / 连接被替换）：安静收尾
            let _ = send.reset(0u32.into());
        }
    }

    /// 写不出去：清账、关流，等内层重传。
    ///
    /// 这里**不判连接死活**——见 [`PeerHealth`] 的说明：写失败只说明这条流的
    /// 额度用完了，不能推出对端已经不在线。
    async fn fail(self, send: Option<&mut SendStream>) {
        // 队列里还没写的 + 当前这一帧，都从积压里扣掉，别让它们继续顶着
        let left = u32::try_from(self.rx.len()).unwrap_or(u32::MAX);
        self.health.note_unqueued(left.saturating_add(1));
        if let Some(send) = send {
            let _ = send.reset(0u32.into());
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
        tokio::spawn(async move {
            let mut kind = [0u8; 1];
            if let Err(e) = recv.read_exact(&mut kind).await {
                tracing::trace!("[tun] 读流类型失败: {e}");
                return;
            }
            match kind[0] {
                KIND_IP => {
                    if let Err(e) = pump_stream(&mut recv, to_tun, activity).await {
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
    fn dead_is_reported_only_once() {
        let h = PeerHealth::new();
        assert!(h.mark_dead(), "第一个调用者拿到 true");
        assert!(!h.mark_dead(), "后续调用者拿到 false，避免重复重建");
        assert!(h.is_dead());
    }

    // --- 对端回包判据（第二版） -------------------------------------------
    //
    // 这几个用例都喂假时间戳，不真等 8 秒：判据的核心是"我方在发、对端不回"，
    // 用真实时钟测就只能测到"测试挂了 8 秒还没死"。

    /// 涓流：我方零星在发，对端一个包都不回 → 8 秒后判死。
    #[test]
    fn silence_while_sending_kills_the_link() {
        let h = PeerHealth::new();
        // t=0 建立连接：tx/rx 都是 100
        assert!(!h.observe_at(100, 100, 0), "刚采样的第一轮不能判死");
        // t=1s 我方又发了几个包（对端仍无回应）
        assert!(!h.observe_at(106, 100, 1_000), "8 秒没到不能判死");
        // t=7.9s 还没到阈值
        assert!(!h.observe_at(112, 100, 7_900));
        // t=8s：对端整整 8 秒没回任何一个包，而我方一直在发 → 判死
        assert!(
            h.observe_at(118, 100, 8_000),
            "我方在发、对端 8 秒没回包，就该判死"
        );
    }

    /// 对端一直在回包 → 永远不判死，哪怕我们发了很久。
    #[test]
    fn replies_keep_the_link_alive() {
        let h = PeerHealth::new();
        let mut tx = 0u64;
        let mut rx = 0u64;
        let mut t = 0u64;
        for _ in 0..30 {
            t += 1_000;
            tx += 50;
            // 每个周期都有回包（ACK/数据）
            rx += 40;
            assert!(!h.observe_at(tx, rx, t), "对端一直在回包，不能判死");
        }
    }

    /// 发过一阵就彻底安静：过了 SEND_WINDOW 就不能再拿"对端没回"判死。
    ///
    /// 注意 8 秒那一刻判死是**对的**：我们发了包、对端一个回包都没有，
    /// 那就是黑洞。真正的空闲是"我们自己也没在发"，见下一个用例。
    #[test]
    fn long_idle_after_a_burst_is_not_judged() {
        let h = PeerHealth::new();
        assert!(!h.observe_at(0, 0, 0));
        assert!(!h.observe_at(5, 0, 500), "才 0.5 秒，不能判");
        // 最后一次发送在 t=0.5s；6 秒之后（t>6.5s）就不该再判了，哪怕对端一直没回
        for t in (8_500..300_000).step_by(5_000) {
            assert!(
                !h.observe_at(5, 0, t),
                "自己 6 秒以上没发过包，就不能用'对端不回'判死（t={t}）"
            );
        }
    }

    /// 空闲链路：15 秒一个 keepalive，PING 与 ACK 同时发生，中间什么都不发。
    ///
    /// 这是最容易被判据误杀的形态——两次 keepalive 之间的 8~12 秒里，
    /// "对端没回包"和"我们也没发包"同时成立，但链路完全健康。
    #[test]
    fn keepalive_spacing_is_not_a_blackhole() {
        let h = PeerHealth::new();
        assert!(!h.observe_at(0, 0, 0), "连接刚建立");
        let mut tx = 0u64;
        let mut rx = 0u64;
        let mut t = 0u64;
        for _ in 0..5 {
            t += 15_000;
            tx += 1; // keepalive PING
            rx += 1; // 对端的 ACK
            assert!(!h.observe_at(tx, rx, t));
            // 之后每 2 秒扫一次，一直到下一个 keepalive 之前
            for k in 1..7 {
                assert!(
                    !h.observe_at(tx, rx, t + k * 2_000),
                    "空闲链路的 keepalive 间隔不能被当成黑洞（t+{}s）",
                    k * 2
                );
            }
        }
    }

    /// 从没发过包的新连接，无论等多久都不能判死。
    #[test]
    fn never_sent_never_judged() {
        let h = PeerHealth::new();
        assert!(!h.observe_at(0, 0, 0));
        assert!(!h.observe_at(0, 0, 60_000), "一个包都没发过，凭什么判死");
    }

    /// 空闲很久之后入队的第一个包，不能被旧时间戳当成"停滞 30 秒"。
    #[test]
    fn first_packet_after_idle_is_not_stalled() {
        let h = PeerHealth::new();
        h.note_queued();
        h.note_write_ok(); // 模拟很久以前写过一帧
        std::thread::sleep(Duration::from_millis(5));
        h.note_queued(); // 空闲之后第一个包入队：计时必须从这一刻重新开始
        assert!(
            !h.stalled_after(Duration::from_millis(1)),
            "刚入队的包算停滞，会把健康连接杀掉"
        );
    }
}
