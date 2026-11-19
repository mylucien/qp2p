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
//! # 失效判据（A 方案，第三版）
//!
//! 不新增任何探测包，判据只看 **QUIC 自己的统计**：
//!
//! - 我方发出了**需要对方回应**的帧（`frame_tx.stream + frame_tx.ping` 在涨），
//!   而对端连续 [`PEER_SILENT`] 一个 UDP 包都没回（`udp_rx` 不动）→ 链路黑洞。
//! - 流级只做"废掉这一条流"，不判连接死活：单帧写超过 [`WRITE_TIMEOUT`] 就
//!   `reset`，主循环换一条新流继续；连续 [`STALL_TIMEOUT`] 每一次写都失败才兜底
//!   判死（对端 ACK 但不消费，连接级流控窗口关死）。
//!
//! ## 为什么不用"我方最近发过包 + 对端好久没回"
//!
//! 第二版就是这么写的，会误杀健康空闲连接。`silent` 量的是"距上次收到包多久"，
//! 空闲链路上那个时间戳本来就是十几秒前的（`rx_at` 只在扫描点更新）；keepalive
//! 的 PING 一发出，`sending` 立刻翻真，只要扫描点恰好落在"PING 已发、ACK 在途"
//! 那一个 RTT 里，健康连接当场被摘除。周期 15 秒、扫描 2 秒，相位一直在漂，
//! 撞上只是时间问题。
//!
//! 现在的判据记的是"**第一个没被回应的发包时刻**"：只有在我方发出需回应帧、
//! 且**同一轮扫描里没有任何回包**时才开表；一旦收到任何回包就清零。空闲链路
//! 上（哪怕只发了个 keepalive）ACK 一回来就清掉，不会累积。
//!
//! ## 为什么用 `frame_tx` 而不是 `udp_tx`
//!
//! `udp_tx.datagrams` 里混着**纯 ACK 帧**，而 QUIC 不对 ACK 回 ACK。TCP 传输
//! 刚结束、我方只回了一个延迟 ACK 的那一刻，如果 rx 与 tx 的增长落在相邻两轮
//! 扫描里，用 `udp_tx` 就会开出一张永远等不到回应的表，8 秒后误杀。只统计
//! `stream`（数据帧）和 `ping`（keepalive / PTO / MTU 探测）就不会：这两类都
//! 必须被对端 ACK。
//!
//! 代价是漏算 `max_data`、`reset_stream` 这类也需回应的帧 —— 方向是少判，
//! 不会误杀，可以接受。
//!
//! 第一版拿"本地写成功"当判据（连败 3 条流就换连接）更不可靠：一条流被 reset
//! 后主循环立刻在同一条连接上开新流，新流自带全新的 1.25MB 流控额度，前几帧
//! 必然"写成功"——而它们可能一帧都没到对端，于是连败计数被反复清零，黑洞期间
//! 一条判据都不触发，全靠 QUIC 默认的 30 秒 idle timeout 收场。那个判据还会
//! 误杀：6 秒抖动就能凑够 3 条超时流，把本来能自愈的连接掐掉。

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use quinn::{Connection, ReadExactError, RecvStream, SendStream, Side};
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
/// 连续写失败这么久 → 整条连接的流控停死（兜底，正常判据是下面那条）。
///
/// 判的是"从第一次写失败起，中间一次成功的写都没有"。不能用"积压 + 零进展"
/// 代替：`FlowWriter::fail` 会把积压清账，下一个包入队又从零开始算。
const STALL_TIMEOUT: Duration = Duration::from_secs(30);
/// 写失败窗口的"新鲜度"要求：最近一次失败必须落在这么久以内，窗口才算数。
///
/// 真停死时，一条流每 [`WRITE_TIMEOUT`] 就失败一次，`last_fail` 会被不断刷新；
/// 反过来，失败之后一直没有新的写入，只说明这条链路没人用了，不能判死。
/// 取 2×[`WRITE_TIMEOUT`] + 一个[`SWEEP_INTERVAL`]：留够一次重试加一轮扫描的余量，
/// 稀疏流量（失败间隔超过它）也只是把检出推迟到下一次失败，不会漏。
const STALL_GRACE: Duration = Duration::from_secs(8);
/// 我方发出了需要回应的帧，对端却这么久没有任何 UDP 回包 → 判死。
///
/// 8 秒：够 QUIC 在丢包重传、路径切换（WiFi↔4G）里缓过来，又能把黑洞的
/// 发现时间压到「8 秒 + 一个扫描周期」。
const PEER_SILENT: Duration = Duration::from_secs(8);
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
/// - 连接级（唯一可信信号）：我方发出了需要对方回应的帧，对端连续
///   [`PEER_SILENT`] 没回任何 UDP 包 → 黑洞。数据来自 `conn.stats()`，不额外
///   发探测包。
/// - 流级（只废流，不判连接）：单帧写超过 [`WRITE_TIMEOUT`] 就换一条流；
///   连续 [`STALL_TIMEOUT`] 每一次写都失败才兜底判死（对端 ACK 但不消费）。
///
/// "写成功"不能当判据：一条流被 reset 后，主循环立刻在同一条连接上开新流，
/// 新流自带全新的流控额度，前几帧必然写成功——哪怕一帧都没出过网卡。
struct PeerHealth {
    base: Instant,
    /// 连续写失败的起点，[`NO_FAIL`] 表示当前没有在失败。
    ///
    /// 单独记这个窗口，不复用"积压"：`FlowWriter::fail` 会把积压清账，
    /// 下一个包入队又从零算起，`pending > 0 且 30 秒零进展` 这个组合
    /// 在单流下永远凑不齐（多流并发时才偶尔成立）。
    fail_since_ms: AtomicU64,
    /// 最近一次写失败的时刻，[`NO_FAIL`] 表示当前没有在失败。
    ///
    /// 光有起点不够：一次写失败之后如果整段时间没有任何写入（用户停手、
    /// 流被回收），窗口会一直挂着，30 秒后把一条健康的连接判死——对端明明
    /// 还在好好回 keepalive 的 ACK。只有"还在持续失败"才算停死。
    last_fail_ms: AtomicU64,
    /// 对端回包的采样状态（只有扫描线程读写）
    silence: std::sync::Mutex<Silence>,
    /// 已经判定失效（只告一次，避免多条流的 writer 同时触发重建）
    dead: AtomicBool,
}

/// `fail_since_ms` 的哨兵。`0` 是合法的时刻（连接刚建就失败），不能拿来当"没有失败"。
const NO_FAIL: u64 = u64::MAX;

/// 从 QUIC 统计里取出"对端必须回应"的发包计数。
///
/// 只算 `stream`（数据帧）和 `ping`（keepalive、PTO 探测、MTU 探测）——这两种
/// 对端必须回 ACK。**不**算 `acks`：QUIC 不对纯 ACK 回 ACK，算进去就会在
/// "我方只回了延迟 ACK"的时刻开出一张永远等不到回应的表，8 秒后误杀健康连接。
///
/// 抽成函数是为了能测：`observe_at` 的单测喂的是数字，测不到"取哪个计数"。
fn needing_reply(stats: &quinn::ConnectionStats) -> u64 {
    stats.frame_tx.stream + stats.frame_tx.ping
}

/// 对端回包的采样状态。
///
/// 只保留一个判据：**第一个没被回应的发包时刻**。
///
/// 不能用"上次收到包是多久前"——空闲链路上那个时间戳本来就陈旧，keepalive
/// 一发就会撞上，健康连接被误杀。
#[derive(Default)]
struct Silence {
    tx: u64,
    rx: u64,
    /// 我方发出了需回应的帧、而对方还没回任何包的那个时刻。
    /// `None` = 当前没有被吊着的发包，不判死。
    unanswered_since_ms: Option<u64>,
    started: bool,
}

impl PeerHealth {
    fn new() -> Self {
        Self {
            base: Instant::now(),
            fail_since_ms: AtomicU64::new(NO_FAIL),
            last_fail_ms: AtomicU64::new(NO_FAIL),
            silence: std::sync::Mutex::new(Silence::default()),
            dead: AtomicBool::new(false),
        }
    }

    fn now_ms(&self) -> u64 {
        self.base.elapsed().as_millis() as u64
    }

    fn note_write_ok(&self) {
        // 写成功就清窗口。注意这会被"新流自带额度"骗一次：一条流 reset 后
        // 新流前几帧必然写得出去。真正的兜底要等连接级流控窗口关死、
        // 所有流都写不动时才开始计时——这正是这条判据能覆盖的场景。
        self.fail_since_ms.store(NO_FAIL, Ordering::Relaxed);
        self.last_fail_ms.store(NO_FAIL, Ordering::Relaxed);
    }

    /// 记一次写失败。只有第一个失败者能定起点，后来的失败不能把它往后推；
    /// 但每次失败都要刷新"最近一次失败"，否则持续失败会被当成空闲。
    ///
    /// 起点唯一的例外是**过期**：上一个窗口已经作废（最近一次失败早于
    /// [`STALL_GRACE`]）或已被写成功清掉时，这次失败要重新起表。否则
    /// "t=1s 失败一次 → 空闲 300 秒 → t=300s 又瞬时失败一次"会让 1 秒前
    /// 的旧起点当场满足 30 秒条件，把一条健康连接判死。
    fn note_fail(&self) {
        let now = self.now_ms();
        let prev = self.last_fail_ms.load(Ordering::Relaxed);
        self.last_fail_ms.store(now, Ordering::Relaxed);
        let expired = prev == NO_FAIL || now.saturating_sub(prev) > STALL_GRACE.as_millis() as u64;
        if expired {
            self.fail_since_ms.store(now, Ordering::Relaxed);
            return;
        }
        let _ =
            self.fail_since_ms
                .compare_exchange(NO_FAIL, now, Ordering::Relaxed, Ordering::Relaxed);
    }

    /// 采一次 QUIC 统计，判断对端是不是已经不理我们了。
    ///
    /// `tx` = `conn.stats().frame_tx.stream + frame_tx.ping`，只统计**需要对方
    /// 回应**的帧（数据帧、keepalive/PTO/MTU 探测的 PING）；故意不算 `acks`，
    /// 因为 QUIC 不对纯 ACK 回 ACK，算进去会开出永远等不到回应的表。
    ///
    /// `rx` = `conn.stats().udp_rx.datagrams`，对端任何回包（含纯 ACK）都算活着。
    ///
    /// 返回 true = 判定失效。
    fn observe(&self, tx: u64, rx: u64) -> bool {
        self.observe_at(tx, rx, self.now_ms())
    }

    /// 同 [`Self::observe`]，但时间戳由调用方给（单测用假时间，免得真等 8 秒）。
    fn observe_at(&self, tx: u64, rx: u64, now_ms: u64) -> bool {
        let mut s = self.silence.lock().unwrap_or_else(|e| e.into_inner());
        if !s.started {
            // 首次采样只建基线：握手阶段的帧数已经很多，拿来判死会当场误杀
            *s = Silence {
                tx,
                rx,
                unanswered_since_ms: None,
                started: true,
            };
            return false;
        }
        let rx_grew = rx > s.rx;
        let tx_grew = tx > s.tx;
        s.rx = rx;
        s.tx = tx;

        if rx_grew {
            // 收到任何回包：清零，且**本轮不重开**。
            // 同一轮里 rx 和 tx 一起涨，说明"上次发的、这次回的"配上了，
            // 重新开表会让空闲链路的 keepalive 每轮都开一次，8 秒后误杀。
            s.unanswered_since_ms = None;
        } else if tx_grew && s.unanswered_since_ms.is_none() {
            // 发了需要回应的帧，而这一轮一个回包都没有 → 从这一刻开始计
            s.unanswered_since_ms = Some(now_ms);
        }

        match s.unanswered_since_ms {
            Some(t) => now_ms.saturating_sub(t) >= PEER_SILENT.as_millis() as u64,
            None => false,
        }
    }

    /// 连续写失败超过 [`STALL_TIMEOUT`]：每一条流都写不动，内层重传也没用。
    ///
    /// 覆盖"对端 ACK 但不消费"：那时连接级流控窗口会关死，所有流同时写不动，
    /// 而 QUIC 还在回 ACK，连接级判据（对端不回包）不会触发。
    ///
    /// 还要求窗口是**新鲜的**（最近一次失败在 [`STALL_GRACE`] 以内）：一次写
    /// 失败之后整整 30 秒没有任何写入，只能说明这条链路没人用了，不是停死。
    fn write_failing(&self) -> bool {
        self.write_failing_for(STALL_TIMEOUT)
    }

    /// 同 [`Self::write_failing`]，但可指定阈值（测试用短阈值，免得真等 30 秒）。
    fn write_failing_for(&self, limit: Duration) -> bool {
        let since = self.fail_since_ms.load(Ordering::Relaxed);
        if since == NO_FAIL {
            return false;
        }
        let last = self.last_fail_ms.load(Ordering::Relaxed);
        if last == NO_FAIL {
            // 读 since 之后、读 last 之前被 `note_write_ok` 清掉了：
            // `now - NO_FAIL` 会饱和成 0，看起来像"刚刚失败过"，必须显式挡掉。
            return false;
        }
        let now = self.now_ms();
        // 窗口过期：这段时间根本没有写入尝试，判不了死
        if now.saturating_sub(last) > STALL_GRACE.as_millis() as u64 {
            return false;
        }
        now.saturating_sub(since) > limit.as_millis() as u64
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
    /// 这条是本机拨的还是对端拨的（`Connection::side()`），选边用
    dialed_by_us: bool,
    /// 对端在认证里声明了 [`crate::peer::auth::CAP_DEDUPE`]
    dedupe: bool,
}

/// [`MeshLinks::attach`] 的结果。
pub enum Attach {
    /// 挂上了。`replaced` 是被顶掉的旧连接——调用方必须在**标记新连接之后**
    /// 再关它，否则旧连接的 `closed()` 回调会抢在标记前匹配上当时的
    /// `conn_id`，把 `connected` 短暂清成 false。
    Accepted { replaced: Option<Connection> },
    /// 输给了表里那条重复连接：调用方直接关掉这条，不要动状态。
    Rejected,
}

/// 选边只在**两端都声明**了能力、且表里那条还活着时才生效。
///
/// 只升一端时必须整体退回旧行为：新版单方面选边、旧版仍旧"后到顶替"，
/// 两者在很宽的相位区间里会选出不同的一条——那比升级前更糟（失败率从
/// 个位数升到约一半）。
fn dedupe_enabled(old_alive: bool, old_dedupe: bool, new_dedupe: bool) -> bool {
    old_alive && old_dedupe && new_dedupe
}

/// 两条重复连接里该不该保留**新到的那条**。
///
/// 规则：**拨号方 node_id 较小**的那条赢。两端各自用同一个规则判断，不论
/// 到达顺序如何都会留下同一条——这正是它比"后到顶替"强的地方。
///
/// `None` = 两条都是同一端拨的（同端并发拨号），规则分不出胜负，
/// 退回"后到顶替"。
fn duplicate_keeps_new(
    old_dialed_by_us: bool,
    new_dialed_by_us: bool,
    my_id: &str,
    peer_id: &str,
) -> Option<bool> {
    if old_dialed_by_us == new_dialed_by_us {
        return None;
    }
    // 新连接是拨号方拨的 → 它赢当且仅当拨号方 id 更小
    Some(new_dialed_by_us == (my_id < peer_id))
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
    /// 同一个虚拟 IP 已有旧连接时直接替换（对端重启或 NAT 重新映射都会这样）。
    /// 唯一的例外是**两端同时重拨**：它在同一时刻各建一条，如果不选边，
    /// 两端会各留一条、又互相把对方那条关掉，直连全灭。所以两条都是新建立
    /// 的重复连接时，按 [`duplicate_keeps_new`] 选边。
    ///
    /// 选边和插入必须在**同一个写锁**里完成：先只读判断、再单独插入的话，
    /// 两个 `on_connected` 同时到达会各自看到"表里没有旧连接"，两条都留下。
    ///
    /// **没有年龄窗口**：任何一次打洞都是从"mesh 里没有这个对端"开始的
    /// （`should_dial` 与 `answer_punch` 都先看 `connected`），所以走到这里时
    /// 表里若已有一条，只可能是这次打洞期间新建立的重复连接。加窗口反而会在
    /// 两端各自判定"是否新鲜"的边界上制造不对称，重新引入同类失败。
    pub async fn attach(
        self: &Arc<Self>,
        ip: Ipv4Addr,
        conn: Connection,
        my_id: &str,
        peer_id: &str,
        dedupe: bool,
    ) -> Attach {
        let dialed_by_us = conn.side() == Side::Client;
        let peer = MeshPeer {
            conn: conn.clone(),
            health: Arc::new(PeerHealth::new()),
            dialed_by_us,
            dedupe,
        };

        let replaced = {
            let mut peers = self.peers.write().await;
            match peers.insert(ip, peer) {
                None => None,
                Some(old) => {
                    // 同一条连接被重复挂上：把旧表项放回去，别重置它的健康统计
                    if old.conn.stable_id() == conn.stable_id() {
                        let _ = peers.insert(ip, old);
                        return Attach::Accepted { replaced: None };
                    }
                    // 已经关掉的旧连接不是竞争者：两端"关连接"和"摘表"是两个
                    // 监视任务，中间有极短的错位，别把新连接判给一条死连接。
                    let old_alive = old.conn.close_reason().is_none();
                    let verdict = if dedupe_enabled(old_alive, old.dedupe, dedupe) {
                        duplicate_keeps_new(old.dialed_by_us, dialed_by_us, my_id, peer_id)
                    } else {
                        None
                    };
                    if verdict == Some(false) {
                        // 输家：表项换回去，新连接交给调用方关掉
                        let _ = peers.insert(ip, old);
                        return Attach::Rejected;
                    }
                    tracing::debug!("[tun] {ip} 的连接已刷新，关闭旧连接");
                    old.health.mark_dead();
                    Some(old.conn)
                }
            }
        };

        self.spawn_reader(ip, conn);
        Attach::Accepted { replaced }
    }

    /// 为刚挂上的连接起接收循环与摘表监视。
    fn spawn_reader(self: &Arc<Self>, ip: Ipv4Addr, conn: Connection) {
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
        let watch = conn;
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
        conn.close(0u32.into(), b"unresponsive");
        tracing::warn!("[tun] 直连 {ip} 已失效（{reason}），准备重建");
        self.say(&format!("· 与 {ip} 的直连已失效，正在重建"));
        self.force_wake(ip).await;
    }

    /// 扫描所有对端：对端不回包、或连续写失败的，摘表并重拨。
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
                    // 连接级判据：我方发了需回应的帧、对端一个包都没回。
                    // 只算 stream + ping：纯 ACK 不需要对端回应，算进去会误杀
                    let stats = p.conn.stats();
                    if p.health
                        .observe(needing_reply(&stats), stats.udp_rx.datagrams)
                    {
                        return Some((*ip, p.conn.clone(), "对端 8 秒没有回包"));
                    }
                    // 兜底：对端在 ACK 但不消费，每一条流都写不动
                    if p.health.write_failing() {
                        return Some((*ip, p.conn.clone(), "连续 30 秒每次写都失败"));
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
                // 单连接模式不走 `attach`，选边相关的两个字段用不到
                dialed_by_us: false,
                dedupe: false,
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
        let (_, tx, _) = flows.get_mut(&key, now).expect("刚判断过存在");
        match tx.try_send(packet) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Full(_)) => {
                // 队列满说明这条流的写动作跟不上。丢包让内层 TCP 退避重传，
                // 比让主循环等它强得多。
                tracing::trace!("[tun] {key:?} 发送队列满，丢包");
                return Ok(());
            }
            Err(TrySendError::Closed(back)) => {
                // writer 已经退出了（写超时/出错）。这条流作废，下面重开一条，
                // 把这个包挂在新的流上——不必等 TCP 重传。
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

    let _ = tx.try_send(packet);

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

    /// 写不出去：关流、记一笔失败，等内层重传。
    ///
    /// 这里**不判连接死活**——见 [`PeerHealth`] 的说明：写失败只说明这条流的
    /// 额度用完了，不能推出对端已经不在线。连续失败到 [`STALL_TIMEOUT`]
    /// 才由扫描统一判（[`PeerHealth::write_failing`]）。
    async fn fail(self, send: Option<&mut SendStream>) {
        if let Some(send) = send {
            let _ = send.reset(0u32.into());
        }
        self.health.note_fail();
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

    // --- 连续写失败窗口（第三版的兜底判据） -------------------------------

    #[test]
    fn healthy_link_never_reports_write_failing() {
        let h = PeerHealth::new();
        std::thread::sleep(Duration::from_millis(3));
        assert!(!h.write_failing_for(Duration::ZERO), "从没失败过就不能判");
    }

    #[test]
    fn continuous_write_failures_are_detected() {
        let h = PeerHealth::new();
        h.note_fail();
        std::thread::sleep(Duration::from_millis(2));
        // 阈值放到 0 就能立刻观测到：起点已经记下
        assert!(
            h.write_failing_for(Duration::ZERO),
            "连续写失败超过阈值就该判死"
        );
    }

    #[test]
    fn late_failures_do_not_postpone_the_deadline() {
        let h = PeerHealth::new();
        h.note_fail();
        std::thread::sleep(Duration::from_millis(2));
        h.note_fail(); // 后来的失败不能把起点往后推
        assert!(h.write_failing_for(Duration::from_millis(1)));
    }

    #[test]
    fn one_successful_write_clears_the_window() {
        let h = PeerHealth::new();
        h.note_fail();
        h.note_write_ok();
        std::thread::sleep(Duration::from_millis(2));
        assert!(
            !h.write_failing_for(Duration::ZERO),
            "写成功过就不算连续失败"
        );
    }

    /// 把连接的时钟往前拨：能造出"很久以前失败过"的窗口，又不用真等。
    fn aged(age: Duration) -> PeerHealth {
        let mut h = PeerHealth::new();
        h.base = Instant::now() - age;
        h
    }

    #[test]
    fn a_failure_followed_by_idle_is_not_a_stall() {
        // 回归：一次写超时之后用户停手、流被回收，30 秒里一次写都没有。
        // 旧判据只看起点，会把一条对端还在回 ACK 的健康连接判死。
        let h = aged(Duration::from_secs(60));
        let long_ago = 1_000;
        h.fail_since_ms.store(long_ago, Ordering::Relaxed);
        h.last_fail_ms.store(long_ago, Ordering::Relaxed);
        assert!(
            !h.write_failing_for(Duration::ZERO),
            "窗口过期 = 空闲，不是停死"
        );
    }

    #[test]
    fn a_repeatedly_failing_link_is_still_detected() {
        // 真停死：起点很久以前，但一直在失败，最后一次失败就发生在刚才。
        let h = aged(Duration::from_secs(60));
        h.fail_since_ms.store(1_000, Ordering::Relaxed);
        h.last_fail_ms.store(59_000, Ordering::Relaxed);
        assert!(
            h.write_failing_for(STALL_TIMEOUT),
            "有流量时失败会不断刷新新鲜度"
        );
    }

    #[test]
    fn a_failure_after_a_long_idle_period_restarts_the_window() {
        // 回归：第 1 秒瞬时失败一次，之后 5 分钟没有任何写入；用户恢复使用后
        // 又瞬时失败一次。起点必须重置成"现在"，否则旧起点直接满足 30 秒
        // 条件，一条还在正常回 ACK 的连接被无故重建。
        let h = aged(Duration::from_secs(300));
        h.fail_since_ms.store(1_000, Ordering::Relaxed);
        h.last_fail_ms.store(1_000, Ordering::Relaxed);
        h.note_fail();
        assert!(
            !h.write_failing_for(STALL_TIMEOUT),
            "过期窗口之后的第一次失败要重新起表"
        );
    }

    #[test]
    fn a_failure_inside_the_grace_window_keeps_the_original_start() {
        // 反向保证：窗口还新鲜时，后来的失败仍然不能把起点往后推，
        // 否则持续失败会被无限续命、永远判不出来。
        let h = aged(Duration::from_secs(4));
        h.fail_since_ms.store(1_000, Ordering::Relaxed);
        h.last_fail_ms.store(3_000, Ordering::Relaxed);
        h.note_fail();
        assert!(
            h.write_failing_for(Duration::from_millis(1_500)),
            "起点还是 1 秒前的那个，阈值 1.5 秒就该判死"
        );
    }

    #[test]
    fn dead_is_reported_only_once() {
        let h = PeerHealth::new();
        assert!(h.mark_dead(), "第一个调用者拿到 true");
        assert!(!h.mark_dead(), "后续调用者拿到 false，避免重复重建");
        assert!(h.is_dead());
    }

    // --- 对端回包判据（第三版） -------------------------------------------
    //
    // 全部喂假时间戳，不真等 8 秒。关键是**把"发包时刻"和"扫描时刻"分开**：
    // 第二版的测试每轮都让 tx 和 rx 一起涨，正好绕开了"tx 先涨、rx 晚一个
    // 扫描周期才涨"这个真实时序，所以两个误杀漏洞都没被发现。

    /// 涓流：我方零星在发，对端一个包都不回 → 从第一个未回应的包算起 8 秒判死。
    #[test]
    fn silence_while_sending_kills_the_link() {
        let h = PeerHealth::new();
        assert!(!h.observe_at(100, 100, 0), "首轮只建基线");
        // t=2s 扫描发现我方发了数据帧、对端没回包：从这里开表
        assert!(!h.observe_at(105, 100, 2_000));
        assert!(!h.observe_at(110, 100, 6_000), "才 4 秒");
        assert!(!h.observe_at(115, 100, 9_000), "才 7 秒");
        // t=10s：距离开表整整 8 秒，对端一直没回 → 判死
        assert!(
            h.observe_at(120, 100, 10_000),
            "我方在发、对端 8 秒没回包，就该判死"
        );
    }

    /// 开表之后继续发包，不能把起点往后推——否则黑洞永远攒不够 8 秒。
    #[test]
    fn later_sends_do_not_postpone_the_deadline() {
        let h = PeerHealth::new();
        assert!(!h.observe_at(0, 0, 0));
        assert!(!h.observe_at(1, 0, 2_000));
        assert!(!h.observe_at(2, 0, 4_000));
        assert!(!h.observe_at(3, 0, 6_000));
        assert!(!h.observe_at(4, 0, 8_000));
        assert!(
            h.observe_at(5, 0, 10_000),
            "起点必须固定在第一次没人理的包那一刻"
        );
    }

    /// keepalive 的 PING 已发、ACK 还在路上时被扫到 —— 不能判死。
    ///
    /// 这是第二版最致命的误杀：`silent` 量的是"距上次收包多久"，空闲链路上
    /// 那个值本来就是十几秒，PING 一发就当场判死。
    #[test]
    fn keepalive_with_ack_in_flight_is_not_a_blackhole() {
        let h = PeerHealth::new();
        assert!(!h.observe_at(10, 10, 0));
        // t=16s：keepalive PING 已发出（frame_tx.ping 涨），ACK 还没回来
        assert!(
            !h.observe_at(11, 10, 16_000),
            "PING 刚发出、ACK 在途，这不是黑洞"
        );
        // t=18s：ACK 到了
        assert!(!h.observe_at(11, 11, 18_000), "ACK 回来就该清零");
        // 之后一直空闲到下一个 keepalive
        for t in (20_000..31_000).step_by(2_000) {
            assert!(!h.observe_at(11, 11, t), "空闲的 keepalive 间隔不是黑洞");
        }
        // 下一次 keepalive，同样 ABC 时序
        assert!(!h.observe_at(12, 11, 32_000));
        assert!(!h.observe_at(12, 12, 34_000));
    }

    /// 纯 ACK 收尾：我方只回了 ACK（`stream + ping` 不动）→ 不开表。
    ///
    /// 第二版用 `udp_tx.datagrams` 会把纯 ACK 算进去：对端数据到达时 rx 涨、
    /// 我方 ACK 落在下一轮扫描，开出一张永远等不到回应的表（QUIC 不对 ACK
    /// 回 ACK），8 秒后误杀一条健康连接。
    #[test]
    fn pure_ack_does_not_open_the_timer() {
        let h = PeerHealth::new();
        assert!(!h.observe_at(100, 100, 0));
        // t=2s：对端发来一批数据，我方回延迟 ACK
        assert!(!h.observe_at(100, 120, 2_000));
        // 若这里把 tx 加 1 就代表"只发了 ACK 帧"——用 udp_tx 会误判，用
        // frame_tx.stream + ping 则压根不涨
        for t in (4_000..120_000).step_by(2_000) {
            assert!(
                !h.observe_at(100, 120, t),
                "只发过纯 ACK，没有任何'需回应帧'被吊着（t={t}）"
            );
        }
    }

    /// 调用处的取值口径：纯 ACK 不能让"需回应帧"计数增长。
    ///
    /// 上一条测的是状态机（喂的是数字），真正防住纯 ACK 的是"取哪个统计量"
    /// 那一行。把调用处改回 `udp_tx.datagrams`、或把 `acks` 加进来，这条立刻失败。
    #[test]
    fn pure_ack_is_not_a_reply_demanding_frame() {
        let mut stats = quinn::ConnectionStats::default();
        stats.udp_tx.datagrams = 50; // 发了很多 UDP 包
        stats.frame_tx.acks = 20; // 其中 20 帧是纯 ACK
        assert_eq!(needing_reply(&stats), 0, "纯 ACK 不需要对端回应");

        stats.frame_tx.stream = 3;
        stats.frame_tx.ping = 1;
        assert_eq!(needing_reply(&stats), 4, "数据帧 + PING 都要对端回 ACK");
    }

    /// 6 秒抖动后恢复：开表后对端回包到达就清零，不能杀。
    #[test]
    fn jitter_that_recovers_is_not_killed() {
        let h = PeerHealth::new();
        assert!(!h.observe_at(100, 100, 0));
        assert!(!h.observe_at(105, 100, 2_000), "抖动开始，开表");
        assert!(!h.observe_at(110, 100, 4_000));
        assert!(!h.observe_at(115, 100, 6_000));
        // t=8s：抖动结束，对端积压的包一次性到达 —— 还差 2 秒才判死，清零
        assert!(!h.observe_at(115, 130, 8_000), "对端恢复回包，必须清零");
        // 之后正常一来一回
        for k in 1..20u64 {
            let t = 8_000 + k * 2_000;
            assert!(!h.observe_at(115 + k, 130 + k, t));
        }
    }

    /// 同一轮 rx 和 tx 一起涨，连续 60 秒：必须清零，不能重新开表。
    ///
    /// 这是第二版的第二个洞：先清 `None` 再立刻 `Some(now)`，等于每轮都重新
    /// 计时。旧用例 `keepalive_spacing_is_not_a_blackhole` 就是这种形态、却
    /// 只扫到"同时涨"之后的 6 个点，看不出问题。
    #[test]
    fn rx_and_tx_growing_together_never_judges() {
        let h = PeerHealth::new();
        let mut tx = 0u64;
        let mut rx = 0u64;
        let mut t = 0u64;
        assert!(!h.observe_at(tx, rx, t));
        for _ in 0..30 {
            t += 2_000;
            tx += 3;
            rx += 3;
            assert!(!h.observe_at(tx, rx, t), "同轮收发都有增长，不能判死");
        }
    }

    /// 从没发过需回应的帧：无论等多久都不能判死。
    #[test]
    fn never_sent_never_judged() {
        let h = PeerHealth::new();
        assert!(!h.observe_at(0, 0, 0));
        assert!(!h.observe_at(0, 5, 60_000), "只收了包、没发过，凭什么判死");
        assert!(!h.observe_at(0, 9, 600_000));
    }

    /// 单向故障判不出来：对端的重传包让 rx 一直涨。
    ///
    /// 这是已知取舍（假定路径对称），不是缺陷。写在这里是为了防止有人
    /// "顺手加一条 rx 不涨的判据" —— 那会误杀所有下行单向流。
    #[test]
    fn one_way_failure_is_not_detected() {
        let h = PeerHealth::new();
        let mut tx = 0u64;
        let mut rx = 0u64;
        let mut t = 0u64;
        assert!(!h.observe_at(tx, rx, t));
        for _ in 0..120 {
            t += 2_000;
            tx += 5; // 我方一直在发（对方收不到）
            rx += 2; // 对方的包我方能收到（对方的重传）
            assert!(!h.observe_at(tx, rx, t), "rx 在涨就不判死，这是设计取舍");
        }
    }

    // ---- 两端同时重拨的选边 ----

    #[test]
    fn the_duplicate_rule_needs_both_sides_and_a_live_old_connection() {
        assert!(dedupe_enabled(true, true, true));
        assert!(
            !dedupe_enabled(false, true, true),
            "表里那条已经关了，它没有资格参与选边"
        );
        assert!(
            !dedupe_enabled(true, false, true),
            "表里那条是旧版本建的（对端没声明能力）"
        );
        assert!(
            !dedupe_enabled(true, true, false),
            "这次的对端没声明能力：单方面选边会让混版本更糟"
        );
    }

    #[test]
    fn the_smaller_dialer_wins_whichever_one_arrives_last() {
        // 我是 a、对端是 b：a 拨的那条赢
        assert_eq!(
            duplicate_keeps_new(true, false, "a", "b"),
            Some(true),
            "新的是我拨的，我 id 小 → 新赢"
        );
        assert_eq!(
            duplicate_keeps_new(false, true, "a", "b"),
            Some(false),
            "新的是对端拨的 → 旧赢"
        );
        // 我是 b、对端是 a：仍然是 a 拨的那条赢
        assert_eq!(
            duplicate_keeps_new(false, true, "b", "a"),
            Some(true),
            "新的是对端(a)拨的 → 新赢"
        );
        assert_eq!(
            duplicate_keeps_new(true, false, "b", "a"),
            Some(false),
            "新的是我(b)拨的 → 旧赢"
        );
        // 同端并发拨号：规则分不出胜负，退回后到顶替
        assert_eq!(duplicate_keeps_new(true, true, "a", "b"), None);
        assert_eq!(duplicate_keeps_new(false, false, "a", "b"), None);
    }

    /// 模拟一端按到达顺序挂两条重复连接，返回最后留下的那条（1 = A 拨，2 = B 拨）。
    ///
    /// `dedupe = false` 等价于旧版本：永远后到顶替。没有年龄窗口，
    /// 所以只需要到达顺序，不需要时间差。
    fn run_side(events: &[(f64, u8, bool)], my_smaller: bool, dedupe: bool) -> u8 {
        let (my_id, peer_id) = if my_smaller { ("a", "b") } else { ("b", "a") };
        let mut table: Option<(u8, bool)> = None;
        for &(_, conn, dialed_by_us) in events {
            let Some((old_conn, old_dialed)) = table else {
                table = Some((conn, dialed_by_us));
                continue;
            };
            if old_conn == conn {
                continue;
            }
            let keep_new = if dedupe {
                duplicate_keeps_new(old_dialed, dialed_by_us, my_id, peer_id).unwrap_or(true)
            } else {
                true
            };
            if keep_new {
                table = Some((conn, dialed_by_us));
            }
        }
        table.map(|t| t.0).unwrap_or(0)
    }

    /// 两端拨号起点相差 Δ，A 拨 C1、B 拨 C2。A 挂 C1 的时刻记作 0，
    /// 则 A 挂 C2 在 Δ+d、B 挂 C2 在 Δ、B 挂 C1 在 d（d = 单程时延）。
    fn phase_events(delta: f64, d: f64) -> (Vec<(f64, u8, bool)>, Vec<(f64, u8, bool)>) {
        let mut a = vec![(0.0f64, 1u8, true), (delta + d, 2u8, false)];
        let mut b = vec![(delta, 2u8, true), (d, 1u8, false)];
        a.sort_by(|x, y| x.0.partial_cmp(&y.0).unwrap());
        b.sort_by(|x, y| x.0.partial_cmp(&y.0).unwrap());
        (a, b)
    }

    #[test]
    fn both_ends_keep_the_same_connection_at_every_phase() {
        // Δ ∈ [-10s, 10s]、RTT 50ms~1s：两端都支持时，任何相位都必须收敛到同一条，
        // 而且是"拨号方 node_id 较小"的那条。带年龄窗口的实现过不了这条：
        // 窗口边界上一端按规则、另一端按后到顶替，会重新选出两条不同的。
        for rtt_ms in [50i64, 100, 300, 600, 1000] {
            let d = rtt_ms as f64 / 2000.0;
            for step in -400..=400 {
                let delta = 10.0 * step as f64 / 400.0;
                for a_smaller in [true, false] {
                    let (a, b) = phase_events(delta, d);
                    let ka = run_side(&a, a_smaller, true);
                    let kb = run_side(&b, !a_smaller, true);
                    assert_eq!(ka, kb, "RTT={rtt_ms}ms Δ={delta:.2}s a_smaller={a_smaller}");
                    assert_eq!(
                        ka,
                        if a_smaller { 1 } else { 2 },
                        "留下的必须是拨号方 id 小的那条"
                    );
                }
            }
        }
    }

    /// 混版本：两端都退回后到顶替，结果与升级前一致——并且确实有相位会失败。
    ///
    /// 这条测试的作用是钉住"为什么必须做能力协商"：只要有一端不声明能力，
    /// 新版就不能单方面启用规则，否则失败率会从个位数升到约一半。
    #[test]
    fn without_the_capability_both_ends_fall_back_to_last_arrival() {
        let d = 0.15; // RTT 300ms
        let mut broken = 0;
        let mut total = 0;
        for step in -400..=400 {
            let delta = 2.0 * step as f64 / 400.0;
            for a_smaller in [true, false] {
                let (a, b) = phase_events(delta, d);
                total += 1;
                if run_side(&a, a_smaller, false) != run_side(&b, !a_smaller, false) {
                    broken += 1;
                }
            }
        }
        assert!(
            broken > 0,
            "关掉规则后必须还能复现互关：说明混版本只能靠能力协商兜住"
        );
        assert!(
            broken * 100 / total < 20,
            "旧行为的失败率应当是个位数（单程时延窗口），实际 {broken}/{total}"
        );
    }
}
