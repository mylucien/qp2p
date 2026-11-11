//! 组网上线后的会话循环：拉事件、应答撮合、按规则拨号、定时重注册。
//!
//! 这段逻辑原来在 CLI 里，Android 也要用同一套（打洞规则、退避、事件应答
//! 任何一处走样都会出现"PC 能连、手机连不上"的怪问题），所以下沉到这里。
//! 面向用户的状态输出用回调，CLI 打 `println!`，Android 塞进通知栏或日志。

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, RwLock};

use crate::engine::Engine;
use crate::identity::{Identity, NodeId};
use crate::link::tun::MeshLinks;
use crate::peer::Role;
use crate::route::Cidr;
use crate::signal::client::{Event, PeerInfo, SignalClient, SignalError};
use crate::signal::ws::{HandshakeRejected, WsItem, WsLink};
use crate::stun::NatKind;

/// 事件轮询间隔：三档自适应。
///
/// 档位只看"现在有没有值得抢时间的事"，而不是"还有没有人没连上"：
/// - **HOT 3 秒**：只在刚发生了值得抢时间的事之后的 [`HOT_WINDOW`] 内——
///   启动、收到对端上线/撮合请求、链路刚断、TUN 来包唤醒、公网映射变化。
/// - **WARM 20 秒**：还有在线且值得尝试的对端没连上；或者一个对端都还不认识（等人加入）；
///   或者全连上了但数据面还在用。
/// - **COLD 60 秒**：全连上且数据面空闲，或休眠。
///
/// 旧版本"只要有一个对端没连上就永远 3 秒"：一台关机的对端，就能让每个在线节点
/// 每天白打 2.9 万次请求（Workers 免费额度 10 万/日）。
const POLL_HOT: Duration = Duration::from_secs(3);
const POLL_WARM: Duration = Duration::from_secs(20);
const POLL_COLD: Duration = Duration::from_secs(60);
/// 事件触发后保持高频轮询的时长。
const HOT_WINDOW: Duration = Duration::from_secs(45);
/// 兜底的重新注册间隔。
///
/// 对端上线靠 `peer_online` 广播事件感知、公网映射变化靠周期 STUN 发现，
/// 这里只是防漏的安全网（register 是最贵的请求：8 次查询 + 3 次写入）。
const REGISTER_EVERY: Duration = Duration::from_secs(1800);
/// 一个都连不上时，重新做 STUN 的间隔。
const RENEW_EVERY: Duration = Duration::from_secs(600);

/// 断路器窗口：这段时间内连续失败够次数就退回轮询。
const WS_FAIL_WINDOW: Duration = Duration::from_secs(120);
/// 窗口内的失败次数上限。
const WS_FAIL_LIMIT: usize = 3;
/// 退回轮询后隔多久再试长连接。
const WS_RETRY: Duration = Duration::from_secs(300);
/// 休眠满这么久就断开长连接（手机省电）。
const WS_SLEEP_AFTER: Duration = Duration::from_secs(60);
/// 两次"重绑端口 + 重探 STUN"之间的最小间隔。
/// 对端不可达时不能每轮都重绑，否则端口一直在变，打洞永远开不了。
const RENEW_MIN: Duration = Duration::from_secs(30);
/// 没有任何直连时，连续这么多次拨号失败就怀疑是自己的映射过期，重绑一次。
const RENEW_AFTER_STREAK: u32 = 3;
/// 没有任何直连时，周期 STUN 保活连续这么多轮零回应，说明映射或网络已经死了。
const STUN_MISS_RENEW: u32 = 3;
/// 数据面静默多久算「彻底空闲」。
const IDLE_AFTER: Duration = Duration::from_secs(120);

/// 对一个"在线却连不上"的对端：首轮连续失败几次后进入冷却。
const COOL_AFTER_FIRST: u32 = 6;
/// 冷却结束后的再次尝试只给这么几次机会，不行就继续冷却。
const COOL_AFTER_REPEAT: u32 = 2;
/// 冷却时长：5 分钟起步，每冷却一轮翻倍，封顶 30 分钟。
const COOLDOWN_BASE: Duration = Duration::from_secs(300);
const COOLDOWN_MAX: Duration = Duration::from_secs(1800);

/// 状态输出回调。
///
/// 包一层而不是直接用 `Arc<dyn Fn>`：后者不能直接当函数调，得 `as_ref()`，
/// 调用点一多就容易写错。这里只暴露 `say`，谁来接都行：
/// CLI 打成 `println!`，Android 写 logcat。
#[derive(Clone)]
pub struct Notify(Arc<dyn Fn(&str) + Send + Sync>);

impl Notify {
    pub fn new<F>(f: F) -> Self
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        Self(Arc::new(f))
    }

    pub fn say(&self, message: &str) {
        self.0.as_ref()(message);
    }
}

/// 一次上线会话里不变的东西：身份、令牌、本机名、网络。
pub struct SessionConfig {
    pub client: SignalClient,
    pub identity: Identity,
    pub node_id: NodeId,
    pub name: String,
    /// 网络网段，用于给老版本 Worker 兜底推导对端虚拟地址
    pub net: Option<Cidr>,
    /// 用户指定 / 上次分配到的虚拟地址，重注册时继续沿用
    pub wanted_ip: Option<Ipv4Addr>,
    /// 直连空闲多久自动断开（None = 从不断，桌面默认）
    pub idle_timeout: Option<Duration>,
    /// 注册时拿到的成员列表
    pub peers: Vec<PeerInfo>,
    /// 事件源怎么选。
    pub ws_mode: WsMode,
}

/// 事件源的选择。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsMode {
    /// 先试长连接，连续失败就退回轮询，过一阵再探测（默认）。
    Auto,
    /// 只用长连接：连不上就一直按退避重试，不退回轮询。
    Always,
    /// 只用轮询。
    Never,
}

impl WsMode {
    /// 允不允许用长连接（`Never` 之外的两种都允许起一条）。
    fn wants_ws(self) -> bool {
        !matches!(self, WsMode::Never)
    }

    /// 连不上时要不要退回轮询。强制模式不退回：那是用户明确要求的。
    fn falls_back(self) -> bool {
        matches!(self, WsMode::Auto)
    }
}

/// 后台 WS 任务往主循环送的东西。
enum WsFeed {
    Event(Event),
    /// 连上了：主循环据此清空失败计数。
    Online,
    /// 连接坏了或握不上手，附带原因；任务自己会按退避重连。
    Down(String),
    /// 服务端明确说"没有 Durable Object"（HTTP 501）：一次就该降级，
    /// 不用等失败次数攒够。
    Unsupported(String),
    /// 令牌/签名被拒（HTTP 401/403）：再重试也不会成功，必须停下来告诉用户。
    Fatal(String),
    /// 服务端主动关闭。
    Closed {
        code: u16,
        reason: String,
    },
    /// 被踢下线：应当停止会话。
    Kick(String),
}

/// 等下一轮时被什么叫醒的。
enum Wake {
    Tick,
    Tun(Ipv4Addr),
    /// 来了一条 WS 消息。**必须把它带回去**：`recv()` 已经从队列里取走了，
    /// 不处理就等于丢事件（曾经在这里丢过一次）。
    Ws(WsFeed),
    /// 后台任务的 channel 关了：它已经彻底退出，不会再有任何消息。
    WsDead,
}

/// 后台任务：维持一条 WS 连接，把事件推进队列。
///
/// 重连由它自己负责（退避 1 → 60 秒）。主循环不需要知道连接是怎么断的，
/// 只会在下一轮看到"这一批没有事件"。
async fn ws_feed(
    client: SignalClient,
    identity: Identity,
    mut since: i64,
    tx: tokio::sync::mpsc::Sender<WsFeed>,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        match WsLink::open(&client, &identity, since, &[]).await {
            Ok(mut link) => {
                let opened = Instant::now();
                let _ = tx.try_send(WsFeed::Online);
                loop {
                    match link.next().await {
                        WsItem::Event(event) => {
                            // 队列满说明主循环一时没跟上：这条不推进游标，重连时服务端会补发。
                            // 不能在这里 await——阻塞住就收不到 pong，服务端会把我们判成离线。
                            match tx.try_send(WsFeed::Event(event.clone())) {
                                Ok(()) => {
                                    if event.seq > since {
                                        since = event.seq;
                                    }
                                }
                                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                    tracing::warn!(
                                        "[session] WS 事件队列已满，丢弃一条，等重连补发"
                                    );
                                }
                                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return,
                            }
                        }
                        // 第一步撮合仍走 HTTP，socket 上的这几种应答只记日志
                        WsItem::ConnectOk(reply) => {
                            tracing::debug!("[ws] 收到 connect_ok：{reply}");
                        }
                        WsItem::ConnectError { req, error, detail } => {
                            tracing::debug!("[ws] 撮合失败 req={req:?} {error}：{detail}");
                        }
                        WsItem::ResumeOk(cursor) => {
                            tracing::debug!("[ws] resume 已补齐到 {cursor}");
                        }
                        WsItem::Kick(reason) => {
                            let _ = tx.try_send(WsFeed::Kick(reason));
                            let _ = link.close().await;
                            return;
                        }
                        WsItem::Closed { code, reason } => {
                            let _ = tx.try_send(WsFeed::Closed { code, reason });
                            break;
                        }
                        WsItem::Down(message) => {
                            let _ = tx.try_send(WsFeed::Down(message));
                            break;
                        }
                    }
                }
                // 连接活得够久就把退避复位，别让偶发断线越退越慢
                if opened.elapsed() >= Duration::from_secs(60) {
                    backoff = Duration::from_secs(1);
                }
                let _ = link.close().await;
            }
            Err(e) => {
                let text = format!("{e:#}");
                if let Some(rejected) = e.downcast_ref::<HandshakeRejected>() {
                    if rejected.is_auth_failure() {
                        let _ = tx.try_send(WsFeed::Fatal(text));
                        return;
                    }
                    if rejected.is_unsupported() {
                        let _ = tx.try_send(WsFeed::Unsupported(text));
                        return;
                    }
                }
                let _ = tx.try_send(WsFeed::Down(text));
                if tx.is_closed() {
                    return;
                }
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

/// 正在跑的一条后台 WS 任务。
struct WsRun {
    rx: tokio::sync::mpsc::Receiver<WsFeed>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for WsRun {
    fn drop(&mut self) {
        // 丢掉它就必须停掉：否则退回轮询期间后台还在偷偷重连，白烧请求
        self.task.abort();
    }
}

fn start_ws(client: &SignalClient, identity: &Identity, since: i64) -> WsRun {
    let (tx, rx) = tokio::sync::mpsc::channel::<WsFeed>(64);
    let task = tokio::spawn(ws_feed(client.clone(), identity.clone(), since, tx));
    WsRun { rx, task }
}

struct PeerState {
    name: String,
    virtual_ip: Option<Ipv4Addr>,
    connected: bool,
    /// 尝试过几次（0 表示从没试过，应当立刻连）。换端口后会清零，用来驱动退避。
    attempts: u32,
    last_try: Instant,
    /// 失败原因只打印一次，避免每 20 秒刷屏
    reported: bool,
    /// 服务端最近一次告诉我们的在线状态；拨号返回"对端离线"时也会置 false
    online: bool,
    /// 对端的 NAT 类型（register 回包里的 `nat_type`）
    nat: String,
    /// 连续失败次数。与 `attempts` 不同，换端口不清零，专门用来决定何时冷却。
    fails: u32,
    /// 冷却到这个时刻之前不主动拨号（在线但打不通的对端，比如双方都是对称 NAT）
    cool_until: Option<Instant>,
    /// 已经冷却过几轮，决定下一次冷却多久
    cool_count: u32,
}

impl PeerState {
    fn new(peer: &PeerInfo) -> Self {
        let mut state = Self::from_parts(
            peer.name.clone(),
            peer.virtual_ip.parse().ok(),
            peer.nat_type.clone(),
        );
        state.online = peer.online;
        state
    }

    fn from_parts(name: String, virtual_ip: Option<Ipv4Addr>, nat: String) -> Self {
        Self {
            name,
            virtual_ip,
            connected: false,
            attempts: 0,
            last_try: Instant::now(),
            reported: false,
            online: true,
            nat,
            fails: 0,
            cool_until: None,
            cool_count: 0,
        }
    }

    /// 退避：10s、20s、40s、60s（封顶）。
    fn backoff(&self) -> Duration {
        let exp = self.attempts.saturating_sub(1).min(3);
        Duration::from_secs(10 * (1u64 << exp)).min(Duration::from_secs(60))
    }

    fn cooling(&self, now: Instant) -> bool {
        self.cool_until.is_some_and(|t| now < t)
    }

    /// 对端刚上线（或刚恢复）：之前积累的失败、冷却、退避统统作废，立刻重试。
    fn mark_online(&mut self) {
        self.online = true;
        self.attempts = 0;
        self.fails = 0;
        self.cool_until = None;
        self.cool_count = 0;
        self.reported = false;
    }

    fn mark_offline(&mut self) {
        self.online = false;
        self.attempts = 0;
        self.fails = 0;
    }

    fn mark_connected(&mut self) {
        self.connected = true;
        self.online = true;
        self.attempts = 0;
        self.fails = 0;
        self.cool_until = None;
        self.cool_count = 0;
        self.reported = false;
    }

    /// 记一次"对端在线却没打通"。连续失败到阈值就进入冷却。
    ///
    /// `hopeless`：已知两端都是对称 NAT，打洞基本不可能成功，试一次就进入最长冷却。
    fn note_failure(&mut self, now: Instant, hopeless: bool) {
        self.fails += 1;
        let limit = if hopeless {
            1
        } else if self.cool_count == 0 {
            COOL_AFTER_FIRST
        } else {
            COOL_AFTER_REPEAT
        };
        if self.fails >= limit {
            let span = if hopeless {
                COOLDOWN_MAX
            } else {
                cooldown(self.cool_count)
            };
            self.cool_until = Some(now + span);
            self.cool_count = self.cool_count.saturating_add(1);
            self.fails = 0;
            self.attempts = 0;
        }
    }
}

/// 第 n 轮冷却的时长：5 分钟起步，每轮翻倍，封顶 30 分钟。
fn cooldown(round: u32) -> Duration {
    COOLDOWN_BASE
        .saturating_mul(1u32 << round.min(6))
        .min(COOLDOWN_MAX)
}

/// 拨号失败的性质：决定是"对端不在线"还是"在线但没打通"。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailKind {
    /// 服务端明确说对端离线 / 不在网络里：不再盲连，等它上线的通知
    Offline,
    /// 其它：撮合失败、没有候选、打洞超时……
    Other,
}

fn error_code(error: &anyhow::Error) -> Option<&str> {
    error.downcast_ref::<SignalError>().map(|e| e.code.as_str())
}

fn fail_kind(error: &anyhow::Error) -> FailKind {
    match error_code(error) {
        Some("target_offline" | "target_not_found") => FailKind::Offline,
        _ => FailKind::Other,
    }
}

/// 是否该主动对这个对端发起一轮拨号。
fn should_dial(state: &PeerState, my_id: &str, peer_id: &str, now: Instant, forced: bool) -> bool {
    if state.connected {
        return false;
    }
    if forced {
        // 有包要发：不等退避、不看在线/冷却，但 2 秒内不重复拨同一个对端
        return !(state.attempts > 0
            && now.duration_since(state.last_try) < Duration::from_secs(2));
    }
    // 双方都拨会各建一条连接；固定由 node_id 小的一方发起
    if my_id >= peer_id {
        return false;
    }
    // 已知离线的不盲连（它上线时会有 peer_online 通知）；冷却中的不打扰
    if !state.online || state.cooling(now) {
        return false;
    }
    !(state.attempts > 0 && now.duration_since(state.last_try) < state.backoff())
}

struct ListChange {
    /// 有对端从"不在"变成"在线"：值得马上抢时间连接
    new_online: bool,
}

/// 以服务端返回的成员列表为准更新本地对端表。
///
/// - 列表里没有、又没连着的对端删掉（服务端 10 分钟没心跳就清掉了，客户端留着只会白白拨号）
/// - `online` 以服务端为准；离线→在线时清空失败与冷却
/// - 已连着的对端不因为服务端说它离线就丢，链路本身才是事实
fn apply_peer_list(table: &mut HashMap<String, PeerState>, list: &[PeerInfo]) -> ListChange {
    let mut new_online = false;
    for peer in list {
        match table.get_mut(&peer.node_id) {
            Some(state) => {
                state.name = peer.name.clone();
                if let Ok(ip) = peer.virtual_ip.parse() {
                    state.virtual_ip = Some(ip);
                }
                state.nat = peer.nat_type.clone();
                if peer.online && !state.online {
                    state.mark_online();
                    new_online = true;
                } else if !peer.online && state.online && !state.connected {
                    state.mark_offline();
                }
            }
            None => {
                let state = PeerState::new(peer);
                new_online |= state.online;
                table.insert(peer.node_id.clone(), state);
            }
        }
    }
    let known: HashSet<&str> = list.iter().map(|p| p.node_id.as_str()).collect();
    table.retain(|id, state| state.connected || known.contains(id.as_str()));
    ListChange { new_online }
}

/// 选轮询档位用的输入。
struct PollInputs {
    sleeping: bool,
    /// 还在 [`HOT_WINDOW`] 内
    hot: bool,
    /// 有在线、没在冷却、却没连上的对端
    wanted_unconnected: bool,
    /// 一个对端都还不认识（等人加入）
    alone: bool,
    /// 数据面已经静默 [`IDLE_AFTER`] 以上
    idle: bool,
}

fn poll_interval(i: &PollInputs) -> Duration {
    if i.sleeping {
        // 休眠时只保留最低频的轮询：新节点加入最多晚 60 秒发现
        POLL_COLD
    } else if i.hot {
        POLL_HOT
    } else if i.wanted_unconnected || i.alone {
        POLL_WARM
    } else if i.idle {
        POLL_COLD
    } else {
        POLL_WARM
    }
}

/// 信令连续出错时的轮询退避：10、20、40、80、160、300 秒（封顶）。
fn error_backoff(streak: u32) -> Duration {
    if streak == 0 {
        return Duration::ZERO;
    }
    let secs = 10u64 << (streak - 1).min(5);
    Duration::from_secs(secs.min(300))
}

struct RenewInputs {
    live: usize,
    all_lost: bool,
    /// 在线且没在冷却的对端里最大的连续尝试次数
    worst_streak: u32,
    sleeping: bool,
    since_renew: Duration,
    stun_misses: u32,
}

struct RenewPlan {
    renew: bool,
    /// 触发了"可能换网/映射失效"的判定：把各对端的退避清零，让它们马上重试
    clear_backoff: bool,
    switch_detected: bool,
}

/// 要不要重绑端口 + 重探 STUN。
///
/// **`renew()` 会关闭端点，所有直连一起断**，所以只要还有活链路就绝不能走这条路。
/// 旧版本的 `worst_streak >= 3` 没有这个前提：表里只要有一个关机的对端，
/// 每隔几十秒就会把所有健康直连打断一次。
fn plan_renew(i: &RenewInputs) -> RenewPlan {
    let none = RenewPlan {
        renew: false,
        clear_backoff: false,
        switch_detected: false,
    };
    if i.live > 0 {
        return none;
    }
    let trigger = i.all_lost
        || (!i.sleeping && i.worst_streak >= RENEW_AFTER_STREAK)
        || (!i.sleeping && i.stun_misses >= STUN_MISS_RENEW);
    let guarded = i.since_renew < RENEW_MIN;
    RenewPlan {
        renew: i.since_renew >= RENEW_EVERY || (trigger && !guarded),
        clear_backoff: trigger,
        switch_detected: trigger && !guarded,
    }
}

type SharedPeers = Arc<Mutex<HashMap<String, PeerState>>>;

/// 上线的会话。`run()` 一直转到被 `stop()` 或令牌失效。
pub struct Session {
    config: SessionConfig,
    engine: Arc<RwLock<Engine>>,
    mesh: Option<Arc<MeshLinks>>,
    peers: SharedPeers,
    notify: Notify,
    stop: Arc<AtomicBool>,
}

impl Session {
    pub fn new(
        config: SessionConfig,
        engine: Arc<RwLock<Engine>>,
        mesh: Option<Arc<MeshLinks>>,
        notify: Notify,
    ) -> Self {
        let peers = Arc::new(Mutex::new(HashMap::new()));
        Self {
            config,
            engine,
            mesh,
            peers,
            notify,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// 用调用方给的停止开关（Android 的「断开」按钮从这里进来）。
    pub fn new_with_stop(
        config: SessionConfig,
        engine: Arc<RwLock<Engine>>,
        mesh: Option<Arc<MeshLinks>>,
        notify: Notify,
        stop: Arc<AtomicBool>,
    ) -> Self {
        let mut session = Self::new(config, engine, mesh, notify);
        session.stop = stop;
        session
    }

    /// 拿一个停止开关：置 true 后循环会在下一轮退出（最多 3 秒）。
    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        self.stop.clone()
    }

    /// 当前已建立的直连数。
    pub async fn connected(&self) -> usize {
        self.peers
            .lock()
            .await
            .values()
            .filter(|p| p.connected)
            .count()
    }

    pub async fn run(self) {
        let SessionConfig {
            client,
            identity,
            node_id,
            name,
            net,
            wanted_ip,
            idle_timeout,
            peers: initial,
            ws_mode,
        } = self.config;

        {
            let mut table = self.peers.lock().await;
            for peer in &initial {
                table.insert(peer.node_id.clone(), PeerState::new(peer));
            }
        }

        let mut cursor: i64 = 0;

        // 事件源：WebSocket 长连接或轮询，两者产出的 Event 完全同构。
        // `ws_run` 为 Some 表示此刻用长连接，None 表示轮询——断路器、休眠、
        // 探测重试都只改这一个状态，下游的事件处理不分叉。
        let mut ws_run: Option<WsRun> = None;
        // 断路器退回轮询后，到点再试长连接
        let mut ws_retry_at: Option<Instant> = None;
        // 窗口内的失败时刻（连上就清空）
        let mut ws_failed: Vec<Instant> = Vec::new();
        // 退回轮询后的探测间隔：每失败一次翻倍，最多 1 小时。
        // 旧服务端（没有 DO）上这是每天 20 多次 501，而不是每 5 分钟一次。
        let mut ws_retry_delay = WS_RETRY;
        // "服务端没有 DO"只提示一次，之后每轮探测失败不再刷屏
        let mut ws_unsupported_notified = false;
        // 休眠起始时刻：满 60 秒断长连接
        let mut sleeping_since: Option<Instant> = None;

        if ws_mode.wants_ws() {
            ws_run = Some(start_ws(&client, &identity, cursor));
            self.notify.say(match ws_mode {
                WsMode::Always => "· 信令走 WebSocket 长连接（强制，连不上会一直重试）",
                _ => "· 优先用 WebSocket 长连接；不可用时自动退回轮询",
            });
        }

        let mut last_register = Instant::now();
        let mut last_renew = Instant::now();
        let mut last_error = String::new();
        // 信令连续出错的轮数：用来退避轮询、暂停拨号与注册
        let mut err_streak: u32 = 0;
        // 高频轮询窗口：只有刚发生了值得抢时间的事才打开
        let mut hot_until = Instant::now() + HOT_WINDOW;
        // 上一轮的直连数：变少了说明链路刚断，要抢时间重连
        let mut last_live: usize = 0;
        let mut seen_generation = self.engine.read().await.stun_generation();

        // TUN 收到"目标没连上"的包时会往这里塞一个虚拟地址：
        // 立刻针对这个对端拨号，不用等下一轮定时器
        let (wake_tx, mut wake_rx) = tokio::sync::mpsc::channel::<Ipv4Addr>(16);
        if let Some(mesh) = self.mesh.as_ref() {
            mesh.set_wake(wake_tx).await;
        }
        let mut forced: Option<Ipv4Addr> = None;
        // 空闲断链之后进入休眠：不主动拨号、也不高频轮询，等 TUN 里有包再来叫醒
        let mut sleeping = false;
        // 上一轮是否有直连：用来识别"原本连着、现在全断了"（多半是换网）
        let mut had_links = false;
        // select 用来唤醒循环的那条 WS 消息，下一轮开头必须先处理掉
        let mut ws_early: Option<WsFeed> = None;

        while !self.stop.load(Ordering::Relaxed) {
            // 本轮是否需要马上重新登记（事件、STUN 观测都可能置位）
            let mut need_register = false;

            // 0) 到点就（重新）试长连接：断路器退避结束、或者休眠被唤醒。
            //    休眠期间不重连——刚为省电断开的连接不能立刻又建回来。
            if ws_run.is_none() && ws_mode.wants_ws() && !sleeping {
                let due = ws_retry_at.is_none_or(|t| Instant::now() >= t);
                if due {
                    // 从 cursor 续上：断线期间攒的事件由服务端按 since 补发一次
                    ws_run = Some(start_ws(&client, &identity, cursor));
                    ws_retry_at = None;
                }
            }

            // 1) 取事件：对端请求撮合时，服务端会往这里塞 punch_request；
            //    对端上线 / 换地址时会塞 peer_online 广播。
            //    WS 模式下这些事件是推来的，主循环只负责把队列掏空。
            let mut ws_failure: Option<String> = None;
            // 服务端明说没有 DO：一次就降级，不用攒失败次数
            let mut ws_unsupported = false;
            let fetched: Result<Vec<Event>, anyhow::Error> = match ws_run.as_mut() {
                Some(run) => {
                    // 上一轮用来唤醒循环的那条也要一起处理（见 Wake::Ws 的注释）
                    let mut items: Vec<WsFeed> = ws_early.take().into_iter().collect();
                    while let Ok(item) = run.rx.try_recv() {
                        items.push(item);
                    }

                    let mut batch = Vec::new();
                    for item in items {
                        match item {
                            WsFeed::Event(event) => batch.push(event),
                            WsFeed::Online => {
                                ws_failed.clear();
                                // 连上了就把探测间隔复位，下次断了还从 5 分钟起
                                ws_retry_delay = WS_RETRY;
                            }
                            WsFeed::Kick(reason) => {
                                self.notify.say(&format!(
                                    "⚠ {reason}（本节点已被移出这个网络，无法继续）"
                                ));
                                return;
                            }
                            WsFeed::Closed { code, reason } => {
                                ws_failure = Some(format!("连接被关闭 code={code}"));
                                tracing::debug!("[session] WS 关闭 code={code} {reason}");
                            }
                            WsFeed::Down(message) => {
                                ws_failure = Some(message.clone());
                                tracing::debug!("[session] WS 断开：{message}");
                            }
                            WsFeed::Unsupported(message) => {
                                ws_unsupported = true;
                                ws_failure = Some(message.clone());
                            }
                            WsFeed::Fatal(message) => {
                                // 令牌被换掉 / 网络被删：和轮询模式的处理保持一致
                                self.notify.say(&format!("⚠ 加入令牌被拒绝：{message}"));
                                self.notify.say(
                                    "  现有直连还能用，但新节点连不上来了。重新加入：qp2p join <新令牌>",
                                );
                                return;
                            }
                        }
                    }
                    Ok(batch)
                }
                None => client.events(&identity, cursor).await.map(|reply| {
                    cursor = reply.cursor;
                    reply.events
                }),
            };

            match fetched {
                Ok(events) => {
                    for event in events {
                        // WS 模式下 cursor 靠事件自带 seq 推进，重连时当 since 用
                        if event.seq > cursor {
                            cursor = event.seq;
                        }
                        match event.kind.as_str() {
                            "punch_request" => {
                                let Some(from) = event.str("from").and_then(NodeId::parse) else {
                                    continue;
                                };
                                let addrs: Vec<SocketAddr> = event
                                    .strings("candidates")
                                    .iter()
                                    .filter_map(|c| c.parse().ok())
                                    .collect();
                                // 2.2 起的 Worker 直接给虚拟地址；更早的版本没有这个字段，
                                // 用和 Worker 一致的推导算法兜底
                                let ip = event
                                    .str("virtual_ip")
                                    .and_then(|s| s.parse::<Ipv4Addr>().ok())
                                    .or_else(|| {
                                        net.map(|cidr| {
                                            crate::identity::derive_virtual_ip(
                                                &from,
                                                cidr.base,
                                                cidr.prefix,
                                                0,
                                            )
                                        })
                                    });
                                let label =
                                    event.str("from_name").unwrap_or("未知节点").to_string();
                                // 对方马上要打进来：这段时间要尽快应答后续事件
                                hot_until = Instant::now() + HOT_WINDOW;

                                let engine = self.engine.clone();
                                let peers = self.peers.clone();
                                let mesh = self.mesh.clone();
                                let notify = self.notify.clone();
                                tokio::spawn(async move {
                                    answer_punch(
                                        engine, peers, mesh, notify, from, label, ip, addrs,
                                    )
                                    .await;
                                });
                            }
                            "peer_online" => {
                                let Some(id) = event.str("node_id") else {
                                    continue;
                                };
                                if id == node_id.as_str() {
                                    continue;
                                }
                                let ip = event.str("virtual_ip").and_then(|s| s.parse().ok());
                                let label = event.str("name").unwrap_or("").to_string();
                                let nat = event.str("nat_type").unwrap_or("").to_string();
                                let mut table = self.peers.lock().await;
                                match table.get_mut(id) {
                                    Some(state) => {
                                        if !label.is_empty() {
                                            state.name = label;
                                        }
                                        if ip.is_some() {
                                            state.virtual_ip = ip;
                                        }
                                        state.nat = nat;
                                        if !state.connected {
                                            state.mark_online();
                                        }
                                    }
                                    None => {
                                        table.insert(
                                            id.to_string(),
                                            PeerState::from_parts(label, ip, nat),
                                        );
                                    }
                                }
                                // 它马上会来连我，或者我这一轮就能去连它
                                hot_until = Instant::now() + HOT_WINDOW;
                            }
                            _ => {}
                        }
                    }
                    if err_streak >= 2 {
                        // 信令断了一阵子：期间的 peer_online 可能已经被服务端清掉，补一次全量同步
                        need_register = true;
                    }
                    if !last_error.is_empty() {
                        self.notify.say("· 信令已恢复");
                        last_error.clear();
                    }
                    err_streak = 0;
                }
                Err(e) => {
                    // 令牌被换掉 / 网络被删：再轮询也没有意义
                    if token_rejected(&e) {
                        self.notify.say("⚠ 加入令牌已失效（网络被删除，或管理员换了准入密码）。现有直连还能用，但新节点连不上来了。");
                        return;
                    }
                    if error_code(&e) == Some("unknown_node") {
                        // 服务端已经把本节点清掉了（睡眠 / 离线超过 10 分钟）：
                        // 马上重新登记。这不是信令故障，不进退避。
                        need_register = true;
                    } else {
                        err_streak = err_streak.saturating_add(1);
                        // 只在不重复的时候喊一声
                        let text = format!("{e:#}");
                        if text != last_error {
                            self.notify.say(&format!("⚠ 拉取事件失败：{text}"));
                            last_error = text;
                        }
                    }
                }
            }

            // 1.2) 断路器：长连接连着失败够次数就退回轮询，过一阵再探
            if let Some(reason) = ws_failure {
                ws_failed.push(Instant::now());
                ws_failed.retain(|t| t.elapsed() < WS_FAIL_WINDOW);
                let over_limit = ws_failed.len() >= WS_FAIL_LIMIT;
                // 501 表示服务端没有 DO——这不是"连不上"，是"没这个功能"，
                // 任何模式下都必须退回轮询，否则连事件源都没了。
                // 其余失败只有 auto 模式才降级；强制模式继续按短退避重连。
                let must_poll = ws_unsupported || (ws_mode.falls_back() && over_limit);
                if must_poll {
                    if ws_unsupported && !ws_unsupported_notified {
                        ws_unsupported_notified = true;
                        self.notify.say(&format!(
                            "· 服务端没有 Durable Object（{reason}），本次只能用轮询；之后每隔一段时间再探一次"
                        ));
                    } else if !ws_unsupported {
                        self.notify.say(&format!(
                            "⚠ 长连接连续失败（{reason}），改用轮询，{} 分钟后再试",
                            ws_retry_delay.as_secs() / 60
                        ));
                    }
                    // drop 会 abort 后台任务，别让它在轮询期间继续重连
                    ws_run = None;
                    ws_early = None;
                    ws_retry_at = Some(Instant::now() + ws_retry_delay);
                    ws_retry_delay = (ws_retry_delay * 2).min(Duration::from_secs(3600));
                    ws_failed.clear();
                    // 断开期间的事件可能已被服务端清理（5 分钟 TTL），补一次全量同步
                    need_register = true;
                }
            }

            // 1.5) 把"链路上其实已经没了"的对端标回未连接：
            // 否则全连上之后会一直停在冷却档，断了也发现不了
            if let Some(mesh) = self.mesh.as_ref() {
                let alive = mesh.peer_ips().await;
                let mut table = self.peers.lock().await;
                for state in table.values_mut() {
                    if state.connected && state.virtual_ip.is_none_or(|ip| !alive.contains(&ip)) {
                        state.connected = false;
                        state.attempts = 0;
                    }
                }
            }

            // 1.6) 直连数变化 + 周期 STUN 保活
            let live_now = {
                let table = self.peers.lock().await;
                table.values().filter(|p| p.connected).count()
            };
            if live_now < last_live && !sleeping {
                // 链路刚断：对端多半马上会重拨，这段时间要快
                hot_until = Instant::now() + HOT_WINDOW;
            }
            last_live = live_now;
            {
                let engine = self.engine.read().await;
                // 有直连时 QUIC 自己的 keepalive 在刷新映射，不必让射频多醒一次
                engine.stun_set_active(live_now == 0 && !sleeping);
                let generation = engine.stun_generation();
                if generation != seen_generation {
                    seen_generation = generation;
                    need_register = true;
                    hot_until = Instant::now() + HOT_WINDOW;
                    tracing::info!("[session] 公网映射变化，重新登记");
                }
            }

            // 2) 主动发起：node_id 小的一方负责拨号，避免两边同时重复建连
            if sleeping {
                // 休眠中不主动连，否则刚断开又立刻拨回去，空闲断链毫无意义
                if forced.is_some() {
                    sleeping = false;
                    hot_until = Instant::now() + HOT_WINDOW;
                }
            }
            // 信令不通时撮合必然失败，别白白打请求、耗电
            if !sleeping && err_streak < 2 {
                let my_symmetric = {
                    let engine = self.engine.read().await;
                    engine.upnp().is_none() && engine.nat_kind() == NatKind::Symmetric
                };
                dial_round(
                    &client,
                    &identity,
                    &node_id,
                    &self.engine,
                    &self.peers,
                    &self.mesh,
                    &self.notify,
                    forced.take(),
                    my_symmetric,
                )
                .await;
            }

            // 2.5) 换网检测：原本有直连、现在一条不剩，或没有直连时连续拨号失败 / STUN 无回应
            //      → 立刻重绑端口 + 重探 STUN，紧接着用新候选注册。
            //      这是"换网后最坏等 10 分钟"的解药：谁换了网，谁自己马上重报。
            let (live, worst_streak) = {
                let table = self.peers.lock().await;
                let now = Instant::now();
                (
                    table.values().filter(|p| p.connected).count(),
                    table
                        .values()
                        .filter(|p| p.online && !p.cooling(now))
                        .map(|p| p.attempts)
                        .max()
                        .unwrap_or(0),
                )
            };
            // 空闲休眠造成的断开是有意的，不能当成换网去重绑端口
            let all_lost = !sleeping && had_links && live == 0;
            had_links = live > 0 && !sleeping;
            let stun_misses = self.engine.read().await.stun_misses();
            let plan = plan_renew(&RenewInputs {
                live,
                all_lost,
                worst_streak,
                sleeping,
                since_renew: last_renew.elapsed(),
                stun_misses,
            });
            let mut force_register = need_register;
            if plan.clear_backoff {
                // 先清退避：不清的话每轮都会判定"连续失败"，把注册打成连发
                for state in self.peers.lock().await.values_mut() {
                    state.attempts = 0;
                }
            }
            if plan.renew {
                last_renew = Instant::now();
                let renewed = {
                    let mut guard = self.engine.write().await;
                    guard.renew().await
                };
                match renewed {
                    Ok(()) => {
                        tracing::info!("[session] 端点已刷新（换网或长时间不通）");
                        if plan.switch_detected {
                            self.notify
                                .say("· 网络可能变了：已重新探测公网地址，正在重报");
                        }
                        // 换了端口就必须立刻上报，否则对端还拿着旧地址打空炮
                        force_register = true;
                        hot_until = Instant::now() + HOT_WINDOW;
                        // renew 之后 generation 会变，这里先对齐，免得下一轮重复登记
                        seen_generation = self.engine.read().await.stun_generation();
                    }
                    Err(e) => {
                        tracing::debug!("[session] 端点刷新失败: {e:#}");
                        // 没换成就没必要强制登记；定时登记照旧
                        force_register = need_register;
                    }
                }
            }

            // 3) 重新注册：兜底定时，或候选地址变了要马上让对端知道
            if (force_register || last_register.elapsed() >= REGISTER_EVERY) && err_streak < 2 {
                last_register = Instant::now();
                let (candidates, fp, nat) = {
                    let engine = self.engine.read().await;
                    (
                        candidate_strings(&engine),
                        engine.tls_fp(),
                        nat_type(&engine),
                    )
                };
                match client
                    .register(&identity, &name, &fp, &candidates, nat, wanted_ip)
                    .await
                {
                    Ok(reply) => {
                        let mut table = self.peers.lock().await;
                        if apply_peer_list(&mut table, &reply.peers).new_online {
                            hot_until = Instant::now() + HOT_WINDOW;
                        }
                    }
                    Err(e) => {
                        tracing::debug!("[session] 刷新注册失败: {e:#}");
                        // 失败了别等 30 分钟：一分钟后再试
                        last_register = Instant::now()
                            .checked_sub(REGISTER_EVERY - Duration::from_secs(60))
                            .unwrap_or_else(Instant::now);
                    }
                }
            }

            // 5) 空闲断链（可选）：移动端省电，桌面默认关
            if let (Some(mesh), Some(timeout)) = (self.mesh.as_ref(), idle_timeout) {
                let dropped = mesh.drop_all_idle(timeout).await;
                if dropped > 0 {
                    let mut table = self.peers.lock().await;
                    for state in table.values_mut() {
                        state.connected = false;
                        state.attempts = 0;
                    }
                    sleeping = true;
                    self.notify.say(&format!(
                        "· 空闲 {}s，断开 {dropped} 条直连（有流量会自动重连）",
                        timeout.as_secs()
                    ));
                }
            }

            // 5.5) 休眠联动：进入休眠满 60 秒就断长连接，省电也省服务端 socket。
            //      不设 ws_retry_at，所以一有流量唤醒就会立刻接回来。
            if sleeping {
                match sleeping_since {
                    Some(t) if t.elapsed() >= WS_SLEEP_AFTER && ws_run.is_some() => {
                        ws_run = None;
                        ws_early = None;
                        tracing::debug!(
                            "[session] 休眠满 {} 秒，断开长连接",
                            WS_SLEEP_AFTER.as_secs()
                        );
                    }
                    None => sleeping_since = Some(Instant::now()),
                    _ => {}
                }
            } else {
                sleeping_since = None;
            }

            // 6) 等下一轮：按"现在有没有值得抢时间的事"选档位；TUN 来了包就立刻醒
            let interval = {
                let now = Instant::now();
                let (wanted_unconnected, alone) = {
                    let table = self.peers.lock().await;
                    (
                        table
                            .values()
                            .any(|p| !p.connected && p.online && !p.cooling(now)),
                        table.is_empty(),
                    )
                };
                let idle = self.mesh.as_ref().map(|m| m.idle_for()).unwrap_or_default();
                poll_interval(&PollInputs {
                    sleeping,
                    hot: now < hot_until,
                    wanted_unconnected,
                    alone,
                    idle: idle >= IDLE_AFTER,
                })
                // 信令出错时只会更慢，不会更快
                .max(error_backoff(err_streak))
            };
            // 长连接在跑时事件会主动叫醒循环，定时器只当兜底（扫描链路、重注册）
            let wake = match ws_run.as_mut() {
                Some(run) => {
                    tokio::select! {
                        _ = tokio::time::sleep(interval) => Wake::Tick,
                        Some(ip) = wake_rx.recv() => Wake::Tun(ip),
                        item = run.rx.recv() => match item {
                            Some(item) => Wake::Ws(item),
                            None => Wake::WsDead,
                        },
                    }
                }
                None => {
                    tokio::select! {
                        _ = tokio::time::sleep(interval) => Wake::Tick,
                        Some(ip) = wake_rx.recv() => Wake::Tun(ip),
                    }
                }
            };
            match wake {
                Wake::Tick => {}
                Wake::Ws(item) => ws_early = Some(item),
                Wake::WsDead => {
                    // 后台任务彻底退出了（panic / 被 abort）。不清掉的话主循环会
                    // 永远等一个再也不会来的事件：既不收事件，也不重连。
                    tracing::warn!("[session] 长连接任务已退出，5 秒后重建");
                    ws_run = None;
                    ws_early = None;
                    ws_retry_at = Some(Instant::now() + Duration::from_secs(5));
                }
                Wake::Tun(ip) => {
                    // 一串包会连发很多次唤醒，只处理最新一个，别把轮询打成连发
                    while wake_rx.try_recv().is_ok() {}
                    forced = Some(ip);
                    hot_until = Instant::now() + HOT_WINDOW;
                    // 休眠里断开的长连接：一有流量就立刻接回来
                    ws_retry_at = None;
                }
            }
        }

        self.notify.say("· 会话已停止");
    }
}

/// 对端请求撮合：我们作为 listener 守着，等它打进来。
#[allow(clippy::too_many_arguments)]
async fn answer_punch(
    engine: Arc<RwLock<Engine>>,
    peers: SharedPeers,
    mesh: Option<Arc<MeshLinks>>,
    notify: Notify,
    from: NodeId,
    label: String,
    ip: Option<Ipv4Addr>,
    addrs: Vec<SocketAddr>,
) {
    if addrs.is_empty() {
        return;
    }
    {
        let mut table = peers.lock().await;
        let state = table
            .entry(from.to_string())
            .or_insert_with(|| PeerState::from_parts(label.clone(), ip, String::new()));
        if state.connected {
            return;
        }
        if ip.is_some() {
            state.virtual_ip = ip;
        }
    }

    let result = {
        let engine = engine.read().await;
        engine
            .punch_as(
                &addrs,
                Role::Listener,
                Engine::attempt_timeout(Role::Listener),
                Some(from.clone()),
            )
            .await
    };

    match result {
        Ok(conn) => on_connected(&peers, &mesh, &notify, from, label, ip, conn).await,
        Err(e) => tracing::debug!("[session] 应答 {label} 的打洞失败: {e}"),
    }
}

/// 主动拨号：只对"我该发起"且没连上的成员执行。
#[allow(clippy::too_many_arguments)]
async fn dial_round(
    client: &SignalClient,
    identity: &Identity,
    node_id: &NodeId,
    engine: &Arc<RwLock<Engine>>,
    peers: &SharedPeers,
    mesh: &Option<Arc<MeshLinks>>,
    notify: &Notify,
    force: Option<Ipv4Addr>,
    my_symmetric: bool,
) {
    let targets: Vec<(String, String, bool)> = {
        let mut table = peers.lock().await;
        let now = Instant::now();
        let mut out = Vec::new();
        for (id, state) in table.iter_mut() {
            let forced = force.is_some() && state.virtual_ip == force;
            if force.is_some() && !forced {
                continue;
            }
            if !should_dial(state, node_id.as_str(), id, now, forced) {
                continue;
            }
            state.attempts += 1;
            state.last_try = now;
            // 两端都是对称 NAT：打洞几乎不可能成功，失败一次就进入最长冷却
            let hopeless = my_symmetric && state.nat == "symmetric";
            out.push((id.clone(), state.name.clone(), hopeless));
        }
        out
    };

    for (target_id, label, hopeless) in targets {
        let Some(target) = NodeId::parse(&target_id) else {
            continue;
        };
        let client = client.clone();
        let identity = identity.clone();
        let engine = engine.clone();
        let peers = peers.clone();
        let mesh = mesh.clone();
        let notify = notify.clone();

        // 每个对端一个任务：撮合是 HTTP，打洞要几十秒，串行会把整轮拖长
        tokio::spawn(async move {
            let reply = match client.connect(&identity, &target).await {
                Ok(reply) => reply,
                Err(e) => {
                    let kind = fail_kind(&e);
                    report_failure(
                        &peers,
                        &notify,
                        &target_id,
                        &label,
                        &format!("{e}"),
                        kind,
                        hopeless,
                    )
                    .await;
                    return;
                }
            };
            let addrs = reply.socket_addrs();
            if addrs.is_empty() {
                report_failure(
                    &peers,
                    &notify,
                    &target_id,
                    &label,
                    "对端没有可用地址",
                    FailKind::Other,
                    hopeless,
                )
                .await;
                return;
            }
            let ip = reply.target_virtual_ip.parse::<Ipv4Addr>().ok();

            let result = {
                let engine = engine.read().await;
                engine
                    .punch_as(
                        &addrs,
                        Role::Dialer,
                        Engine::attempt_timeout(Role::Dialer),
                        Some(target.clone()),
                    )
                    .await
            };

            match result {
                Ok(conn) => on_connected(&peers, &mesh, &notify, target, label, ip, conn).await,
                Err(e) => {
                    report_failure(
                        &peers,
                        &notify,
                        &target_id,
                        &label,
                        &format!("{e}"),
                        FailKind::Other,
                        hopeless,
                    )
                    .await;
                }
            }
        });
    }
}

async fn on_connected(
    peers: &SharedPeers,
    mesh: &Option<Arc<MeshLinks>>,
    notify: &Notify,
    node_id: NodeId,
    label: String,
    ip: Option<Ipv4Addr>,
    conn: quinn::Connection,
) {
    let ip = {
        let mut table = peers.lock().await;
        match table.get_mut(node_id.as_str()) {
            Some(state) => {
                state.mark_connected();
                if ip.is_some() {
                    state.virtual_ip = ip;
                }
                state.virtual_ip
            }
            None => ip,
        }
    };

    if let (Some(mesh), Some(ip)) = (mesh, ip) {
        mesh.attach(ip, conn.clone()).await;
    }

    match ip {
        Some(ip) => notify.say(&format!(
            "✓ 直连已建立：{label} ({ip}) rtt={:?}",
            conn.rtt()
        )),
        None => notify.say(&format!(
            "✓ 直连已建立：{label}（服务端没给虚拟地址）rtt={:?}",
            conn.rtt()
        )),
    }

    // 断开后允许重新拨号
    let peers = peers.clone();
    tokio::spawn(async move {
        let reason = conn.closed().await;
        let mut table = peers.lock().await;
        if let Some(state) = table.get_mut(node_id.as_str()) {
            state.connected = false;
            // attempts 归零 = 允许立刻重连，不用等退避
            state.attempts = 0;
            state.last_try = Instant::now();
        }
        tracing::info!("[session] 与 {label} 的连接断开: {reason}");
    });
}

async fn report_failure(
    peers: &SharedPeers,
    notify: &Notify,
    node_id: &str,
    label: &str,
    reason: &str,
    kind: FailKind,
    hopeless: bool,
) {
    let first = {
        let mut table = peers.lock().await;
        match table.get_mut(node_id) {
            Some(state) => {
                match kind {
                    // 对端不在线：不再盲连，等 peer_online 通知或下一次注册带回它
                    FailKind::Offline => state.mark_offline(),
                    FailKind::Other => state.note_failure(Instant::now(), hopeless),
                }
                let first = !state.reported;
                state.reported = true;
                first
            }
            None => true,
        }
    };
    if !first {
        tracing::debug!("[session] 仍然连不上 {label}: {reason}");
        return;
    }
    match kind {
        FailKind::Offline => notify.say(&format!("· {label} 当前不在线，它上线后会自动连接")),
        FailKind::Other if hopeless => notify.say(&format!(
            "· 暂时连不上 {label}：两端都是对称 NAT，直连基本打不通（会低频重试）"
        )),
        FailKind::Other => notify.say(&format!("· 暂时连不上 {label}：{reason}（会自动重试）")),
    }
}

/// 可用来打洞的候选地址（过滤掉回环、链路本地之类）。
pub fn candidate_strings(engine: &Engine) -> Vec<String> {
    // live_candidates：带着周期 STUN 观测到的最新公网映射，而不是启动时那份
    engine
        .live_candidates()
        .iter()
        .filter(|c| c.is_usable() && dialable(&c.addr))
        .map(|c| c.addr.to_string())
        .collect()
}

/// 注册时报给服务端的 NAT 类型。
///
/// `upnp`：路由器上有确定的端口映射，等同开放；
/// `cone` / `symmetric`：两台以上 STUN 服务器观测后的映射行为；
/// `srflx`：只有一台服务器回应，判不了；`host`：STUN 全都不通。
pub fn nat_type(engine: &Engine) -> &'static str {
    if engine.upnp().is_some() {
        return "upnp";
    }
    match engine.nat_kind() {
        NatKind::Cone => "cone",
        NatKind::Symmetric => "symmetric",
        NatKind::Unknown if engine.srflx().is_some() => "srflx",
        NatKind::Unknown => "host",
    }
}

fn dialable(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => {
            let o = ip.octets();
            o[0] != 0
                && o[0] != 127
                && !(o[0] == 169 && o[1] == 254)
                && o[0] < 224
                && addr.port() != 0
        }
        IpAddr::V6(_) => false,
    }
}

/// 令牌被作废（网络删除 / 换过准入密码）导致的错误。
pub fn token_rejected(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<crate::signal::client::SignalError>()
        .map(|e| {
            matches!(
                e.code.as_str(),
                "wrong_secret" | "invalid_token" | "network_not_found"
            )
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 三种传输方式的语义：auto 允许长连接且会降级，always 不降级，never 不试。
    #[test]
    fn ws_mode_semantics() {
        assert!(WsMode::Auto.wants_ws() && WsMode::Auto.falls_back());
        assert!(WsMode::Always.wants_ws() && !WsMode::Always.falls_back());
        assert!(!WsMode::Never.wants_ws() && !WsMode::Never.falls_back());
    }

    #[test]
    fn only_dialable_candidates_are_reported() {
        let ok: SocketAddr = "203.0.113.7:51820".parse().unwrap();
        assert!(dialable(&ok));
        for bad in [
            "127.0.0.1:51820",
            "0.0.0.0:51820",
            "169.254.1.1:51820",
            "224.0.0.1:51820",
            "[::1]:51820",
        ] {
            assert!(!dialable(&bad.parse().unwrap()), "{bad} 不该上报");
        }
    }

    fn state(attempts: u32) -> PeerState {
        let mut s = PeerState::from_parts(String::new(), None, String::new());
        s.attempts = attempts;
        s
    }

    fn peer(id: &str, online: bool) -> PeerInfo {
        PeerInfo {
            node_id: id.to_string(),
            name: id.to_string(),
            virtual_ip: String::new(),
            nat_type: "cone".to_string(),
            tls_fp: String::new(),
            candidates: Vec::new(),
            last_seen: 0,
            online,
        }
    }

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(state(1).backoff(), Duration::from_secs(10));
        assert_eq!(state(2).backoff(), Duration::from_secs(20));
        assert_eq!(state(3).backoff(), Duration::from_secs(40));
        assert_eq!(state(9).backoff(), Duration::from_secs(60));
    }

    // ---------- 轮询档位 ----------

    fn inputs() -> PollInputs {
        PollInputs {
            sleeping: false,
            hot: false,
            wanted_unconnected: false,
            alone: false,
            idle: false,
        }
    }

    #[test]
    fn unconnected_peer_no_longer_pins_polling_at_hot() {
        // 旧行为：只要有对端没连上就永远 3 秒。现在要靠"刚发生了事"才进 HOT
        let wanting = PollInputs {
            wanted_unconnected: true,
            ..inputs()
        };
        assert_eq!(poll_interval(&wanting), POLL_WARM);
        let hot = PollInputs {
            hot: true,
            wanted_unconnected: true,
            ..inputs()
        };
        assert_eq!(poll_interval(&hot), POLL_HOT);
    }

    #[test]
    fn healthy_idle_goes_cold_and_active_stays_warm() {
        assert_eq!(
            poll_interval(&PollInputs {
                idle: true,
                ..inputs()
            }),
            POLL_COLD
        );
        assert_eq!(poll_interval(&inputs()), POLL_WARM);
    }

    #[test]
    fn alone_polls_warm_not_hot() {
        // 网络里只有自己：等别人加入，但没必要每 3 秒问一次
        assert_eq!(
            poll_interval(&PollInputs {
                alone: true,
                idle: true,
                ..inputs()
            }),
            POLL_WARM
        );
    }

    #[test]
    fn sleeping_is_always_cold_even_inside_hot_window() {
        assert_eq!(
            poll_interval(&PollInputs {
                sleeping: true,
                hot: true,
                wanted_unconnected: true,
                ..inputs()
            }),
            POLL_COLD
        );
    }

    #[test]
    fn error_backoff_grows_and_caps_at_five_minutes() {
        let secs: Vec<u64> = (0..9).map(|n| error_backoff(n).as_secs()).collect();
        assert_eq!(secs, vec![0, 10, 20, 40, 80, 160, 300, 300, 300]);
    }

    // ---------- renew 规划：活链路不能被打断 ----------

    fn renew_inputs() -> RenewInputs {
        RenewInputs {
            live: 0,
            all_lost: false,
            worst_streak: 0,
            sleeping: false,
            since_renew: Duration::from_secs(120),
            stun_misses: 0,
        }
    }

    #[test]
    fn live_links_are_never_torn_down_by_a_failing_peer() {
        // 回归：旧代码里，表里有一个打不通的对端 + 其它直连都健康时，
        // worst_streak >= 3 会触发 renew()，把所有健康直连一起关掉。
        let plan = plan_renew(&RenewInputs {
            live: 2,
            worst_streak: 5,
            stun_misses: 9,
            since_renew: Duration::from_secs(10_000),
            ..renew_inputs()
        });
        assert!(!plan.renew);
        assert!(!plan.clear_backoff);
    }

    #[test]
    fn no_links_and_repeated_failures_trigger_renew() {
        let plan = plan_renew(&RenewInputs {
            worst_streak: 3,
            ..renew_inputs()
        });
        assert!(plan.renew && plan.clear_backoff && plan.switch_detected);
    }

    #[test]
    fn network_switch_triggers_renew() {
        let plan = plan_renew(&RenewInputs {
            all_lost: true,
            ..renew_inputs()
        });
        assert!(plan.renew && plan.switch_detected);
    }

    #[test]
    fn silent_stun_keepalive_triggers_renew_when_idle() {
        let plan = plan_renew(&RenewInputs {
            stun_misses: STUN_MISS_RENEW,
            ..renew_inputs()
        });
        assert!(plan.renew);
        // 休眠时 STUN 保活是关着的，misses 是陈旧值，不能据此重绑
        let sleeping = plan_renew(&RenewInputs {
            stun_misses: STUN_MISS_RENEW,
            sleeping: true,
            ..renew_inputs()
        });
        assert!(!sleeping.renew);
    }

    #[test]
    fn renew_is_rate_limited_but_still_clears_backoff() {
        let plan = plan_renew(&RenewInputs {
            all_lost: true,
            since_renew: Duration::from_secs(5),
            ..renew_inputs()
        });
        assert!(!plan.renew, "刚重绑过，不能连着再绑");
        assert!(plan.clear_backoff, "但要让对端重试");
    }

    #[test]
    fn periodic_renew_only_when_idle_for_long_enough() {
        let due = plan_renew(&RenewInputs {
            since_renew: RENEW_EVERY,
            ..renew_inputs()
        });
        assert!(due.renew && !due.switch_detected);
        assert!(!plan_renew(&renew_inputs()).renew);
    }

    // ---------- 拨号判定 ----------

    #[test]
    fn dial_skips_offline_cooling_and_listener_side() {
        let now = Instant::now();
        let mut s = state(0);
        assert!(should_dial(&s, "aaa", "bbb", now, false), "我小，我拨");
        assert!(!should_dial(&s, "bbb", "aaa", now, false), "我大，等对方拨");

        s.online = false;
        assert!(!should_dial(&s, "aaa", "bbb", now, false), "离线不盲连");
        assert!(should_dial(&s, "aaa", "bbb", now, true), "但有包要发时照连");

        s.online = true;
        s.cool_until = Some(now + Duration::from_secs(60));
        assert!(!should_dial(&s, "aaa", "bbb", now, false), "冷却中不打扰");
        assert!(should_dial(
            &s,
            "aaa",
            "bbb",
            now + Duration::from_secs(61),
            false
        ));
    }

    #[test]
    fn dial_respects_backoff_and_connected() {
        let now = Instant::now();
        let mut s = state(2);
        s.last_try = now;
        assert!(!should_dial(&s, "aaa", "bbb", now, false), "退避期内");
        assert!(should_dial(
            &s,
            "aaa",
            "bbb",
            now + Duration::from_secs(21),
            false
        ));
        s.connected = true;
        assert!(!should_dial(
            &s,
            "aaa",
            "bbb",
            now + Duration::from_secs(99),
            false
        ));
    }

    // ---------- 失败与冷却 ----------

    #[test]
    fn failures_lead_to_cooldown_with_growing_spans() {
        let now = Instant::now();
        let mut s = state(0);
        for _ in 0..COOL_AFTER_FIRST - 1 {
            s.note_failure(now, false);
            assert!(!s.cooling(now));
        }
        s.note_failure(now, false);
        assert!(s.cooling(now));
        assert_eq!(s.cool_until, Some(now + Duration::from_secs(300)));
        assert_eq!((s.fails, s.attempts), (0, 0));

        // 冷却过后只给 2 次机会，下一轮冷却翻倍
        let later = now + Duration::from_secs(301);
        for _ in 0..COOL_AFTER_REPEAT {
            s.note_failure(later, false);
        }
        assert_eq!(s.cool_until, Some(later + Duration::from_secs(600)));
    }

    #[test]
    fn cooldown_caps_at_thirty_minutes() {
        assert_eq!(cooldown(0), Duration::from_secs(300));
        assert_eq!(cooldown(1), Duration::from_secs(600));
        assert_eq!(cooldown(2), Duration::from_secs(1200));
        assert_eq!(cooldown(3), Duration::from_secs(1800));
        assert_eq!(cooldown(40), Duration::from_secs(1800));
    }

    #[test]
    fn hopeless_pair_gets_one_try_then_longest_cooldown() {
        let now = Instant::now();
        let mut s = state(1);
        s.note_failure(now, true);
        assert_eq!(s.cool_until, Some(now + COOLDOWN_MAX));
    }

    #[test]
    fn coming_online_or_connecting_clears_penalties() {
        let now = Instant::now();
        let mut s = state(4);
        s.note_failure(now, true);
        s.mark_offline();
        s.mark_online();
        assert!(!s.cooling(now) && s.cool_count == 0 && s.attempts == 0 && s.fails == 0);

        s.note_failure(now, true);
        s.mark_connected();
        assert!(s.connected && !s.cooling(now) && s.cool_count == 0);
    }

    // ---------- 对端表合并 ----------

    #[test]
    fn peer_list_prunes_vanished_peers_but_keeps_live_links() {
        let mut table: HashMap<String, PeerState> = HashMap::new();
        table.insert("gone".into(), state(0));
        let mut live = state(0);
        live.connected = true;
        table.insert("live-but-forgotten".into(), live);
        table.insert("stay".into(), state(0));

        apply_peer_list(&mut table, &[peer("stay", true)]);

        assert!(!table.contains_key("gone"), "服务端已清掉、又没连着：删除");
        assert!(table.contains_key("live-but-forgotten"), "链路还在：保留");
        assert!(table.contains_key("stay"));
    }

    #[test]
    fn peer_list_tracks_online_flag_and_reports_new_arrivals() {
        let mut table: HashMap<String, PeerState> = HashMap::new();
        // 新出现的在线对端 → new_online
        assert!(apply_peer_list(&mut table, &[peer("a", true)]).new_online);
        // 没变化 → 不算
        assert!(!apply_peer_list(&mut table, &[peer("a", true)]).new_online);
        // 离线
        assert!(!apply_peer_list(&mut table, &[peer("a", false)]).new_online);
        assert!(!table["a"].online);
        // 又上线：清掉之前的惩罚，并报告
        table.get_mut("a").unwrap().cool_count = 3;
        assert!(apply_peer_list(&mut table, &[peer("a", true)]).new_online);
        assert!(table["a"].online && table["a"].cool_count == 0);
    }

    #[test]
    fn new_offline_peer_is_known_but_not_wanted() {
        let mut table: HashMap<String, PeerState> = HashMap::new();
        let change = apply_peer_list(&mut table, &[peer("off", false)]);
        assert!(!change.new_online);
        assert!(!table["off"].online);
    }

    #[test]
    fn old_worker_without_online_field_defaults_to_online() {
        let json = r#"{"node_id":"abc","name":"n"}"#;
        let p: PeerInfo = serde_json::from_str(json).unwrap();
        assert!(p.online, "老 Worker 不返回 online：按在线处理，保持旧行为");
    }

    #[test]
    fn failure_kind_follows_server_error_code() {
        let mk = |code: &str| {
            anyhow::Error::new(SignalError {
                status: 410,
                code: code.to_string(),
                message: String::new(),
            })
        };
        assert_eq!(fail_kind(&mk("target_offline")), FailKind::Offline);
        assert_eq!(fail_kind(&mk("target_not_found")), FailKind::Offline);
        assert_eq!(fail_kind(&mk("target_stale")), FailKind::Other);
        assert_eq!(fail_kind(&anyhow::anyhow!("timeout")), FailKind::Other);
    }
}
