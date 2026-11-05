//! 组网上线后的会话循环：拉事件、应答撮合、按规则拨号、定时重注册。
//!
//! 这段逻辑原来在 CLI 里，Android 也要用同一套（打洞规则、退避、事件应答
//! 任何一处走样都会出现"PC 能连、手机连不上"的怪问题），所以下沉到这里。
//! 面向用户的状态输出用回调，CLI 打 `println!`，Android 塞进通知栏或日志。

use std::collections::HashMap;
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
use crate::signal::client::{PeerInfo, SignalClient};

/// 事件轮询间隔。
const POLL: Duration = Duration::from_secs(3);
/// 重新注册间隔：候选地址可能因 NAT 重新映射而变化。
const REGISTER_EVERY: Duration = Duration::from_secs(60);
/// 一个都连不上时，重新做 STUN 的间隔。
const RENEW_EVERY: Duration = Duration::from_secs(600);

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
    /// 注册时拿到的成员列表
    pub peers: Vec<PeerInfo>,
}

struct PeerState {
    name: String,
    virtual_ip: Option<Ipv4Addr>,
    connected: bool,
    /// 尝试过几次（0 表示从没试过，应当立刻连）
    attempts: u32,
    last_try: Instant,
    /// 失败原因只打印一次，避免每 20 秒刷屏
    reported: bool,
}

impl PeerState {
    fn new(peer: &PeerInfo) -> Self {
        Self {
            name: peer.name.clone(),
            virtual_ip: peer.virtual_ip.parse().ok(),
            connected: false,
            attempts: 0,
            last_try: Instant::now(),
            reported: false,
        }
    }

    /// 退避：10s、20s、40s、60s（封顶）。
    fn backoff(&self) -> Duration {
        let exp = self.attempts.saturating_sub(1).min(3);
        Duration::from_secs(10 * (1u64 << exp)).min(Duration::from_secs(60))
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
            peers: initial,
        } = self.config;

        {
            let mut table = self.peers.lock().await;
            for peer in &initial {
                table.insert(peer.node_id.clone(), PeerState::new(peer));
            }
        }

        let mut cursor: i64 = 0;
        let mut last_register = Instant::now();
        let mut last_renew = Instant::now();
        let mut last_error = String::new();

        while !self.stop.load(Ordering::Relaxed) {
            // 1) 拉事件：对端请求撮合时，服务端会往这里塞 punch_request
            match client.events(&identity, cursor).await {
                Ok(reply) => {
                    cursor = reply.cursor;
                    for event in reply.events {
                        if event.kind != "punch_request" {
                            continue;
                        }
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
                        let label = event.str("from_name").unwrap_or("未知节点").to_string();

                        let engine = self.engine.clone();
                        let peers = self.peers.clone();
                        let mesh = self.mesh.clone();
                        let notify = self.notify.clone();
                        tokio::spawn(async move {
                            answer_punch(engine, peers, mesh, notify, from, label, ip, addrs).await;
                        });
                    }
                    if !last_error.is_empty() {
                        last_error.clear();
                    }
                }
                Err(e) => {
                    // 令牌被换掉 / 网络被删：再轮询也没有意义
                    if token_rejected(&e) {
                        self.notify.say("⚠ 加入令牌已失效（网络被删除，或管理员换了准入密码）。现有直连还能用，但新节点连不上来了。");
                        return;
                    }
                    // 只在不重复的时候喊一声
                    let text = format!("{e:#}");
                    if text != last_error {
                        self.notify.say(&format!("⚠ 拉取事件失败：{text}"));
                        last_error = text;
                    }
                }
            }

            // 2) 主动发起：node_id 小的一方负责拨号，避免两边同时重复建连
            dial_round(
                &client,
                &identity,
                &node_id,
                &self.engine,
                &self.peers,
                &self.mesh,
                &self.notify,
            )
            .await;

            // 3) 定时重新注册：候选地址可能变了，顺便刷新成员列表
            if last_register.elapsed() >= REGISTER_EVERY {
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
                        for peer in &reply.peers {
                            match table.get_mut(&peer.node_id) {
                                Some(state) => {
                                    state.name = peer.name.clone();
                                    if let Ok(ip) = peer.virtual_ip.parse() {
                                        state.virtual_ip = Some(ip);
                                    }
                                }
                                None => {
                                    table.insert(peer.node_id.clone(), PeerState::new(peer));
                                }
                            }
                        }
                    }
                    Err(e) => tracing::debug!("[session] 刷新注册失败: {e:#}"),
                }
            }

            // 4) 一个都连不上很久了：刷新端点重新做 STUN（有直连时绝不能动）
            if last_renew.elapsed() >= RENEW_EVERY {
                let alive = match &self.mesh {
                    Some(mesh) => mesh.peer_count().await > 0,
                    None => self.peers.lock().await.values().any(|p| p.connected),
                };
                if !alive {
                    last_renew = Instant::now();
                    let renewed = {
                        let mut guard = self.engine.write().await;
                        guard.renew().await
                    };
                    match renewed {
                        Ok(()) => tracing::info!("[session] 端点已刷新（重新探测 NAT 映射）"),
                        Err(e) => tracing::debug!("[session] 端点刷新失败: {e:#}"),
                    }
                }
            }

            tokio::time::sleep(POLL).await;
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
        let state = table.entry(from.to_string()).or_insert_with(|| PeerState {
            name: label.clone(),
            virtual_ip: ip,
            connected: false,
            attempts: 0,
            last_try: Instant::now(),
            reported: false,
        });
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
async fn dial_round(
    client: &SignalClient,
    identity: &Identity,
    node_id: &NodeId,
    engine: &Arc<RwLock<Engine>>,
    peers: &SharedPeers,
    mesh: &Option<Arc<MeshLinks>>,
    notify: &Notify,
) {
    let targets: Vec<(String, String)> = {
        let mut table = peers.lock().await;
        let now = Instant::now();
        let mut out = Vec::new();
        for (id, state) in table.iter_mut() {
            if state.connected {
                continue;
            }
            // 双方都拨会各建一条连接；固定由 node_id 小的一方发起
            if node_id.as_str() >= id.as_str() {
                continue;
            }
            if state.attempts > 0 && now.duration_since(state.last_try) < state.backoff() {
                continue;
            }
            state.attempts += 1;
            state.last_try = now;
            out.push((id.clone(), state.name.clone()));
        }
        out
    };

    for (target_id, label) in targets {
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
                    report_failure(&peers, &notify, &target_id, &label, &format!("{e}")).await;
                    return;
                }
            };
            let addrs = reply.socket_addrs();
            if addrs.is_empty() {
                report_failure(&peers, &notify, &target_id, &label, "对端没有可用地址").await;
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
                    report_failure(&peers, &notify, &target_id, &label, &format!("{e}")).await;
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
                state.connected = true;
                state.attempts = 0;
                state.reported = false;
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
) {
    let first = {
        let mut table = peers.lock().await;
        match table.get_mut(node_id) {
            Some(state) => {
                let first = !state.reported;
                state.reported = true;
                first
            }
            None => true,
        }
    };
    if first {
        notify.say(&format!("· 暂时连不上 {label}：{reason}（会自动重试）"));
    } else {
        tracing::debug!("[session] 仍然连不上 {label}: {reason}");
    }
}

/// 可用来打洞的候选地址（过滤掉回环、链路本地之类）。
pub fn candidate_strings(engine: &Engine) -> Vec<String> {
    engine
        .candidates()
        .iter()
        .filter(|c| c.is_usable() && dialable(&c.addr))
        .map(|c| c.addr.to_string())
        .collect()
}

/// 注册时报给服务端的 NAT 类型。
pub fn nat_type(engine: &Engine) -> &'static str {
    if engine.upnp().is_some() {
        "upnp"
    } else if engine.srflx().is_some() {
        "srflx"
    } else {
        "host"
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

    #[test]
    fn backoff_grows_and_caps() {
        let mk = |attempts| PeerState {
            name: String::new(),
            virtual_ip: None,
            connected: false,
            attempts,
            last_try: Instant::now(),
            reported: false,
        };
        assert_eq!(mk(1).backoff(), Duration::from_secs(10));
        assert_eq!(mk(2).backoff(), Duration::from_secs(20));
        assert_eq!(mk(3).backoff(), Duration::from_secs(40));
        assert_eq!(mk(9).backoff(), Duration::from_secs(60));
    }
}
