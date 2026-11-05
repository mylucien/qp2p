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

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use quinn::{Connection, ReadExactError, RecvStream, SendStream};
use tokio::sync::{mpsc, RwLock};

use crate::route::{flow::FlowKey, flow::FlowTable, ip, TunLink};

/// 流类型：IP 包。
const KIND_IP: u8 = 2;
/// 空闲多久回收一条流。
const FLOW_IDLE: Duration = Duration::from_secs(120);
/// 同时存在的流上限，与 quinn 的 `max_concurrent_bidi_streams` 对齐。
const FLOW_CAPACITY: usize = 200;
const READ_BUF: usize = 4096;

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

/// 多对端连接表：目标虚拟地址 → 已建立的直连。
///
/// 组网时一台机器同时和多个节点相连，内核把一个包交给 TUN 之后，
/// 我们只能靠**目标地址**判断该从哪条连接发出去。
pub struct MeshLinks {
    peers: RwLock<HashMap<Ipv4Addr, Connection>>,
    to_tun: mpsc::Sender<Vec<u8>>,
    /// 目标没有直连时，把对端虚拟地址丢进来，让会话循环立刻去打通它
    wake: RwLock<Option<mpsc::Sender<Ipv4Addr>>>,
    activity: Activity,
    /// 上一次唤醒的时间（毫秒）；3 秒冷却，避免持续丢包把信令打成洪水
    started: Instant,
    last_wake_ms: Arc<AtomicU64>,
}

impl MeshLinks {
    pub fn new(to_tun: mpsc::Sender<Vec<u8>>) -> Arc<Self> {
        Arc::new(Self {
            peers: RwLock::new(HashMap::new()),
            to_tun,
            wake: RwLock::new(None),
            activity: Activity::new(),
            started: Instant::now(),
            last_wake_ms: Arc::new(AtomicU64::new(0)),
        })
    }

    /// 会话循环启动时挂上唤醒通道。没挂之前丢包就是丢包，行为和以前一致。
    pub async fn set_wake(&self, tx: mpsc::Sender<Ipv4Addr>) {
        *self.wake.write().await = Some(tx);
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
        for (_, conn) in peers.drain() {
            conn.close(0u32.into(), b"idle");
        }
        count
    }

    /// 挂上一个刚打通的直连：开始接收它的入站包，断开时自动摘除。
    ///
    /// 同一个虚拟 IP 已有旧连接时直接替换（对端重启或 NAT 重新映射都会这样），
    /// 旧连接关掉即可——它的流会在写失败后自然淘汰。
    pub async fn attach(self: &Arc<Self>, ip: Ipv4Addr, conn: Connection) {
        let old = {
            let mut peers = self.peers.write().await;
            peers.insert(ip, conn.clone())
        };
        if let Some(old) = old {
            if old.stable_id() != conn.stable_id() {
                tracing::debug!("[tun] {ip} 的连接已刷新，关闭旧连接");
                old.close(0u32.into(), b"replaced");
            }
        }

        {
            let conn = conn.clone();
            let to_tun = self.to_tun.clone();
            let activity = self.activity.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_inbound(conn, to_tun, activity).await {
                    tracing::debug!("[tun] 接收循环结束: {e:#}");
                }
            });
        }

        // 断开后把表项清掉，否则新包会一直往死连接里塞
        let weak = Arc::downgrade(self);
        let watch = conn.clone();
        tokio::spawn(async move {
            let _ = watch.closed().await;
            let Some(links) = weak.upgrade() else { return };
            let mut peers = links.peers.write().await;
            // 只删自己：这个 IP 可能已经被更新的连接顶上来了
            if peers.get(&ip).map(Connection::stable_id) == Some(watch.stable_id()) {
                peers.remove(&ip);
            }
        });
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

    async fn conn_for(&self, dst: Ipv4Addr) -> Option<Connection> {
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

    let inbound = {
        let conn = conn.clone();
        let to_tun = to_tun.clone();
        let activity = Activity::new();
        tokio::spawn(async move {
            if let Err(e) = serve_inbound(conn, to_tun, activity).await {
                tracing::debug!("[tun] 接收循环结束: {e:#}");
            }
        })
    };

    let result = pump(Route::Single(conn), from_tun, to_tun, local, mtu).await;
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
    Single(Connection),
    Mesh(Arc<MeshLinks>),
}

impl Route {
    async fn conn_for(&self, dst: Ipv4Addr) -> Option<Connection> {
        match self {
            Self::Single(conn) => Some(conn.clone()),
            Self::Mesh(links) => links.conn_for(dst).await,
        }
    }
}

type FlowValue = (Connection, SendStream);

async fn pump(
    route: Route,
    mut from_tun: mpsc::Receiver<Vec<u8>>,
    to_tun: mpsc::Sender<Vec<u8>>,
    local: Ipv4Addr,
    mtu: usize,
) -> Result<()> {
    let mut flows: FlowTable<FlowValue> = FlowTable::new(FLOW_IDLE, FLOW_CAPACITY);
    let mut last_sweep = Instant::now();

    loop {
        tokio::select! {
            packet = from_tun.recv() => {
                let Some(packet) = packet else { break };
                if let Err(e) = dispatch(&route, &mut flows, &to_tun, local, &packet, mtu).await {
                    tracing::debug!("[tun] 转发失败: {e:#}");
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                if last_sweep.elapsed() >= Duration::from_secs(5) {
                    last_sweep = Instant::now();
                    for (key, (_, mut send)) in flows.sweep(Instant::now()) {
                        tracing::trace!("[tun] 回收空闲流 {key:?}");
                        let _ = send.reset(0u32.into());
                    }
                }
            }
        }
    }

    for (_, (_, mut send)) in flows.drain() {
        let _ = send.reset(0u32.into());
    }
    Ok(())
}

async fn dispatch(
    route: &Route,
    flows: &mut FlowTable<FlowValue>,
    to_tun: &mpsc::Sender<Vec<u8>>,
    local: Ipv4Addr,
    packet: &[u8],
    mtu: usize,
) -> Result<()> {
    let Some(parsed) = ip::parse(packet) else {
        return Ok(());
    };

    // 出站包也算活跃：会话循环据此决定轮询档位和要不要断链
    if let Route::Mesh(links) = route {
        links.activity.touch();
    }

    // 1. 打自己的 ping 就地应答，不打扰对端
    if parsed.dst == local && ip::is_echo_request(&parsed) {
        if let Some(reply) = ip::echo_reply(&parsed) {
            let _ = to_tun.send(reply).await;
        }
        return Ok(());
    }

    if packet.len() > mtu {
        bail!("包比 MTU 大（{} > {mtu}），内核本应分片", packet.len());
    }

    // 2. 已有流就复用
    let key = FlowKey::new(parsed.proto, parsed.src, parsed.dst, parsed.ports);
    let now = Instant::now();
    if flows.contains(&key) {
        let (_, send) = flows.get_mut(&key, now).expect("刚判断过存在");
        if write_frame(send, packet).await.is_ok() {
            return Ok(());
        }
        // 写失败说明这条流已经废了，删掉后下面重开一条
        flows.remove(&key);
    }

    // 3. 这个目标没有直连：叫会话循环立刻去打通它，这个包先丢（重传会补上）
    let Some(conn) = route.conn_for(parsed.dst).await else {
        if let Route::Mesh(links) = route {
            links.wake_peer(parsed.dst).await;
        }
        tracing::debug!("[tun] 目标 {} 没有直连，已唤醒打洞", parsed.dst);
        return Ok(());
    };

    // 4. 新开一条流
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .with_context(|| format!("向 {} 打开双向流失败", parsed.dst))?;
    send.write_all(&[KIND_IP]).await.context("写流类型失败")?;
    write_frame(&mut send, packet).await?;

    // 对端可能主动关流：等它，顺便把错误暴露到日志
    tokio::spawn(async move {
        let mut buf = [0u8; 64];
        let _ = recv.read(&mut buf).await;
    });

    if let Some((old, (_, mut old_send))) = flows.insert(key, (conn, send), now) {
        let _ = old_send.reset(0u32.into());
        tracing::debug!("[tun] 流表满，淘汰 {old:?}");
    }
    Ok(())
}

async fn write_frame(send: &mut SendStream, packet: &[u8]) -> Result<()> {
    let len = u16::try_from(packet.len()).context("单个 IP 包超过 64KB")?;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(packet).await?;
    Ok(())
}

/// 接收方向：对端每开一条流就是一个新 flow。
async fn serve_inbound(
    conn: Connection,
    to_tun: mpsc::Sender<Vec<u8>>,
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
        tokio::spawn(async move {
            if let Err(e) = pump_stream(&mut recv, to_tun, activity).await {
                tracing::trace!("[tun] 流结束: {e:#}");
            }
            drop(send);
        });
    }
}

async fn pump_stream(
    recv: &mut RecvStream,
    to_tun: mpsc::Sender<Vec<u8>>,
    activity: Activity,
) -> Result<()> {
    let mut kind = [0u8; 1];
    recv.read_exact(&mut kind).await.context("读流类型失败")?;
    if kind[0] != KIND_IP {
        bail!("不是 IP 流（类型 {}）", kind[0]);
    }

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
        if to_tun.send(buf).await.is_err() {
            return Ok(());
        }
    }
}
