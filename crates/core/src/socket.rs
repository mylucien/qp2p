//! 绑定 UDP socket、STUN 探测、UPnP 预映射，然后把同一个 socket 交给 quinn。
//!
//! 顺序不能变：先绑 → 在**这个** socket 上 STUN → 再创建端点。
//! 旧版用另一个随机端口的 socket 探测再替换端口，NAT 映射按五元组算，
//! 两者毫无关系。

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rand::RngCore;
use tokio::sync::mpsc;

use crate::candidate::{normalize, Candidate, CandidateKind};
use crate::stun;
use crate::upnp;

/// 一次绑定得到的全部结果。
pub struct Bound {
    pub endpoint: quinn::Endpoint,
    /// 实际绑定的地址，`renew` 用它重绑同一个端口
    pub bind_addr: SocketAddr,
    pub local_addr: SocketAddr,
    pub srflx: Option<SocketAddr>,
    pub upnp: Option<SocketAddr>,
    /// UPnP 映射句柄：Engine 负责续租，退出时删除
    pub mapping: Option<upnp::Mapping>,
    pub candidates: Vec<Candidate>,
    /// 与 quinn 共享同一个 UDP socket 的额外句柄，只用于发保活包
    pub keepalive: Arc<std::net::UdpSocket>,
    /// 启动时的 NAT 映射行为判定
    pub nat: stun::NatKind,
    /// 周期性 STUN 保活的目标：优先用启动时有回应的，全都没回应就用解析到的全部
    pub stun_targets: Vec<SocketAddr>,
    /// quinn 接管 socket 后，旁路收到的 STUN 响应从这里出来（只能被取走一次）
    pub stun_rx: Option<mpsc::UnboundedReceiver<StunReply>>,
}

/// 旁路观察到的一条 STUN 响应。
#[derive(Debug, Clone, Copy)]
pub struct StunReply {
    pub from: SocketAddr,
    pub txid: [u8; 12],
    pub mapped: SocketAddr,
}

/// 启动探测时某台服务器给出的观测。
#[derive(Debug, Clone, Copy)]
pub struct StunObservation {
    pub server: SocketAddr,
    pub mapped: SocketAddr,
}

/// 绑定并初始化端点。
///
/// `tls` 决定服务端出示哪张证书：同一份 `TlsIdentity` 重启后指纹不变，
/// 对端才能钉扎。
pub async fn bind(
    bind_addr: SocketAddr,
    stun_servers: &[String],
    tls: &crate::tls::TlsIdentity,
) -> Result<Bound> {
    let socket = bind_socket(bind_addr)?;
    socket
        .set_nonblocking(false)
        .context("切换 socket 为阻塞模式失败")?;

    let local_addr = socket.local_addr().context("读取本地地址失败")?;
    let keepalive = Arc::new(socket.try_clone().context("复制 socket 句柄失败")?);

    // 1) STUN：必须在交给 quinn 之前，且用同一个 socket
    let probe = probe_stun(&socket, stun_servers, Duration::from_secs(3)).await;
    let srflx = probe.observations.first().map(|o| o.mapped);
    let pairs: Vec<(IpAddr, SocketAddr)> = probe
        .observations
        .iter()
        .map(|o| (o.server.ip(), o.mapped))
        .collect();
    let nat = stun::classify(&pairs);
    let stun_targets: Vec<SocketAddr> = if probe.observations.is_empty() {
        probe.resolved.iter().copied().take(4).collect()
    } else {
        probe
            .observations
            .iter()
            .map(|o| o.server)
            .take(2)
            .collect()
    };
    tracing::info!(
        "[socket] NAT 映射判定: {}（{} 台服务器有回应）",
        nat.as_str(),
        probe.observations.len()
    );

    // 2) UPnP：失败只是少一个候选；回环地址上没有路由器可问，直接跳过
    let mapping = if local_addr.ip().is_loopback() {
        None
    } else {
        try_upnp(local_addr, Duration::from_secs(2)).await
    };
    let upnp_mapping = mapping.as_ref().map(upnp::Mapping::external);

    socket
        .set_nonblocking(true)
        .context("切换 socket 为非阻塞模式失败")?;

    let mut candidates = host_candidates(local_addr, bind_addr);
    if let Some(addr) = srflx {
        candidates.push(Candidate::new(CandidateKind::Srflx, addr));
    }
    if let Some(addr) = upnp_mapping {
        candidates.push(Candidate::new(CandidateKind::Upnp, addr));
    }
    let candidates = normalize(candidates);

    let server_config = tls.server_config()?;
    let client_config = crate::tls::client_config(None)?;

    // 用旁观 socket 包一层：quinn 照常收发，STUN 响应顺手抄一份出来
    let (stun_tx, stun_rx) = mpsc::unbounded_channel();
    let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
    let inner = runtime
        .wrap_udp_socket(socket)
        .context("包装 UDP socket 失败")?;
    let observing: Arc<dyn quinn::AsyncUdpSocket> =
        Arc::new(ObservingSocket { inner, tx: stun_tx });
    let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_config),
        observing,
        runtime,
    )
    .context("创建 QUIC 端点失败")?;
    endpoint.set_default_client_config(client_config);

    Ok(Bound {
        endpoint,
        bind_addr: local_addr,
        local_addr,
        srflx,
        upnp: upnp_mapping,
        mapping,
        candidates,
        keepalive,
        nat,
        stun_targets,
        stun_rx: Some(stun_rx),
    })
}

/// 包着 quinn 自带 socket 的旁观者：行为完全委托，只额外检查收到的包是不是 STUN 响应。
///
/// 只"看"不"拿"：STUN 包原样留在批次里，quinn 会把它当作无效 QUIC 包丢掉——
/// 和现有保活探针的处理方式一致，不改变任何收包语义。
#[derive(Debug)]
struct ObservingSocket {
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    tx: mpsc::UnboundedSender<StunReply>,
}

impl quinn::AsyncUdpSocket for ObservingSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut TaskContext,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let polled = self.inner.poll_recv(cx, bufs, meta);
        if let Poll::Ready(Ok(n)) = &polled {
            for i in 0..*n {
                let len = meta[i].len.min(bufs[i].len());
                let data = &bufs[i][..len];
                if !stun::is_stun(data) {
                    continue;
                }
                if let (Some(txid), Ok(mapped)) =
                    (stun::txid_of(data), stun::parse_binding_response(data))
                {
                    // 接收端没了（Engine 已销毁）时发送失败，忽略即可
                    let _ = self.tx.send(StunReply {
                        from: meta[i].addr,
                        txid,
                        mapped,
                    });
                }
            }
        }
        polled
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

fn bind_socket(addr: SocketAddr) -> Result<std::net::UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .context("创建 UDP socket 失败")?;
    socket
        .bind(&addr.into())
        .with_context(|| format!("绑定 {addr} 失败"))?;
    Ok(socket.into())
}

/// 启动探测的结果。
pub struct StunProbe {
    /// 按到达顺序排列；第一条用作 srflx
    pub observations: Vec<StunObservation>,
    /// 解析到的全部服务器地址（IPv4），探测全部失败时留给周期保活继续尝试
    pub resolved: Vec<SocketAddr>,
}

/// 拿到第一个响应之后，再多等多久看有没有第二台服务器回应（用于分类）。
const SECOND_ANSWER_WAIT: Duration = Duration::from_millis(400);

/// 同时向所有 STUN 服务器发请求。
///
/// - 第一个响应到手后只再多等 `SECOND_ANSWER_WAIT`，凑够两台**不同 IP**的服务器就立刻返回，
///   这样既不拖慢启动，又能判定 NAT 映射行为。
/// - 国内外服务器混着配：不可达的那几台只是没有回应，不会拖累结果。
async fn probe_stun(
    socket: &std::net::UdpSocket,
    servers: &[String],
    timeout: Duration,
) -> StunProbe {
    let empty = || StunProbe {
        observations: Vec::new(),
        resolved: Vec::new(),
    };
    let Ok(socket) = socket.try_clone() else {
        return empty();
    };
    let servers: Vec<String> = servers.to_vec();

    tokio::task::spawn_blocking(move || probe_stun_blocking(&socket, &servers, timeout))
        .await
        .unwrap_or_else(|_| empty())
}

fn probe_stun_blocking(
    socket: &std::net::UdpSocket,
    servers: &[String],
    timeout: Duration,
) -> StunProbe {
    // txid -> (服务器名, 期望来源)，用来把响应和请求对上
    let mut pending: HashMap<[u8; 12], (String, SocketAddr)> = HashMap::new();
    let mut resolved: Vec<SocketAddr> = Vec::new();

    for server in servers {
        let Some(addrs) = resolve(server) else {
            tracing::warn!("[socket] STUN 地址无法解析: {server}");
            continue;
        };
        // socket 是 IPv4 的；每个域名最多取 2 个地址，避免一次发出一大片
        for addr in addrs.into_iter().filter(SocketAddr::is_ipv4).take(2) {
            resolved.push(addr);
            let mut txid = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut txid);
            match socket.send_to(&stun::build_binding_request(txid), addr) {
                Ok(_) => {
                    pending.insert(txid, (server.clone(), addr));
                }
                Err(e) => tracing::info!("[socket] STUN {server} ({addr}) 发送失败: {e}"),
            }
        }
    }

    let mut observations: Vec<StunObservation> = Vec::new();
    if pending.is_empty() {
        return StunProbe {
            observations,
            resolved,
        };
    }

    let deadline = Instant::now() + timeout;
    let mut first_at: Option<Instant> = None;
    let mut buf = [0u8; 512];

    while !pending.is_empty() {
        // 有了第一条之后，截止时间收紧到 first_at + SECOND_ANSWER_WAIT
        let limit = match first_at {
            Some(t) => deadline.min(t + SECOND_ANSWER_WAIT),
            None => deadline,
        };
        let left = limit.saturating_duration_since(Instant::now());
        if left.is_zero() || socket.set_read_timeout(Some(left)).is_err() {
            break;
        }

        let (n, from) = match socket.recv_from(&mut buf) {
            Ok(pair) => pair,
            Err(_) => break, // 超时
        };
        let response = &buf[..n];
        if !stun::is_stun(response) {
            continue;
        }
        let Some(txid) = stun::txid_of(response) else {
            continue;
        };
        let Some((server, expected)) = pending.get(&txid) else {
            // 不是我们这次发的请求（可能是上一次探测的迟到包）
            continue;
        };
        if from != *expected {
            tracing::info!("[socket] STUN {server} 响应来源不符: {from}");
            continue;
        }
        let (server, expected) = (server.clone(), *expected);
        pending.remove(&txid);

        match stun::parse_binding_response(response) {
            Ok(mapped) => {
                tracing::info!("[socket] STUN {server} 观测到公网映射 {mapped}");
                observations.push(StunObservation {
                    server: expected,
                    mapped,
                });
                first_at.get_or_insert_with(Instant::now);
                // 两台不同 IP 的服务器都回应了：够分类，不用再等
                let mut ips: Vec<IpAddr> = observations.iter().map(|o| o.server.ip()).collect();
                ips.sort();
                ips.dedup();
                if ips.len() >= 2 {
                    break;
                }
            }
            Err(e) => tracing::info!("[socket] STUN {server} 响应解析失败: {e}"),
        }
    }

    StunProbe {
        observations,
        resolved,
    }
}

/// `host:port` 解析，支持域名。
fn resolve(server: &str) -> Option<Vec<SocketAddr>> {
    use std::net::ToSocketAddrs;
    match server.to_socket_addrs() {
        Ok(addrs) => {
            let list: Vec<SocketAddr> = addrs.collect();
            (!list.is_empty()).then_some(list)
        }
        Err(_) => None,
    }
}

async fn try_upnp(local_addr: SocketAddr, timeout: Duration) -> Option<upnp::Mapping> {
    // 绑 0.0.0.0 时不能把 0.0.0.0 当内网地址发给路由器
    let local_ip = match local_addr.ip() {
        IpAddr::V4(v4) if !v4.is_unspecified() => v4,
        _ => match primary_ipv4() {
            Some(ip) => ip,
            None => {
                tracing::info!("[socket] 拿不到本机出口地址，跳过 UPnP");
                return None;
            }
        },
    };

    match upnp::map_udp_port(local_ip, local_addr.port(), timeout).await {
        Ok(mapping) => {
            tracing::info!(
                "[socket] UPnP 映射成功 {}（租约 {} 秒）",
                mapping.external(),
                mapping.lease()
            );
            Some(mapping)
        }
        Err(e) => {
            tracing::info!("[socket] UPnP 不可用（继续打洞）: {e}");
            None
        }
    }
}

/// 枚举本机网卡地址作为内网候选。
///
/// 过滤掉链路本地地址和虚拟网卡（docker / Hyper-V / VMware 等）：
/// 这些地址通告出去只会让别人打到错误的设备。
fn host_candidates(local_addr: SocketAddr, requested: SocketAddr) -> Vec<Candidate> {
    let mut out = Vec::new();
    if !requested.ip().is_unspecified() {
        out.push(Candidate::new(CandidateKind::Host, local_addr));
    }

    if let Ok(interfaces) = if_addrs::get_if_addrs() {
        for iface in interfaces {
            if iface.is_loopback() || is_virtual_interface(&iface.name) {
                continue;
            }
            if let IpAddr::V4(v4) = iface.ip() {
                if v4.is_link_local() || v4.is_unspecified() {
                    continue;
                }
                out.push(Candidate::new(
                    CandidateKind::Host,
                    SocketAddr::new(IpAddr::V4(v4), local_addr.port()),
                ));
            }
        }
    }
    out
}

fn is_virtual_interface(name: &str) -> bool {
    const VIRTUAL: [&str; 10] = [
        "docker",
        "veth",
        "br-",
        "vmnet",
        "vboxnet",
        "vethernet",
        "hyper-v",
        "tailscale",
        "utun",
        "tun",
    ];
    let lower = name.to_ascii_lowercase();
    VIRTUAL.iter().any(|prefix| lower.contains(prefix))
}

/// 取本机出口 IPv4（不发包，只让内核选路）。
pub fn primary_ipv4() -> Option<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:53").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    }
}
