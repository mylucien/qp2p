//! 绑定 UDP socket、STUN 探测、UPnP 预映射，然后把同一个 socket 交给 quinn。
//!
//! 顺序不能变：先绑 → 在**这个** socket 上 STUN → 再创建端点。
//! 旧版用另一个随机端口的 socket 探测再替换端口，NAT 映射按五元组算，
//! 两者毫无关系。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};

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
    pub candidates: Vec<Candidate>,
    /// 与 quinn 共享同一个 UDP socket 的额外句柄，只用于发保活包
    pub keepalive: Arc<std::net::UdpSocket>,
}

/// 绑定并初始化端点。
pub async fn bind(bind_addr: SocketAddr, stun_servers: &[String]) -> Result<Bound> {
    let socket = bind_socket(bind_addr)?;
    socket
        .set_nonblocking(false)
        .context("切换 socket 为阻塞模式失败")?;

    let local_addr = socket.local_addr().context("读取本地地址失败")?;
    let keepalive = Arc::new(socket.try_clone().context("复制 socket 句柄失败")?);

    // 1) STUN：必须在交给 quinn 之前，且用同一个 socket
    let srflx = probe_stun(&socket, stun_servers, Duration::from_secs(3)).await;

    // 2) UPnP：失败只是少一个候选
    let upnp_mapping = try_upnp(local_addr, Duration::from_secs(2)).await;

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

    let server_config = crate::tls::server_config()?;
    let client_config = crate::tls::client_config()?;

    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .context("创建 QUIC 端点失败")?;
    endpoint.set_default_client_config(client_config);

    Ok(Bound {
        endpoint,
        bind_addr: local_addr,
        local_addr,
        srflx,
        upnp: upnp_mapping,
        candidates,
        keepalive,
    })
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

/// 依次尝试配置里的 STUN 服务器，拿第一个成功的结果。
async fn probe_stun(
    socket: &std::net::UdpSocket,
    servers: &[String],
    timeout: Duration,
) -> Option<SocketAddr> {
    let socket = socket.try_clone().ok()?;

    let mut addrs = Vec::new();
    for server in servers {
        match server.parse::<SocketAddr>() {
            Ok(addr) => addrs.push(addr),
            Err(_) => tracing::warn!("[socket] STUN 地址格式无效: {server}"),
        }
    }

    tokio::task::spawn_blocking(move || {
        for server in addrs {
            match stun::probe_blocking(&socket, server, timeout) {
                Ok(addr) => {
                    tracing::info!("[socket] STUN {server} 观测到公网映射 {addr}");
                    return Some(addr);
                }
                Err(e) => tracing::info!("[socket] STUN {server} 探测失败: {e}"),
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

async fn try_upnp(local_addr: SocketAddr, timeout: Duration) -> Option<SocketAddr> {
    let IpAddr::V4(local_ip) = local_addr.ip() else {
        return None;
    };
    match upnp::map_udp_port(local_ip, local_addr.port(), timeout).await {
        Ok(addr) => {
            tracing::info!("[socket] UPnP 映射成功 {addr}");
            Some(addr)
        }
        Err(e) => {
            tracing::info!("[socket] UPnP 不可用（继续打洞）: {e}");
            None
        }
    }
}

/// 枚举本机网卡地址作为内网候选。
fn host_candidates(local_addr: SocketAddr, requested: SocketAddr) -> Vec<Candidate> {
    let mut out = Vec::new();
    if !requested.ip().is_unspecified() {
        out.push(Candidate::new(CandidateKind::Host, local_addr));
    }

    if let Ok(interfaces) = if_addrs::get_if_addrs() {
        for iface in interfaces {
            if iface.is_loopback() {
                continue;
            }
            if let IpAddr::V4(v4) = iface.ip() {
                out.push(Candidate::new(
                    CandidateKind::Host,
                    SocketAddr::new(IpAddr::V4(v4), local_addr.port()),
                ));
            }
        }
    }
    out
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
