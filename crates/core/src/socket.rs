//! 绑定 UDP socket，并在同一个 socket 上做 STUN 探测。
//!
//! 这是对旧版最关键的一处修正：旧版用另一个随机端口的 socket 探测，
//! 再把端口号替换成 QUIC 端口——而 NAT 映射按五元组计算，换 socket
//! 观测到的映射与 QUIC 毫无关系。
//!
//! 顺序必须是：先绑 socket → 在同一 socket 上 STUN → 再把 socket 交给 quinn。

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::candidate::{normalize, Candidate, CandidateKind};
use crate::stun;

/// 一次绑定得到的全部结果。
pub struct Bound {
    pub endpoint: quinn::Endpoint,
    pub local_addr: SocketAddr,
    /// STUN 观测到的公网映射；探测失败时为 None
    pub srflx: Option<SocketAddr>,
    /// 已排序、去重的候选地址
    pub candidates: Vec<Candidate>,
}

/// 绑定并初始化端点。
pub async fn bind(
    bind_addr: SocketAddr,
    stun_servers: &[String],
    stun_timeout: Duration,
) -> Result<Bound> {
    let socket =
        std::net::UdpSocket::bind(bind_addr).with_context(|| format!("绑定 {bind_addr} 失败"))?;
    socket
        .set_nonblocking(false)
        .context("切换 socket 为阻塞模式失败")?;

    let server = stun_servers
        .first()
        .map(|s| s.parse::<SocketAddr>())
        .transpose()
        .context("STUN 服务器地址格式无效")?;

    // STUN 必须在把 socket 交给 quinn 之前完成，且用同一个 socket
    let probe = tokio::task::spawn_blocking(move || {
        let result = match server {
            Some(server) => stun::probe_blocking(&socket, server, stun_timeout),
            None => Err(stun::StunError::Io("未配置 STUN 服务器".to_string())),
        };
        (socket, result)
    })
    .await
    .context("STUN 探测任务失败")?;

    let (socket, srflx_result) = probe;
    let srflx = match srflx_result {
        Ok(addr) => Some(addr),
        Err(e) => {
            tracing::info!("[socket] STUN 探测失败，仅使用内网候选: {e}");
            None
        }
    };

    let local_addr = socket.local_addr().context("读取本地地址失败")?;

    socket
        .set_nonblocking(true)
        .context("切换 socket 为非阻塞模式失败")?;

    let mut candidates = host_candidates(local_addr, bind_addr);
    if let Some(addr) = srflx {
        candidates.push(Candidate::new(CandidateKind::Srflx, addr));
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
        local_addr,
        srflx,
        candidates,
    })
}

/// 枚举本机所有网卡地址作为内网候选。
fn host_candidates(local_addr: SocketAddr, requested: SocketAddr) -> Vec<Candidate> {
    let mut out = Vec::new();
    let ip = requested.ip();
    if !ip.is_unspecified() {
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
