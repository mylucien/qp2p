//! # stun.rs — STUN 探测
//!
//! 向 STUN 服务器发送 Binding Request，获取本机的公网 IP 和映射端口（srflx 地址）。
//! 结果缓存 5 分钟，避免同一启动流程内重复查询（重打洞循环、心跳）。
//!
//! 探测失败时降级：仅返回内网 host 地址，srflx 缺失不影响启动。

use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tracing::info;

use crate::types::{Candidate, CandidateType};

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

/// STUN 查询超时
const STUN_TIMEOUT: Duration = Duration::from_secs(5);

/// 结果缓存 TTL（防止短时间重复探测；心跳间隔 6h，不受此 TTL 影响）
const CACHE_TTL: Duration = Duration::from_secs(300); // 5 分钟

/// STUN Magic Cookie (RFC 5389)
const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

/// Binding Request 消息类型
const BINDING_REQUEST: u16 = 0x0001;

/// Binding Response 消息类型
const BINDING_RESPONSE: u16 = 0x0101;

/// XOR-MAPPED-ADDRESS attribute 类型
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

// ---------------------------------------------------------------------------
// STUN 探测入口
// ---------------------------------------------------------------------------

/// 执行 STUN 探测，返回本机候选地址列表。
///
/// `local_port` 是 QUIC endpoint 实际绑定的端口，host 候选和 STUN socket 均使用此端口。
///
/// 排序：host 在前，srflx 在后。
/// 结果缓存 5 分钟，过期后下次调用自动重新探测。
/// 探测失败时降级为仅返回内网 host 地址。
pub async fn probe(stun_server: &str, local_port: u16) -> Result<Vec<Candidate>> {
    if let Some(cached) = get_cached() {
        return Ok(cached);
    }

    let host_candidates = get_host_candidates(local_port);

    let srflx = match stun_query(stun_server, local_port).await {
        Ok(addr) => {
            info!("[stun] 公网映射: {addr}");
            Some(addr)
        }
        Err(e) => {
            info!("[stun] 探测失败（降级为纯内网）: {e}");
            None
        }
    };

    let mut candidates = host_candidates;
    if let Some(addr) = srflx {
        candidates.push(Candidate {
            addr_type: CandidateType::Srflx,
            address: addr,
        });
    }

    set_cached(candidates.clone());
    Ok(candidates)
}

// ---------------------------------------------------------------------------
// STUN 查询（RFC 5389）
// ---------------------------------------------------------------------------

/// 向 STUN 服务器发送 Binding Request，返回服务器观测到的映射地址。
///
/// 用随机端口探测获取公网 IP，端口替换为 QUIC endpoint 的实际绑定端口
/// `local_port`，使 srflx 候选的 IP:Port 与 QUIC 连接一致。
async fn stun_query(server: &str, local_port: u16) -> Result<SocketAddr> {
    let server_addr: SocketAddr = server
        .parse()
        .context("STUN 服务器地址格式无效")?;

    // 用任意端口探测，只取 IP
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .context("创建 STUN socket 失败")?;

    let req = build_binding_request();
    socket
        .send_to(&req, server_addr)
        .await
        .context("发送 STUN Binding Request 失败")?;

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(STUN_TIMEOUT, socket.recv(&mut buf))
        .await
        .context("STUN 探测超时")?
        .context("接收 STUN 响应失败")?;

    let mut mapped = parse_binding_response(&buf[..n])?;
    // 端口替换为 QUIC endpoint 的实际端口
    mapped.set_port(local_port);
    Ok(mapped)
}

/// 构造 STUN Binding Request。
///
/// RFC 5389 头部格式：
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |0 0|     STUN Message Type     |         Message Length        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Magic Cookie                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |                     Transaction ID (12 bytes)                  |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
fn build_binding_request() -> Vec<u8> {
    let mut msg = Vec::with_capacity(20);

    msg.extend_from_slice(&BINDING_REQUEST.to_be_bytes()); // 2 bytes
    msg.extend_from_slice(&0x0000u16.to_be_bytes());       // 2 bytes length (no attrs)
    msg.extend_from_slice(&MAGIC_COOKIE);                  // 4 bytes
    for _ in 0..12 {                                        // 12 bytes random tx id
        msg.push(rand::random::<u8>());
    }

    msg
}

/// 解析 STUN Binding Response，提取 XOR-MAPPED-ADDRESS。
fn parse_binding_response(data: &[u8]) -> Result<SocketAddr> {
    if data.len() < 20 {
        anyhow::bail!("STUN 响应太短 ({})", data.len());
    }

    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != BINDING_RESPONSE {
        anyhow::bail!("非 Binding Response (type=0x{msg_type:04x})");
    }

    let _msg_len = u16::from_be_bytes([data[2], data[3]]);

    if data[4..8] != MAGIC_COOKIE {
        anyhow::bail!("Magic Cookie 不匹配");
    }

    let mut pos = 20;
    while pos + 4 <= data.len() {
        let attr_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let attr_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        let end = pos + attr_len;
        let padded_len = if attr_len % 4 == 0 { attr_len } else { attr_len + 4 - (attr_len % 4) };
        let padded_end = pos + padded_len;

        if end > data.len() {
            break;
        }

        if attr_type == ATTR_XOR_MAPPED_ADDRESS && attr_len >= 8 {
            return parse_xor_mapped_address(&data[pos..end]);
        }

        pos = padded_end;
    }

    anyhow::bail!("未找到 XOR-MAPPED-ADDRESS attribute")
}

/// 解析 XOR-MAPPED-ADDRESS（RFC 5389 Section 15.2）。
fn parse_xor_mapped_address(data: &[u8]) -> Result<SocketAddr> {
    if data.len() < 8 {
        anyhow::bail!("XOR-MAPPED-ADDRESS 太短");
    }

    let family = data[1];
    let xor_port = u16::from_be_bytes([data[2], data[3]]);
    let magic_u16 = u16::from_be_bytes([MAGIC_COOKIE[0], MAGIC_COOKIE[1]]);
    let port = xor_port ^ magic_u16;

    match family {
        0x01 => {
            if data.len() < 8 {
                anyhow::bail!("XOR-MAPPED-ADDRESS IPv4 数据不足");
            }
            let mut ip_bytes = [0u8; 4];
            ip_bytes.copy_from_slice(&data[4..8]);
            for i in 0..4 {
                ip_bytes[i] ^= MAGIC_COOKIE[i];
            }
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(ip_bytes));
            Ok(SocketAddr::new(ip, port))
        }
        0x02 => anyhow::bail!("IPv6 XOR-MAPPED-ADDRESS 暂不支持"),
        _ => anyhow::bail!("不支持的地址族: 0x{family:02x}"),
    }
}

// ---------------------------------------------------------------------------
// 内网地址获取
// ---------------------------------------------------------------------------

/// 获取本机所有非 loopback 的 IPv4 地址，使用 `local_port` 作为候选端口。
fn get_host_candidates(local_port: u16) -> Vec<Candidate> {
    let mut candidates = Vec::new();

    // 通过本机主机名解析获取地址（跨平台，返回非 loopback IPv4 地址）
    if let Ok(hostname) = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")) {
        if let Ok(addrs) = (hostname + ":0").to_socket_addrs() {
            for addr in addrs {
                let ip = addr.ip();
                if !ip.is_loopback() && ip.is_ipv4() {
                    candidates.push(Candidate {
                        addr_type: CandidateType::Host,
                        address: SocketAddr::new(ip, local_port),
                    });
                }
            }
        }
    }

    if candidates.is_empty() {
        if let Some(local_ip) = get_default_local_ip() {
            candidates.push(Candidate {
                addr_type: CandidateType::Host,
                address: SocketAddr::new(local_ip, local_port),
            });
        }
    }

    candidates
}

/// 通过 UDP socket 连接一个外部地址来获取本机 IP。
fn get_default_local_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:53").ok()?;
    let local_addr = socket.local_addr().ok()?;
    let ip = local_addr.ip();
    if !ip.is_loopback() && ip.is_ipv4() {
        Some(ip)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// 结果缓存
// ---------------------------------------------------------------------------

static CACHE: OnceLock<std::sync::Mutex<Option<(Instant, Vec<Candidate>)>>> = OnceLock::new();

fn cache() -> &'static std::sync::Mutex<Option<(Instant, Vec<Candidate>)>> {
    CACHE.get_or_init(|| std::sync::Mutex::new(None))
}

fn get_cached() -> Option<Vec<Candidate>> {
    let guard = cache().lock().unwrap();
    if let Some((expires, candidates)) = guard.as_ref() {
        if expires.elapsed() < CACHE_TTL {
            return Some(candidates.clone());
        }
    }
    None
}

fn set_cached(candidates: Vec<Candidate>) {
    // port=0 的结果不缓存（local_port 获取失败时的降级）
    if candidates.is_empty() || candidates.iter().any(|c| c.address.port() == 0) {
        return;
    }
    let mut guard = cache().lock().unwrap();
    *guard = Some((Instant::now(), candidates));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_binding_request_length() {
        let req = build_binding_request();
        assert_eq!(req.len(), 20);
        assert_eq!(req[0], 0x00);
        assert_eq!(req[1], 0x01);
        assert_eq!(req[4..8], MAGIC_COOKIE);
    }

    #[test]
    fn test_parse_binding_response_ipv4() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&[0x00, 0x0C]);
        resp.extend_from_slice(&MAGIC_COOKIE);
        resp.extend_from_slice(&[0x00u8; 12]);
        resp.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        resp.extend_from_slice(&[0x00, 0x08]);
        resp.extend_from_slice(&[0x00, 0x01]);
        let port_xor = 4433u16 ^ 0x2112;
        resp.extend_from_slice(&port_xor.to_be_bytes());
        let ip_bytes = [203u8, 0, 113, 5];
        for i in 0..4 {
            resp.push(ip_bytes[i] ^ MAGIC_COOKIE[i]);
        }

        let addr = parse_binding_response(&resp).unwrap();
        assert_eq!(addr.port(), 4433);
        assert_eq!(addr.ip(), std::net::Ipv4Addr::new(203, 0, 113, 5));
    }

    #[test]
    fn test_parse_binding_response_too_short() {
        assert!(parse_binding_response(&[0; 10]).is_err());
    }

    #[test]
    fn test_parse_binding_response_wrong_type() {
        let mut resp = vec![0x00, 0x00];
        resp.extend_from_slice(&[0x00, 0x00]);
        resp.extend_from_slice(&MAGIC_COOKIE);
        resp.extend_from_slice(&[0u8; 12]);
        assert!(parse_binding_response(&resp).is_err());
    }

    #[test]
    fn test_host_candidates_port() {
        let candidates = get_host_candidates(4433);
        eprintln!("[test] host candidates: {} 个", candidates.len());
        for c in candidates {
            assert_ne!(c.address.port(), 0, "host candidate port 不应为 0");
        }
    }

    #[test]
    fn test_cache() {
        let c = vec![Candidate {
            addr_type: CandidateType::Host,
            address: "10.0.0.1:4433".parse().unwrap(),
        }];
        set_cached(c.clone());
        let got = get_cached().unwrap_or_default();
        assert!(!got.is_empty());
        assert_eq!(got[0].address.ip(), "10.0.0.1".parse::<IpAddr>().unwrap());
    }
}
