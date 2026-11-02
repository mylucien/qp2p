//! 数据面：一条 QUIC 连接上的流复用。
//!
//! 每个 TCP 流映射成一条双向 QUIC 流，头部 7 字节声明目标地址：
//! `[kind:u8][ip:4][port:2]`。这对应 DESIGN D7，只是 P3 阶段先做
//! L4 端口映射，L3（TUN）在 P5 接入时复用同一套帧。

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use quinn::{Connection, RecvStream, SendStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::peer::punch;

const KIND_TCP: u8 = 1;
const HEADER_LEN: usize = 7;
const COPY_BUF: usize = 16 * 1024;

fn encode_target(addr: SocketAddr) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[0] = KIND_TCP;
    match addr.ip() {
        std::net::IpAddr::V4(v4) => header[1..5].copy_from_slice(&v4.octets()),
        std::net::IpAddr::V6(_) => {
            // P3 只支持 IPv4 目标；IPv6 在 TUN 阶段一并处理
            header[1..5].copy_from_slice(&[0, 0, 0, 0]);
        }
    }
    header[5..7].copy_from_slice(&addr.port().to_be_bytes());
    header
}

fn decode_target(header: &[u8; HEADER_LEN]) -> Result<SocketAddr> {
    if header[0] != KIND_TCP {
        bail!("未知的流类型: {}", header[0]);
    }
    let ip = Ipv4Addr::new(header[1], header[2], header[3], header[4]);
    let port = u16::from_be_bytes([header[5], header[6]]);
    Ok(SocketAddr::new(ip.into(), port))
}

/// 在被叫端接受来自对端的流，并连接本地目标。
pub async fn serve_flows(conn: Connection) -> Result<()> {
    loop {
        let (send, recv) = conn.accept_bi().await.context("接受双向流失败")?;
        tokio::spawn(async move {
            if let Err(e) = handle_incoming_flow(send, recv).await {
                tracing::debug!("[link] 流处理结束: {e}");
            }
        });
    }
}

async fn handle_incoming_flow(send: SendStream, mut recv: RecvStream) -> Result<()> {
    let mut header = [0u8; HEADER_LEN];
    recv.read_exact(&mut header)
        .await
        .context("读取目标头部失败")?;
    let target = decode_target(&header)?;

    let tcp = TcpStream::connect(target)
        .await
        .with_context(|| format!("连接目标 {target} 失败"))?;

    pump(tcp, send, recv).await
}

/// 在本机监听端口，把每个连接转发到对端的 `target`。
pub async fn forward_listen(
    conn: Connection,
    listen: SocketAddr,
    target: SocketAddr,
) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("监听 {listen} 失败"))?;
    tracing::info!("[link] 端口映射 {listen} → {target}");

    loop {
        let (tcp, from) = listener.accept().await.context("接受本地连接失败")?;
        let conn = conn.clone();
        tokio::spawn(async move {
            match open_flow(&conn, target).await {
                Ok((send, recv)) => {
                    tracing::debug!("[link] {from} → {target} 已建立");
                    if let Err(e) = pump(tcp, send, recv).await {
                        tracing::debug!("[link] 转发结束: {e}");
                    }
                }
                Err(e) => tracing::warn!("[link] 打开流失败: {e}"),
            }
        });
    }
}

async fn open_flow(conn: &Connection, target: SocketAddr) -> Result<(SendStream, RecvStream)> {
    let (mut send, recv) = tokio::time::timeout(Duration::from_secs(5), conn.open_bi())
        .await
        .context("打开流超时")?
        .context("打开流失败")?;
    send.write_all(&encode_target(target))
        .await
        .context("写入目标头部失败")?;
    Ok((send, recv))
}

/// 双向搬运数据，任一方向结束就收尾。
async fn pump(tcp: TcpStream, mut send: SendStream, mut recv: RecvStream) -> Result<()> {
    let (mut tcp_r, mut tcp_w) = tcp.into_split();

    let up = async {
        let mut buf = vec![0u8; COPY_BUF];
        loop {
            let n = tcp_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            send.write_all(&buf[..n]).await?;
        }
        let _ = send.finish();
        Ok::<(), anyhow::Error>(())
    };

    let down = async {
        let mut buf = vec![0u8; COPY_BUF];
        loop {
            let n = recv.read(&mut buf).await?;
            match n {
                Some(0) | None => break,
                Some(n) => tcp_w.write_all(&buf[..n]).await?,
            }
        }
        let _ = tcp_w.shutdown().await;
        Ok::<(), anyhow::Error>(())
    };

    let (a, b) = tokio::join!(up, down);
    a?;
    b?;
    Ok(())
}

/// 一步到位：打洞 + 转发。
pub async fn connect_and_forward(
    endpoint: &quinn::Endpoint,
    peer: SocketAddr,
    role: crate::peer::Role,
    listen: SocketAddr,
    target: SocketAddr,
) -> Result<Connection> {
    let start = tokio::time::Instant::now() + Duration::from_millis(300);
    let conn = punch::execute(endpoint, peer, role, start, punch::DEFAULT_WINDOW)
        .await
        .context("打洞失败")?;
    tracing::info!("[link] 直连已建立 rtt={:?}", conn.rtt());

    if matches!(role, crate::peer::Role::Listener) {
        let conn_clone = conn.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_flows(conn_clone).await {
                tracing::warn!("[link] 流服务退出: {e}");
            }
        });
    }

    let conn_for_forward = conn.clone();
    tokio::spawn(async move {
        if let Err(e) = forward_listen(conn_for_forward, listen, target).await {
            tracing::warn!("[link] 转发退出: {e}");
        }
    });

    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let addr: SocketAddr = "10.64.1.7:8080".parse().unwrap();
        let header = encode_target(addr);
        assert_eq!(header[0], KIND_TCP);
        assert_eq!(decode_target(&header).unwrap(), addr);
    }

    #[test]
    fn rejects_unknown_kind() {
        let mut header = encode_target("10.64.1.7:80".parse().unwrap());
        header[0] = 9;
        assert!(decode_target(&header).is_err());
    }
}
