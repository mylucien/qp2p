//! 数据面：一条 QUIC 连接上的流复用。
//!
//! 每个 TCP 流映射成一条双向 QUIC 流，头部 7 字节声明目标地址：
//! `[kind:u8][ip:4][port:2]`，随后对端回 1 字节状态码，再开始搬数据。
//!
//! 安全边界：接受端只连**白名单里**的目标。否则任何能完成握手的人都能
//! 把它当成访问内网/云元数据的开放代理。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use quinn::{Connection, RecvStream, SendStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const KIND_TCP: u8 = 1;
const HEADER_LEN: usize = 7;
const COPY_BUF: usize = 16 * 1024;

/// 状态码：0 成功，其余为拒绝原因。
const STATUS_OK: u8 = 0;
const STATUS_DENIED: u8 = 1;
const STATUS_CONNECT_FAILED: u8 = 2;

fn encode_target(addr: SocketAddr) -> Result<[u8; HEADER_LEN]> {
    let IpAddr::V4(v4) = addr.ip() else {
        bail!("暂不支持 IPv6 目标：{addr}");
    };
    let mut header = [0u8; HEADER_LEN];
    header[0] = KIND_TCP;
    header[1..5].copy_from_slice(&v4.octets());
    header[5..7].copy_from_slice(&addr.port().to_be_bytes());
    Ok(header)
}

fn decode_target(header: &[u8; HEADER_LEN]) -> Result<SocketAddr> {
    if header[0] != KIND_TCP {
        bail!("未知的流类型: {}", header[0]);
    }
    let ip = Ipv4Addr::new(header[1], header[2], header[3], header[4]);
    let port = u16::from_be_bytes([header[5], header[6]]);
    Ok(SocketAddr::new(ip.into(), port))
}

/// 在被叫端接受来自对端的流。
///
/// `allowed` 是允许访问的目标白名单；为空表示拒绝一切（宁可不通，也不当代理）。
pub async fn serve_flows(conn: Connection, allowed: Arc<Vec<SocketAddr>>) -> Result<()> {
    loop {
        let (send, recv) = conn.accept_bi().await.context("接受双向流失败")?;
        let allowed = allowed.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_incoming_flow(send, recv, &allowed).await {
                tracing::debug!("[link] 流处理结束: {e}");
            }
        });
    }
}

async fn handle_incoming_flow(
    mut send: SendStream,
    mut recv: RecvStream,
    allowed: &[SocketAddr],
) -> Result<()> {
    let mut header = [0u8; HEADER_LEN];
    recv.read_exact(&mut header)
        .await
        .context("读取目标头部失败")?;
    let target = decode_target(&header)?;

    if !allowed.contains(&target) {
        tracing::warn!("[link] 拒绝未授权目标 {target}");
        let _ = send.write_all(&[STATUS_DENIED]).await;
        let _ = send.finish();
        return Ok(());
    }

    let tcp = match TcpStream::connect(target).await {
        Ok(tcp) => tcp,
        Err(e) => {
            tracing::warn!("[link] 连接目标 {target} 失败: {e}");
            let _ = send.write_all(&[STATUS_CONNECT_FAILED]).await;
            let _ = send.finish();
            return Ok(());
        }
    };

    send.write_all(&[STATUS_OK]).await.context("写状态码失败")?;
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
        let (tcp, from) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                // 临时错误（EMFILE 等）不应该让整个转发退出
                tracing::warn!("[link] accept 失败，继续: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
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
    let (mut send, mut recv) = tokio::time::timeout(Duration::from_secs(5), conn.open_bi())
        .await
        .context("打开流超时")?
        .context("打开流失败")?;

    send.write_all(&encode_target(target)?)
        .await
        .context("写入目标头部失败")?;

    let mut status = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(5), recv.read_exact(&mut status))
        .await
        .context("等待对端状态超时")?
        .context("读取对端状态失败")?;

    match status[0] {
        STATUS_OK => Ok((send, recv)),
        STATUS_DENIED => bail!("对端拒绝该目标 {target}"),
        STATUS_CONNECT_FAILED => bail!("对端连接 {target} 失败"),
        other => bail!("未知状态码 {other}"),
    }
}

/// 双向搬运数据；任一方向结束就收尾，避免另一端挂住占名额。
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
            match recv.read(&mut buf).await? {
                Some(0) | None => break,
                Some(n) => tcp_w.write_all(&buf[..n]).await?,
            }
        }
        let _ = tcp_w.shutdown().await;
        Ok::<(), anyhow::Error>(())
    };

    tokio::pin!(up);
    tokio::pin!(down);

    let result = tokio::select! {
        r = &mut up => r,
        r = &mut down => r,
    };

    // 不需要显式 abort：两个 future 在这里被 drop，写端会随之关闭
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let addr: SocketAddr = "10.64.1.7:8080".parse().unwrap();
        let header = encode_target(addr).unwrap();
        assert_eq!(header[0], KIND_TCP);
        assert_eq!(decode_target(&header).unwrap(), addr);
    }

    #[test]
    fn rejects_ipv6_target() {
        let addr: SocketAddr = "[::1]:8080".parse().unwrap();
        assert!(encode_target(addr).is_err());
    }

    #[test]
    fn rejects_unknown_kind() {
        let mut header = encode_target("10.64.1.7:80".parse().unwrap()).unwrap();
        header[0] = 9;
        assert!(decode_target(&header).is_err());
    }
}
