//! 数据面：一条 QUIC 连接上的流复用。
//!
//! 每个 TCP 流映射成一条双向 QUIC 流，头部 7 字节声明目标地址：
//! `[kind:u8][ip:4][port:2]`，随后对端回 1 字节状态码，再开始搬数据。
//!
//! 安全边界：接受端只连**白名单里**的目标。否则任何能完成握手的人都能
//! 把它当成访问内网/云元数据的开放代理。

pub mod tun;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use quinn::{Connection, RecvStream, SendStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;

const KIND_TCP: u8 = 1;
const HEADER_LEN: usize = 7;
const COPY_BUF: usize = 16 * 1024;

/// 连目标要快于发起方的等待（5s），否则发起方先报超时，错误信息会误导。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// 读目标头部也要有上限：恶意或半死的对端可以只开流不发头。
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);

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
    tracing::info!(
        "[link] 接流已启动 peer={} 白名单 {} 条",
        conn.remote_address(),
        allowed.len()
    );
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let allowed = allowed.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_incoming_flow(send, recv, &allowed).await {
                        tracing::debug!("[link] 流处理结束: {e}");
                    }
                });
            }
            Err(e) => {
                tracing::warn!("[link] 接流循环退出: {e}");
                return Err(e).context("接受双向流失败");
            }
        }
    }
}

async fn handle_incoming_flow(
    mut send: SendStream,
    mut recv: RecvStream,
    allowed: &[SocketAddr],
) -> Result<()> {
    let mut header = [0u8; HEADER_LEN];
    tokio::time::timeout(HEADER_TIMEOUT, recv.read_exact(&mut header))
        .await
        .context("读取目标头部超时")?
        .context("读取目标头部失败")?;
    let target = decode_target(&header)?;

    if !allowed.contains(&target) {
        tracing::warn!("[link] 拒绝未授权目标 {target}");
        let _ = send.write_all(&[STATUS_DENIED]).await;
        let _ = send.finish();
        return Ok(());
    }

    let tcp = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(target)).await {
        Ok(Ok(tcp)) => tcp,
        Ok(Err(e)) => {
            tracing::warn!("[link] 连接目标 {target} 失败: {e}");
            let _ = send.write_all(&[STATUS_CONNECT_FAILED]).await;
            let _ = send.finish();
            return Ok(());
        }
        Err(_) => {
            tracing::warn!("[link] 连接目标 {target} 超时");
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

/// 半关闭后的空闲上限：一端关了写端、双方又都不再有数据往来时，流不该无限挂着。
const DEFAULT_HALF_CLOSE_IDLE_MS: u64 = 60_000;
static HALF_CLOSE_IDLE_MS: AtomicU64 = AtomicU64::new(DEFAULT_HALF_CLOSE_IDLE_MS);

/// 调整半关闭后的空闲上限（默认 60 秒）。主要给测试用，对之后新建的流生效。
pub fn set_half_close_idle(idle: Duration) {
    let ms = u64::try_from(idle.as_millis()).unwrap_or(u64::MAX).max(1);
    HALF_CLOSE_IDLE_MS.store(ms, Ordering::Relaxed);
}

fn half_close_idle() -> Duration {
    Duration::from_millis(HALF_CLOSE_IDLE_MS.load(Ordering::Relaxed))
}

/// 一条流的活动记录：任何方向每搬运一块数据就刷新时间戳。
///
/// 空闲判断必须基于"最后一次有数据往来"，而不是"半关闭那一刻"：
/// 客户端发完请求就半关闭、服务端再持续回很久的响应（下载、导出、日志流）
/// 是完全正常的，只要数据还在流动就不能收尾。
struct Activity {
    start: Instant,
    last_ms: AtomicU64,
    half_closed: AtomicBool,
}

impl Activity {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            start: Instant::now(),
            last_ms: AtomicU64::new(0),
            half_closed: AtomicBool::new(false),
        })
    }

    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// 有数据往来。
    fn touch(&self) {
        self.last_ms.store(self.elapsed_ms(), Ordering::Relaxed);
    }

    /// 某个方向结束了。关闭本身也算一次活动：空闲从这一刻起重新计时。
    fn mark_half_closed(&self) {
        self.touch();
        self.half_closed.store(true, Ordering::Relaxed);
    }

    /// 已经半关闭，并且最近 `limit` 内没有任何数据往来。
    fn idle_exceeded(&self, limit: Duration) -> bool {
        if !self.half_closed.load(Ordering::Relaxed) {
            return false;
        }
        let limit_ms = u64::try_from(limit.as_millis()).unwrap_or(u64::MAX);
        self.elapsed_ms()
            .saturating_sub(self.last_ms.load(Ordering::Relaxed))
            >= limit_ms
    }
}

/// 周期性检查，直到满足"半关闭 + 空闲超限"。
async fn half_close_watchdog(activity: &Activity, limit: Duration) {
    let step = (limit / 4).clamp(Duration::from_millis(50), Duration::from_secs(1));
    loop {
        tokio::time::sleep(step).await;
        if activity.idle_exceeded(limit) {
            return;
        }
    }
}

/// 双向搬运数据。
///
/// 用 `try_join!` 而不是 `select!`：TCP 是半关闭的，客户端 `shutdown(Write)`
/// 之后往往还等着响应，此时上行结束不能把下行也丢掉。只有真正出错才提前收尾。
///
/// 兜底：任一方向结束后，如果双方在 `half_close_idle()` 内都没有再搬运过数据，
/// 才主动收尾，否则这条流会一直占着连接直到整条连接关闭。
/// 全双工且两个方向都还开着的连接（比如空闲的 SSH）不受影响。
async fn pump(tcp: TcpStream, mut send: SendStream, mut recv: RecvStream) -> Result<()> {
    let (mut tcp_r, mut tcp_w) = tcp.into_split();
    let activity = Activity::new();

    let up_activity = activity.clone();
    let up = async move {
        let mut buf = vec![0u8; COPY_BUF];
        loop {
            let n = tcp_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            up_activity.touch();
            send.write_all(&buf[..n]).await?;
            up_activity.touch();
        }
        let _ = send.finish();
        up_activity.mark_half_closed();
        Ok::<(), anyhow::Error>(())
    };

    let down_activity = activity.clone();
    let down = async move {
        let mut buf = vec![0u8; COPY_BUF];
        loop {
            match recv.read(&mut buf).await? {
                Some(0) | None => break,
                Some(n) => {
                    down_activity.touch();
                    tcp_w.write_all(&buf[..n]).await?;
                    down_activity.touch();
                }
            }
        }
        let _ = tcp_w.shutdown().await;
        down_activity.mark_half_closed();
        Ok::<(), anyhow::Error>(())
    };

    let limit = half_close_idle();
    let both = async { tokio::try_join!(up, down).map(|_| ()) };

    tokio::select! {
        result = both => result,
        _ = half_close_watchdog(&activity, limit) => {
            bail!("半关闭后 {limit:?} 内双方都没有数据往来，主动收尾")
        }
    }
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
