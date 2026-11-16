//! 本机当局域网出口：在虚拟地址上监听端口，替对端连接内网目标。
//!
//! 和 [`super::serve_flows`] 的区别只在「谁接住第一段 TCP」：
//!
//! - `serve_flows`：远端监听本地端口 → 字节经 QUIC 流送过来 → 本机 `connect`
//! - 这里：本机直接监听虚拟地址 → 远端把 IP 包发到该地址（走它自己的 TUN）
//!   → 本机内核对到达包做本地投递 → `accept` → `connect`
//!
//! 后者对远端是完全透明的，远端只要访问 `<虚拟地址>:<端口>` 就行，不需要任何
//! 端口映射配置。代价是端口号得自己定：Android 非 root 应用绑不了 1024 以下。

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};

/// 连目标要快于远端的等待，否则对方先报超时，错误信息会误导。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// 同时最多挂多少条连接。手机被当跳板时，至少不会把内存和文件描述符打爆。
const MAX_CONNS: usize = 64;
/// 停会话的检查间隔：够快能及时收手，又不至于空转。
const STOP_POLL: Duration = Duration::from_millis(500);

/// 一条映射：本机虚拟地址上的 `listen` 端口 → 内网 `target`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LanMap {
    pub listen: u16,
    pub target: SocketAddr,
}

/// 每条映射起一个监听任务，返回各自句柄（调用方可以 abort）。
///
/// `local` 是本机虚拟地址：绑在这个地址上，只有经隧道进来的连接才会命中，
/// 手机在家庭 WiFi 下不会被同网段的邻居直接打到。
pub fn spawn(
    local: Ipv4Addr,
    maps: Vec<LanMap>,
    stop: Arc<AtomicBool>,
) -> Vec<tokio::task::JoinHandle<()>> {
    maps.into_iter()
        .map(|map| {
            let stop = stop.clone();
            tokio::spawn(async move {
                if let Err(e) = run_one(local, map, stop).await {
                    tracing::warn!("[lan] {} 号映射退出：{e:#}", map.listen);
                }
            })
        })
        .collect()
}

async fn run_one(local: Ipv4Addr, map: LanMap, stop: Arc<AtomicBool>) -> Result<()> {
    let listener = TcpListener::bind((local, map.listen))
        .await
        .with_context(|| format!("绑定 {local}:{} 失败（端口可能被占用）", map.listen))?;
    tracing::info!("[lan] 监听 {local}:{} → {}", map.listen, map.target);

    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONNS));
    loop {
        let accepted = tokio::select! {
            _ = until_stop(&stop) => return Ok(()),
            res = listener.accept() => res,
        };
        let (stream, peer) = match accepted {
            Ok(pair) => pair,
            Err(e) => {
                // 单次 accept 失败（对端已断开等）不该终止整个监听
                tracing::debug!("[lan] accept 失败：{e}");
                continue;
            }
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            tracing::warn!("[lan] 并发已满（{MAX_CONNS}），拒绝 {peer}");
            drop(stream);
            continue;
        };
        let target = map.target;
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = relay(stream, peer, target).await {
                tracing::debug!("[lan] {peer} → {target} 结束：{e:#}");
            }
        });
    }
}

async fn relay(mut incoming: TcpStream, peer: SocketAddr, target: SocketAddr) -> Result<()> {
    let mut outgoing = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(target))
        .await
        .with_context(|| format!("连接 {target} 超时"))?
        .with_context(|| format!("连接 {target} 失败"))?;
    // 内网交互多是短请求，禁掉 Nagle 少一个 RTT 的等待
    let _ = incoming.set_nodelay(true);
    let _ = outgoing.set_nodelay(true);

    let (up, down) = copy_bidirectional(&mut incoming, &mut outgoing).await?;
    tracing::debug!("[lan] {peer} → {target} 关闭，上行 {up} 下行 {down}");
    Ok(())
}

async fn until_stop(stop: &AtomicBool) {
    while !stop.load(Ordering::Relaxed) {
        tokio::time::sleep(STOP_POLL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn free_port() -> u16 {
        // 绑 0 让系统挑一个空闲端口再立刻释放，够测试用
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// 监听任务刚 spawn 时还没 bind 完，直接连会偶发失败，所以给个重试窗口
    async fn connect_retry(port: u16) -> TcpStream {
        let mut last = None;
        for _ in 0..40 {
            match TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await {
                Ok(stream) => return stream,
                Err(e) => {
                    last = Some(e);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
        panic!("2 秒内没连上 127.0.0.1:{port}：{last:?}");
    }

    /// 主流程：远端连虚拟地址上的端口，字节应原样送到目标，回程也通。
    #[tokio::test]
    async fn relays_bytes_to_target() {
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = target.accept().await.unwrap();
            let mut buf = [0u8; 4];
            sock.read_exact(&mut buf).await.unwrap();
            sock.write_all(&buf).await.unwrap();
            sock.flush().await.unwrap();
        });

        let listen = free_port();
        let stop = Arc::new(AtomicBool::new(false));
        let map = LanMap {
            listen,
            target: target_addr,
        };
        spawn(Ipv4Addr::LOCALHOST, vec![map], stop.clone());

        let mut client = connect_retry(listen).await;
        client.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
        stop.store(true, Ordering::Relaxed);
    }

    /// 目标连不上时只该断这条连接，监听本身还得能接下一单。
    #[tokio::test]
    async fn keeps_listening_after_failed_target() {
        let listen = free_port();
        let dead = free_port();
        let stop = Arc::new(AtomicBool::new(false));
        let map = LanMap {
            listen,
            target: SocketAddr::from(([127, 0, 0, 1], dead)),
        };
        spawn(Ipv4Addr::LOCALHOST, vec![map], stop.clone());

        // 第一次：目标没人听，连接很快被断开
        let mut first = connect_retry(listen).await;
        let mut buf = [0u8; 1];
        let _ = tokio::time::timeout(Duration::from_secs(3), first.read(&mut buf)).await;

        // 第二次：监听仍在，还能建立连接（随后同样被断）
        let second = connect_retry(listen).await;
        drop(second);
        stop.store(true, Ordering::Relaxed);
    }

    /// 端口已被占用时只记警告，不影响其余映射（`spawn` 逐个起任务）。
    #[tokio::test]
    async fn bind_conflict_does_not_block_other_maps() {
        let taken = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let taken_addr = taken.local_addr().unwrap();

        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = echo.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 2];
                    if sock.read_exact(&mut buf).await.is_ok() {
                        let _ = sock.write_all(&buf).await;
                    }
                });
            }
        });

        let good_port = free_port();
        let stop = Arc::new(AtomicBool::new(false));
        spawn(
            Ipv4Addr::LOCALHOST,
            vec![
                LanMap {
                    listen: taken_addr.port(),
                    target: echo_addr,
                },
                LanMap {
                    listen: good_port,
                    target: echo_addr,
                },
            ],
            stop.clone(),
        );

        let mut client = connect_retry(good_port).await;
        client.write_all(b"ok").await.unwrap();
        let mut echoed = [0u8; 2];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ok");
        drop(taken);
        stop.store(true, Ordering::Relaxed);
    }
}
