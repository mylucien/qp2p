//! 打洞执行器。
//!
//! 角色固定（见 DESIGN D2）：dialer 发 QUIC Initial，listener 发一次性
//! Initial 打开自己这侧 NAT，然后等待入站连接。两侧不会同时当客户端。
//!
//! 当前实现用 QUIC Initial 兼作打洞包（P2），把探针与握手完全解耦需要
//! 自定义 `AsyncUdpSocket`（DESIGN D1/D6），留到 P2.1。

use std::net::SocketAddr;
use std::time::Duration;

use quinn::{Connection, Endpoint};
use tokio::time::Instant;

use crate::peer::Role;
use crate::tls::SERVER_NAME;

/// 单次打洞窗口。
pub const DEFAULT_WINDOW: Duration = Duration::from_millis(800);
/// 窗口内重发间隔。
pub const RETRY_INTERVAL: Duration = Duration::from_millis(120);
/// 单次握手等待上限，超过就再发一轮 Initial。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(400);

#[derive(Debug, thiserror::Error)]
pub enum PunchError {
    #[error("打洞窗口内未建立连接")]
    Timeout,
    #[error("连接失败：{0}")]
    Dial(String),
}

/// 执行一次打洞，等待直连建立。
pub async fn execute(
    endpoint: &Endpoint,
    peer: SocketAddr,
    role: Role,
    start: Instant,
    window: Duration,
) -> Result<Connection, PunchError> {
    match role {
        Role::Dialer => dial_until(endpoint, peer, start, window).await,
        Role::Listener => listen_until(endpoint, peer, start, window).await,
    }
}

async fn dial_until(
    endpoint: &Endpoint,
    peer: SocketAddr,
    start: Instant,
    window: Duration,
) -> Result<Connection, PunchError> {
    let deadline = start + window;
    let mut last_error = String::new();

    // dialer 不需要入站连接，但必须排空 accept 队列，否则对端探针会堆积
    let drain = endpoint.clone();
    let drain_task = tokio::spawn(async move {
        while let Some(incoming) = drain.accept().await {
            tokio::spawn(async move {
                if let Ok(conn) = incoming.await {
                    conn.close(0u32.into(), b"punch-probe");
                }
            });
        }
    });

    if Instant::now() < start {
        tokio::time::sleep_until(start).await;
    }

    while Instant::now() <= deadline {
        match endpoint.connect(peer, SERVER_NAME) {
            Ok(connecting) => match tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting).await {
                Ok(Ok(conn)) => {
                    drain_task.abort();
                    return Ok(conn);
                }
                Ok(Err(e)) => last_error = e.to_string(),
                Err(_) => last_error = "握手超时".to_string(),
            },
            Err(e) => last_error = e.to_string(),
        }
        tokio::time::sleep(RETRY_INTERVAL).await;
    }

    drain_task.abort();
    if last_error.is_empty() {
        Err(PunchError::Timeout)
    } else {
        Err(PunchError::Dial(last_error))
    }
}

async fn listen_until(
    endpoint: &Endpoint,
    peer: SocketAddr,
    start: Instant,
    window: Duration,
) -> Result<Connection, PunchError> {
    let deadline = start + window;

    let accept_endpoint = endpoint.clone();
    let accept_loop = async move {
        loop {
            let Some(incoming) = accept_endpoint.accept().await else {
                return Err(PunchError::Timeout);
            };
            match incoming.await {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    tracing::debug!("[punch] 入站连接失败: {e}");
                }
            }
        }
    };
    tokio::pin!(accept_loop);

    let mut next_probe = start;
    loop {
        tokio::select! {
            result = &mut accept_loop => return result,
            _ = tokio::time::sleep_until(deadline) => return Err(PunchError::Timeout),
            _ = tokio::time::sleep_until(next_probe) => {
                // 发一个用后即弃的 Initial，只为自己这侧开孔
                if let Ok(connecting) = endpoint.connect(peer, SERVER_NAME) {
                    tokio::spawn(async move {
                        if let Ok(conn) = connecting.await {
                            conn.close(0u32.into(), b"probe");
                        }
                    });
                }
                next_probe = Instant::now() + RETRY_INTERVAL;
            }
        }
    }
}
