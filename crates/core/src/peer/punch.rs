//! 打洞执行器。
//!
//! 角色固定（DESIGN D2）：dialer 发 QUIC Initial，listener 发一次性
//! Initial 打开自己这侧 NAT，然后等待入站连接。两侧不会同时当客户端。
//!
//! 候选是**并集**：所有候选地址同时打，先通先用。旧实现只打一个地址，
//! 一旦选中过期映射就整轮失败。

use std::net::SocketAddr;
use std::time::Duration;

use quinn::{Connection, Endpoint};
use tokio::task::JoinSet;
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
    #[error("没有可用的候选地址")]
    NoCandidates,
    #[error("打洞窗口内未建立连接")]
    Timeout,
    #[error("连接失败：{0}")]
    Dial(String),
}

/// 对一组候选地址并行打洞。
pub async fn execute(
    endpoint: &Endpoint,
    candidates: &[SocketAddr],
    role: Role,
    start: Instant,
    window: Duration,
) -> Result<Connection, PunchError> {
    if candidates.is_empty() {
        return Err(PunchError::NoCandidates);
    }
    match role {
        Role::Dialer => dial_all(endpoint, candidates, start, window).await,
        Role::Listener => listen_with_probes(endpoint, candidates, start, window).await,
    }
}

async fn dial_all(
    endpoint: &Endpoint,
    candidates: &[SocketAddr],
    start: Instant,
    window: Duration,
) -> Result<Connection, PunchError> {
    let deadline = start + window;

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

    let mut tasks: JoinSet<Result<Connection, PunchError>> = JoinSet::new();
    for addr in candidates {
        let endpoint = endpoint.clone();
        let addr = *addr;
        tasks.spawn(async move { dial_one(&endpoint, addr, start, deadline).await });
    }

    let mut last_error = None;
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(Ok(conn)) => {
                tasks.abort_all();
                drain_task.abort();
                return Ok(conn);
            }
            Ok(Err(e)) => last_error = Some(e),
            Err(_) => {}
        }
    }

    drain_task.abort();
    Err(last_error.unwrap_or(PunchError::Timeout))
}

async fn dial_one(
    endpoint: &Endpoint,
    peer: SocketAddr,
    start: Instant,
    deadline: Instant,
) -> Result<Connection, PunchError> {
    if Instant::now() < start {
        tokio::time::sleep_until(start).await;
    }

    let mut last_error = String::new();
    while Instant::now() <= deadline {
        match endpoint.connect(peer, SERVER_NAME) {
            Ok(connecting) => match tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting).await {
                Ok(Ok(conn)) => return Ok(conn),
                Ok(Err(e)) => last_error = e.to_string(),
                Err(_) => last_error = "握手超时".to_string(),
            },
            Err(e) => last_error = e.to_string(),
        }
        tokio::time::sleep(RETRY_INTERVAL).await;
    }

    if last_error.is_empty() {
        Err(PunchError::Timeout)
    } else {
        Err(PunchError::Dial(last_error))
    }
}

async fn listen_with_probes(
    endpoint: &Endpoint,
    candidates: &[SocketAddr],
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
                Err(e) => tracing::debug!("[punch] 入站连接失败: {e}"),
            }
        }
    };
    tokio::pin!(accept_loop);

    // 每个候选都发探针：自己这侧的开孔要对所有可能路径都有效
    let mut next_probe = start;
    loop {
        tokio::select! {
            result = &mut accept_loop => return result,
            _ = tokio::time::sleep_until(deadline) => return Err(PunchError::Timeout),
            _ = tokio::time::sleep_until(next_probe) => {
                for peer in candidates {
                    if let Ok(connecting) = endpoint.connect(*peer, SERVER_NAME) {
                        tokio::spawn(async move {
                            if let Ok(conn) = connecting.await {
                                conn.close(0u32.into(), b"probe");
                            }
                        });
                    }
                }
                next_probe = Instant::now() + RETRY_INTERVAL;
            }
        }
    }
}
