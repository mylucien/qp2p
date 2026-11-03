//! 打洞执行器。
//!
//! 不依赖两端启动对齐：dialer 持续按节奏发 Initial，listener 长时间
//! accept 并周期性发探针。谁先起来都能通，差异只体现在耗时上。
//!
//! 旧实现是"双方在同一个 800ms 窗口里同时发"，启动差 1.5 秒就必然错过，
//! 而重试间隔是 30 秒起——手动开两个终端基本打不通。

use std::net::SocketAddr;
use std::time::Duration;

use quinn::{Connection, Endpoint};
use tokio::task::JoinSet;
use tokio::time::{interval, Instant};

use crate::peer::Role;
use crate::tls::SERVER_NAME;

/// 每次尝试间隔。对端只要在这个节奏里发过包，映射就能被撞上。
pub const ATTEMPT_INTERVAL: Duration = Duration::from_millis(150);
/// 单次握手等待上限，超时就再发一轮。
const ATTEMPT_TIMEOUT: Duration = Duration::from_millis(700);
/// listener 发探针的间隔（只为自己这侧开孔）。
const PROBE_INTERVAL: Duration = Duration::from_millis(300);

/// 建连确认：双方必须落在**同一条** QUIC 连接上。
///
/// 持续重发会有多条并发尝试，dialer 拿到的那条和 listener accept 到的那条
/// 可能不是同一条；不做确认就会出现"双方都以为连上了，数据却发进黑洞"。
const HELLO: &[u8] = b"QP2P-HELLO-1";
const HELLO_ACK: &[u8] = b"QP2P-ACK-1";
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, thiserror::Error)]
pub enum PunchError {
    #[error("没有可用的候选地址")]
    NoCandidates,
    #[error("打洞超时（{0:?}）")]
    Timeout(Duration),
    #[error("连接失败：{0}")]
    Dial(String),
}

/// 在给定时间内尝试建立直连。
///
/// `timeout` 由调用方决定：dialer 短（十几秒），listener 长（几十秒），
/// 这样先启动的一方会一直等着后启动的一方。
pub async fn execute(
    endpoint: &Endpoint,
    candidates: &[SocketAddr],
    role: Role,
    timeout: Duration,
) -> Result<Connection, PunchError> {
    if candidates.is_empty() {
        return Err(PunchError::NoCandidates);
    }
    match role {
        Role::Dialer => dial_all(endpoint, candidates, timeout).await,
        Role::Listener => listen_with_probes(endpoint, candidates, timeout).await,
    }
}

async fn dial_all(
    endpoint: &Endpoint,
    candidates: &[SocketAddr],
    timeout: Duration,
) -> Result<Connection, PunchError> {
    // dialer 不接收入站，但必须排空 accept 队列，否则对端探针会堆积
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

    let deadline = Instant::now() + timeout;
    let result = dial_loop(endpoint, candidates, deadline).await;

    drain_task.abort();
    result
}

async fn dial_loop(
    endpoint: &Endpoint,
    candidates: &[SocketAddr],
    deadline: Instant,
) -> Result<Connection, PunchError> {
    let mut attempts: JoinSet<Option<Connection>> = JoinSet::new();
    let mut ticker = interval(ATTEMPT_INTERVAL);
    let mut last_error = String::new();
    let started = Instant::now();

    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                attempts.abort_all();
                if last_error.is_empty() {
                    return Err(PunchError::Timeout(started.elapsed()));
                }
                return Err(PunchError::Dial(last_error));
            }
            _ = ticker.tick() => {
                for addr in candidates {
                    let endpoint = endpoint.clone();
                    let addr = *addr;
                    attempts.spawn(async move { attempt_once(&endpoint, addr).await });
                }
            }
            // 空 JoinSet 的 join_next 会立即返回 None，必须加 guard，否则空转把定时器饿死
            joined = attempts.join_next(), if !attempts.is_empty() => {
                match joined {
                    Some(Ok(Some(conn))) => {
                        attempts.abort_all();
                        return Ok(conn);
                    }
                    Some(Err(e)) => last_error = e.to_string(),
                    _ => {}
                }
            }
        }
    }
}

async fn attempt_once(endpoint: &Endpoint, peer: SocketAddr) -> Option<Connection> {
    let connecting = endpoint.connect(peer, SERVER_NAME).ok()?;
    let conn = tokio::time::timeout(ATTEMPT_TIMEOUT, connecting)
        .await
        .ok()?
        .ok()?;
    if confirm_as_dialer(&conn).await {
        Some(conn)
    } else {
        conn.close(0u32.into(), b"unconfirmed");
        None
    }
}

/// dialer 侧：开一条流发 HELLO，等 listener 回 ACK。
async fn confirm_as_dialer(conn: &Connection) -> bool {
    let Ok(Ok((mut send, mut recv))) = tokio::time::timeout(CONFIRM_TIMEOUT, conn.open_bi()).await
    else {
        return false;
    };
    if send.write_all(HELLO).await.is_err() {
        return false;
    }

    let mut buf = [0u8; HELLO_ACK.len()];
    matches!(
        tokio::time::timeout(CONFIRM_TIMEOUT, recv.read_exact(&mut buf)).await,
        Ok(Ok(_))
    ) && buf == HELLO_ACK
}

/// listener 侧：等到对端开的流并读到 HELLO，回 ACK。
async fn confirm_as_listener(conn: &Connection) -> bool {
    let Ok(Ok((mut send, mut recv))) =
        tokio::time::timeout(CONFIRM_TIMEOUT, conn.accept_bi()).await
    else {
        return false;
    };

    let mut buf = [0u8; HELLO.len()];
    if recv.read_exact(&mut buf).await.is_err() || buf != HELLO {
        return false;
    }
    send.write_all(HELLO_ACK).await.is_ok()
}

async fn listen_with_probes(
    endpoint: &Endpoint,
    candidates: &[SocketAddr],
    timeout: Duration,
) -> Result<Connection, PunchError> {
    let deadline = Instant::now() + timeout;

    let accept_endpoint = endpoint.clone();
    let allowed: Vec<SocketAddr> = candidates.to_vec();
    let accept_loop = async move {
        let mut handshakes: JoinSet<Option<Connection>> = JoinSet::new();
        loop {
            tokio::select! {
                // 并发握手：一个卡住的连接不能堵住真正的 dialer
                joined = handshakes.join_next(), if !handshakes.is_empty() => {
                    if let Some(Ok(Some(conn))) = joined {
                        handshakes.abort_all();
                        return Ok(conn);
                    }
                }
                incoming = accept_endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        return Err(PunchError::Dial("端点已关闭".to_string()));
                    };
                    let remote = incoming.remote_address();
                    // 只接受候选列表里的来源，避免被无关流量占位
                    if !allowed.is_empty() && !allowed.contains(&remote) {
                        tracing::debug!("[punch] 忽略未知来源 {remote}");
                        continue;
                    }
                    handshakes.spawn(async move {
                        match tokio::time::timeout(ATTEMPT_TIMEOUT * 4, incoming).await {
                            Ok(Ok(conn)) => {
                                if confirm_as_listener(&conn).await {
                                    Some(conn)
                                } else {
                                    conn.close(0u32.into(), b"unconfirmed");
                                    None
                                }
                            }
                            _ => None,
                        }
                    });
                }
            }
        }
    };
    tokio::pin!(accept_loop);

    let mut next_probe = Instant::now();
    loop {
        tokio::select! {
            result = &mut accept_loop => return result,
            _ = tokio::time::sleep_until(deadline) => return Err(PunchError::Timeout(timeout)),
            _ = tokio::time::sleep_until(next_probe) => {
                for peer in candidates {
                    if let Ok(connecting) = endpoint.connect(*peer, SERVER_NAME) {
                        // 用后即弃的 Initial，只为打通自己这侧的 NAT
                        tokio::spawn(async move {
                            let _ = tokio::time::timeout(ATTEMPT_TIMEOUT, connecting).await;
                        });
                    }
                }
                next_probe = Instant::now() + PROBE_INTERVAL;
            }
        }
    }
}
