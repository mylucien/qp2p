//! 打洞执行器。
//!
//! 不依赖两端启动对齐：dialer 持续按节奏发 Initial，listener 长时间
//! accept 并周期性发探针。谁先起来都能通，差异只体现在耗时上。
//!
//! 旧实现是"双方在同一个 800ms 窗口里同时发"，启动差 1.5 秒就必然错过，
//! 而重试间隔是 30 秒起——手动开两个终端基本打不通。

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use quinn::{Connection, Endpoint};
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::peer::Role;
use crate::tls::SERVER_NAME;

/// 单次握手等待上限，超时就再发一轮。
const ATTEMPT_TIMEOUT: Duration = Duration::from_millis(700);
/// 单次尝试的上限。留短一点，免得一个卡死的候选把整轮重试拖到超时。
const ATTEMPT_CAP: Duration = Duration::from_secs(4);
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
    let started = Instant::now();
    let mut last_error = String::new();

    let result = loop {
        // 每个候选只发一条连接，让 QUIC 自己重传 Initial；
        // 以前每 150ms 新建一条，10 秒就是几百次握手，还会让两端各自
        // 选中不同的连接（已复现：一端拿到连接后立刻被对端关掉）。
        let mut attempts: JoinSet<Result<Connection, String>> = JoinSet::new();
        for addr in candidates {
            let endpoint = endpoint.clone();
            let addr = *addr;
            attempts.spawn(async move { attempt_once(&endpoint, addr, deadline).await });
        }

        let mut winner = None;
        while let Some(joined) = attempts.join_next().await {
            match joined {
                Ok(Ok(conn)) => {
                    winner = Some(conn);
                    break;
                }
                Ok(Err(e)) => last_error = e,
                Err(e) => last_error = e.to_string(),
            }
        }
        attempts.abort_all();

        if let Some(conn) = winner {
            break Ok(conn);
        }
        if Instant::now() >= deadline {
            break if last_error.is_empty() {
                Err(PunchError::Timeout(started.elapsed()))
            } else {
                Err(PunchError::Dial(last_error))
            };
        }
        // 全部失败（比如 ICMP 端口不可达）：歇一下再来一轮，直到超时
        tokio::time::sleep(Duration::from_millis(300)).await;
    };

    drain_task.abort();
    result
}

async fn attempt_once(
    endpoint: &Endpoint,
    peer: SocketAddr,
    deadline: Instant,
) -> Result<Connection, String> {
    let connecting = endpoint
        .connect(peer, SERVER_NAME)
        .map_err(|e| format!("{peer}: 发起连接失败 {e}"))?;

    // 单个候选最多等 ATTEMPT_CAP，失败就进入下一轮，不拖住其他候选
    let attempt_deadline = deadline.min(Instant::now() + ATTEMPT_CAP);
    let conn = match tokio::time::timeout_at(attempt_deadline, connecting).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => return Err(format!("{peer}: 握手失败 {e}")),
        Err(_) => return Err(format!("{peer}: 握手超时")),
    };

    if confirm_as_dialer(&conn).await {
        Ok(conn)
    } else {
        conn.close(0u32.into(), b"unconfirmed");
        Err(format!("{peer}: 建连确认失败（对端没回 ACK）"))
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
    // 按 IP 而不是 ip:port 过滤：NAT 重映射后端口会变，但 IP 不会
    let allowed_ips: Vec<std::net::IpAddr> = candidates.iter().map(|c| c.ip()).collect();
    let claimed = Arc::new(AtomicBool::new(false));
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
                    // 只接受候选里出现过的 IP，避免被无关流量占位
                    if !allowed_ips.is_empty() && !allowed_ips.contains(&remote.ip()) {
                        tracing::debug!("[punch] 忽略未知来源 {remote}");
                        continue;
                    }
                    let claim = claimed.clone();
                    handshakes.spawn(async move {
                        let conn = match tokio::time::timeout(ATTEMPT_TIMEOUT * 4, incoming).await {
                            Ok(Ok(conn)) => conn,
                            _ => return None,
                        };
                        // 先抢占再回 ACK：如果先回 ACK 再放弃，对端会确认这条连接，
                        // 而我们随后把它关掉——表现为"两端都连上了，但一用就断"
                        if claim.swap(true, Ordering::SeqCst) {
                            conn.close(0u32.into(), b"another-winner");
                            return None;
                        }
                        if confirm_as_listener(&conn).await {
                            Some(conn)
                        } else {
                            // 确认失败就把机会让回去，否则整个打洞卡在一条坏连接上
                            claim.store(false, Ordering::SeqCst);
                            conn.close(0u32.into(), b"unconfirmed");
                            None
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
