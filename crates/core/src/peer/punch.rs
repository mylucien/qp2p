//! 打洞执行器。
//!
//! 不依赖两端启动对齐：dialer 持续按节奏发 Initial，listener 长时间
//! accept 并周期性发探针。谁先起来都能通，差异只体现在耗时上。
//!
//! 旧实现是"双方在同一个 800ms 窗口里同时发"，启动差 1.5 秒就必然错过，
//! 而重试间隔是 30 秒起——手动开两个终端基本打不通。

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use quinn::{Connection, Endpoint};
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::identity::{Identity, NodeId};
use crate::peer::{auth, Role};
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
    /// 身份不对：重试没有意义，调用方应当直接停下
    #[error("对端认证失败：{0}")]
    Auth(String),
}

/// 连接建立后要做的一次对端认证。
///
/// QUIC 这一层没有证书校验，能完成握手不等于对面是谁；
/// 真正决定"这条连接能不能用"的是这里的签名交换。
#[derive(Clone)]
pub struct AuthHandles {
    pub identity: Identity,
    pub expected: Option<NodeId>,
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
    auth: Option<AuthHandles>,
) -> Result<Connection, PunchError> {
    if candidates.is_empty() {
        return Err(PunchError::NoCandidates);
    }
    match role {
        Role::Dialer => dial_all(endpoint, candidates, timeout, auth).await,
        Role::Listener => listen_with_probes(endpoint, candidates, timeout, auth).await,
    }
}

/// 单次尝试的失败原因。
///
/// 区分"网络不通"和"对面身份不对"：前者值得换个时刻再试，
/// 后者是确定的结论——重试只会一直失败，而且会把有用的信息盖成"超时"。
enum AttemptError {
    Transient(String),
    Auth(String),
}

impl AttemptError {
    fn message(&self) -> &str {
        match self {
            Self::Transient(m) | Self::Auth(m) => m,
        }
    }
}

/// 双方交换身份并互相验签；失败就关掉这条连接，当作一次失败的尝试。
async fn verify_peer(
    conn: &Connection,
    handles: &Option<AuthHandles>,
    dialer: bool,
) -> Result<(), String> {
    let Some(handles) = handles else {
        return Ok(());
    };
    let identity = &handles.identity;
    let expected = handles.expected.as_ref();

    let result = if dialer {
        auth::authenticate_dialer(conn, identity, expected).await
    } else {
        auth::authenticate_listener(conn, identity, expected).await
    };

    match result {
        Ok(peer) => {
            tracing::info!("[punch] 对端认证通过 peer={}", peer.node_id);
            Ok(())
        }
        Err(e) => Err(format!("对端认证失败: {e:#}")),
    }
}

async fn dial_all(
    endpoint: &Endpoint,
    candidates: &[SocketAddr],
    timeout: Duration,
    auth: Option<AuthHandles>,
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

    // 身份不符的候选：它背后是别的节点（比如同网段里另一台 qp2p），
    // 不能因为它就放弃其他候选，但也没必要在后续轮次里再去敲它。
    // 去重但保持调用方给的顺序（内网优先、upnp 先于 srflx）：
    // 换成 HashSet 虽然能去重，但日志顺序会随进程变化，排障时对不上。
    let mut distinct: Vec<SocketAddr> = Vec::with_capacity(candidates.len());
    for addr in candidates {
        if !distinct.contains(addr) {
            distinct.push(*addr);
        }
    }
    let mut wrong_identity: HashSet<SocketAddr> = HashSet::new();
    let mut auth_notes: Vec<String> = Vec::new();

    let result = loop {
        // 每个候选只发一条连接，让 QUIC 自己重传 Initial；
        // 以前每 150ms 新建一条，10 秒就是几百次握手，还会让两端各自
        // 选中不同的连接（已复现：一端拿到连接后立刻被对端关掉）。
        let mut attempts: JoinSet<(SocketAddr, Result<Connection, AttemptError>)> = JoinSet::new();
        for addr in distinct.iter().filter(|a| !wrong_identity.contains(a)) {
            let endpoint = endpoint.clone();
            let addr = *addr;
            let auth = auth.clone();
            attempts
                .spawn(async move { (addr, attempt_once(&endpoint, addr, deadline, auth).await) });
        }

        let mut winner = None;
        while let Some(joined) = attempts.join_next().await {
            match joined {
                Ok((_, Ok(conn))) => {
                    winner = Some(conn);
                    break;
                }
                Ok((addr, Err(AttemptError::Auth(msg)))) => {
                    tracing::warn!("[punch] 候选 {addr} 不是要找的节点，后续不再尝试它：{msg}");
                    wrong_identity.insert(addr);
                    auth_notes.push(msg);
                    // 所有候选都是别人：重试只会一直失败，立刻收尾并说清原因
                    if wrong_identity.len() >= distinct.len() {
                        attempts.abort_all();
                        drain_task.abort();
                        return Err(PunchError::Auth(auth_notes.join("；")));
                    }
                }
                Ok((_, Err(e))) => last_error = e.message().to_string(),
                Err(e) => last_error = e.to_string(),
            }
        }
        attempts.abort_all();

        if let Some(conn) = winner {
            break Ok(conn);
        }
        if Instant::now() >= deadline {
            break if !auth_notes.is_empty() {
                // 只剩"别人"和"没连上"：把两件事都讲出来，别只报一个超时
                let rest = if last_error.is_empty() {
                    String::new()
                } else {
                    format!("；其余候选：{last_error}")
                };
                Err(PunchError::Dial(format!(
                    "{} 个候选身份不符（{}）{rest}",
                    wrong_identity.len(),
                    auth_notes[0]
                )))
            } else if last_error.is_empty() {
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
    auth: Option<AuthHandles>,
) -> Result<Connection, AttemptError> {
    let connecting = endpoint
        .connect(peer, SERVER_NAME)
        .map_err(|e| AttemptError::Transient(format!("{peer}: 发起连接失败 {e}")))?;

    // 单个候选最多等 ATTEMPT_CAP，失败就进入下一轮，不拖住其他候选
    let attempt_deadline = deadline.min(Instant::now() + ATTEMPT_CAP);
    let conn = match tokio::time::timeout_at(attempt_deadline, connecting).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => return Err(AttemptError::Transient(format!("{peer}: 握手失败 {e}"))),
        Err(_) => return Err(AttemptError::Transient(format!("{peer}: 握手超时"))),
    };

    if !confirm_as_dialer(&conn).await {
        conn.close(0u32.into(), b"unconfirmed");
        return Err(AttemptError::Transient(format!(
            "{peer}: 建连确认失败（对端没回 ACK）"
        )));
    }

    if let Err(e) = verify_peer(&conn, &auth, true).await {
        conn.close(0u32.into(), b"auth-failed");
        return Err(AttemptError::Auth(format!("{peer}: {e}")));
    }

    Ok(conn)
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
    auth: Option<AuthHandles>,
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
                    let auth = auth.clone();
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
                        // 确认失败就把机会让回去，否则整个打洞卡在一条坏连接上
                        if !confirm_as_listener(&conn).await {
                            claim.store(false, Ordering::SeqCst);
                            conn.close(0u32.into(), b"unconfirmed");
                            return None;
                        }
                        // 认证失败要留下痕迹：否则有人在试探时，这一侧什么都看不到
                        if let Err(e) = verify_peer(&conn, &auth, false).await {
                            tracing::warn!("[punch] 拒绝来自 {remote} 的连接：{e}");
                            claim.store(false, Ordering::SeqCst);
                            conn.close(0u32.into(), b"auth-failed");
                            return None;
                        }
                        Some(conn)
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
