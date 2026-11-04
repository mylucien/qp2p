//! 认证的两条回归：
//!
//! 1. 通道绑定：路径上的中间人终结两段 QUIC、逐流转发，认证帧原样过去，
//!    两端也不能"认证通过"。修复前这个场景下 dialer 设了 `expect_peer`
//!    照样通过，业务明文被中间人读到。
//! 2. 候选里混进"别的 qp2p 节点"（同网段、同地址段很常见）时，
//!    只能丢掉那个候选，不能连累真正可达的对端。

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use qp2p_core::peer::punch::PunchError;
use qp2p_core::tls::{client_config, TlsIdentity, SERVER_NAME};
use qp2p_core::{Engine, Role};

async fn engine() -> Engine {
    Engine::bind_in("127.0.0.1:0".parse().unwrap(), &[], None)
        .await
        .unwrap()
}

/// 把一条流转给另一条流，同时把经过的字节记下来。
async fn relay(
    mut from: quinn::RecvStream,
    mut to: quinn::SendStream,
    log: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
) {
    let mut buf = [0u8; 4096];
    while let Ok(Some(n)) = from.read(&mut buf).await {
        log.lock().unwrap().extend_from_slice(&buf[..n]);
        if to.write_all(&buf[..n]).await.is_err() {
            return;
        }
    }
    let _ = to.finish();
}

/// 中间人 M：对 dialer 扮演 listener，对 listener 扮演 dialer，TLS 全部放行，
/// 其余原样转发——包括握手确认帧和认证帧。
#[tokio::test(flavor = "multi_thread")]
async fn relay_in_the_middle_cannot_pass_authentication() {
    let mut dialer = engine().await;
    let listener = engine().await;
    // 最严格的身份期望：dialer 明确只要 listener 这个 node_id
    dialer.expect_peer(Some(listener.node_id()));

    let tls = TlsIdentity::load_or_create(None).unwrap();
    let m_srv =
        quinn::Endpoint::server(tls.server_config().unwrap(), "127.0.0.1:0".parse().unwrap())
            .unwrap();
    let mut m_cli = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    m_cli.set_default_client_config(client_config(None).unwrap());
    let (m_srv_addr, m_cli_addr) = (m_srv.local_addr().unwrap(), m_cli.local_addr().unwrap());
    let l_addr = listener.local_addr();

    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let seen_m = seen.clone();
    tokio::spawn(async move {
        let Ok(incoming) = m_srv.accept().await.unwrap().await else {
            return;
        };
        let Ok(connecting) = m_cli.connect(l_addr, SERVER_NAME) else {
            return;
        };
        let Ok(out_l) = connecting.await else { return };
        loop {
            let Ok((send_d, recv_d)) = incoming.accept_bi().await else {
                break;
            };
            let Ok((send_l, recv_l)) = out_l.open_bi().await else {
                break;
            };
            tokio::spawn(relay(recv_d, send_l, seen_m.clone()));
            tokio::spawn(relay(recv_l, send_d, seen_m.clone()));
        }
    });

    let window = Duration::from_secs(6);
    let (to_m, from_m) = ([m_srv_addr], [m_cli_addr]);
    let (d, l) = tokio::join!(
        dialer.punch(&to_m, Role::Dialer, window),
        listener.punch(&from_m, Role::Listener, window),
    );

    match &d {
        Err(PunchError::Auth(msg)) => {
            assert!(msg.contains("签名"), "应当是签名校验失败，实际：{msg}");
        }
        other => panic!(
            "dialer 不应认证通过，实际：{:?}",
            other.as_ref().map(|c| c.remote_address())
        ),
    }
    assert!(
        l.is_err(),
        "listener 也不应认证通过：{:?}",
        l.as_ref().map(|c| c.remote_address())
    );
}

/// 两个"别人"：本地起两个陌生 qp2p 节点占着候选地址。
async fn strangers(dialer_addr: SocketAddr, count: usize, window: Duration) -> Vec<SocketAddr> {
    let mut addrs = Vec::new();
    for _ in 0..count {
        let stranger = engine().await;
        addrs.push(stranger.local_addr());
        tokio::spawn(async move {
            let peers = [dialer_addr];
            // 陌生节点自己并不挑剔，会把认证走完；是 dialer 这边发现它不是要找的人
            let _ = stranger.punch(&peers, Role::Listener, window).await;
        });
    }
    addrs
}

#[tokio::test(flavor = "multi_thread")]
async fn stranger_candidate_does_not_abort_the_real_peer() {
    let mut dialer = engine().await;
    let listener = engine().await;
    dialer.expect_peer(Some(listener.node_id()));
    let (d_addr, l_addr) = (dialer.local_addr(), listener.local_addr());

    let window = Duration::from_secs(10);
    let stranger = strangers(d_addr, 1, window).await;
    tokio::spawn(async move {
        let peers = [d_addr];
        let _ = listener.punch(&peers, Role::Listener, window).await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 陌生节点排在前面，真正的对端在后面
    let candidates = [stranger[0], l_addr];
    let conn = dialer
        .punch(&candidates, Role::Dialer, window)
        .await
        .expect("真正的对端可达，不应被陌生候选连累");
    assert_eq!(conn.remote_address(), l_addr);
}

#[tokio::test(flavor = "multi_thread")]
async fn all_candidates_wrong_fails_fast_with_auth_error() {
    let mut dialer = engine().await;
    let wanted = engine().await; // 想找的人，但候选里没有它
    dialer.expect_peer(Some(wanted.node_id()));
    let d_addr = dialer.local_addr();

    let window = Duration::from_secs(10);
    let candidates = strangers(d_addr, 2, window).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let started = Instant::now();
    let result = dialer.punch(&candidates, Role::Dialer, window).await;
    assert!(
        matches!(result, Err(PunchError::Auth(_))),
        "全是别人应当立刻报认证失败：{:?}",
        result.as_ref().map(|c| c.remote_address())
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "不应等到窗口结束：{:?}",
        started.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_identity_plus_unreachable_candidate_reports_both() {
    let mut dialer = engine().await;
    let wanted = engine().await;
    dialer.expect_peer(Some(wanted.node_id()));
    let d_addr = dialer.local_addr();

    let window = Duration::from_secs(4);
    let stranger = strangers(d_addr, 1, window).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 一个是别人，一个根本没人听（回环上的 9 号端口）
    let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let candidates = [stranger[0], dead];
    let result = dialer.punch(&candidates, Role::Dialer, window).await;

    match result {
        // 还有候选没连上，不能武断地说"身份不对"而停止重试：应是可重试的 Dial 错误，
        // 同时把"有候选是别人"这件事讲出来
        Err(PunchError::Dial(msg)) => {
            assert!(msg.contains("身份不符"), "错误信息里应提到身份不符：{msg}");
        }
        other => panic!(
            "预期 Dial 错误，实际：{:?}",
            other.as_ref().map(|c| c.remote_address())
        ),
    }
}
