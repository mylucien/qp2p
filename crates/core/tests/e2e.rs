//! 端到端：两个引擎在环回上打洞，并通过 QUIC 流做端口转发。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use qp2p_core::{link, Engine, Role};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if socket.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// 读满整个请求、延迟一会儿再回、然后关闭写端的服务。
/// 用来验证"客户端先关写端、服务端后回"这种半关闭时序。
async fn spawn_delayed_reply(delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = Vec::new();
                let _ = socket.read_to_end(&mut request).await;
                tokio::time::sleep(delay).await;
                let mut reply = b"pong:".to_vec();
                reply.extend_from_slice(&request);
                let _ = socket.write_all(&reply).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    addr
}

async fn free_port() -> SocketAddr {
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    addr
}

async fn punch_pair(a: &Engine, b: &Engine) -> (quinn::Connection, quinn::Connection) {
    let a_peers = [b.local_addr()];
    let b_peers = [a.local_addr()];
    let (dialer, listener) = tokio::join!(
        a.punch(&a_peers, Role::Dialer, Duration::from_secs(10)),
        b.punch(&b_peers, Role::Listener, Duration::from_secs(10))
    );
    (
        dialer.expect("dialer 打洞失败"),
        listener.expect("listener 打洞失败"),
    )
}

#[tokio::test]
async fn forward_works_in_both_directions() {
    let target = spawn_echo().await;

    let a = Engine::bind("127.0.0.1:0".parse().unwrap(), &[])
        .await
        .expect("引擎 A 绑定失败");
    let b = Engine::bind("127.0.0.1:0".parse().unwrap(), &[])
        .await
        .expect("引擎 B 绑定失败");

    let (ca, cb) = punch_pair(&a, &b).await;

    // 两端都必须能接流，否则反方向会挂住
    let allowed = Arc::new(vec![target]);
    let serve_ca = ca.clone();
    let serve_cb = cb.clone();
    let allowed_b = allowed.clone();
    tokio::spawn(async move {
        let _ = link::serve_flows(serve_ca, allowed).await;
    });
    tokio::spawn(async move {
        let _ = link::serve_flows(serve_cb, allowed_b).await;
    });

    // 方向 1：A 在本机监听，经 B 访问 target
    let listen_a = free_port().await;
    let fwd_ca = ca.clone();
    tokio::spawn(async move {
        let _ = link::forward_listen(fwd_ca, listen_a, target).await;
    });

    // 方向 2：B 在本机监听，经 A 访问 target
    let listen_b = free_port().await;
    let fwd_cb = cb.clone();
    tokio::spawn(async move {
        let _ = link::forward_listen(fwd_cb, listen_b, target).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    for listen in [listen_a, listen_b] {
        let mut client = TcpStream::connect(listen).await.expect("连接映射端口失败");
        client.write_all(b"hello qp2p").await.unwrap();
        let mut buf = [0u8; 10];
        client.read_exact(&mut buf).await.expect("读取回显失败");
        assert_eq!(&buf, b"hello qp2p", "方向 {listen} 未回显");
    }
}

/// 白名单必须是「对端的 target」，不是自己的 target。
///
/// 两个方向用不同的目标地址，任何一侧把自己的 --target 当白名单都会双向失败
/// ——这正是旧实现的问题，用同一个 target 的用例发现不了。
#[tokio::test]
async fn whitelist_tracks_peer_target_not_own() {
    let on_a = spawn_echo().await;
    let on_b = spawn_echo().await;
    assert_ne!(on_a, on_b, "两个目标地址必须不同，否则测不出方向错误");

    let (ca, cb) = {
        let a = Engine::bind("127.0.0.1:0".parse().unwrap(), &[])
            .await
            .expect("引擎 A 绑定失败");
        let b = Engine::bind("127.0.0.1:0".parse().unwrap(), &[])
            .await
            .expect("引擎 B 绑定失败");
        punch_pair(&a, &b).await
    };

    // A 只替对端连 on_a（对端要访问的地址）；B 只替对端连 on_b
    let serve_a = ca.clone();
    tokio::spawn(async move {
        let _ = link::serve_flows(serve_a, Arc::new(vec![on_a])).await;
    });
    let serve_b = cb.clone();
    tokio::spawn(async move {
        let _ = link::serve_flows(serve_b, Arc::new(vec![on_b])).await;
    });

    // A 的 target 是 on_b（对端侧），B 的 target 是 on_a（对端侧）
    let listen_a = free_port().await;
    let fwd_ca = ca.clone();
    tokio::spawn(async move {
        let _ = link::forward_listen(fwd_ca, listen_a, on_b).await;
    });
    let listen_b = free_port().await;
    let fwd_cb = cb.clone();
    tokio::spawn(async move {
        let _ = link::forward_listen(fwd_cb, listen_b, on_a).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    for listen in [listen_a, listen_b] {
        let mut client = TcpStream::connect(listen).await.expect("连接映射端口失败");
        client.write_all(b"cross").await.unwrap();
        let mut buf = [0u8; 5];
        tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("方向 {listen} 超时：白名单可能用错了 target"))
            .expect("读取回显失败");
        assert_eq!(&buf, b"cross", "方向 {listen} 未回显");
    }
}

/// 客户端先关写端、服务端稍后才回，数据必须还能回来（TCP 半关闭）。
#[tokio::test]
async fn half_close_still_receives_reply() {
    let target = spawn_delayed_reply(Duration::from_millis(150)).await;

    let (ca, cb) = {
        let a = Engine::bind("127.0.0.1:0".parse().unwrap(), &[])
            .await
            .expect("引擎 A 绑定失败");
        let b = Engine::bind("127.0.0.1:0".parse().unwrap(), &[])
            .await
            .expect("引擎 B 绑定失败");
        punch_pair(&a, &b).await
    };

    let serve = cb.clone();
    tokio::spawn(async move {
        let _ = link::serve_flows(serve, Arc::new(vec![target])).await;
    });

    let listen = free_port().await;
    let fwd = ca.clone();
    tokio::spawn(async move {
        let _ = link::forward_listen(fwd, listen, target).await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut client = TcpStream::connect(listen).await.expect("连接映射端口失败");
    client.write_all(b"ping").await.unwrap();
    client.shutdown().await.expect("关闭写端失败");

    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut reply))
        .await
        .expect("半关闭后响应超时——下行可能被提前丢弃")
        .expect("读取响应失败");
    assert_eq!(reply, b"pong:ping", "半关闭后应收到完整响应");
}

/// 一端先启动 1.5 秒，另一端后启动，仍然要能打通。
#[tokio::test]
async fn startup_skew_is_tolerated() {
    let a = Engine::bind("127.0.0.1:0".parse().unwrap(), &[])
        .await
        .expect("引擎 A 绑定失败");
    let b = Engine::bind("127.0.0.1:0".parse().unwrap(), &[])
        .await
        .expect("引擎 B 绑定失败");

    let a_peers = [b.local_addr()];
    let b_peers = [a.local_addr()];

    // listener 先起来守候，dialer 1.5 秒后才开始
    let listener = tokio::spawn(async move {
        b.punch(&b_peers, Role::Listener, Duration::from_secs(10))
            .await
    });
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let dialer = a
        .punch(&a_peers, Role::Dialer, Duration::from_secs(10))
        .await;

    assert!(
        dialer.is_ok(),
        "后启动的 dialer 应能打通: {:?}",
        dialer.err()
    );
    assert!(
        listener.await.expect("listener 任务失败").is_ok(),
        "listener 应能等到 dialer"
    );
}

#[tokio::test]
async fn unauthorized_target_is_rejected() {
    let echo = spawn_echo().await;
    let other = spawn_echo().await;

    let a = Engine::bind("127.0.0.1:0".parse().unwrap(), &[])
        .await
        .expect("引擎 A 绑定失败");
    let b = Engine::bind("127.0.0.1:0".parse().unwrap(), &[])
        .await
        .expect("引擎 B 绑定失败");

    let (ca, cb) = punch_pair(&a, &b).await;

    // B 只授权 echo，不授权 other
    let allowed = Arc::new(vec![echo]);
    tokio::spawn(async move {
        let _ = link::serve_flows(cb, allowed).await;
    });

    // A 试图访问未授权的 other，应该在读状态码时被拒绝
    let listen = free_port().await;
    let fwd = ca.clone();
    tokio::spawn(async move {
        let _ = link::forward_listen(fwd, listen, other).await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut client = TcpStream::connect(listen).await.expect("连接映射端口失败");
    let _ = client.write_all(b"x").await;
    let mut buf = [0u8; 4];
    // 对端拒绝后会关闭流，这里读到 EOF 或错误都算通过
    let result = tokio::time::timeout(Duration::from_secs(3), client.read(&mut buf)).await;
    assert!(result.is_ok(), "拒绝路径不应挂住");
}

/// 刷新端点后引擎仍然可用（端口可能因系统占用而变，但必须能继续打洞）。
#[tokio::test]
async fn renew_keeps_engine_usable() {
    let mut a = Engine::bind("127.0.0.1:0".parse().unwrap(), &[])
        .await
        .expect("绑定失败");
    let b = Engine::bind("127.0.0.1:0".parse().unwrap(), &[])
        .await
        .expect("绑定失败");

    a.renew().await.expect("刷新端点失败");
    assert!(!a.candidates().is_empty(), "刷新后仍应有候选");

    let a_peers = [b.local_addr()];
    let b_peers = [a.local_addr()];
    let window = Duration::from_secs(10);
    let (dialer, listener) = tokio::join!(
        a.punch(&a_peers, Role::Dialer, window),
        b.punch(&b_peers, Role::Listener, window)
    );
    assert!(dialer.is_ok(), "刷新后打洞失败: {:?}", dialer.err());
    assert!(listener.is_ok(), "刷新后打洞失败: {:?}", listener.err());
}
