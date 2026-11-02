//! 端到端：两个引擎在环回上打洞，并通过 QUIC 流做端口转发。

use std::net::SocketAddr;
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

#[tokio::test]
async fn punch_and_forward_over_loopback() {
    let target = spawn_echo().await;

    let a = Engine::bind("127.0.0.1:0".parse().unwrap(), &[])
        .await
        .expect("引擎 A 绑定失败");
    let b = Engine::bind("127.0.0.1:0".parse().unwrap(), &[])
        .await
        .expect("引擎 B 绑定失败");
    let (a_addr, b_addr) = (a.local_addr(), b.local_addr());

    let window = Duration::from_secs(5);
    let a_peers = [b_addr];
    let b_peers = [a_addr];
    let (dialer, listener) = tokio::join!(
        a.punch(&a_peers, Role::Dialer, window),
        b.punch(&b_peers, Role::Listener, window)
    );
    let dialer = dialer.expect("dialer 打洞失败");
    let listener = listener.expect("listener 打洞失败");
    assert_eq!(dialer.remote_address(), b_addr);
    assert_eq!(listener.remote_address(), a_addr);

    tokio::spawn(async move {
        let _ = link::serve_flows(listener).await;
    });

    // 选一个空闲端口交给 forward_listen，避免与其绑定冲突
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = probe.local_addr().unwrap();
    drop(probe);

    let conn = dialer.clone();
    tokio::spawn(async move {
        let _ = link::forward_listen(conn, listen_addr, target).await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut client = TcpStream::connect(listen_addr)
        .await
        .expect("连接映射端口失败");
    client.write_all(b"hello qp2p").await.unwrap();
    let mut buf = [0u8; 10];
    client.read_exact(&mut buf).await.expect("读取回显失败");
    assert_eq!(&buf, b"hello qp2p");
}

/// 候选里混入不可达地址时，仍然能靠并行打洞连通。
#[tokio::test]
async fn parallel_candidates_tolerate_dead_addresses() {
    let a = Engine::bind("127.0.0.1:0".parse().unwrap(), &[])
        .await
        .expect("引擎 A 绑定失败");
    let b = Engine::bind("127.0.0.1:0".parse().unwrap(), &[])
        .await
        .expect("引擎 B 绑定失败");

    // 一个必然打不通的地址，排在真实地址前面
    let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let a_peers = [dead, b.local_addr()];
    let b_peers = [dead, a.local_addr()];

    let window = Duration::from_secs(5);
    let (dialer, listener) = tokio::join!(
        a.punch(&a_peers, Role::Dialer, window),
        b.punch(&b_peers, Role::Listener, window)
    );

    let dialer = dialer.expect("并行候选下 dialer 应能连通");
    let listener = listener.expect("并行候选下 listener 应能连通");
    assert_eq!(dialer.remote_address(), b.local_addr());
    assert_eq!(listener.remote_address(), a.local_addr());
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
    let window = Duration::from_secs(5);
    let (dialer, listener) = tokio::join!(
        a.punch(&a_peers, Role::Dialer, window),
        b.punch(&b_peers, Role::Listener, window)
    );
    assert!(dialer.is_ok(), "刷新后打洞失败: {:?}", dialer.err());
    assert!(listener.is_ok(), "刷新后打洞失败: {:?}", listener.err());
}
