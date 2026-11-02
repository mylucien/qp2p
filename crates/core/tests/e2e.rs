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

    let window = Duration::from_secs(3);
    let (dialer, listener) = tokio::join!(
        a.punch(b_addr, Role::Dialer, window),
        b.punch(a_addr, Role::Listener, window)
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
