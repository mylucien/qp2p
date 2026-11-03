//! 半关闭后的空闲收尾：只在"双方都没有数据往来"时才触发。
//!
//! 单独一个测试文件 = 单独一个进程，改全局的空闲上限不会影响别的测试。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use qp2p_core::{link, Engine, Role};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const IDLE: Duration = Duration::from_secs(2);

/// 建好一条直连，返回 (本地转发入口, 目标服务地址)。
/// `serve` 是目标服务的行为：先读到客户端半关闭，再自行决定怎么回。
async fn setup<F, Fut>(serve: F) -> (SocketAddr, Engine, Engine)
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    link::set_half_close_idle(IDLE);

    let service = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = service.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = service.accept().await.unwrap();
        serve(stream).await;
    });

    let a = Engine::bind("127.0.0.1:0".parse().unwrap(), &[])
        .await
        .unwrap();
    let b = Engine::bind("127.0.0.1:0".parse().unwrap(), &[])
        .await
        .unwrap();
    let (pa, pb) = ([b.local_addr()], [a.local_addr()]);
    let window = Duration::from_secs(8);
    let (dialer, listener) = tokio::join!(
        a.punch(&pa, Role::Dialer, window),
        b.punch(&pb, Role::Listener, window)
    );
    let (dialer, listener) = (dialer.unwrap(), listener.unwrap());

    tokio::spawn(link::serve_flows(listener, Arc::new(vec![target])));

    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let entry = probe.local_addr().unwrap();
    drop(probe);
    tokio::spawn(link::forward_listen(dialer, entry, target));
    tokio::time::sleep(Duration::from_millis(200)).await;
    (entry, a, b)
}

/// 回归：数据一直在流动时，即使总时长远超空闲上限也不能被截断。
/// 旧实现把计时器挂在"上行结束"那一刻，到点就强行收尾，响应被静默截断。
#[tokio::test(flavor = "multi_thread")]
async fn active_transfer_survives_past_idle_limit() {
    const CHUNKS: usize = 8; // 8 × 600ms = 4.8s，是空闲上限 2s 的两倍多
    let (entry, _a, _b) = setup(|mut s| async move {
        let mut req = Vec::new();
        s.read_to_end(&mut req).await.ok(); // 读到客户端半关闭
        for _ in 0..CHUNKS {
            tokio::time::sleep(Duration::from_millis(600)).await;
            if s.write_all(b"x").await.is_err() {
                break;
            }
        }
    })
    .await;

    let mut client = TcpStream::connect(entry).await.unwrap();
    client.write_all(b"req").await.unwrap();
    client.shutdown().await.unwrap(); // 半关闭，之后只等响应

    let started = Instant::now();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), client.read_to_end(&mut out))
        .await
        .expect("读取不应超时")
        .expect("读取失败");

    assert_eq!(
        out.len(),
        CHUNKS,
        "持续有数据的响应被截断了：收到 {} / {CHUNKS} 字节，耗时 {:?}",
        out.len(),
        started.elapsed()
    );
    assert!(started.elapsed() > IDLE, "测试时长必须超过空闲上限才有意义");
}

/// 真正沉默：半关闭后服务端既不回数据也不关流，应在空闲上限附近被收尾，
/// 而不是一直占着流名额。
#[tokio::test(flavor = "multi_thread")]
async fn silent_half_closed_flow_is_reclaimed() {
    let (entry, _a, _b) = setup(|mut s| async move {
        let mut req = Vec::new();
        s.read_to_end(&mut req).await.ok();
        tokio::time::sleep(Duration::from_secs(60)).await; // 一直不回、不关
    })
    .await;

    let mut client = TcpStream::connect(entry).await.unwrap();
    client.write_all(b"req").await.unwrap();
    client.shutdown().await.unwrap();

    let started = Instant::now();
    let mut out = Vec::new();
    let finished =
        tokio::time::timeout(Duration::from_secs(15), client.read_to_end(&mut out)).await;

    assert!(finished.is_ok(), "沉默的半关闭流没有被回收（等了 15s）");
    let took = started.elapsed();
    assert!(took >= IDLE, "不应早于空闲上限收尾：{took:?}");
    assert!(took < IDLE * 4, "收尾太晚：{took:?}");
    assert!(out.is_empty());
}
