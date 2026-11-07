//! 周期 STUN 保活的端到端测试：真实 Engine + 两台本地假 STUN 服务器
//! （127.0.0.1 与 127.0.0.2，Linux/macOS 回环网段都能绑）。
//!
//! 假服务器把"看到的来源端口 + offset"当作公网映射回给客户端，
//! 改 offset 就等于模拟 NAT 换了端口。

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use qp2p_core::engine::Engine;
use qp2p_core::stun::NatKind;

const COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

struct Fake {
    addr: SocketAddr,
    offset: Arc<AtomicU16>,
    /// false 时假装服务器不可达（收到也不回）
    answering: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
}

impl Fake {
    fn spawn(ip: &str, offset: u16) -> Self {
        let sock = UdpSocket::bind((ip, 0)).unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(30)))
            .unwrap();
        let addr = sock.local_addr().unwrap();
        let offset = Arc::new(AtomicU16::new(offset));
        let answering = Arc::new(AtomicBool::new(true));
        let stop = Arc::new(AtomicBool::new(false));
        let (o, a, s) = (offset.clone(), answering.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while !s.load(Ordering::Relaxed) {
                let Ok((n, from)) = sock.recv_from(&mut buf) else {
                    continue;
                };
                if n < 20 || buf[0] != 0x00 || buf[1] != 0x01 || !a.load(Ordering::Relaxed) {
                    continue;
                }
                let mut txid = [0u8; 12];
                txid.copy_from_slice(&buf[8..20]);
                let mapped_port = from.port().wrapping_add(o.load(Ordering::Relaxed));
                let _ = sock.send_to(&response(txid, [198, 51, 100, 7], mapped_port), from);
            }
        });
        Self {
            addr,
            offset,
            answering,
            stop,
        }
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn response(txid: [u8; 12], ip: [u8; 4], port: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0x0101u16.to_be_bytes());
    buf.extend_from_slice(&12u16.to_be_bytes());
    buf.extend_from_slice(&COOKIE);
    buf.extend_from_slice(&txid);
    buf.extend_from_slice(&0x0020u16.to_be_bytes());
    buf.extend_from_slice(&8u16.to_be_bytes());
    buf.extend_from_slice(&[0x00, 0x01]);
    buf.extend_from_slice(&(port ^ 0x2112).to_be_bytes());
    for (i, b) in ip.iter().enumerate() {
        buf.push(b ^ COOKIE[i]);
    }
    buf
}

async fn engine_with(a: &Fake, b: &Fake) -> Engine {
    let servers = vec![a.addr.to_string(), b.addr.to_string()];
    Engine::bind("127.0.0.1:0".parse().unwrap(), &servers)
        .await
        .expect("bind")
}

async fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    panic!("等待超时：{what}");
}

fn expected(engine: &Engine, offset: u16) -> SocketAddr {
    let port = engine.local_addr().port().wrapping_add(offset);
    format!("198.51.100.7:{port}").parse().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn startup_probe_classifies_cone_and_sets_srflx() {
    let (a, b) = (
        Fake::spawn("127.0.0.1", 1000),
        Fake::spawn("127.0.0.2", 1000),
    );
    let engine = engine_with(&a, &b).await;
    assert_eq!(engine.nat_kind(), NatKind::Cone);
    assert_eq!(engine.srflx(), Some(expected(&engine, 1000)));
}

#[tokio::test(flavor = "multi_thread")]
async fn startup_probe_classifies_symmetric_when_ports_differ() {
    let (a, b) = (
        Fake::spawn("127.0.0.1", 1000),
        Fake::spawn("127.0.0.2", 1500),
    );
    let engine = engine_with(&a, &b).await;
    assert_eq!(engine.nat_kind(), NatKind::Symmetric);
}

#[tokio::test(flavor = "multi_thread")]
async fn keepalive_detects_mapping_change_through_observing_socket() {
    let (a, b) = (
        Fake::spawn("127.0.0.1", 1000),
        Fake::spawn("127.0.0.2", 1000),
    );
    let engine = engine_with(&a, &b).await;
    let before = engine.stun_generation();

    engine.stun_set_interval(Duration::from_millis(60));
    engine.stun_set_active(true);
    // 模拟 NAT 换了端口
    a.offset.store(2000, Ordering::Relaxed);
    b.offset.store(2000, Ordering::Relaxed);

    wait_until("generation 增加", || engine.stun_generation() > before).await;
    assert_eq!(engine.srflx(), Some(expected(&engine, 2000)));
    assert!(
        engine
            .live_candidates()
            .iter()
            .any(|c| c.addr == expected(&engine, 2000)),
        "live_candidates 应带上新的 srflx"
    );
    assert_eq!(engine.nat_kind(), NatKind::Cone);
}

#[tokio::test(flavor = "multi_thread")]
async fn keepalive_is_silent_when_inactive() {
    let (a, b) = (
        Fake::spawn("127.0.0.1", 1000),
        Fake::spawn("127.0.0.2", 1000),
    );
    let engine = engine_with(&a, &b).await;
    let before = engine.stun_generation();

    engine.stun_set_interval(Duration::from_millis(50));
    // 不打开开关
    a.offset.store(2000, Ordering::Relaxed);
    b.offset.store(2000, Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_eq!(
        engine.stun_generation(),
        before,
        "关着的时候不应发包也不应有变化"
    );
    assert_eq!(engine.srflx(), Some(expected(&engine, 1000)));
}

#[tokio::test(flavor = "multi_thread")]
async fn keepalive_counts_misses_when_servers_go_silent() {
    let (a, b) = (
        Fake::spawn("127.0.0.1", 1000),
        Fake::spawn("127.0.0.2", 1000),
    );
    let engine = engine_with(&a, &b).await;

    a.answering.store(false, Ordering::Relaxed);
    b.answering.store(false, Ordering::Relaxed);
    engine.stun_set_interval(Duration::from_millis(50));
    engine.stun_set_active(true);

    wait_until("记到至少一次 miss", || engine.stun_misses() >= 1).await;
    // 服务器恢复后 miss 清零
    a.answering.store(true, Ordering::Relaxed);
    b.answering.store(true, Ordering::Relaxed);
    wait_until("miss 清零", || engine.stun_misses() == 0).await;
}
