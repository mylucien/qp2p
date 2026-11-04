//! Linux 虚拟网卡的真实创建（需要 root）。
//!
//! 默认 `#[ignore]`：普通 `cargo test` 不碰它。CI 里单独用 sudo 跑一次，
//! 目的是把"设备能建、地址能配上、路由能下发"这条链验证掉——这部分
//! 光编译通过说明不了任何问题。

#![cfg(target_os = "linux")]

use std::process::Command;

use qp2p_core::route::{self, Cidr, TunConfig};

const DEV: &str = "qp2pt0";
const ADDR: &str = "10.64.99.2";

#[test]
#[ignore = "需要 root 与 /dev/net/tun"]
fn creates_device_and_applies_config() {
    let config = TunConfig {
        name: DEV.to_string(),
        address: ADDR.parse().unwrap(),
        prefix: 16,
        mtu: 1400,
    };
    let device = route::open(&config).expect("创建 TUN 设备失败（需要 root）");

    // 地址与 MTU 必须真的落到了设备上
    let out = Command::new("ip")
        .args(["-4", "addr", "show", "dev", DEV])
        .output()
        .expect("执行 ip 失败");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains(ADDR), "地址没有配上，ip addr 输出：{text}");
    assert!(
        text.contains("mtu 1400"),
        "MTU 没有配上，ip addr 输出：{text}"
    );

    // 网段路由应当指向这块设备
    let expected: Cidr = "10.64.0.0/16".parse().unwrap();
    let out = Command::new("ip")
        .args(["route", "show", &expected.to_string()])
        .output()
        .expect("执行 ip route 失败");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains(DEV),
        "网段路由没有指向 {DEV}，ip route 输出：{text}"
    );

    // 写一个包进去不应该报错（内核会当作从隧道收到的入站包处理）
    let packet = qp2p_core::route::ip::build_echo_request(
        ADDR.parse().unwrap(),
        "10.64.0.1".parse().unwrap(),
        1,
        1,
    );
    device.write_packet(&packet).expect("写 TUN 失败");
}
