//! # tun.rs — TUN 虚拟网卡模块（v0.8 新增）
//!
//! 职责：
//! - 创建 TUN 虚拟网卡，绑定 `Config.virtual_ip`
//! - 持续读取 TUN 设备的出站 IP 包，通过 `VirtualIpRegistry` + `ConnRegistry` 路由
//! - 接收外部（QUIC 接收端）的入站 IP 包，写入 TUN 设备
//! - 收到 `cancel` 信号时关闭设备并退出
//!
//! ## 平台支持
//! | 平台        | 实现                          | 状态 |
//! |------------|-------------------------------|------|
//! | Linux      | `/dev/tun` + `tun` crate      | ✅   |
//! | OpenWrt    | `/dev/tun` + `tun` crate      | ✅   |
//! | Windows    | WinTun 驱动 + `wintun` crate  | ⏳ 步骤 15 |
//! | Android    | VpnService（需 JNI 协作）     | ❌ 暂不支持 |

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::types::{ConnRegistry, ConnState, VirtualIpRegistry};

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

/// TUN 设备 MTU
const TUN_MTU: i32 = 1500;

/// 读取 buffer 大小 = MTU + PI header(4) + 余量。
/// Linux packet_information 模式每个包前有 4 字节 PI header。
const TUN_READ_BUFFER: usize = TUN_MTU as usize + 64;

/// 入站包 channel buffer 大小
const INBOUND_CHANNEL_SIZE: usize = 1024;

// ---------------------------------------------------------------------------
// TunHandle
// ---------------------------------------------------------------------------

/// TUN 虚拟网卡控制句柄。
///
/// 外部模块（如 QUIC 接收端）通过 `send_packet()` 将入站 IP 包写入 TUN 设备。
#[derive(Debug, Clone)]
pub struct TunHandle {
    inbound_tx: mpsc::Sender<Vec<u8>>,
}

impl TunHandle {
    /// 向 TUN 设备写入一个 IP 包（供 QUIC 接收端调用）。
    pub async fn send_packet(&self, data: Vec<u8>) -> Result<()> {
        self.inbound_tx
            .send(data)
            .await
            .map_err(|_| anyhow::anyhow!("TUN 写入通道已关闭"))
    }
}

// ---------------------------------------------------------------------------
// platform — 平台相关 TUN 设备实现
// ---------------------------------------------------------------------------

#[cfg(target_os = "android")]
compile_error!("Android 暂不支持 TUN 设备（VpnService 需 Java 层协作）");

// ---- Linux / OpenWrt ----

#[cfg(any(target_os = "linux", target_vendor = "openwrt"))]
mod platform {
    use anyhow::{bail, Context, Result};
    use tokio::io::{AsyncRead, AsyncWrite};

    pub struct TunSplit {
        pub reader: Box<dyn AsyncRead + Send + Unpin>,
        pub writer: Box<dyn AsyncWrite + Send + Unpin>,
    }

    pub fn create(ip: std::net::IpAddr, prefix_len: u8) -> Result<TunSplit> {
        let std::net::IpAddr::V4(ipv4) = ip else {
            bail!("Linux TUN 当前仅支持 IPv4 虚拟地址");
        };
        let mut config = tun::Configuration::default();
        config
            .address(ipv4)
            .netmask(prefix_len_to_netmask(prefix_len))
            .mtu(super::TUN_MTU)
            .up();
        config.platform(|p| {
            p.packet_information(true);
        });

        let device = tun::create_as_async(&config)
            .context("创建 TUN 设备失败（需要 root / CAP_NET_ADMIN）")?;

        let (reader, writer) = tokio::io::split(device);
        Ok(TunSplit {
            reader: Box::new(reader),
            writer: Box::new(writer),
        })
    }

    fn prefix_len_to_netmask(prefix: u8) -> std::net::Ipv4Addr {
        let mask = !0u32 << (32 - prefix);
        std::net::Ipv4Addr::from(mask.to_be_bytes())
    }
}

// ---- Windows (WinTun through tun crate) ----

#[cfg(target_os = "windows")]
mod platform {
    use anyhow::{bail, Context, Result};
    use tokio::io::{AsyncRead, AsyncWrite};

    pub struct TunSplit {
        pub reader: Box<dyn AsyncRead + Send + Unpin>,
        pub writer: Box<dyn AsyncWrite + Send + Unpin>,
    }

    pub fn create(ip: std::net::IpAddr, prefix_len: u8) -> Result<TunSplit> {
        let std::net::IpAddr::V4(ipv4) = ip else {
            bail!("Windows TUN 当前仅支持 IPv4 虚拟地址");
        };
        let mut config = tun::Configuration::default();
        config
            .address(ipv4)
            .netmask(netmask_from_prefix(prefix_len))
            .mtu(super::TUN_MTU)
            .up();

        let device = tun::create_as_async(&config)
            .context("创建 TUN 设备失败（需要安装 WinTun 驱动 https://www.wintun.net）")?;

        let (reader, writer) = tokio::io::split(device);
        Ok(TunSplit {
            reader: Box::new(reader),
            writer: Box::new(writer),
        })
    }

    fn netmask_from_prefix(prefix: u8) -> std::net::Ipv4Addr {
        let mask = !0u32 << (32 - prefix);
        std::net::Ipv4Addr::from(mask.to_be_bytes())
    }
}

// ---------------------------------------------------------------------------
// spawn_tun — 启动 TUN 虚拟网卡任务
// ---------------------------------------------------------------------------

/// 创建 TUN 虚拟网卡并启动读写任务。
pub fn spawn_tun(
    config: Arc<Config>,
    conn_registry: ConnRegistry,
    vip_registry: VirtualIpRegistry,
    cancel: CancellationToken,
) -> (TunHandle, tokio::task::JoinHandle<Result<()>>) {
    let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_CHANNEL_SIZE);
    let handle = TunHandle { inbound_tx };

    let task = tokio::spawn(async move {
        let cidr = config
            .virtual_ip
            .parse::<ipnetwork::IpNetwork>()
            .context("解析 virtual_ip CIDR 失败")?;
        let ip = cidr.ip();
        let prefix_len = cidr.prefix();

        info!("[tun] 启动 TUN 设备: ip={ip}, /{prefix_len}");

        let tun_split = platform::create(ip, prefix_len)
            .context("创建 TUN 设备失败（需要 root / CAP_NET_ADMIN）")?;

        info!("[tun] TUN 设备已创建");

        let (mut reader, mut writer) = (tun_split.reader, tun_split.writer);

        let result: Result<()> = tokio::select! {
            res = read_loop(&mut reader, &conn_registry, &vip_registry, &cancel) => {
                warn!("[tun] 出站读取循环退出: {res:?}");
                res
            }
            res = write_loop(&mut writer, inbound_rx, &cancel) => {
                warn!("[tun] 入站写入循环退出: {res:?}");
                res
            }
            _ = cancel.cancelled() => {
                info!("[tun] 收到取消信号，关闭 TUN 设备");
                Ok(())
            }
        };

        if let Err(e) = &result {
            error!("[tun] TUN 模块异常退出: {e}");
        }
        result
    });

    (handle, task)
}

// ---------------------------------------------------------------------------
// 出站读取循环（TUN → 网络）
// ---------------------------------------------------------------------------

async fn read_loop(
    reader: &mut (dyn AsyncRead + Unpin + Send),
    conn_registry: &ConnRegistry,
    vip_registry: &VirtualIpRegistry,
    cancel: &CancellationToken,
) -> Result<()> {
    let mut buf = vec![0u8; TUN_READ_BUFFER];

    loop {
        let n = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            res = reader.read(&mut buf) => res.context("TUN 设备读取失败")?,
        };

        if n == 0 {
            info!("[tun] TUN 设备读取返回 EOF");
            return Ok(());
        }

        // 跳过平台相关头部（Linux PI header 4 字节）
        #[cfg(any(target_os = "linux", target_vendor = "openwrt"))]
        let data = {
            if n <= 4 {
                continue; // PI header 不完整，丢弃
            }
            &buf[4..n]
        };
        #[cfg(not(any(target_os = "linux", target_vendor = "openwrt")))]
        let data = &buf[..n];

        match parse_dst_ip(data) {
            Ok(dst_ip) => {
                if let Some(peer_id) = vip_registry.get(&dst_ip).as_deref().cloned() {
                    if let Some(entry) = conn_registry.get(&peer_id) {
                        let conn_state = entry.value().clone();
                        drop(entry);

                        match conn_state {
                            ConnState::Direct(conn) => {
                                let data = data.to_vec();
                                tokio::spawn(async move {
                                    if let Err(e) = send_over_quic(conn, data).await {
                                        warn!("[tun] QUIC 发送失败: {e}");
                                    }
                                });
                            }
                            ConnState::Relay => {
                                warn!("[tun] 对端 {peer_id} 处于 Relay 状态，TUN 包暂时丢弃");
                            }
                            _ => {}
                        }
                    }
                }
            }
            Err(e) => warn!("[tun] 解析 IP 包目标地址失败: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// 入站写入循环（网络 → TUN）
// ---------------------------------------------------------------------------

async fn write_loop(
    writer: &mut (dyn AsyncWrite + Unpin + Send),
    mut inbound_rx: mpsc::Receiver<Vec<u8>>,
    cancel: &CancellationToken,
) -> Result<()> {
    // 入站包（从网络接收，无 PI header），写入 TUN 设备
    loop {
        let packet = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            pkt = inbound_rx.recv() => match pkt {
                Some(data) => data,
                None => {
                    info!("[tun] 入站通道已关闭，停止写入");
                    return Ok(());
                }
            },
        };

        #[cfg(any(target_os = "linux", target_vendor = "openwrt"))]
        {
            // Linux PI header + IP packet 合成一个 buffer 一次写入，
            // 避免分两次 write 导致内核收到两个独立 TUN 帧。
            let pi: &[u8] = if packet.first().map(|b| b >> 4) == Some(6) {
                &[0x00, 0x00, 0x86, 0xDD] // IPv6
            } else {
                &[0x00, 0x00, 0x08, 0x00] // IPv4
            };
            let mut frame = Vec::with_capacity(4 + packet.len());
            frame.extend_from_slice(pi);
            frame.extend_from_slice(&packet);
            writer
                .write_all(&frame)
                .await
                .context("TUN 设备写入失败")?;
        }
        #[cfg(not(any(target_os = "linux", target_vendor = "openwrt")))]
        writer
            .write_all(&packet)
            .await
            .context("TUN 设备写入失败")?;
    }
}

// ---------------------------------------------------------------------------
// Windows 读写循环（WinTun 异步桥接）
// ---------------------------------------------------------------------------



async fn send_over_quic(conn: quinn::Connection, data: Vec<u8>) -> Result<()> {
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        conn.open_uni(),
    )
    .await
    .context("open_uni 超时（对端 stream 并发数已满）")?
    .context("打开 QUIC 单向流失败")?;

    stream.write_all(&data).await.context("QUIC 流写入失败")?;
    stream.finish().context("QUIC 流关闭失败")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// IP 包解析
// ---------------------------------------------------------------------------

fn parse_dst_ip(packet: &[u8]) -> Result<IpAddr> {
    if packet.is_empty() {
        bail!("空包");
    }
    let version = packet[0] >> 4;
    match version {
        4 => {
            if packet.len() < 20 {
                bail!("IPv4 包长度不足 ({})", packet.len());
            }
            let octets: [u8; 4] = packet[16..20].try_into().unwrap();
            Ok(IpAddr::V4(std::net::Ipv4Addr::from(octets)))
        }
        6 => {
            if packet.len() < 40 {
                bail!("IPv6 包长度不足 ({})", packet.len());
            }
            let octets: [u8; 16] = packet[24..40].try_into().unwrap();
            Ok(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        _ => bail!("不支持的 IP 版本: {version}"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dst_ip_v4() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);

        let dst = parse_dst_ip(&pkt).unwrap();
        assert_eq!(dst, std::net::Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn test_parse_dst_ip_v4_too_short() {
        assert!(parse_dst_ip(&[0x45; 10]).is_err());
    }

    #[test]
    fn test_parse_dst_ip_empty() {
        assert!(parse_dst_ip(&[]).is_err());
    }

    #[test]
    fn test_parse_dst_ip_unsupported_version() {
        assert!(parse_dst_ip(&[0x70; 20]).is_err());
    }

    #[test]
    fn test_parse_dst_ip_v6() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60; // IPv6
        // dst = ::1 (127.0.0.1 in IPv6)
        pkt[24..40].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = parse_dst_ip(&pkt).unwrap();
        assert_eq!(dst, std::net::Ipv6Addr::LOCALHOST);
    }
}

