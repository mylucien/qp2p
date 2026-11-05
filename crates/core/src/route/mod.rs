//! 路由与虚拟网卡。
//!
//! 分三块：
//! - `ip`：IPv4 报文解析与 ICMP echo 应答（纯函数，任何平台都能测）
//! - `flow`：五元组 → 一条 QUIC 流的映射与回收（纯逻辑）
//! - 平台设备：Linux `/dev/net/tun`、Windows WinTun，都实现 [`TunDevice`]

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;
use tokio::sync::mpsc;

use anyhow::{bail, Context, Result};

pub mod flow;
pub mod ip;

#[cfg(target_os = "android")]
mod tun_android;
#[cfg(target_os = "linux")]
mod tun_linux;
#[cfg(windows)]
mod tun_windows;

/// Android：把 VpnService 建好的 tun 描述符包成设备。
///
/// fd 的生命周期由 Java 层的 `ParcelFileDescriptor` 管，这里只借用。
#[cfg(target_os = "android")]
pub fn from_fd(fd: i32) -> Result<Box<dyn TunDevice>> {
    if fd < 0 {
        bail!("VpnService 没给出有效的 tun 描述符（fd={fd}）");
    }
    Ok(Box::new(tun_android::FdTun::new(fd)))
}

/// 一个 IPv4 网段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub base: Ipv4Addr,
    pub prefix: u8,
}

impl Cidr {
    pub fn new(base: Ipv4Addr, prefix: u8) -> Result<Self> {
        if prefix > 32 {
            bail!("前缀长度必须在 0..=32：{prefix}");
        }
        let mask = mask_of(prefix);
        Ok(Self {
            base: Ipv4Addr::from(u32::from(base) & mask),
            prefix,
        })
    }

    pub fn mask(&self) -> u32 {
        mask_of(self.prefix)
    }

    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        u32::from(addr) & self.mask() == u32::from(self.base)
    }

    /// 网络里可用的主机数（去掉网络地址与广播地址，/31 与 /32 例外）。
    pub fn usable_hosts(&self) -> u32 {
        match self.prefix {
            32 => 1,
            31 => 2,
            p => (1u32 << (32 - p)) - 2,
        }
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.base, self.prefix)
    }
}

impl FromStr for Cidr {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> Result<Self> {
        let (addr, prefix) = text
            .split_once('/')
            .with_context(|| format!("网段要写成 a.b.c.d/len：{text}"))?;
        let addr: Ipv4Addr = addr
            .parse()
            .with_context(|| format!("不是合法 IPv4：{addr}"))?;
        let prefix: u8 = prefix
            .parse()
            .with_context(|| format!("前缀长度不是数字：{prefix}"))?;
        Cidr::new(addr, prefix)
    }
}

fn mask_of(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

/// 虚拟网卡的配置。
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// 设备名。Linux 上限 15 字节；Windows 上是适配器名，可任意。
    pub name: String,
    /// 本机的虚拟地址。
    pub address: Ipv4Addr,
    /// 虚拟网段前缀长度，默认 /16。
    pub prefix: u8,
    /// 设备 MTU。内层 TCP 的 MSS 由它推出来。
    pub mtu: u16,
}

impl TunConfig {
    /// 按 node_id 派生的虚拟地址加上网段，拼出一份配置。
    pub fn for_network(network: Cidr, address: Ipv4Addr, mtu: u16) -> Self {
        Self {
            name: "qp2p0".to_string(),
            address,
            prefix: network.prefix,
            mtu,
        }
    }

    pub fn cidr(&self) -> Result<Cidr> {
        Cidr::new(self.address, self.prefix)
    }
}

/// 虚拟网卡的最小接口。读到的包是"本机要发出去的"，写进去的是"远端送来的"。
///
/// 方法取 `&self`：读写必须能同时进行（读阻塞时不能把写也堵住），
/// 所以实现方要么用内部可变性，要么本来就线程安全（WinTun 与 `/dev/net/tun` 都是）。
pub trait TunDevice: Send + Sync + 'static {
    fn read_packet(&self, buf: &mut [u8]) -> std::io::Result<usize>;
    fn write_packet(&self, buf: &[u8]) -> std::io::Result<usize>;
}

/// 打开平台对应的虚拟网卡，并配好地址、MTU、以及到虚拟网段的直连路由。
pub fn open(config: &TunConfig) -> Result<Box<dyn TunDevice>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(tun_linux::LinuxTun::open(config)?))
    }
    #[cfg(windows)]
    {
        Ok(Box::new(tun_windows::WindowsTun::open(config)?))
    }
    #[cfg(not(any(target_os = "linux", windows, target_os = "android")))]
    {
        let _ = config;
        bail!("当前平台还不支持虚拟网卡（Linux / Windows / Android 之外）")
    }
    #[cfg(target_os = "android")]
    {
        let _ = config;
        bail!("Android 的虚拟网卡由 VpnService 创建，请用 route::from_fd 接管它的描述符")
    }
}

/// 让一个网段走这条隧道。
///
/// 典型用法：对端网卡背后还有一片局域网（192.168.1.0/24），
/// 在本地加一条指向隧道的路由之后，访问那些地址就像访问本网段一样。
pub fn add_route(device: &str, cidr: &Cidr) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        tun_linux::LinuxTun::route_to(device, cidr)
    }
    #[cfg(windows)]
    {
        tun_windows::route_to(device, cidr)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (device, cidr);
        bail!("当前平台还不支持添加隧道路由")
    }
}

/// 把同步的设备读写搬到两个独立线程，转成异步通道。
///
/// TUN 设备的读写是阻塞的，放进 tokio 任务里会卡住整个运行时；
/// 开两个专用线程最省事，也避免为每个平台写一遍 epoll/IOCP。
pub struct TunLink {
    /// 从内核收到的包（要发往对端）。
    pub from_tun: mpsc::Receiver<Vec<u8>>,
    /// 要写进内核的包（从对端收到的）。
    pub to_tun: mpsc::Sender<Vec<u8>>,
    pub mtu: usize,
}

pub fn spawn_io(device: Box<dyn TunDevice>, mtu: u16) -> TunLink {
    // 容量取 MTU 量级的几倍：太小会频繁阻塞读线程，太大等于把内核的丢包挪到用户态
    let (tx_out, from_tun) = mpsc::channel::<Vec<u8>>(512);
    let (to_tun, mut rx_in) = mpsc::channel::<Vec<u8>>(512);

    let device: std::sync::Arc<dyn TunDevice> = std::sync::Arc::from(device);
    let reader = device.clone();
    let writer = device.clone();
    std::thread::Builder::new()
        .name("qp2p-tun-read".into())
        .spawn(move || {
            let mut buf = vec![0u8; usize::from(mtu) + 64];
            loop {
                match reader.read_packet(&mut buf) {
                    Ok(0) => continue,
                    Ok(n) => {
                        // 通道容量有限：阻塞着等消费者，别把内核队列丢空
                        if tx_out.blocking_send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    Err(e) => {
                        tracing::warn!("[tun] 读取失败: {e}");
                        break;
                    }
                }
            }
            tracing::debug!("[tun] 读线程退出");
        })
        .expect("创建 TUN 读线程失败");

    std::thread::Builder::new()
        .name("qp2p-tun-write".into())
        .spawn(move || {
            while let Some(packet) = rx_in.blocking_recv() {
                if let Err(e) = writer.write_packet(&packet) {
                    tracing::debug!("[tun] 写入失败: {e}");
                }
            }
            tracing::debug!("[tun] 写线程退出");
        })
        .expect("创建 TUN 写线程失败");

    TunLink {
        from_tun,
        to_tun,
        mtu: usize::from(mtu),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_normalizes_cidr() {
        let c: Cidr = "10.64.1.2/16".parse().unwrap();
        assert_eq!(c.base, Ipv4Addr::new(10, 64, 0, 0), "主机位要被清掉");
        assert_eq!(c.to_string(), "10.64.0.0/16");
        assert!(c.contains(Ipv4Addr::new(10, 64, 200, 7)));
        assert!(!c.contains(Ipv4Addr::new(10, 65, 0, 1)));
    }

    #[test]
    fn rejects_bad_prefix() {
        assert!("10.0.0.0/33".parse::<Cidr>().is_err());
        assert!("10.0.0.0".parse::<Cidr>().is_err());
        assert!("not-an-ip/24".parse::<Cidr>().is_err());
    }

    #[test]
    fn usable_hosts_edge_cases() {
        assert_eq!("10.0.0.0/24".parse::<Cidr>().unwrap().usable_hosts(), 254);
        assert_eq!("10.0.0.0/31".parse::<Cidr>().unwrap().usable_hosts(), 2);
        assert_eq!("10.0.0.1/32".parse::<Cidr>().unwrap().usable_hosts(), 1);
        assert_eq!("10.0.0.0/16".parse::<Cidr>().unwrap().usable_hosts(), 65534);
    }

    #[test]
    fn prefix_zero_matches_everything() {
        let c: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(c.contains(Ipv4Addr::new(203, 0, 113, 9)));
    }
}
