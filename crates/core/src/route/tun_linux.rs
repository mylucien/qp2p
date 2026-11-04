//! Linux 的 TUN 设备：`/dev/net/tun` + `ip` 命令。
//!
//! 需要 `CAP_NET_ADMIN`（通常就是 root）。地址、MTU、路由都用 `ip` 命令下发，
//! 而不是自己算 netlink——这条路径可读、可复现，出错时把命令原文打出来即可定位。

use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::process::Command;

use anyhow::{bail, Context, Result};

use super::{Cidr, TunConfig, TunDevice};

const DEV_NET_TUN: &str = "/dev/net/tun";
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const IFNAMSIZ: usize = 16;

#[repr(C)]
struct IfReq {
    name: [libc::c_char; IFNAMSIZ],
    flags: libc::c_short,
    // struct ifreq 在内核里是 40 字节（16 名字 + 24 联合体），补齐避免 ioctl 越界
    _pad: [u8; 22],
}

pub struct LinuxTun {
    file: File,
    name: String,
}

impl LinuxTun {
    pub fn open(config: &TunConfig) -> Result<Self> {
        if config.name.len() >= IFNAMSIZ {
            bail!("Linux 网卡名最长 15 字节：{}", config.name);
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(DEV_NET_TUN)
            .with_context(|| format!("打开 {DEV_NET_TUN} 失败（需要 root 或 CAP_NET_ADMIN）"))?;

        let mut req = IfReq {
            name: [0; IFNAMSIZ],
            flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };
        for (dst, src) in req.name.iter_mut().zip(config.name.as_bytes()) {
            *dst = *src as libc::c_char;
        }

        // SAFETY: fd 有效，req 是 #[repr(C)] 且大小与内核期望的 ifreq 一致
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &mut req) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("创建 TUN 设备 {} 失败", config.name));
        }

        let tun = Self {
            file,
            name: config.name.clone(),
        };
        tun.configure(config)?;
        Ok(tun)
    }

    /// 配地址、MTU、拉起设备，并加一条到虚拟网段的直连路由。
    ///
    /// 有了这条路由，10.64.0.0/16 的包才会进 TUN；只配地址不加路由的话，
    /// 内核只会有本机那一个 /16 的直连条目（其实也够用，但显式写出来更清楚）。
    fn configure(&self, config: &TunConfig) -> Result<()> {
        let cidr = Cidr::new(config.address, config.prefix)?;
        run_ip(&[
            "addr",
            "add",
            &format!("{}/{}", config.address, config.prefix),
            "dev",
            &self.name,
        ])?;
        run_ip(&[
            "link",
            "set",
            "dev",
            &self.name,
            "mtu",
            &config.mtu.to_string(),
        ])?;
        run_ip(&["link", "set", "dev", &self.name, "up"])?;
        // 网段路由（已存在时忽略错误，重复启动不该失败）
        if let Err(e) = run_ip(&["route", "add", &cidr.to_string(), "dev", &self.name]) {
            tracing::debug!("[tun] 网段路由已存在或添加失败（可忽略）：{e}");
        }
        tracing::info!(
            "[tun] {} 已就绪 addr={}/{} mtu={}",
            self.name,
            config.address,
            config.prefix,
            config.mtu
        );
        Ok(())
    }

    /// 让某个网段走这条隧道（`--advertise` 的另一半：访问对端背后的局域网）。
    pub fn route_to(device: &str, cidr: &Cidr) -> Result<()> {
        run_ip(&["route", "add", &cidr.to_string(), "dev", device])
            .with_context(|| format!("添加路由 {cidr} 失败"))
    }
}

fn run_ip(args: &[&str]) -> Result<()> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .context("执行 ip 命令失败（iproute2 没装？）")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("ip {} 失败：{}", args.join(" "), stderr.trim());
    }
    Ok(())
}

impl TunDevice for LinuxTun {
    fn read_packet(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::io::Read;
        // &File 也能读：这样读线程与写线程可以共用一个 fd，不会互相阻塞
        (&self.file).read(buf)
    }

    fn write_packet(&self, buf: &[u8]) -> std::io::Result<usize> {
        use std::io::Write;
        (&self.file).write_all(buf)?;
        Ok(buf.len())
    }
}
