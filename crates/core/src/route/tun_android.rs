//! Android 的 TUN：VpnService 建好之后把 fd 交过来，这里直接读写 IP 包。
//!
//! 和 Linux 的 `/dev/net/tun` 不同，Android 上应用没有权限自己开网卡：
//! 必须走 `VpnService.Builder.establish()`，由系统建接口、配地址和路由，
//! 再把可读写的描述符交给我们。所以这里只管收发，配置全在 Kotlin 侧完成。
//!
//! fd 的所有权归 Java 层（`ParcelFileDescriptor` 持有），这里只借用，不关闭。

use std::os::fd::RawFd;

use super::TunDevice;

pub struct FdTun {
    fd: RawFd,
}

impl FdTun {
    pub fn new(fd: RawFd) -> Self {
        Self { fd }
    }
}

impl TunDevice for FdTun {
    fn read_packet(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            // SAFETY: fd 有效且由 Java 侧保证生命周期；buf 的容量由调用方给出
            let n =
                unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n >= 0 {
                return Ok(n as usize);
            }
            let err = std::io::Error::last_os_error();
            // 信号打断不算错误
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
    }

    fn write_packet(&self, buf: &[u8]) -> std::io::Result<usize> {
        let n = unsafe { libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        Err(std::io::Error::last_os_error())
    }
}
