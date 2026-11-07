//! Windows 的 TUN 设备：WinTun（wintun.dll）+ `netsh` / `route`。
//!
//! 需要管理员权限（创建网络适配器）。**优先用编译时内嵌的 wintun 0.14.1**：
//! 装过 WireGuard / Tailscale 的机器常在 `C:\Windows\System32` 留一份 0.13X，
//! 用裸名字加载会命中它——LoadLibrary 成功，但它没有 `WintunCloseAdapter`，
//! 于是「外部找不到就用内嵌」的回退根本不会触发，最后报 os error 127 并降级成只打洞。
//! 内嵌那份用独立文件名 + 完整路径加载，彻底绕开系统的 DLL 搜索顺序。

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use libloading::Library;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::WaitForSingleObject;

use super::{Cidr, TunConfig, TunDevice};

const WINTUN_DLL: &str = "wintun.dll";
/// 内嵌 dll 落盘用的名字。刻意不叫 `wintun.dll`：Windows 加载模块时可能按
/// 基名复用进程里已加载的同名 dll，换个名字才能确保用的是我们这份。
const EMBEDDED_DLL_NAME: &str = "wintun-0.14.1.dll";
/// 内嵌的官方 wintun 0.14.1（amd64）。只发一个 exe 也能建虚拟网卡。
const EMBEDDED_WINTUN: &[u8] = include_bytes!("../../../../assets/wintun.dll");

/// 内置 dll 的落盘位置：优先 %LOCALAPPDATA%\qp2p（用户可写、不进 Program Files）。
fn embedded_dll_path() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join("qp2p");
    std::fs::create_dir_all(&dir).ok()?;
    let path = dir.join(EMBEDDED_DLL_NAME);
    // 内嵌版本换了就覆盖，避免旧文件一直留在用户目录里。
    let stale = std::fs::read(&path)
        .map(|existing| existing != EMBEDDED_WINTUN)
        .unwrap_or(true);
    if stale {
        std::fs::write(&path, EMBEDDED_WINTUN).ok()?;
    }
    Some(path)
}
/// 会话环形缓冲区大小，也是单包上限（WinTun 要求 128KiB 起步）。
const RING_CAPACITY: u32 = 0x40_0000;
const ERROR_NO_MORE_ITEMS: u32 = 259;

type AdapterHandle = isize;
type SessionHandle = isize;

type CreateAdapterFn =
    unsafe extern "system" fn(*const u16, *const u16, *const u8) -> AdapterHandle;
/// wintun 没有 `WintunDeleteAdapter`：0.14 的 API 里关闭适配器就是
/// `WintunCloseAdapter(adapter)`（void），删除驱动才是 `WintunDeleteDriver()`。
/// 之前误用了不存在的符号，`GetProcAddress` 返回空，报 os error 127。
type CloseAdapterFn = unsafe extern "system" fn(AdapterHandle);
type StartSessionFn = unsafe extern "system" fn(AdapterHandle, u32) -> SessionHandle;
type EndSessionFn = unsafe extern "system" fn(SessionHandle);
type GetReadWaitEventFn = unsafe extern "system" fn(SessionHandle) -> HANDLE;
type ReceivePacketFn = unsafe extern "system" fn(SessionHandle, *mut u32) -> *mut u8;
type ReleaseReceivePacketFn = unsafe extern "system" fn(SessionHandle, *const u8);
type AllocateSendPacketFn = unsafe extern "system" fn(SessionHandle, u32) -> *mut u8;
type SendPacketFn = unsafe extern "system" fn(SessionHandle, *const u8);

struct WintunApi {
    _lib: Library,
    create_adapter: CreateAdapterFn,
    close_adapter: CloseAdapterFn,
    start_session: StartSessionFn,
    end_session: EndSessionFn,
    read_wait_event: GetReadWaitEventFn,
    receive_packet: ReceivePacketFn,
    release_receive_packet: ReleaseReceivePacketFn,
    allocate_send_packet: AllocateSendPacketFn,
    send_packet: SendPacketFn,
}

impl WintunApi {
    fn load() -> Result<Self> {
        // 注意：加载失败的报错只挂在 load_library 上。符号缺失是另一种病
        // （系统里装了 0.13X 的旧 dll），混在一起会把「版本不对」误报成
        // 「文件没找到」，排查时会绕远路。
        let lib = load_library()
            .with_context(|| format!("加载 {WINTUN_DLL} 失败。{}", download_hint()))?;

        // SAFETY: 名字与 wintun.h 一致；dll 生命周期由 self._lib 持有
        unsafe {
            Ok(Self {
                create_adapter: sym(&lib, b"WintunCreateAdapter\0")?,
                close_adapter: sym(&lib, b"WintunCloseAdapter\0")?,
                start_session: sym(&lib, b"WintunStartSession\0")?,
                end_session: sym(&lib, b"WintunEndSession\0")?,
                read_wait_event: sym(&lib, b"WintunGetReadWaitEvent\0")?,
                receive_packet: sym(&lib, b"WintunReceivePacket\0")?,
                release_receive_packet: sym(&lib, b"WintunReleaseReceivePacket\0")?,
                allocate_send_packet: sym(&lib, b"WintunAllocateSendPacket\0")?,
                send_packet: sym(&lib, b"WintunSendPacket\0")?,
                _lib: lib,
            })
        }
    }
}

/// 优先加载编译期内嵌的 0.14.1，解不出来才按老顺序找外部 dll。
///
/// 顺序不能反：`Library::new("wintun.dll")` 走 Windows 的 DLL 搜索路径，
/// System32 里那份 0.13X 会**加载成功**（只是没有 0.14 的符号），
/// 于是「外部找不到就用内嵌」的回退永远不触发，用户只看到降级为只打洞。
fn load_library() -> std::result::Result<Library, libloading::Error> {
    if let Some(lib) = embedded_dll_path().and_then(|path| unsafe { Library::new(&path) }.ok()) {
        tracing::debug!("[tun] 使用内嵌 wintun 0.14.1");
        return Ok(lib);
    }
    // 内嵌那份解不出来，才按老顺序找外部 dll
    unsafe { Library::new(WINTUN_DLL) }.or_else(|e| {
        let beside = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join(WINTUN_DLL)));
        match beside {
            Some(path) if path.exists() => unsafe { Library::new(path) },
            _ => Err(e),
        }
    })
}

/// 按名字取导出函数；缺失时给出「版本太老」的提示而不是裸的GetProcAddress 错误。
///
/// `lib.get` 返回 `Symbol<T>`（Deref 到 T），函数指针都是 Copy，
/// `map(|s| *s)` 取值后字段直接存值，dll 生命周期由 self._lib 兜住。
unsafe fn sym<T: Copy>(lib: &Library, name: &[u8]) -> Result<T> {
    unsafe { lib.get(name) }
        .map(|s| *s)
        .with_context(|| {
            format!(
                "加载的 wintun.dll 里没有 {}。多半是系统里装了 0.13X 或更老的版本（例如 C:\\Windows\\System32\\wintun.dll），需要 wintun.net 的 0.14+ amd64 版",
                String::from_utf8_lossy(&name[..name.len() - 1])
            )
        })
}

fn download_hint() -> &'static str {
    "程序自带 wintun 0.14.1，正常无需另装 dll；若 %LOCALAPPDATA%\\qp2p 不可写， \
     可把 wintun.net 的 0.14+ amd64 版 wintun.dll 放到 qp2p.exe 同目录"
}

/// 当前进程是否以管理员身份运行。
///
/// 用 `net session` 探测而不是查令牌：这个命令只有提升过的进程才能成功，
/// 而且不需要为 `GetTokenInformation` 再引入一堆 windows-sys 特性。
/// 只在创建网卡时调用一次，几十毫秒的代价可以接受。
fn is_elevated() -> bool {
    use std::process::{Command, Stdio};

    Command::new("net")
        .arg("session")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

pub struct WindowsTun {
    api: WintunApi,
    adapter: AdapterHandle,
    session: SessionHandle,
    wait_event: HANDLE,
    name: String,
}

// WinTun 的会话允许并发 Receive/Send，句柄本身只是指针：读线程与写线程共用它是安全的
unsafe impl Send for WindowsTun {}
unsafe impl Sync for WindowsTun {}

impl WindowsTun {
    pub fn open(config: &TunConfig) -> Result<Self> {
        // 先看权限：非管理员调用 WintunCreateAdapter 必然失败，而且在某些机器上
        // 驱动会直接把进程带崩（实测过 access violation）。与其崩掉，不如
        // 在碰 DLL 之前就把"要以管理员运行"说清楚。
        if !is_elevated() {
            bail!(
                "创建虚拟网卡需要管理员权限。请用「以管理员身份运行」打开终端，\
                 再执行同一条命令"
            );
        }

        tracing::debug!("[tun] 加载 WinTun");
        let api = WintunApi::load()?;

        let name = wide(&config.name);
        let tunnel_type = wide("qp2p");

        // SAFETY: 入参是合法的 NUL 结尾宽字符串，GUID 传 NULL 让驱动自己生成
        tracing::debug!("[tun] 创建适配器 {}", config.name);
        let adapter =
            unsafe { (api.create_adapter)(name.as_ptr(), tunnel_type.as_ptr(), std::ptr::null()) };
        if adapter == 0 {
            let err = std::io::Error::last_os_error();
            return Err(err).with_context(|| {
                format!("创建 WinTun 适配器 {} 失败（需要管理员权限）", config.name)
            });
        }

        // SAFETY: adapter 刚创建成功
        let session = unsafe { (api.start_session)(adapter, RING_CAPACITY) };
        if session == 0 {
            let err = std::io::Error::last_os_error();
            unsafe { (api.close_adapter)(adapter) };
            return Err(err).context("启动 WinTun 会话失败");
        }

        // SAFETY: session 有效
        let wait_event = unsafe { (api.read_wait_event)(session) };

        let tun = Self {
            api,
            adapter,
            session,
            wait_event,
            name: config.name.clone(),
        };
        tun.configure(config)?;
        Ok(tun)
    }

    fn configure(&self, config: &TunConfig) -> Result<()> {
        let mask = Ipv4Mask::of(config.prefix);
        run(
            "netsh",
            &[
                "interface",
                "ipv4",
                "set",
                "address",
                &format!("name={}", self.name),
                "static",
                &config.address.to_string(),
                &mask.0,
            ],
        )?;
        run(
            "netsh",
            &[
                "interface",
                "ipv4",
                "set",
                "subinterface",
                &format!("name={}", self.name),
                &format!("mtu={}", config.mtu),
                "store=persistent",
            ],
        )?;
        // 网段路由：有了它 10.x 的包才会进这块虚拟网卡
        let cidr = Cidr::new(config.address, config.prefix)?;
        let _ = run(
            "route",
            &[
                "add",
                &cidr.base.to_string(),
                "mask",
                &mask.0,
                "0.0.0.0",
                "if",
                &self.if_index().unwrap_or_default().to_string(),
            ],
        );

        tracing::info!(
            "[tun] {} 已就绪 addr={}/{} mtu={}",
            self.name,
            config.address,
            config.prefix,
            config.mtu
        );
        Ok(())
    }

    /// 找接口索引，找不到就交给系统挑。
    fn if_index(&self) -> Option<u32> {
        if_index_of(&self.name)
    }
}

struct Ipv4Mask(String);

impl Ipv4Mask {
    fn of(prefix: u8) -> Self {
        let bits = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix.min(32))
        };
        let o = bits.to_be_bytes();
        Self(format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3]))
    }
}

fn wide(text: &str) -> Vec<u16> {
    OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn run(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("执行 {program} 失败"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "{} {} 失败：{}{}",
            program,
            args.join(" "),
            stdout.trim(),
            stderr.trim()
        );
    }
    Ok(())
}

impl TunDevice for WindowsTun {
    fn read_packet(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let mut size: u32 = 0;
            // SAFETY: session 有效；返回的指针在下一次 Receive 或 Release 前有效
            let ptr = unsafe { (self.api.receive_packet)(self.session, &mut size) };
            if !ptr.is_null() {
                let len = (size as usize).min(buf.len());
                unsafe {
                    std::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), len);
                    (self.api.release_receive_packet)(self.session, ptr);
                }
                return Ok(len);
            }

            let code = unsafe { GetLastError() };
            if code != ERROR_NO_MORE_ITEMS {
                return Err(std::io::Error::from_raw_os_error(code as i32));
            }
            // 没包就等驱动给事件，避免空转
            let waited = unsafe { WaitForSingleObject(self.wait_event, 1_000) };
            if waited != WAIT_OBJECT_0 {
                return Ok(0); // 超时：交给上层继续循环
            }
        }
    }

    fn write_packet(&self, buf: &[u8]) -> std::io::Result<usize> {
        // SAFETY: session 有效；分配到的缓冲区大小足够
        let ptr = unsafe { (self.api.allocate_send_packet)(self.session, buf.len() as u32) };
        if ptr.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        unsafe {
            std::ptr::copy_nonoverlapping(buf.as_ptr(), ptr, buf.len());
            (self.api.send_packet)(self.session, ptr);
        }
        Ok(buf.len())
    }
}

impl Drop for WindowsTun {
    fn drop(&mut self) {
        // SAFETY: 句柄来自本结构，且只在这里关闭一次
        unsafe {
            (self.api.end_session)(self.session);
            (self.api.close_adapter)(self.adapter);
            if !self.wait_event.is_null() {
                CloseHandle(self.wait_event);
            }
        }
    }
}

/// 让某个网段走这条隧道。
///
/// `route add ... if` 要的是**接口索引**而不是名字，所以先把名字换成索引；
/// 换不到就让系统自己挑（不加 if 参数）。
pub fn route_to(device: &str, cidr: &Cidr) -> Result<()> {
    let mask = Ipv4Mask::of(cidr.prefix);
    let mut args = vec![
        "add".to_string(),
        cidr.base.to_string(),
        "mask".to_string(),
        mask.0.clone(),
        "0.0.0.0".to_string(),
    ];
    if let Some(index) = if_index_of(device) {
        args.push("if".to_string());
        args.push(index.to_string());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run("route", &refs).with_context(|| format!("添加路由 {cidr} 失败"))
}

fn if_index_of(name: &str) -> Option<u32> {
    let output = Command::new("netsh")
        .args(["interface", "ipv4", "show", "interfaces"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if line.contains(name) {
            return line.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

/// 出问题时给用户看的 dll 位置提示（当前实现优先用内嵌那份，这里只是兜底路径）。
#[allow(dead_code)]
pub fn expected_dll_path() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(PathBuf::from))
        .map(|d| d.join(WINTUN_DLL).display().to_string())
        .unwrap_or_else(|| WINTUN_DLL.to_string())
}
