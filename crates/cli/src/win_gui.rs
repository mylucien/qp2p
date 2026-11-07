//! Windows 原生窗口 + 系统托盘。
//!
//! 不引 GUI 框架，直接调 user32/gdi32：
//!
//! - 真正的 Win32 窗口（标题栏、最小化、最大化、关闭都在）；
//! - 关窗口 = 收进托盘，不退出；托盘左键单击/双击还原窗口；
//! - 托盘右键菜单：打开界面 / 连接 / 断开 / 退出；
//! - 图标用内嵌的 qp2p.ico（窗口、任务栏、托盘同一份）。
//!
//! 线程模型：窗口、控件、托盘全部在调用 `run` 的那个线程上，靠消息循环驱动；
//! 隧道子进程的日志由 `gui::spawn_reader` 的后台线程写进共享状态，界面用
//! 1 秒定时器拉取增量。

#![cfg(windows)]

use std::cell::RefCell;
use std::ffi::c_void;

use anyhow::Result;
use windows_sys::Win32::Foundation::{HANDLE, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    CreateFontIndirectW, GetStockObject, UpdateWindow, COLOR_BTNFACE, DEFAULT_GUI_FONT, HFONT,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::HiDpi::{
    GetDpiForSystem, SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
};
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY,
    NIM_SETVERSION, NIN_SELECT, NOTIFYICONDATAW, NOTIFYICON_VERSION_4,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AdjustWindowRect, AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu,
    DestroyWindow, DispatchMessageW, FindWindowW, GetCursorPos, GetMessageW, GetWindowTextW,
    LoadCursorW, LoadImageW, MessageBoxW, PostQuitMessage, RegisterClassW, RegisterWindowMessageW,
    SendMessageW, SetForegroundWindow, SetTimer, SetWindowTextW, ShowWindow, SystemParametersInfoW,
    TrackPopupMenu, TranslateMessage, BS_PUSHBUTTON, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT,
    ES_AUTOHSCROLL, ES_AUTOVSCROLL, ES_MULTILINE, ES_READONLY, ICON_BIG, ICON_SMALL, IDC_ARROW,
    IMAGE_ICON, LR_LOADFROMFILE, MB_ICONWARNING, MF_SEPARATOR, MF_STRING, MSG, NONCLIENTMETRICSW,
    SPI_GETNONCLIENTMETRICS, SW_HIDE, SW_SHOW, SW_SHOWNORMAL, TPM_BOTTOMALIGN, TPM_LEFTALIGN,
    TPM_RIGHTBUTTON, WM_APP, WM_CLOSE, WM_COMMAND, WM_CONTEXTMENU, WM_DESTROY, WM_GETTEXTLENGTH,
    WM_LBUTTONDBLCLK, WM_LBUTTONUP, WM_RBUTTONUP, WM_SETFONT, WM_SETICON, WM_TIMER, WNDCLASSW,
    WS_BORDER, WS_CHILD, WS_MAXIMIZEBOX, WS_OVERLAPPEDWINDOW, WS_TABSTOP, WS_THICKFRAME,
    WS_VISIBLE, WS_VSCROLL,
};

use crate::gui::{self, State};

const CLASS_NAME: &str = "qp2pMainWindow";
const WINDOW_TITLE: &str = "qp2p 配置";
const WM_TRAY: u32 = WM_APP + 1;
const TIMER_ID: usize = 1;

const ID_WORKER: i32 = 100;
const ID_TOKEN: i32 = 101;
const ID_NAME: i32 = 102;
const ID_IP: i32 = 103;
const ID_MTU: i32 = 104;
const ID_IDLE: i32 = 105;
const ID_CONNECT: i32 = 110;
const ID_SAVE: i32 = 111;
const ID_OPEN_DIR: i32 = 112;
const ID_HIDE: i32 = 113;
const ID_STATUS: i32 = 120;
const ID_LINKS: i32 = 130;
const ID_LOG: i32 = 131;

const CMD_OPEN: i32 = 1;
const CMD_CONNECT: i32 = 2;
const CMD_STOP: i32 = 3;
const CMD_QUIT: i32 = 4;

// listbox / edit 的消息码，windows-sys 没给这些宏
const LB_ADDSTRING: u32 = 0x0180;
const LB_RESETCONTENT: u32 = 0x0184;
const LBS_NOINTEGRALHEIGHT: u32 = 0x0100;
const EM_SETSEL: u32 = 0x00B1;
const EM_REPLACESEL: u32 = 0x00C2;
const NIIF_INFO: u32 = 0x0000_0001;

/// 内嵌的应用图标：窗口、任务栏、托盘共用。
const ICON_BYTES: &[u8] = include_bytes!("../../../assets/qp2p.ico");

struct Ui {
    state: State,
    icon: HANDLE,
    tray: NOTIFYICONDATAW,
    worker: HWND,
    token: HWND,
    name: HWND,
    ip: HWND,
    mtu: HWND,
    idle: HWND,
    connect: HWND,
    status: HWND,
    links: HWND,
    log: HWND,
    rendered_log: usize,
    rendered_links: String,
    /// 是否已经提示过"已收到托盘"
    hinted: bool,
}

thread_local! {
    static UI: RefCell<Option<Ui>> = const { RefCell::new(None) };
}

fn with_ui<R>(f: impl FnOnce(&Ui) -> R) -> Option<R> {
    UI.with(|cell| cell.borrow().as_ref().map(f))
}

fn with_ui_mut<R>(f: impl FnOnce(&mut Ui) -> R) -> Option<R> {
    UI.with(|cell| cell.borrow_mut().as_mut().map(f))
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn set_text(hwnd: HWND, text: &str) {
    let w = wide(text);
    unsafe {
        SetWindowTextW(hwnd, w.as_ptr());
    }
}

fn text_of(hwnd: HWND) -> String {
    let mut buf = vec![0u16; 4096];
    let n = unsafe { GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32) };
    if n <= 0 {
        return String::new();
    }
    String::from_utf16_lossy(&buf[..n as usize])
}

fn dialog_font() -> HFONT {
    unsafe {
        let mut ncm: NONCLIENTMETRICSW = std::mem::zeroed();
        ncm.cbSize = std::mem::size_of::<NONCLIENTMETRICSW>() as u32;
        let ok = SystemParametersInfoW(
            SPI_GETNONCLIENTMETRICS,
            ncm.cbSize,
            &mut ncm as *mut _ as *mut c_void,
            0,
        );
        if ok != 0 {
            let font = CreateFontIndirectW(&ncm.lfMessageFont);
            if !font.is_null() {
                return font;
            }
        }
        GetStockObject(DEFAULT_GUI_FONT)
    }
}

/// 把内嵌 ico 落到本地再加载：`LoadImageW` 只认文件或资源 ID，
/// 而单文件分发时没有 .rc 资源可用。
fn load_icon() -> HANDLE {
    let dir = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("qp2p");
    std::fs::create_dir_all(&dir).ok();
    let path = dir.join("qp2p.ico");
    let stale = std::fs::read(&path)
        .map(|existing| existing != ICON_BYTES)
        .unwrap_or(true);
    if stale {
        std::fs::write(&path, ICON_BYTES).ok();
    }
    let w = wide(&path.display().to_string());
    unsafe {
        LoadImageW(
            std::ptr::null_mut(),
            w.as_ptr(),
            IMAGE_ICON,
            0,
            0,
            LR_LOADFROMFILE,
        )
    }
}

pub fn run(state: State) -> Result<()> {
    unsafe {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }
    let scale = unsafe { GetDpiForSystem() } as f32 / 96.0;
    let icon = load_icon();

    unsafe {
        let instance = GetModuleHandleW(std::ptr::null());
        let class = wide(CLASS_NAME);

        // 已经开着就把它提到前台，别开第二个
        let existing = FindWindowW(class.as_ptr(), std::ptr::null());
        if !existing.is_null() {
            ShowWindow(existing, SW_SHOW);
            SetForegroundWindow(existing);
            return Ok(());
        }

        let wc = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wnd_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: instance,
            hIcon: icon,
            hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
            // COLOR_BTNFACE + 1：对话框灰，和原生控件一致
            hbrBackground: (COLOR_BTNFACE + 1) as usize as *mut c_void,
            lpszMenuName: std::ptr::null(),
            lpszClassName: class.as_ptr(),
        };
        if RegisterClassW(&wc) == 0 {
            return Err(anyhow::anyhow!("注册窗口类失败"));
        }

        // 先按 96dpi 算客户区，再按实际缩放补上边框
        let style = WS_OVERLAPPEDWINDOW & !(WS_THICKFRAME | WS_MAXIMIZEBOX);
        let mut rect = RECT {
            left: 0,
            top: 0,
            right: (620.0 * scale) as i32,
            bottom: (664.0 * scale) as i32,
        };
        AdjustWindowRect(&mut rect, style, 0);
        let (w, h) = (rect.right - rect.left, rect.bottom - rect.top);

        let hwnd = CreateWindowExW(
            0,
            class.as_ptr(),
            wide(WINDOW_TITLE).as_ptr(),
            style,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            w,
            h,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        );
        if hwnd.is_null() {
            return Err(anyhow::anyhow!("创建窗口失败"));
        }
        SendMessageW(hwnd, WM_SETICON, ICON_BIG as usize, icon as isize);
        SendMessageW(hwnd, WM_SETICON, ICON_SMALL as usize, icon as isize);

        let ui = build_ui(state, hwnd, icon, scale);
        UI.with(|cell| cell.borrow_mut().replace(ui));

        // 托盘
        let nid = tray_icon(hwnd, icon, "qp2p · 未连接");
        if Shell_NotifyIconW(NIM_ADD, &nid) == 0 {
            return Err(anyhow::anyhow!("放置托盘图标失败（资源管理器没起来？）"));
        }
        let mut version = nid;
        version.Anonymous.uVersion = NOTIFYICON_VERSION_4;
        Shell_NotifyIconW(NIM_SETVERSION, &version);
        let _ = with_ui_mut(|ui| ui.tray = nid);

        SetTimer(hwnd, TIMER_ID, 1_000, None);
        ShowWindow(hwnd, SW_SHOWNORMAL);
        UpdateWindow(hwnd);

        // 先把配置文件里的值灌进输入框
        load_config_into_ui();
        refresh();

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    Ok(())
}

/// 建一个子控件，坐标按 96dpi 给，自动乘缩放。
#[allow(clippy::too_many_arguments)]
fn child(
    parent: HWND,
    class: &str,
    text: &str,
    style: u32,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: i32,
    scale: f32,
) -> HWND {
    let d = |v: i32| (v as f32 * scale).round() as i32;
    unsafe {
        CreateWindowExW(
            0,
            wide(class).as_ptr(),
            wide(text).as_ptr(),
            WS_CHILD | WS_VISIBLE | style,
            d(x),
            d(y),
            d(w),
            d(h),
            parent,
            id as usize as *mut c_void,
            GetModuleHandleW(std::ptr::null()),
            std::ptr::null(),
        )
    }
}

/// 控件布局：所有尺寸按 96dpi 描述，`child` 里再乘缩放系数。
fn build_ui(state: State, main: HWND, icon: HANDLE, scale: f32) -> Ui {
    let f = dialog_font();
    let mut ids: Vec<HWND> = Vec::new();

    // 用宏而不是闭包：闭包要 `mut` 才能推 push，而且 8 个参数会触发 clippy
    macro_rules! mk {
        ($class:expr, $text:expr, $style:expr, $x:expr, $y:expr, $w:expr, $hh:expr, $id:expr $(,)?) => {{
            let handle = child(main, $class, $text, $style, $x, $y, $w, $hh, $id, scale);
            ids.push(handle);
            handle
        }};
    }

    const M: i32 = 16;
    const LW: i32 = 78;
    const EX: i32 = 102;
    const EW: i32 = 502;
    const RH: i32 = 24;

    mk!("STATIC", "信令地址", 0, M, 18, LW, RH, 0);
    let worker = mk!(
        "EDIT",
        "",
        WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL as u32,
        EX,
        16,
        EW,
        RH,
        ID_WORKER,
    );

    mk!("STATIC", "加入令牌", 0, M, 50, LW, RH, 0);
    let token = mk!(
        "EDIT",
        "",
        WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL as u32,
        EX,
        48,
        EW,
        RH,
        ID_TOKEN,
    );

    mk!("STATIC", "本机名称", 0, M, 82, LW, RH, 0);
    let name = mk!(
        "EDIT",
        "",
        WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL as u32,
        EX,
        80,
        EW,
        RH,
        ID_NAME,
    );

    mk!("STATIC", "虚拟 IP", 0, M, 114, LW, RH, 0);
    let ip = mk!(
        "EDIT",
        "",
        WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL as u32,
        EX,
        112,
        160,
        RH,
        ID_IP,
    );
    mk!(
        "STATIC",
        "留空 = 服务端自动分配",
        0,
        EX + 168,
        118,
        320,
        20,
        0,
    );

    mk!("STATIC", "MTU", 0, M, 152, 40, RH, 0);
    let mtu = mk!(
        "EDIT",
        "1400",
        WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL as u32,
        M + 40,
        150,
        70,
        RH,
        ID_MTU,
    );
    mk!("STATIC", "空闲断开（秒）", 0, M + 138, 152, 92, RH, 0);
    let idle = mk!(
        "EDIT",
        "0",
        WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL as u32,
        M + 232,
        150,
        70,
        RH,
        ID_IDLE,
    );
    mk!(
        "STATIC",
        "0 = 从不断开（桌面建议 0，手机场景可填 600）",
        0,
        M + 312,
        154,
        280,
        20,
        0,
    );

    let bw = 110;
    let connect = mk!(
        "BUTTON",
        "连接",
        WS_TABSTOP | BS_PUSHBUTTON as u32,
        M,
        188,
        bw,
        30,
        ID_CONNECT,
    );
    mk!(
        "BUTTON",
        "仅保存",
        WS_TABSTOP | BS_PUSHBUTTON as u32,
        M + 118,
        188,
        bw,
        30,
        ID_SAVE,
    );
    mk!(
        "BUTTON",
        "打开数据目录",
        WS_TABSTOP | BS_PUSHBUTTON as u32,
        M + 236,
        188,
        bw + 20,
        30,
        ID_OPEN_DIR,
    );
    mk!(
        "BUTTON",
        "收进托盘",
        WS_TABSTOP | BS_PUSHBUTTON as u32,
        M + 374,
        188,
        bw,
        30,
        ID_HIDE,
    );

    let status = mk!("STATIC", "未连接", 0, M, 232, 588, 24, ID_STATUS);
    mk!("STATIC", "直连", 0, M, 264, 60, 18, 0);
    let links = mk!(
        "LISTBOX",
        "",
        WS_BORDER | WS_VSCROLL | LBS_NOINTEGRALHEIGHT,
        M,
        284,
        588,
        96,
        ID_LINKS,
    );
    mk!("STATIC", "日志", 0, M, 390, 60, 18, 0);
    let log = mk!(
        "EDIT",
        "",
        WS_BORDER | WS_VSCROLL | ES_MULTILINE as u32 | ES_AUTOVSCROLL as u32 | ES_READONLY as u32,
        M,
        410,
        588,
        220,
        ID_LOG,
    );

    for handle in &ids {
        unsafe {
            SendMessageW(*handle, WM_SETFONT, f as usize, 1);
        }
    }

    Ui {
        state,
        icon,
        tray: unsafe { std::mem::zeroed() },
        worker,
        token,
        name,
        ip,
        mtu,
        idle,
        connect,
        status,
        links,
        log,
        rendered_log: 0,
        rendered_links: String::new(),
        hinted: false,
    }
}

fn tray_icon(hwnd: HWND, icon: HANDLE, tip: &str) -> NOTIFYICONDATAW {
    let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = 1;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = WM_TRAY;
    nid.hIcon = icon;
    let units: Vec<u16> = tip.encode_utf16().take(127).collect();
    let len = units.len();
    for (slot, unit) in nid.szTip.iter_mut().zip(units) {
        *slot = unit;
    }
    if let Some(last) = nid.szTip.get_mut(len) {
        *last = 0;
    }
    nid
}

fn load_config_into_ui() {
    let Some(values) = with_ui(|ui| gui::form_values(&ui.state)) else {
        return;
    };
    let _ = with_ui(|ui| {
        set_text(ui.worker, &values.worker);
        set_text(ui.token, &values.token);
        set_text(ui.name, &values.name);
        set_text(ui.ip, &values.ip);
        set_text(ui.mtu, &values.mtu.to_string());
        set_text(ui.idle, &values.idle.to_string());
    });
}

/// 把输入框内容落到配置里；返回错误给调用方弹框。
fn apply_form(ui: &Ui) -> Result<String> {
    let worker = text_of(ui.worker);
    let token = text_of(ui.token);
    let name = text_of(ui.name);
    let ip = text_of(ui.ip);
    let mtu = text_of(ui.mtu).parse::<u64>().unwrap_or(1400);
    let idle = text_of(ui.idle).parse::<u64>().unwrap_or(0);
    gui::apply_form(&ui.state, &worker, &token, &name, &ip, mtu, idle)
}

fn refresh() {
    let Some(tick) = with_ui(|ui| gui::tick(&ui.state)) else {
        return;
    };

    let _ = with_ui_mut(|ui| {
        let status = match &tick.warn {
            Some(warn) => format!("{} · {}", tick.status, warn.lines().next().unwrap_or("")),
            None => tick.status.clone(),
        };
        set_text(ui.status, &status);
        set_text(ui.connect, if tick.running { "断开" } else { "连接" });

        let joined = tick
            .links
            .iter()
            .map(|(name, ip, rtt)| format!("{name}  {ip}  {rtt}"))
            .collect::<Vec<_>>()
            .join("\n");
        if joined != ui.rendered_links {
            unsafe {
                SendMessageW(ui.links, LB_RESETCONTENT, 0, 0);
                for (name, ip, rtt) in &tick.links {
                    let line = wide(&format!("{name}   {ip}   {rtt}"));
                    SendMessageW(ui.links, LB_ADDSTRING, 0, line.as_ptr() as isize);
                }
            }
            ui.rendered_links = joined;
        }

        // 只追加新行：log 是环形缓冲，靠单调计数算差值才不会漏
        let fresh = tick.log_total.saturating_sub(ui.rendered_log as u64) as usize;
        let fresh = fresh.min(tick.log.len());
        for line in &tick.log[tick.log.len() - fresh..] {
            unsafe {
                let len = SendMessageW(ui.log, WM_GETTEXTLENGTH, 0, 0) as usize;
                SendMessageW(ui.log, EM_SETSEL, len, len as isize);
                let text = wide(&format!("{line}\r\n"));
                SendMessageW(ui.log, EM_REPLACESEL, 0, text.as_ptr() as isize);
            }
        }
        ui.rendered_log = tick.log_total as usize;

        // 托盘悬停提示跟着状态走
        let tip = format!("qp2p · {}", status);
        let mut nid = ui.tray;
        let units: Vec<u16> = tip.encode_utf16().take(127).collect();
        let len = units.len();
        for (slot, unit) in nid.szTip.iter_mut().zip(units) {
            *slot = unit;
        }
        if let Some(last) = nid.szTip.get_mut(len) {
            *last = 0;
        }
        nid.uFlags = NIF_TIP;
        unsafe {
            Shell_NotifyIconW(NIM_MODIFY, &nid);
        }
    });
}

fn show_window(hwnd: HWND) {
    unsafe {
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
    }
}

fn hide_to_tray(hwnd: HWND) {
    unsafe {
        ShowWindow(hwnd, SW_HIDE);
    }
    let first = with_ui_mut(|ui| {
        let first = !ui.hinted;
        ui.hinted = true;
        first
    })
    .unwrap_or(false);
    if first {
        let _ = with_ui(|ui| {
            let mut nid = ui.tray;
            nid.uFlags = NIF_INFO;
            nid.dwInfoFlags = NIIF_INFO;
            nid.szInfoTitle = [0; 64];
            let title = wide("qp2p 还在运行");
            for (slot, unit) in nid.szInfoTitle.iter_mut().zip(title) {
                *slot = unit;
            }
            let body = wide("已收进托盘，双击图标可重新打开；右键可断开或退出。");
            for (slot, unit) in nid.szInfo.iter_mut().zip(body) {
                *slot = unit;
            }
            unsafe {
                Shell_NotifyIconW(NIM_MODIFY, &nid);
            }
        });
    }
}

fn show_menu(hwnd: HWND) {
    unsafe {
        let menu = CreatePopupMenu();
        if menu.is_null() {
            return;
        }
        let running = with_ui(|ui| gui::is_running(&ui.state)).unwrap_or(false);
        AppendMenuW(
            menu,
            MF_STRING,
            CMD_OPEN as usize,
            wide("打开界面").as_ptr(),
        );
        AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
        if running {
            AppendMenuW(menu, MF_STRING, CMD_STOP as usize, wide("断开").as_ptr());
        } else {
            AppendMenuW(menu, MF_STRING, CMD_CONNECT as usize, wide("连接").as_ptr());
        }
        AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
        AppendMenuW(menu, MF_STRING, CMD_QUIT as usize, wide("退出").as_ptr());

        let mut pt = POINT { x: 0, y: 0 };
        GetCursorPos(&mut pt);
        // 菜单要能"点外面就消失"，必须先把自己提到前台
        SetForegroundWindow(hwnd);
        TrackPopupMenu(
            menu,
            TPM_RIGHTBUTTON | TPM_LEFTALIGN | TPM_BOTTOMALIGN,
            pt.x,
            pt.y,
            0,
            hwnd,
            std::ptr::null(),
        );
        DestroyMenu(menu);
    }
}

/// 控制台被藏起来时用它报错：否则错误只打在看不见的 stderr 里。
pub(crate) fn alert(text: &str) {
    message_box(std::ptr::null_mut(), text);
}

fn message_box(hwnd: HWND, text: &str) {
    unsafe {
        MessageBoxW(
            hwnd,
            wide(text).as_ptr(),
            wide("qp2p").as_ptr(),
            MB_ICONWARNING,
        );
    }
}

fn do_connect(hwnd: HWND) {
    let result = with_ui(|ui| apply_form(ui).and_then(|_| gui::spawn_up(&ui.state)))
        .unwrap_or_else(|| Err(anyhow::anyhow!("界面还没准备好")));
    if let Err(e) = result {
        message_box(hwnd, &format!("{e:#}"));
    }
    refresh();
}

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // Explorer 重启后托盘图标会消失，靠这条广播重新加上
    static TASKBAR_CREATED: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    let created = *TASKBAR_CREATED
        .get_or_init(|| unsafe { RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()) });
    if message == created && created != 0 {
        let _ = with_ui(|ui| {
            let mut nid = ui.tray;
            nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
            nid.hIcon = ui.icon;
            unsafe {
                Shell_NotifyIconW(NIM_ADD, &nid);
            }
        });
        return 0;
    }

    match message {
        WM_TRAY => {
            // NOTIFYICON_VERSION_4：低 16 位是事件
            let event = (lparam as u32) & 0xffff;
            match event {
                WM_CONTEXTMENU | WM_RBUTTONUP => show_menu(hwnd),
                NIN_SELECT | WM_LBUTTONUP | WM_LBUTTONDBLCLK => show_window(hwnd),
                _ => {}
            }
            0
        }
        WM_COMMAND => {
            let id = (wparam & 0xffff) as i32;
            match id {
                ID_CONNECT => {
                    let running = with_ui(|ui| gui::is_running(&ui.state)).unwrap_or(false);
                    if running {
                        let _ = with_ui(|ui| {
                            let _ = gui::stop_child(&ui.state);
                        });
                        refresh();
                    } else {
                        do_connect(hwnd);
                    }
                }
                ID_SAVE => {
                    let result = with_ui(apply_form)
                        .unwrap_or_else(|| Err(anyhow::anyhow!("界面还没准备好")));
                    match result {
                        Ok(msg) => {
                            let _ = with_ui(|ui| set_text(ui.status, &msg));
                        }
                        Err(e) => message_box(hwnd, &format!("{e:#}")),
                    }
                }
                ID_OPEN_DIR => {
                    let result = with_ui(|ui| gui::open_dir(&ui.state))
                        .unwrap_or_else(|| Err(anyhow::anyhow!("界面还没准备好")));
                    if let Err(e) = result {
                        message_box(hwnd, &format!("{e:#}"));
                    }
                }
                ID_HIDE => hide_to_tray(hwnd),
                CMD_OPEN => {
                    show_window(hwnd);
                    load_config_into_ui();
                }
                CMD_CONNECT => do_connect(hwnd),
                CMD_STOP => {
                    let _ = with_ui(|ui| {
                        let _ = gui::stop_child(&ui.state);
                    });
                    refresh();
                }
                CMD_QUIT => {
                    let _ = with_ui(|ui| {
                        let _ = gui::stop_child(&ui.state);
                        unsafe {
                            Shell_NotifyIconW(NIM_DELETE, &ui.tray);
                        }
                    });
                    DestroyWindow(hwnd);
                }
                _ => {}
            }
            0
        }
        WM_TIMER => {
            refresh();
            0
        }
        WM_CLOSE => {
            hide_to_tray(hwnd);
            0
        }
        WM_DESTROY => {
            let _ = with_ui(|ui| unsafe {
                Shell_NotifyIconW(NIM_DELETE, &ui.tray);
            });
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, message, wparam, lparam),
    }
}
