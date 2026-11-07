//! 托盘图标 + 右键菜单（Windows）。
//!
//! 只依赖 windows-sys，不引入 GUI 框架：一个隐藏窗口 + `Shell_NotifyIconW`，
//! 右键菜单里放「打开配置界面 / 连接 / 断开 / 退出」。配置界面本身还是浏览器页面，
//! 所以"最小化到右下角"表现为：关掉网页不会退出，程序常驻托盘。

#![cfg(windows)]

use std::sync::OnceLock;

use anyhow::Result;
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY,
    NOTIFYICONDATAW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DispatchMessageW,
    GetCursorPos, GetMessageW, LoadIconW, PostQuitMessage, RegisterClassW, SetForegroundWindow,
    SetTimer, TrackPopupMenu, TranslateMessage, IDI_APPLICATION, MF_SEPARATOR, MF_STRING, MSG,
    TPM_LEFTALIGN, TPM_RIGHTBUTTON, WM_APP, WM_COMMAND, WM_DESTROY, WM_LBUTTONDBLCLK, WM_RBUTTONUP,
    WM_TIMER, WNDCLASSW,
};

use crate::gui::{self, State};

const WM_TRAY: u32 = WM_APP + 1;
const TIMER_ID: usize = 1;
const CMD_OPEN: usize = 1;
const CMD_CONNECT: usize = 2;
const CMD_STOP: usize = 3;
const CMD_QUIT: usize = 4;

static CONTEXT: OnceLock<(State, u16)> = OnceLock::new();

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 在主线程跑消息循环；HTTP 服务在另一个线程里。
pub fn run(state: State, port: u16) -> Result<()> {
    CONTEXT.set((state, port)).ok();
    unsafe {
        let instance = GetModuleHandleW(std::ptr::null());
        let class_name = wide("qp2pTrayWindow");
        let wc = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(wnd_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: instance,
            hIcon: LoadIconW(std::ptr::null_mut(), IDI_APPLICATION),
            hCursor: std::ptr::null_mut(),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: class_name.as_ptr(),
        };
        if RegisterClassW(&wc) == 0 {
            return Err(anyhow::anyhow!("注册托盘窗口类失败"));
        }

        // 隐藏的普通窗口：tray 回调需要它，但它从不显示
        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            wide("qp2p").as_ptr(),
            0,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        );
        if hwnd.is_null() {
            return Err(anyhow::anyhow!("创建托盘窗口失败"));
        }

        let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = 1;
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        nid.uCallbackMessage = WM_TRAY;
        nid.hIcon = LoadIconW(std::ptr::null_mut(), IDI_APPLICATION);
        write_tip(&mut nid, "qp2p · 未连接");

        if Shell_NotifyIconW(NIM_ADD, &nid) == 0 {
            return Err(anyhow::anyhow!("放置托盘图标失败（资源管理器没起来？）"));
        }
        // 每 3 秒刷新一次悬停提示：状态、已连对端数
        SetTimer(hwnd, TIMER_ID, 3_000, None);
        TRAY.with(|t| t.borrow_mut().replace(nid));

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Ok(())
    }
}

thread_local! {
    static TRAY: std::cell::RefCell<Option<NOTIFYICONDATAW>> = const { std::cell::RefCell::new(None) };
}

fn write_tip(nid: &mut NOTIFYICONDATAW, text: &str) {
    let units: Vec<u16> = text.encode_utf16().take(127).collect();
    let len = units.len();
    for (slot, unit) in nid.szTip.iter_mut().zip(units.into_iter()) {
        *slot = unit;
    }
    if let Some(last) = nid.szTip.get_mut(len) {
        *last = 0;
    }
}

fn refresh_tip(_hwnd: HWND) {
    let Some((state, _)) = CONTEXT.get() else {
        return;
    };
    let text = gui::status_text(state);
    TRAY.with(|t| {
        if let Some(mut nid) = t.borrow_mut().clone() {
            write_tip(&mut nid, &text);
            nid.uFlags = NIF_TIP;
            unsafe {
                Shell_NotifyIconW(NIM_MODIFY, &nid);
            }
        }
    });
}

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        WM_TRAY => {
            let event = (lparam as u32) & 0xffff;
            if event == WM_RBUTTONUP {
                show_menu(hwnd);
            } else if event == WM_LBUTTONDBLCLK {
                open_ui();
            }
            0
        }
        WM_COMMAND => {
            match wparam & 0xffff {
                CMD_OPEN => open_ui(),
                CMD_CONNECT => {
                    if let Some((state, _)) = CONTEXT.get() {
                        if let Err(e) = gui::spawn_up(state) {
                            message_box(hwnd, &format!("{e:#}"));
                        }
                    }
                }
                CMD_STOP => {
                    if let Some((state, _)) = CONTEXT.get() {
                        let _ = gui::stop_child(state);
                    }
                }
                CMD_QUIT => {
                    if let Some((state, _)) = CONTEXT.get() {
                        let _ = gui::stop_child(state);
                    }
                    TRAY.with(|t| {
                        if let Some(nid) = t.borrow().as_ref() {
                            Shell_NotifyIconW(NIM_DELETE, nid);
                        }
                    });
                    PostQuitMessage(0);
                }
                _ => {}
            }
            0
        }
        WM_TIMER => {
            refresh_tip(hwnd);
            0
        }
        WM_DESTROY => {
            TRAY.with(|t| {
                if let Some(nid) = t.borrow().as_ref() {
                    Shell_NotifyIconW(NIM_DELETE, nid);
                }
            });
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, message, wparam, lparam),
    }
}

fn show_menu(hwnd: HWND) {
    unsafe {
        let menu = CreatePopupMenu();
        if menu.is_null() {
            return;
        }
        let open = wide("打开配置界面");
        let connect = wide("连接");
        let stop = wide("断开");
        let quit = wide("退出");
        AppendMenuW(menu, MF_STRING, CMD_OPEN, open.as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
        AppendMenuW(menu, MF_STRING, CMD_CONNECT, connect.as_ptr());
        AppendMenuW(menu, MF_STRING, CMD_STOP, stop.as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
        AppendMenuW(menu, MF_STRING, CMD_QUIT, quit.as_ptr());

        let mut pt: POINT = std::mem::zeroed();
        GetCursorPos(&mut pt);
        // 菜单点外面就消失，需要先把窗口提到前台
        SetForegroundWindow(hwnd);
        TrackPopupMenu(
            menu,
            TPM_RIGHTBUTTON | TPM_LEFTALIGN,
            pt.x,
            pt.y,
            0,
            hwnd,
            std::ptr::null(),
        );
        DestroyMenu(menu);
    }
}

fn open_ui() {
    if let Some((_, port)) = CONTEXT.get() {
        let url = format!("http://127.0.0.1:{}/", port);
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", &url])
            .spawn();
    }
}

fn message_box(hwnd: HWND, text: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONWARNING};
    let body = wide(text);
    let title = wide("qp2p");
    unsafe {
        MessageBoxW(hwnd, body.as_ptr(), title.as_ptr(), MB_ICONWARNING);
    }
}
