//! # tunnel.rs — cloudflared 子进程管理
//!
//! 职责：
//! - 平台差异化查找 cloudflared 二进制路径
//! - 启动子进程：`cloudflared tunnel run --token <token>`
//! - 轮询 `http://localhost:2000/ready` 检测 Tunnel 就绪状态
//! - 子进程退出时指数退避重启（最大 3 次，间隔 5/10/20s）
//! - 3 次重启均失败后返回 Err，JoinHandle 完成让 tokio::select! 捕获
//! - 收到 cancel 信号时由子进程管理任务统一处理关闭

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::config::Config;

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

/// 最大重启次数
const MAX_RESTARTS: u32 = 3;

/// 计算第 n 次重启的等待秒数（n 从 1 开始）：5s, 10s, 20s...
fn restart_delay(attempt: u32) -> u64 {
    5u64 * 2u64.pow(attempt.saturating_sub(1))
}

/// cloudflared 的 metrics/health 端口（从启动日志 "Starting metrics server on" 获取）
const METRICS_PORT: u16 = 20241;

/// 等待 Tunnel 就绪的超时时间（秒）
const READY_TIMEOUT_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// TunnelHandle
// ---------------------------------------------------------------------------

/// cloudflared 子进程句柄。
///
/// 由 `spawn_tunnel()` 创建，可通过 `is_ready()` 和 `tunnel_url()` 查询状态，
/// `shutdown()` 触发 `cancel.cancel()` 统一由子进程管理任务处理关闭。
#[derive(Debug)]
pub struct TunnelHandle {
    /// Tunnel 是否已就绪
    ready: Arc<AtomicBool>,
    /// Tunnel 入站 URL（如 `https://xxx.cfargotunnel.com`）
    tunnel_url: Arc<RwLock<String>>,
    /// 取消信号（关联的主 cancel token）
    cancel: CancellationToken,
}

impl TunnelHandle {
    /// Tunnel 是否已就绪（cloudflared 成功建立出站连接，/ready 返回 200）
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// 获取 Tunnel 入站 URL。
    ///
    /// 返回空字符串表示尚未就绪或 URL 未知。
    /// URL 在 cloudflared 启动后由 `determine_tunnel_url()` 探测。
    pub async fn tunnel_url(&self) -> String {
        self.tunnel_url.read().await.clone()
    }

    /// 触发优雅关闭，由子进程管理任务统一处理子进程停止。
    pub async fn shutdown(&self) {
        info!("[tunnel] 触发 cloudflared shutdown");
        self.cancel.cancel();
    }

    /// 创建一个占位句柄（用于测试或尚未启动 tunnel 的场景）。
    /// 不会与实际子进程关联，`is_ready()` 始终返回 false。
    pub fn new_placeholder() -> Self {
        Self {
            ready: Arc::new(AtomicBool::new(false)),
            tunnel_url: Arc::new(RwLock::new(String::new())),
            cancel: CancellationToken::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// spawn_tunnel — 启动 cloudflared 子进程任务
// ---------------------------------------------------------------------------

/// 启动 cloudflared 子进程并返回句柄 + 后台任务 JoinHandle。
///
/// # 参数
/// * `config` — 引用配置（需在启动前转为 Arc）
/// * `cancel` — 主 CancellationToken，收到信号时停止子进程并退出
///
/// # 返回
/// * `TunnelHandle` — 查询子进程状态的控制句柄
/// * `JoinHandle<Result<()>>` — 后台任务句柄，由 main.rs 的 select! 管理。
///   退出意味着子进程重启耗尽或收到 cancel 信号。
pub fn spawn_tunnel(
    config: Arc<Config>,
    cancel: CancellationToken,
) -> (TunnelHandle, tokio::task::JoinHandle<Result<()>>) {
    let ready = Arc::new(AtomicBool::new(false));
    let tunnel_url: Arc<RwLock<String>> = Arc::default();
    let ready_clone = ready.clone();
    let tunnel_url_clone = tunnel_url.clone();
    let cancel_clone = cancel.clone();

    let handle = TunnelHandle {
        ready,
        tunnel_url,
        cancel,
    };

    let task = tokio::spawn(async move {
        let cloudflared_path = resolve_cloudflared_path(&config)
            .await
            .context("cloudflared 二进制未找到")?;

        info!(
            "[tunnel] cloudflared 路径: {}",
            cloudflared_path.display()
        );

        for attempt in 1..=MAX_RESTARTS {
            // 启动前检查 cancel 信号
            if cancel_clone.is_cancelled() {
                info!("[tunnel] 收到取消信号，停止启动 cloudflared");
                return Ok(());
            }

            info!(
                "[tunnel] 启动 cloudflared (第 {attempt}/{MAX_RESTARTS} 次)..."
            );

            match run_cloudflared(
                &cloudflared_path,
                &config,
                &ready_clone,
                &tunnel_url_clone,
                &cancel_clone,
            )
            .await
            {
                Ok(()) => {
                    // run_cloudflared 正常退出（收到 cancel）
                    return Ok(());
                }
                Err(e) => {
                    // 标记为未就绪
                    ready_clone.store(false, Ordering::Release);

                    if cancel_clone.is_cancelled() {
                        info!("[tunnel] 收到取消信号，停止重试");
                        return Ok(());
                    }

                    if attempt < MAX_RESTARTS {
                        let delay = restart_delay(attempt);
                        warn!(
                            "[tunnel] cloudflared 退出 ({attempt}/{MAX_RESTARTS}), {delay}s 后重启: {e}"
                        );

                        // 重启前等待，同时响应 cancel
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_secs(delay)) => {}
                            _ = cancel_clone.cancelled() => {
                                info!("[tunnel] 收到取消信号，停止重试");
                                return Ok(());
                            }
                        }
                    } else {
                        error!("[tunnel] cloudflared 已退出 {MAX_RESTARTS} 次，不再重启");
                        return Err(e).context(format!(
                            "cloudflared 连续退出 {MAX_RESTARTS} 次，触发 shutdown"
                        ));
                    }
                }
            }
        }

        Ok(())
    });

    (handle, task)
}

// ---------------------------------------------------------------------------
// 内部函数
// ---------------------------------------------------------------------------

/// 启动 cloudflared 子进程，等待就绪，监控退出。
///
/// 返回时确保子进程已停止。
async fn run_cloudflared(
    bin_path: &Path,
    config: &Config,
    ready: &Arc<AtomicBool>,
    tunnel_url: &Arc<RwLock<String>>,
    cancel: &CancellationToken,
) -> Result<()> {
    let mut child = spawn_child(bin_path, config)?;

    info!("[tunnel] cloudflared 已启动 (pid={})", child.id().unwrap_or(0));

    // 读取 stderr 提取 Tunnel URL（cloudflared 的 Tunnel URL 输出在 stderr 上）
    let stderr = child.stderr.take().unwrap();
    let url_writer = tunnel_url.clone();
    let cancel_clone = cancel.clone();
    let stderr_task = tokio::spawn(async move {
        let reader = BufReader::new(stderr);
        let mut lines = reader.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            // 尝试提取 Tunnel URL
            if let Some(url) = extract_tunnel_url_from_line(&line) {
                *url_writer.write().await = url;
            }
            // debug 模式下输出 stderr
            if cfg!(debug_assertions) {
                eprintln!("{line}");
            }
            if cancel_clone.is_cancelled() {
                break;
            }
        }
    });

    // 等待就绪
    match wait_for_ready(cancel).await {
        Ok(()) => {
            ready.store(true, Ordering::Release);
            info!("[tunnel] Tunnel 就绪");
        }
        Err(e) => {
            if cancel.is_cancelled() {
                info!("[tunnel] 取消等待 cloudflared 就绪");
                stderr_task.abort();
                return Ok(());
            }
            let _ = child.kill().await;
            stderr_task.abort();
            return Err(e);
        }
    }

    // 等待子进程退出或被 cancel
    let exit_status = tokio::select! {
        status = child.wait() => status?,
        _ = cancel.cancelled() => {
            info!("[tunnel] 收到取消信号，停止 cloudflared");
            send_shutdown(&mut child).await;
            stderr_task.abort();
            return Ok(());
        }
    };

    info!("[tunnel] cloudflared 进程退出: {exit_status}");
    stderr_task.abort();

    let should_continue = {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            exit_status.success() || exit_status.signal() == Some(15)
        }
        #[cfg(not(unix))]
        {
            exit_status.success()
        }
    };

    if should_continue {
        Ok(())
    } else {
        bail!("cloudflared 异常退出: {exit_status}")
    }
}

/// 从 cloudflared 的 stderr 行中提取 Tunnel URL。
fn extract_tunnel_url_from_line(line: &str) -> Option<String> {
    // 格式 1 — Quick Tunnel: "Your quick Tunnel has been created! Visit it at https://xxxx.cfargotunnel.com"
    if line.contains("Visit it at https://") || line.contains("Your quick Tunnel has been created") {
        if let Some(start) = line.find("https://") {
            let rest = &line[start..];
            if let Some(end) = rest.find(|c: char| c.is_whitespace() || c == ',' || c == '}') {
                return Some(rest[..end].to_string());
            }
            return Some(rest.to_string());
        }
    }

    // 格式 2 — Named Tunnel: "Starting tunnel tunnelID=2c0fb371-..."
    // 构造 https://<tunnel-id>.cfargotunnel.com
    if let Some(prefix_pos) = line.find("tunnelID=") {
        let id = &line[prefix_pos + 9..];
        // 取 UUID 部分（到空白或行尾）
        let id_trimmed = if let Some(end) = id.find(|c: char| c.is_whitespace()) {
            &id[..end]
        } else {
            id
        };
        if id_trimmed.len() == 36 && id_trimmed.chars().filter(|&c| c == '-').count() == 4 {
            return Some(format!("https://{id_trimmed}.cfargotunnel.com"));
        }
    }

    None
}

/// 执行 cloudflared 子进程。
///
/// stdout 完全丢弃（仅用于 HTTP 健康检测，无关键信息）。
/// stderr 用 pipe 捕获，用于提取 Tunnel URL；同时转发到日志。
fn spawn_child(bin_path: &Path, config: &Config) -> Result<Child> {
    let mut cmd = Command::new(bin_path);
    cmd.args(["tunnel", "run"])
        .env("TUNNEL_TOKEN", &config.tunnel_token)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped()) // pipe 捕获，提取 Tunnel URL
        .kill_on_drop(true);

    let child = cmd
        .spawn()
        .with_context(|| format!("启动 cloudflared 失败: {}", bin_path.display()))?;

    Ok(child)
}

/// 轮询 cloudflared /ready 端点，最多等 READY_TIMEOUT_SECS 秒。
///
/// 轮询 cloudflared 健康端点，最多等 READY_TIMEOUT_SECS 秒。
///
/// 依次尝试 /health 和 /ready（cloudflared 版本不同端点名有别）。
async fn wait_for_ready(
    cancel: &CancellationToken,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .context("构建 reqwest Client 失败")?;

    let endpoints = [
        format!("http://127.0.0.1:{METRICS_PORT}/health"),
        format!("http://127.0.0.1:{METRICS_PORT}/ready"),
        format!("http://127.0.0.1:{METRICS_PORT}/metrics"),
    ];

    let poll_fn = async {
        loop {
            for url in &endpoints {
                let resp = tokio::select! {
                    _ = cancel.cancelled() => bail!("收到取消信号"),
                    r = client.get(url).send() => r,
                };
                if let Ok(r) = resp {
                    if r.status().is_success() {
                        return Ok(());
                    }
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                _ = cancel.cancelled() => bail!("收到取消信号"),
            }
        }
    };

    tokio::time::timeout(
        Duration::from_secs(READY_TIMEOUT_SECS),
        poll_fn,
    )
    .await
    .context(format!("等待 cloudflared 就绪超时 (>{READY_TIMEOUT_SECS}s)"))?
}

/// 向子进程发送停止信号。
async fn send_shutdown(child: &mut Child) {
    #[cfg(unix)]
    {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;
        if let Some(id) = child.id() {
            let _ = kill(Pid::from_raw(id as i32), Signal::SIGTERM);
        }
        // 给 5s 优雅退出时间
        tokio::select! {
            _ = child.wait() => {}
            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                let _ = child.kill().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        // Windows：先温和 taskkill，5s 后再 /F 确保退出
        if let Some(id) = child.id() {
            let _ = Command::new("taskkill")
                .args(["/PID", &id.to_string()])
                .output()
                .await;
        }
        tokio::select! {
            _ = child.wait() => {}
            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                if let Some(id) = child.id() {
                    let _ = Command::new("taskkill")
                        .args(["/PID", &id.to_string(), "/F"])
                        .output()
                        .await;
                }
                let _ = child.kill().await;
                let _ = child.wait().await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 二进制路径查找
// ---------------------------------------------------------------------------

/// 根据当前平台查找 cloudflared 二进制路径。
///
/// | 平台    | 查找逻辑                                   |
/// |---------|--------------------------------------------|
/// | Linux   | `config.cloudflared_path` → `which` 查 PATH |
/// | Windows | `config.cloudflared_path` → exe 同目录 → PATH |
/// | Android | `$EDGE_AGENT_DATA_DIR/cloudflared` 必须存在 |
async fn resolve_cloudflared_path(config: &Config) -> Result<PathBuf> {
    // 配置中指定了路径
    if let Some(path) = &config.cloudflared_path {
        if path.exists() {
            return Ok(path.clone());
        }
        bail!(
            "cloudflared_path 指定的路径不存在: {}",
            path.display()
        );
    }

    // 平台默认查找
    #[cfg(target_os = "android")]
    {
        // Android：必须在 data_dir 下
        let candidate = config.data_dir.join("cloudflared");
        if candidate.exists() {
            return Ok(candidate);
        }
        bail!(
            "Android 下 cloudflared 必须在 {} 目录中",
            config.data_dir.display()
        );
    }

    #[cfg(not(target_os = "android"))]
    {
        // Windows：优先 exe 同目录
        #[cfg(target_os = "windows")]
        {
            if let Ok(exe_path) = std::env::current_exe() {
                let candidate = exe_path.parent().unwrap().join("cloudflared.exe");
                if candidate.exists() {
                    return Ok(candidate);
                }
            }
        }

        // 通过 PATH 查找
        match which::which("cloudflared") {
            Ok(path) => Ok(path),
            Err(_) => bail!(
                "cloudflared 未在 PATH 中找到。\
                 请安装 cloudflared 或通过 config.toml 的 cloudflared_path 指定路径"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 路径查找不 panic（虽然大概率找不到）
    #[tokio::test]
    async fn test_resolve_path_fails_gracefully() {
        let cfg = Config::default();
        let result = resolve_cloudflared_path(&cfg).await;
        // 没装 cloudflared 的 CI 环境下应返回明确的错误信息
        if let Err(e) = result {
            let msg = format!("{e}");
            assert!(
                msg.contains("cloudflared"),
                "错误信息应包含 'cloudflared', 得到: {msg}"
            );
        }
    }

    #[test]
    fn test_restart_delays_length() {
        // 第 1 次重启等 5s，第 2 次等 10s，最后一次无延迟
        assert_eq!(restart_delay(1), 5);
        assert_eq!(restart_delay(2), 10);
        assert_eq!(restart_delay(3), 20);
        assert_eq!(restart_delay(0), 5); // saturating_sub -> 0 -> 2^0 -> 1 -> 5
    }
}
