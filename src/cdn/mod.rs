//! # cdn — CDN 分发模块
//!
//! 对外接口：`spawn_cdn()`，监听 `ReloadCmd` 指令。
//! 收到 `Reload` 时重新解析 TOML 清单，用写锁更新规则表。
//! 写操作极少（用户手动触发重载），读路径无锁竞争。

pub mod rules;
pub mod utils;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::types::{CdnRules, ReloadCmd};

// ---------------------------------------------------------------------------
// spawn_cdn
// ---------------------------------------------------------------------------

/// 启动 CDN 模块，监听 `ReloadCmd` 指令。
///
/// # 参数
/// * `rx` — 接收重载指令的 mpsc Receiver
/// * `cdn_rules` — CDN 规则表（写锁替换）
/// * `manifest_path` — TOML 清单路径
/// * `cancel` — 收到信号时退出
///
/// # 返回
/// `JoinHandle<Result<()>>` — 退出时冒泡触发 shutdown
pub fn spawn_cdn(
    rx: mpsc::Receiver<ReloadCmd>,
    cdn_rules: CdnRules,
    manifest_path: PathBuf,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        cdn_main(rx, cdn_rules, manifest_path, cancel).await
    })
}

// ---------------------------------------------------------------------------
// cdn_main — 主循环
// ---------------------------------------------------------------------------

async fn cdn_main(
    mut rx: mpsc::Receiver<ReloadCmd>,
    cdn_rules: CdnRules,
    manifest_path: PathBuf,
    cancel: CancellationToken,
) -> Result<()> {
    // 启动时加载一次
    match reload_rules(&cdn_rules, manifest_path.clone()).await {
        Ok(count) => info!("[cdn] 初始加载完成: {count} 条规则"),
        Err(e) => warn!("[cdn] 初始加载失败: {e}（稍后可通过重载修复）"),
    }

    // 可选：启动文件监听（Linux inotify / 通用轮询）
    let watcher = spawn_file_watcher(manifest_path.clone(), cancel.clone());

    loop {
        let cmd = tokio::select! {
            _ = cancel.cancelled() => {
                info!("[cdn] 收到取消信号，退出");
                watcher.abort();
                return Ok(());
            }
            cmd = rx.recv() => match cmd {
                Some(c) => c,
                None => {
                    info!("[cdn] channel 已关闭，退出");
                    watcher.abort();
                    return Ok(());
                }
            },
        };

        match cmd {
            ReloadCmd::Reload => {
                match reload_rules(&cdn_rules, manifest_path.clone()).await {
                    Ok(count) => info!("[cdn] 热重载成功: {count} 条规则"),
                    Err(e) => error!("[cdn] 热重载失败: {e}"),
                }
            }
            ReloadCmd::Shutdown => {
                info!("[cdn] 收到 Shutdown 指令");
                watcher.abort();
                return Ok(());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// reload_rules — 重载规则
// ---------------------------------------------------------------------------

/// 重新解析 TOML 清单并替换 cdn_rules。
async fn reload_rules(cdn_rules: &CdnRules, manifest_path: PathBuf) -> Result<usize> {
    let rules = tokio::task::spawn_blocking({
        let path = manifest_path.clone();
        move || rules::parse_manifest(&path)
    })
    .await
    .context("重载任务失败")??;

    let count = rules.len();

    // 写锁替换
    {
        let mut guard = cdn_rules.write().await;
        *guard = rules;
    }

    Ok(count)
}

// ---------------------------------------------------------------------------
// 文件变更监听（平台通用轮询）
// ---------------------------------------------------------------------------

/// 文件监听预留，当前版本不自动监听，依赖 HTTP POST /reload 手动触发。
fn spawn_file_watcher(
    _path: PathBuf,
    _cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    // 不自动监听，任务永远挂起直到被 abort
    tokio::spawn(async move {
        std::future::pending::<()>().await
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::new_reload_channel;
    use std::time::Duration;

    #[tokio::test]
    async fn test_reload_updates_rules() {
        let cdn_rules: CdnRules = Arc::new(tokio::sync::RwLock::new(vec![]));
        let (tx, rx) = new_reload_channel();

        // 写一个临时清单
        let dir = std::env::temp_dir().join("edge_agent_cdn_test");
        let _ = std::fs::create_dir_all(&dir);
        let manifest = dir.join("cdn_list.toml");
        std::fs::write(
            &manifest,
            r#"
[[rules]]
path = "/files/videos/"
mode = "cdn"
max_age = 86400
cdn_url = "https://cdn.example.com/"
"#,
        )
        .unwrap();

        let cancel = CancellationToken::new();
        let _task = spawn_cdn(rx, cdn_rules.clone(), manifest.clone(), cancel.clone());

        // 发送重载指令
        tx.send(ReloadCmd::Reload).await.unwrap();

        // 等待规则加载
        tokio::time::sleep(Duration::from_millis(100)).await;

        let guard = cdn_rules.read().await;
        assert_eq!(guard.len(), 1);
        assert_eq!(guard[0].path, "/files/videos/");

        // 清理
        cancel.cancel();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_shutdown_closes_cleanly() {
        let cdn_rules: CdnRules = Arc::new(tokio::sync::RwLock::new(vec![]));
        let (tx, rx) = new_reload_channel();
        let cancel = CancellationToken::new();

        let task = spawn_cdn(rx, cdn_rules, PathBuf::from("/nonexistent"), cancel.clone());
        tx.send(ReloadCmd::Shutdown).await.unwrap();
        let result = task.await;
        assert!(result.is_ok());
    }
}
