//! # http — HTTP 服务模块
//!
//! axum Router 组装，启动 HTTP 服务监听 `127.0.0.1:8080`。
//! cloudflared 的 ingress 指向此端口，Worker 的 Tunnel 通知由此入口进入。

mod files;
mod health;
pub mod notify;

use anyhow::Context;
use axum::routing::{get, post};
use axum::Router;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::config::AppState;

/// 启动 HTTP 服务。
///
/// 监听 `127.0.0.1:8080`（只接受本机 cloudflared Tunnel 入站）。
///
/// 返回 `JoinHandle<Result<()>>` 供 main.rs 的 select! 监听：
/// - `Ok(())` = 正常退出（cancel 触发优雅关闭）
/// - `Err(_)` = 异常退出（绑定失败或 serve 失败），触发 shutdown
pub fn spawn_http(
    state: AppState,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    let app = Router::new()
        .route("/notify", post(notify::notify_handler))
        .route("/files/*path", get(files::files_handler))
        .route("/health", get(health::health_handler))
        .route("/reload", post(health::reload_handler))
        .with_state(state);

    tokio::spawn(async move {
        // 在 cancel 信号到来前阻塞绑定操作
        let listener = tokio::select! {
            _ = cancel.cancelled() => {
                info!("[http] 收到取消信号，不启动 HTTP 服务");
                return Ok(());
            }
            res = tokio::net::TcpListener::bind("127.0.0.1:8080") => {
                res.context("绑定 127.0.0.1:8080 失败")?
            }
        };

        info!("[http] HTTP 服务已启动: 127.0.0.1:8080");

        let shutdown_signal = cancel.clone();
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                shutdown_signal.cancelled().await;
                info!("[http] 开始优雅关闭");
            })
            .await
            .context("HTTP 服务异常")?;

        // serve 正常退出（监听器关闭）后通知其他模块
        cancel.cancel();
        tracing::error!("[http] HTTP 服务监听器已关闭，触发 shutdown");

        Ok(())
    })
}
