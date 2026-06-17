//! # auth.rs — Token 管理
//!
//! 职责：
//! - 启动时调用 Worker `POST /token` 换取 Bearer Token
//! - 将 Token 写入 `AppState.token`（`Arc<tokio::sync::RwLock<String>>`）
//! - 启动定时续签任务：Token 过期前 1h 自动重新换取并更新
//! - 续签失败时指数退避重试（30s → 60s → 120s），连续 5 次失败触发 shutdown

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config::Config;

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

/// init_token 首次获取时的最大重试次数（每次间隔 2s）。
const INIT_RETRIES: u32 = 3;

/// spawn_token_refresher 后台续签连续失败阈值，超出后返回 Err 触发 shutdown。
const MAX_CONSECUTIVE_FAILURES: u32 = 5;

/// 退避起始：30 秒
const BACKOFF_INITIAL: u64 = 30;

/// 退避上限：120 秒
const BACKOFF_MAX: u64 = 120;

// ---------------------------------------------------------------------------
// Token 响应体
// ---------------------------------------------------------------------------

/// `POST /token` 的成功响应。
#[derive(Debug, Clone, Deserialize)]
struct TokenResponse {
    /// JWT Bearer Token
    token: String,
    /// Token 有效期（秒），默认 86400（24h）
    expires_in: u64,
}

// ---------------------------------------------------------------------------
// TokenClient — 轻量 HTTP client 封装
// ---------------------------------------------------------------------------

/// 与 Worker `/token` 接口通信的 client。
///
/// 每次调用独立构造，不共享 state（避免生命周期耦合）。
struct TokenClient {
    worker_url: String,
    edge_id: String,
    auth_secret: String,
    tunnel_url: String,
    http: reqwest::Client,
}

impl TokenClient {
    fn from_config(config: &Config) -> Self {
        Self {
            worker_url: config.worker_url.trim_end_matches('/').to_string(),
            edge_id: config.edge_id.clone(),
            auth_secret: config.auth_secret.clone(),
            tunnel_url: String::new(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest Client 构建失败"),
        }
    }

    /// 调用 `POST /token` 获取新的 Token。
    async fn fetch_token(&self) -> Result<TokenResponse> {
        let url = format!("{}/token", self.worker_url);
        let body = serde_json::json!({
            "edge_id": self.edge_id,
            "secret": self.auth_secret,
            "tunnel_url": self.tunnel_url,
        });

        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {url} 请求失败"))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            bail!("POST {url} 返回 {status}: {text}");
        }

        let token_resp: TokenResponse = resp
            .json()
            .await
            .context("解析 Token 响应失败")?;

        Ok(token_resp)
    }
}

// ---------------------------------------------------------------------------
// 公开接口
// ---------------------------------------------------------------------------

/// 启动时同步获取 Token，最多重试 3 次（间隔 2s）。
///
/// `tunnel_url` 是 cloudflared 分配的真实 Tunnel URL，Tunnel 就绪后获取。
///
/// 返回 `(token, expires_in)`，`expires_in` 供 `spawn_token_refresher` 使用。
/// 所有重试均失败后返回最后一个错误，由调用者（`main.rs`）决定是否 panic。
pub async fn init_token(config: &Config, tunnel_url: &str) -> Result<(String, u64)> {
    let client = TokenClient { tunnel_url: tunnel_url.to_string(), ..TokenClient::from_config(config) };
    let mut last_err: Option<anyhow::Error> = None;

    for attempt in 1..=INIT_RETRIES {
        match client.fetch_token().await {
            Ok(resp) => {
                let prefix = resp.token.get(..12).unwrap_or(&resp.token);
                info!(
                    "Token 获取成功 (第 {attempt} 次): expires_in={}s, token_prefix={}...",
                    resp.expires_in, prefix
                );
                return Ok((resp.token, resp.expires_in));
            }
            Err(e) => {
                warn!("[auth] init_token 第 {attempt} 次失败: {e}");
                last_err = Some(e);
                if attempt < INIT_RETRIES {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("init_token 失败（所有重试均未执行）")))
}

/// 启动后台 Token 续签任务。
///
/// 基于 `init_expires_in` 计算首次续签间隔（过期前 1h），
/// Worker 返回的实际 `expires_in` 会动态调整后续间隔。
///
/// 连续 `MAX_CONSECUTIVE_FAILURES` 次失败后返回 `Err`，
/// `JoinHandle` 完成使 `main.rs` 的 `select!` 捕获并触发 shutdown。
///
/// 收到 `cancel` 信号时立即退出（`Ok(())`）。
pub fn spawn_token_refresher(
    config: Arc<Config>,
    token: Arc<RwLock<String>>,
    init_expires_in: u64,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let client = TokenClient::from_config(&config);
        let mut fail_count = 0u32;

        // 动态间隔：基于最近一次 expires_in 计算
        let mut refresh_interval = Duration::from_secs(
            init_expires_in.saturating_sub(3600).max(60),
        );
        // 重试退避状态：None = 正常周期，Some(n) = n 秒后重试
        let mut retry_delay: Option<u64> = None;

        loop {
            // 计算本次 sleep 时长
            let sleep_dur = match retry_delay {
                None => refresh_interval,
                Some(d) => Duration::from_secs(d),
            };

            // 等待阶段：响应 cancel 信号
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("[auth] Token 续签任务收到取消信号，退出");
                    return Ok(());
                }
                _ = tokio::time::sleep(sleep_dur) => {}
            }

            // fetch 阶段：同样响应 cancel 信号（最长 timeout 10s）
            let result = tokio::select! {
                _ = cancel.cancelled() => {
                    info!("[auth] Token 续签任务收到取消信号，退出");
                    return Ok(());
                }
                res = client.fetch_token() => res,
            };

            match result {
                Ok(resp) => {
                    *token.write().await = resp.token;
                    // 基于实际 expires_in 更新下次续签间隔
                    refresh_interval = Duration::from_secs(
                        resp.expires_in.saturating_sub(3600).max(60),
                    );
                    retry_delay = None;
                    fail_count = 0; // 成功后重置
                    info!("[auth] Token 已续签");
                }
                Err(e) => {
                    fail_count += 1;
                    let d = retry_delay.get_or_insert(BACKOFF_INITIAL);
                    warn!(
                        "[auth] Token 续签失败 ({fail_count}/{MAX_CONSECUTIVE_FAILURES}, {d}s 后重试): {e}"
                    );
                    // 翻倍供下次使用
                    if fail_count < MAX_CONSECUTIVE_FAILURES {
                        *d = (*d * 2).min(BACKOFF_MAX);
                    }
                    if fail_count >= MAX_CONSECUTIVE_FAILURES {
                        return Err(anyhow::anyhow!(
                            "Token 续签连续失败 {MAX_CONSECUTIVE_FAILURES} 次，触发 shutdown"
                        ));
                    }
                }
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // 注意：Config 需实现 Default（由 config.rs 提供），auth 测试依赖此行为。
    use super::*;
    use crate::config::Config;

    /// TokenClient 构造不依赖网络
    #[test]
    fn test_token_client_from_config() {
        let mut cfg = Config::default();
        cfg.worker_url = "https://worker.test".into();
        cfg.edge_id = "node-test".into();
        cfg.auth_secret = "secret-123".into();

        let client = TokenClient::from_config(&cfg);
        assert_eq!(client.worker_url, "https://worker.test");
        assert_eq!(client.edge_id, "node-test");
    }

    /// TokenResponse 反序列化
    #[test]
    fn test_token_response_deserialize() {
        let json = r#"{"token":"eyJhbGciOiJIUzI1NiJ9.test","expires_in":86400}"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.token, "eyJhbGciOiJIUzI1NiJ9.test");
        assert_eq!(resp.expires_in, 86400);
    }

    /// saturating_sub 在 expires_in 较小时不会 panic，至少 60s
    #[test]
    fn test_refresh_interval_saturating() {
        let interval = 1800u64.saturating_sub(3600).max(60);
        assert_eq!(interval, 60);
    }

    /// 常量语义验证
    #[test]
    fn test_constants_sane() {
        assert!(BACKOFF_INITIAL < BACKOFF_MAX);
        assert!(MAX_CONSECUTIVE_FAILURES > 0);
    }
}
