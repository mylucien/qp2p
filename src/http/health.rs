//! # health.rs — GET /health + POST /reload handler
//!
//! GET /health — 健康检查，返回节点状态 JSON。
//! POST /reload — 触发 CDN 清单热重载。

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use base64::Engine;
use serde::Serialize;
use tracing::info;

use crate::config::AppState;
use crate::types::ReloadCmd;

#[derive(Serialize)]
pub struct HealthResponse {
    ok: bool,
    status: String,
    tunnel_ready: bool,
    peer_count: usize,
    /// Token 过期时间戳（Unix 秒），0 表示未知或已过期
    token_exp: u64,
    version: &'static str,
}

/// GET /health — 健康检查（免鉴权）。
pub async fn health_handler(State(state): State<AppState>) -> Json<HealthResponse> {
    let peer_count = state.conn_registry.len();
    let token_exp = extract_token_exp(&state.token);

    Json(HealthResponse {
        ok: true,
        status: "running".into(),
        tunnel_ready: state.tunnel.is_ready(),
        peer_count,
        token_exp,
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// 从 JWT Token 中提取 exp 字段（不验证签名）。
/// 失败时返回 0，调用方应视为未知。
fn extract_token_exp(token: &tokio::sync::RwLock<String>) -> u64 {
    let guard = match token.try_read() {
        Ok(g) => g,
        Err(_) => return 0,
    };
    if guard.is_empty() {
        return 0;
    }

    // JWT 格式：header.payload.signature
    let parts: Vec<&str> = guard.split('.').collect();
    if parts.len() < 2 {
        return 0;
    }

    // Base64 URL-safe decode payload
    let decoded = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1]) {
        Ok(d) => d,
        Err(_) => return 0,
    };

    // 解析 JSON，提取 exp
    let payload: serde_json::Value = match serde_json::from_slice(&decoded) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    payload["exp"].as_u64().unwrap_or(0)
}

/// POST /reload — 触发 CDN 清单热重载。
///
/// ⚠ 无鉴权：监听在 127.0.0.1 仅接受本地 Tunnel 入站，无外部暴露风险。
/// 如需权限管理，可结合 Cloudflare Access 做身份验证。
pub async fn reload_handler(
    State(state): State<AppState>,
) -> Result<Json<&'static str>, StatusCode> {
    state
        .reload_sender
        .send(ReloadCmd::Reload)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    info!("[reload] CDN 清单热重载已触发");
    Ok(Json("reload triggered"))
}
