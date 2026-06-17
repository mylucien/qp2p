//! # notify.rs — POST /notify handler
//!
//! Worker 通过 cloudflared Tunnel 推送打洞通知到此端点。
//! handler 只做三件事：
//! 1. 解析 JSON body，字段对齐 Worker 实际推送格式
//! 2. 基本参数校验
//! 3. 构造 HolePunchTask 并通过 mpsc Sender 发送给打洞引擎
//!
//! **设计原则**：fire-and-forget，不等打洞结果立即返回 200。

use std::net::IpAddr;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use tracing::{info, warn};

use crate::config::AppState;
use crate::types::{Candidate, HolePunchTask};

// ---------------------------------------------------------------------------
// 请求体
// ---------------------------------------------------------------------------

/// Worker `/notify` 推送的完整 payload。
#[derive(Debug, Deserialize)]
pub struct NotifyPayload {
    #[serde(rename = "type")]
    msg_type: Option<String>,
    from: String,
    from_candidates: Vec<Candidate>,
    /// Worker 固定下发 null，B 侧忽略
    from_conn_id: Option<String>,
    /// v0.8 新增：对端 virtual_ip
    from_virtual_ip: Option<IpAddr>,
    /// 绝对打洞时间戳（Unix ms）
    t: u64,
}

// ---------------------------------------------------------------------------
// handler
// ---------------------------------------------------------------------------

/// POST /notify
///
/// 接收 Worker 的打洞推送，投递给打洞引擎。
pub async fn notify_handler(
    State(state): State<AppState>,
    Json(payload): Json<NotifyPayload>,
) -> StatusCode {
    // 校验消息类型
    if payload.msg_type.as_deref() != Some("hole_punch") {
        warn!("[notify] 未知消息类型: {:?}", payload.msg_type);
        return StatusCode::BAD_REQUEST;
    }

    // 基本校验
    if payload.from.is_empty() {
        warn!("[notify] from 为空");
        return StatusCode::BAD_REQUEST;
    }
    if payload.from_candidates.is_empty() {
        warn!("[notify] from_candidates 为空 (from={})", payload.from);
        return StatusCode::BAD_REQUEST;
    }
    // 检查时间戳是否在合理范围（当前时间 ±30s，防止重放攻击）
    // 30s 窗口兼顾 OpenWrt 等 NTP 未配置设备的时钟偏差
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let diff = (payload.t as i64 - now_ms as i64).abs();
    if diff > 30_000 {
        warn!("[notify] 时间戳偏差过大 ({}ms, from={})", diff, payload.from);
        return StatusCode::BAD_REQUEST;
    }

    // 构造打洞任务
    // 注意：B 侧不需要对端 CID，强制设为 None 防止未来 Worker 行为变化影响
    let task = HolePunchTask {
        peer_id: payload.from,
        candidates: payload.from_candidates,
        conn_id: None,
        peer_virtual_ip: payload.from_virtual_ip,
        punch_at: payload.t,
    };

    // 投递给打洞引擎（fire-and-forget，不等结果）
    // 注意：Worker 推送是单向的，不会重试 B 侧的 503。
    // 如果 channel 满，B 侧通知丢失，A 侧会走中继回落，不影响连接建立。
    match state.hp_sender.send(task).await {
        Ok(()) => {
            info!("[notify] 打洞任务已投递");
            StatusCode::OK
        }
        Err(e) => {
            warn!("[notify] 投递打洞任务失败: {e}");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}
