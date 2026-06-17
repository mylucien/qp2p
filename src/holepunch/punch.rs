//! # punch.rs — QUIC 打洞核心
//!
//! 收到 `HolePunchTask` 后执行一次完整打洞流程。
//! Endpoint 由调用方传入（main.rs 启动时创建一次，固定端口），
//! 确保打洞端口与 STUN 探测一致，NAT 映射稳定。

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use quinn::Endpoint;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::types::{
    ConnRegistry, ConnState, HolePunchTask, PUNCH_WINDOW_MS, VirtualIpRegistry,
};

/// 执行一次打洞尝试。
///
/// `endpoint` 由调用方传入（启动时创建一次），确保本地端口固定。
pub async fn execute(
    task: HolePunchTask,
    endpoint: &Endpoint,
    conn_registry: &ConnRegistry,
    vip_registry: &VirtualIpRegistry,
    cancel: &CancellationToken,
) {
    let peer_id = task.peer_id.clone();

    // ---- 时间对齐 ----
    let now_ms = now_millis();
    let remaining = task.punch_at as i64 - now_ms as i64;

    if remaining > 0 {
        let wait_ms = remaining as u64;
        // 时钟偏差过大时直接回落 Relay，不做无效等待
        if wait_ms > PUNCH_WINDOW_MS * 4 {
            warn!("[punch] punch_at 异常偏大 ({wait_ms}ms), 直接回落 Relay (peer={peer_id})");
            conn_registry.insert(peer_id, ConnState::Relay);
            return;
        }
        let capped = wait_ms.min(2000);
        info!("[punch] 等待 {capped}ms 后对齐打洞 (peer={peer_id})");
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(capped)) => {}
            _ = cancel.cancelled() => {
                info!("[punch] 打洞被取消 (peer={peer_id})");
                return;
            }
        }
    } else if remaining.abs() > PUNCH_WINDOW_MS as i64 {
        info!("[punch] 窗口已过期 ({remaining}ms), 跳过 (peer={peer_id})");
        conn_registry.insert(peer_id, ConnState::Relay);
        return;
    } else {
        info!("[punch] 立即打洞, 已过窗口 {remaining}ms (peer={peer_id})");
    }

    conn_registry.insert(peer_id.clone(), ConnState::Punching);

    // ---- 并发连接所有候选 ----
    let mut join_set = tokio::task::JoinSet::new();

    for candidate in &task.candidates {
        let ep = endpoint.clone();
        let addr = candidate.address;

        join_set.spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), async move {
                // server_name 必须与自签证书的 CN 一致（tls.rs "edge-agent.local"）。
                // SkipVerify 跳过了证书验证，但 quinn 仍会做 SNI 匹配，
                // 所以传任何值都行，保持与证书一致避免混淆。
                ep.connect(addr, "edge-agent.local")
                    .map_err(|e| anyhow::anyhow!("发起连接失败: {e}"))?
                    .await
                    .map_err(|e| anyhow::anyhow!("握手失败: {e}"))
            })
            .await
            .map_err(|e| anyhow::anyhow!("候选连接超时: {e}"))?
        });
    }

    // ---- 收集结果 ----
    let mut success: Option<quinn::Connection> = None;

    while let Some(res) = join_set.join_next().await {
        match res {
            Ok(Ok(conn)) => {
                info!("[punch] 候选连接成功 (peer={peer_id})");
                success = Some(conn);
                join_set.abort_all();
                // drain 剩余结果确保任务真正退出，避免静默 panic
                while join_set.join_next().await.is_some() {}
                break;
            }
            Ok(Err(e)) => info!("[punch] 候选失败: {e} (peer={peer_id})"),
            Err(e) => info!("[punch] 候选异常: {e} (peer={peer_id})"),
        }
    }

    // ---- 写入结果 ----
    match success {
        Some(conn) => {
            info!("[punch] 打洞成功 (peer={peer_id})");

            // 用 flag 标记是否实际写入了 Direct，防止与已有 Direct 冲突
            let mut did_insert = false;
            conn_registry
                .entry(peer_id.clone())
                .and_modify(|state| {
                    if matches!(state, ConnState::Punching | ConnState::Relay) {
                        *state = ConnState::Direct(conn.clone());
                        did_insert = true;
                    }
                })
                .or_insert_with(|| {
                    did_insert = true;
                    ConnState::Direct(conn.clone())
                });

            if did_insert {
                if let Some(vip) = task.peer_virtual_ip {
                    vip_registry.insert(vip, peer_id.clone());
                }
            }
        }
        None => {
            warn!("[punch] 打洞失败 (peer={peer_id})");
            conn_registry.insert(peer_id, ConnState::Relay);
        }
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
