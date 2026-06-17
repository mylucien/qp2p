//! # retry.rs — 后台重打洞
//!
//! 扫描 `ConnRegistry` 中 `Relay` 状态的节点，通过 Worker `/connect` 接口
//! 获取对端最新 candidates，发起重打洞。成功后将状态升级为 `Direct`。
//!
//! 指数退避：30s → 60s → 120s，每次 ±10s 随机 jitter。
//! 收到 `cancel` 信号立即退出。

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use dashmap::DashMap;
use rand::Rng;
use serde::Deserialize;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config::Config;
use crate::types::{
    Candidate, ConnRegistry, ConnState, HolePunchTask, PeerId, VirtualIpRegistry,
};

use super::punch;

/// 退避区间（秒）
const BACKOFF_INITIAL: u64 = 30;
const BACKOFF_MAX: u64 = 120;

/// Jitter 范围（秒）
const JITTER_RANGE: i64 = 10;

/// 扫描间隔（秒）
const SCAN_INTERVAL: u64 = 15;

// ---------------------------------------------------------------------------
// Worker /connect 响应格式
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
struct ConnectResponse {
    #[serde(default)]
    ok: bool,
    t: u64,
    target_candidates: Vec<Candidate>,
    target_conn_id: Option<String>,
    target_virtual_ip: Option<std::net::IpAddr>,
}

// ---------------------------------------------------------------------------
// 公开接口
// ---------------------------------------------------------------------------

/// 启动后台重打洞循环。
pub async fn retry_loop(
    config: Arc<Config>,
    token: Arc<RwLock<String>>,
    conn_registry: ConnRegistry,
    vip_registry: VirtualIpRegistry,
    endpoint: quinn::Endpoint,
    cancel: CancellationToken,
) -> Result<()> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("构建 reqwest Client 失败")?;

    let local_port = endpoint
        .local_addr()
        .map(|a| a.port())
        .unwrap_or(0);

    // per-peer 退避状态表（共享，子任务可更新退避值）
    let backoff_map: Arc<DashMap<PeerId, u64>> = Arc::new(DashMap::new());
    // 飞行中标记：含 sleep 等待阶段，防止同一 peer 在退避期间被重复调度。
    // 标记在 spawn 时设置，子任务完成（无论成功/失败）后清除。
    let in_flight: Arc<DashMap<PeerId, ()>> = Arc::new(DashMap::new());

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("[retry] 收到取消信号，退出");
                return Ok(());
            }
            _ = tokio::time::sleep(Duration::from_secs(SCAN_INTERVAL)) => {}
        }

        // 扫描 Relay 状态的节点
        let relay_peers: Vec<PeerId> = conn_registry
            .iter()
            .filter(|entry| matches!(entry.value(), ConnState::Relay))
            .map(|entry| entry.key().clone())
            .collect();

        if relay_peers.is_empty() {
            continue;
        }

        // 清理已不再是 Relay 的退避记录
        backoff_map.retain(|peer_id, _| {
            matches!(conn_registry.get(peer_id).as_deref(), Some(ConnState::Relay))
        });

        for peer_id in relay_peers {
            if !matches!(
                conn_registry.get(&peer_id).as_deref(),
                Some(ConnState::Relay)
            ) {
                continue;
            }

            // 读取退避秒数（copy 值，避免跨 await 持有引用）
            let backoff_secs_val = *backoff_map
                .entry(peer_id.clone())
                .or_insert(BACKOFF_INITIAL);

            // 检查是否有任务已在飞行中（含 sleep 等待阶段），避免重复调度
            if in_flight.contains_key(&peer_id) {
                continue;
            }
            in_flight.insert(peer_id.clone(), ());

            // 带 jitter 的延迟
            let jitter: i64 = rand::thread_rng().gen_range(-JITTER_RANGE..=JITTER_RANGE);
            let delay = (backoff_secs_val as i64 + jitter).max(5) as u64;
            info!("[retry] 调度 {delay}s 后重试 (peer={peer_id})");

            let (cfg, tk, cr, vr, ep, cc, hc, bm, ifc) = (
                config.clone(),
                token.clone(),
                conn_registry.clone(),
                vip_registry.clone(),
                endpoint.clone(),
                cancel.clone(),
                http.clone(),
                backoff_map.clone(),
                in_flight.clone(),
            );

            tokio::spawn(async move {
                // 清除飞行中标记（在函数返回和正常结束处执行）
                let pid = peer_id.clone();

                tokio::time::sleep(Duration::from_secs(delay)).await;

                let candidates = super::stun::probe(&cfg.stun_server, local_port)
                    .await
                    .unwrap_or_default();
                let token_guard = tk.read().await;
                match fetch_connect(&hc, &cfg, &token_guard, &peer_id, candidates).await {
                    Ok(Some(task)) => {
                        drop(token_guard);
                        punch::execute(task, &ep, &cr, &vr, &cc).await;
                        // 不操作 bm：打洞成功节点变 Direct 后 retain 自动清理
                    }
                    Ok(None) => info!("[retry] 对端 {peer_id} 可能已离线"),
                    Err(e) => {
                        let err_str = format!("{e}");
                        if err_str.contains("group_mismatch") {
                            warn!("[retry] 对端 {peer_id} 分组不匹配，永久移除");
                            cr.remove(&peer_id);
                            bm.remove(&peer_id);
                            ifc.remove(&pid);
                            return;
                        }
                        if err_str.contains("from_offline") {
                            warn!("[retry] 本节点被标 offline，等待心跳重注册 ({peer_id})");
                            ifc.remove(&pid);
                            return;
                        }
                        warn!("[retry] 查询失败 (peer={peer_id}): {e}");
                        // 翻倍退避
                        let mut entry = bm.entry(peer_id.clone()).or_insert(BACKOFF_INITIAL);
                        *entry = (*entry * 2).min(BACKOFF_MAX);
                    }
                }
                ifc.remove(&pid);
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Worker /connect 调用
// ---------------------------------------------------------------------------

async fn fetch_connect(
    http: &reqwest::Client,
    config: &Config,
    token: &str,
    target: &str,
    candidates: Vec<Candidate>,
) -> Result<Option<HolePunchTask>> {
    let url = format!("{}/connect", config.worker_url.trim_end_matches('/'));

    let body = serde_json::json!({
        "from": config.edge_id,
        "target": target,
        "candidates": candidates,
    });

    let resp = http
        .post(&url)
        .header("Authorization", format!("Bearer {token}"))
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {url} 失败"))?;

    let status = resp.status();
    if status == 404 {
        return Ok(None);
    }
    if status == 403 {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        let err = body["error"].as_str().unwrap_or("unknown").to_string();
        anyhow::bail!("fetch_connect 403: {err}");
    }
    if !status.is_success() {
        anyhow::bail!("Worker 返回 {status}");
    }

    let cr: ConnectResponse = resp
        .json()
        .await
        .context("解析 /connect 响应失败")?;

    if !cr.ok {
        anyhow::bail!("Worker 返回 ok=false");
    }

    Ok(Some(HolePunchTask {
        peer_id: target.to_string(),
        candidates: cr.target_candidates,
        conn_id: cr.target_conn_id,
        peer_virtual_ip: cr.target_virtual_ip,
        punch_at: cr.t,
    }))
}
