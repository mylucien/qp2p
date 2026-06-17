//! # holepunch — 打洞引擎
//!
//! 对外接口：`spawn_engine()`，启动三个子任务：
//! 1. `punch_listener` — 监听 mpsc rx，逐个执行 `punch::execute()`
//! 2. `retry_loop` — 扫描 Relay 状态的后台重打洞
//! 3. `register_heartbeat` — 每 6h 重新 STUN 探测 + 更新注册
//!
//! 三个子任务共用 `CancellationToken`，任意子任务退出时通知其余任务，
//! `JoinHandle` 向外冒泡触发 `main.rs` shutdown。

mod punch;
mod retry;
pub mod stun;
pub mod tls;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::tunnel::TunnelHandle;
use crate::types::{
    ConnRegistry, HolePunchReceiver, HolePunchTask, VirtualIpRegistry,
};

/// 心跳间隔（秒）
const HEARTBEAT_INTERVAL_SECS: u64 = 6 * 3600; // 6h

/// 心跳连续失败阈值
const HEARTBEAT_MAX_FAILURES: u32 = 3;

// ---------------------------------------------------------------------------
// spawn_engine
// ---------------------------------------------------------------------------

/// 启动打洞引擎，包含三个子任务。
///
/// # 参数
/// * `rx` — 从 HTTP `/notify` 接收打洞任务的 mpsc Receiver
/// * `conn_registry` — 连接状态表
/// * `vip_registry` — virtual_ip 映射表（v0.8 新增）
/// * `config` — 应用配置
/// * `token` — Bearer Token（用于 Worker API 调用）
/// * `endpoint` — 启动时创建的 QUIC Endpoint（固定端口，打洞/STUN 共用）
/// * `tunnel` — cloudflared 子进程句柄（用于获取 tunnel_url）
/// * `cancel` — 主 CancellationToken，收到信号时所有子任务退出
///
/// # 返回
/// `JoinHandle<Result<()>>` — 任意子任务退出时此 handle 完成，冒泡触发 shutdown
pub fn spawn_engine(
    rx: HolePunchReceiver,
    conn_registry: ConnRegistry,
    vip_registry: VirtualIpRegistry,
    config: Arc<Config>,
    token: Arc<RwLock<String>>,
    endpoint: quinn::Endpoint,
    tunnel: Arc<TunnelHandle>,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        // 子 cancel token 自动级联：父 token 取消时子 token 同步取消
        let engine_cancel = cancel.child_token();

        let local_port = endpoint
            .local_addr()
            .map(|a| a.port())
            .unwrap_or(0);

        let ep = endpoint.clone();

        // 启动三个子任务
        let punch = tokio::spawn(punch_listener(
            rx,
            conn_registry.clone(),
            vip_registry.clone(),
            ep,
            engine_cancel.clone(),
        ));

        let retry = tokio::spawn(retry::retry_loop(
            config.clone(),
            token.clone(),
            conn_registry.clone(),
            vip_registry.clone(),
            endpoint,
            engine_cancel.clone(),
        ));

        let heartbeat = tokio::spawn(register_heartbeat(
            config.clone(),
            token.clone(),
            tunnel,
            local_port,
            engine_cancel.clone(),
        ));

        // 等待任意子任务退出
        let result = tokio::select! {
            r = punch => {
                warn!("[engine] punch_listener 退出");
                r.context("punch_listener 任务异常")?
            }
            r = retry => {
                warn!("[engine] retry_loop 退出");
                r.context("retry_loop 任务异常")?
            }
            r = heartbeat => {
                warn!("[engine] register_heartbeat 退出");
                r.context("register_heartbeat 任务异常")?
            }
        };

        // 通知其他子任务退出
        engine_cancel.cancel();
        result
    })
}

// ---------------------------------------------------------------------------
// punch_listener — 打洞监听
// ---------------------------------------------------------------------------

/// 从 mpsc channel 接收打洞任务并逐一执行。
async fn punch_listener(
    mut rx: HolePunchReceiver,
    conn_registry: ConnRegistry,
    vip_registry: VirtualIpRegistry,
    endpoint: quinn::Endpoint,
    cancel: CancellationToken,
) -> Result<()> {
    loop {
        let task: HolePunchTask = tokio::select! {
            _ = cancel.cancelled() => {
                info!("[punch_listener] 收到取消信号，退出");
                return Ok(());
            }
            task = rx.recv() => match task {
                Some(t) => t,
                None => {
                    info!("[punch_listener] channel 已关闭，退出");
                    return Ok(());
                }
            },
        };

        info!(
            "[punch_listener] 收到打洞任务: peer={}, candidates={}",
            task.peer_id,
            task.candidates.len()
        );

        let ep = endpoint.clone();
        let cr = conn_registry.clone();
        let vr = vip_registry.clone();
        let c = cancel.clone();
        tokio::spawn(async move {
            punch::execute(task, &ep, &cr, &vr, &c).await;
        });
    }
}

// ---------------------------------------------------------------------------
// register_heartbeat — 注册心跳
// ---------------------------------------------------------------------------

/// 每 6h 重新 STUN 探测并调用 Worker `/register` 更新 candidates。
async fn register_heartbeat(
    config: Arc<Config>,
    token: Arc<RwLock<String>>,
    tunnel: Arc<TunnelHandle>,
    local_port: u16,
    cancel: CancellationToken,
) -> Result<()> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .context("构建 reqwest Client 失败")?;

    let mut consecutive_failures: u32 = 0;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("[heartbeat] 收到取消信号，退出");
                return Ok(());
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(HEARTBEAT_INTERVAL_SECS)) => {}
        }

        // STUN 探测
        let candidates = match stun::probe(&config.stun_server, local_port).await {
            Ok(c) => c,
            Err(e) => {
                warn!("[heartbeat] STUN 探测失败: {e}");
                consecutive_failures += 1;
                if consecutive_failures >= HEARTBEAT_MAX_FAILURES {
                    error!("[heartbeat] 连续 {HEARTBEAT_MAX_FAILURES} 次失败，触发 shutdown");
                    return Err(anyhow::anyhow!(
                        "STUN 探测连续失败 {HEARTBEAT_MAX_FAILURES} 次"
                    ));
                }
                continue;
            }
        };

        // 注册到 Worker
        let token_guard = token.read().await;
        let tunnel_url = tunnel.tunnel_url().await;
        let url = format!("{}/register", config.worker_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "edge_id": config.edge_id,
            "quic_conn_id": config.quic_conn_id,
            "candidates": candidates,
            "tunnel_url": tunnel_url,
            "group_name": config.group_name,
            "group_password": config.group_password,
            "virtual_ip": config.virtual_ip,
        });

        match http
            .post(&url)
            .header("Authorization", format!("Bearer {}", *token_guard))
            .json(&body)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                consecutive_failures = 0;
                info!("[heartbeat] 注册更新成功");
            }
            Ok(resp) => {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                warn!("[heartbeat] 注册失败 ({status}): {text}");
                consecutive_failures += 1;
            }
            Err(e) => {
                warn!("[heartbeat] 注册请求失败: {e}");
                consecutive_failures += 1;
            }
        }

        if consecutive_failures >= HEARTBEAT_MAX_FAILURES {
            error!("[heartbeat] 连续 {HEARTBEAT_MAX_FAILURES} 次注册失败，触发 shutdown");
            return Err(anyhow::anyhow!(
                "Worker 注册连续失败 {HEARTBEAT_MAX_FAILURES} 次"
            ));
        }
    }
}