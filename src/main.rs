//! # edge-agent — QUIC P2P 边缘节点代理
//!
//! 单一静态二进制，承担本地 HTTP 服务、QUIC 打洞、CDN 清单决策三个职责。
//!
//! ## 启动顺序（设计文档第 10 节）
//! 1. 加载配置 + 生成 quic_conn_id
//! 2. 获取 Token
//! 3. 初始化 ConnRegistry、CdnRules、VirtualIpRegistry
//! 4. 创建 mpsc channels
//! 5. 启动 cloudflared
//! 6. 等待 Tunnel 就绪
//! 7. STUN 探测
//! 8. 注册到 Worker
//! 9. 启动 Token 续签
//! 10. 启动打洞引擎
//! 11. 启动 CDN 模块
//! 12. 启动 HTTP 服务
//! 13. 启动 TUN 设备

mod auth;
mod cdn;
mod config;
mod holepunch;
mod http;
mod tun;
mod tunnel;
mod types;

use std::sync::Arc;

use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::tunnel::TunnelHandle;
use crate::types::VirtualIpRegistry;

#[tokio::main]
async fn main() {
    // 初始化日志
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "qp2p=info".into()),
        )
        .init();

    // 根 CancellationToken，所有子任务共用
    let root_cancel = CancellationToken::new();

    // ================================================================
    // 步骤 1: 加载配置 + 生成 quic_conn_id
    // ================================================================
    info!("[main] 加载配置...");
    let mut cfg = config::Config::load(None).expect("配置加载失败");
    cfg.quic_conn_id = uuid::Uuid::new_v4().to_string();
    // edge_id 由 Worker 生成并持久化到 data_dir/edge_id，首次启动可能为空
    let saved_edge_id = config::load_edge_id(&cfg.data_dir);
    if let Some(ref id) = saved_edge_id {
        cfg.edge_id.clone_from(id);
    }
    let config = Arc::new(cfg);
    info!(
        "[main] edge_id={}, quic_conn_id={}",
        config.edge_id, config.quic_conn_id
    );

    // ================================================================
    // 步骤 2-3: 初始化全局注册表 + 创建 mpsc channels
    // ================================================================
    let conn_registry: types::ConnRegistry = Arc::new(dashmap::DashMap::new());
    let cdn_rules: types::CdnRules = Arc::new(tokio::sync::RwLock::new(Vec::new()));
    let vip_registry: VirtualIpRegistry = Arc::new(dashmap::DashMap::new());
    let (hp_sender, hp_rx) = types::new_hp_channel();
    let (reload_sender, reload_rx) = types::new_reload_channel();

    // ================================================================
    // 步骤 3: 创建 QUIC Endpoint（固定端口，打洞/STUN 共用）
    // ================================================================
    let quic_endpoint = create_quic_endpoint(&config).await;
    let quic_endpoint = match quic_endpoint {
        Ok(ep) => ep,
        Err(e) => {
            error!("[main] 创建 QUIC Endpoint 失败: {e}");
            return;
        }
    };
    let local_port = quic_endpoint
        .local_addr()
        .map(|a| a.port())
        .unwrap_or(0);
    info!("[main] QUIC Endpoint 已创建, 端口={local_port}");

    // ================================================================
    // 步骤 4: 启动 cloudflared + 等待 Tunnel 就绪
    // ================================================================
    info!("[main] 启动 cloudflared...");
    let (tunnel_handle_own, tunnel_task) = tunnel::spawn_tunnel(
        config.clone(),
        root_cancel.child_token(),
    );
    let tunnel_handle: Arc<TunnelHandle> = Arc::new(tunnel_handle_own);

    info!("[main] 等待 Tunnel 就绪...");
    let tunnel_ready = wait_for_tunnel(tunnel_handle.as_ref(), &root_cancel).await;
    if !tunnel_ready {
        error!("[main] Tunnel 就绪超时，退出");
        root_cancel.cancel();
        return;
    }
    info!("[main] Tunnel 就绪");

    // ================================================================
        // ================================================================
    // ================================================================
    // 步骤 5: 获取 Token（Tunnel 就绪后，tunnel_url 已从 stderr 提取）
    // ================================================================
    info!("[main] 获取 Token...");
    let tunnel_url_for_token = tunnel_handle.tunnel_url().await;
    info!("[main] tunnel_url={}", tunnel_url_for_token);
    let (token_str, expires_in) = auth::init_token(&config, &tunnel_url_for_token)
        .await
        .expect("Token 获取失败（检查 auth_secret 和 Worker 地址）");
    let token: Arc<RwLock<String>> = Arc::new(RwLock::new(token_str));
    info!("[main] Token 获取成功, expires_in={expires_in}s");

    // ================================================================
    // 步骤 6: STUN 探测
    // ================================================================
    info!("[main] STUN 探测...");
    let candidates = match holepunch::stun::probe(&config.stun_server, local_port).await {
        Ok(c) => c,
        Err(e) => {
            warn!("[main] STUN 探测失败: {e}，使用空候选列表");
            Vec::new()
        }
    };
    info!("[main] 候选地址: {} 个", candidates.len());

    // ================================================================
    // 步骤 7: 注册到 Worker
    // ================================================================
    info!("[main] 注册到 Worker...");
    let mut current_edge_id = config.edge_id.clone();
    match register_to_worker(&config, &token, &candidates, &tunnel_url_for_token).await {
        Ok(Some(worker_edge_id)) => {
            info!("[main] 注册成功, edge_id={worker_edge_id}");
            if worker_edge_id != current_edge_id {
                // 持久化 Worker 分配的 edge_id
                if let Err(e) = config::save_edge_id(&config.data_dir, &worker_edge_id) {
                    warn!("[main] 持久化 edge_id 失败: {e}");
                }
                current_edge_id = worker_edge_id;
            }
        }
        Ok(None) => {
            info!("[main] 注册成功");
        }
        Err(e) => {
            warn!("[main] 首次注册失败: {e}（心跳会重试）");
        }
    }

    // 将最终 edge_id 写回 config（用于后续步骤中的 config.edge_id 引用）
    // 通过 Arc::make_mut 或直接修改：由于 config 是 Arc<Config>
    // 且 Clone，无法原地修改。但后续注册和心跳使用的 edge_id
    // 来自 config.edge_id，我们已经用 load_edge_id 加载了文件中的值。
    // 心跳中的 register_heartbeat 使用 config.edge_id（初始值），
    // 如果首次注册获得了新 edge_id，重启后 config.toml 不变但文件已更新。

    // ================================================================
    // 步骤 9: 启动 Token 续签
    // ================================================================
    info!("[main] 启动 Token 续签...");
    let token_task = auth::spawn_token_refresher(
        config.clone(),
        token.clone(),
        expires_in,
        root_cancel.child_token(),
    );

    // ================================================================
    // 步骤 10: 启动打洞引擎
    // ================================================================
    info!("[main] 启动打洞引擎...");
    let holepunch_task = holepunch::spawn_engine(
        hp_rx,
        conn_registry.clone(),
        vip_registry.clone(),
        config.clone(),
        token.clone(),
        quic_endpoint.clone(),
        tunnel_handle.clone(),
        root_cancel.child_token(),
    );

    // ================================================================
    // 步骤 11: 启动 CDN 模块
    // ================================================================
    info!("[main] 启动 CDN 模块...");
    let cdn_task = cdn::spawn_cdn(
        reload_rx,
        cdn_rules.clone(),
        config.data_dir.join("cdn_list.toml"),
        root_cancel.child_token(),
    );

    // ================================================================
    // 步骤 12: 构建 AppState + 启动 HTTP 服务
    // ================================================================
    info!("[main] 启动 HTTP 服务...");
    let app_state = config::AppState::new(
        (*config).clone(),
        token.clone(),
        tunnel_handle.clone(),
        conn_registry.clone(),
        hp_sender,
        reload_sender,
        vip_registry.clone(),
    );
    let http_task = http::spawn_http(app_state, root_cancel.child_token());

    // ================================================================
    // 步骤 13: 启动 TUN 设备（非关键任务，Windows 上暂不支持）
    // ================================================================
    info!("[main] 启动 TUN 设备...");
    let (_tun_handle, mut tun_task) = tun::spawn_tun(
        config.clone(),
        conn_registry.clone(),
        vip_registry.clone(),
        root_cancel.child_token(),
    );
    // TUN 设备不在 select! 中——Windows 上暂不支持，失败不影响核心功能
    let _ = tokio::spawn(async move {
        match (&mut tun_task).await {
            Ok(Ok(())) => info!("[main] TUN 设备正常退出"),
            Ok(Err(e)) => warn!("[main] TUN 设备退出（非致命）: {e}"),
            Err(e) => warn!("[main] TUN 设备 panic: {e}"),
        }
    });

    // ================================================================
    // tokio::select! 守护 — 任意任务退出触发 shutdown
    // ================================================================
    info!("[main] 所有模块已启动，进入守护模式");

    tokio::select! {
        res = tunnel_task => {
            match res {
                Ok(Ok(())) => info!("[main] Tunnel 任务正常退出"),
                Ok(Err(e)) => error!("[main] Tunnel 任务异常退出: {e}"),
                Err(e) => error!("[main] Tunnel 任务 panic: {e}"),
            }
        }
        res = token_task => {
            match res {
                Ok(Ok(())) => info!("[main] Token 续签任务退出"),
                Ok(Err(e)) => error!("[main] Token 续签任务异常退出: {e}"),
                Err(e) => error!("[main] Token 续签任务 panic: {e}"),
            }
        }
        res = holepunch_task => {
            match res {
                Ok(Ok(())) => info!("[main] 打洞引擎正常退出"),
                Ok(Err(e)) => error!("[main] 打洞引擎异常退出: {e}"),
                Err(e) => error!("[main] 打洞引擎 panic: {e}"),
            }
        }
        res = cdn_task => {
            match res {
                Ok(Ok(())) => info!("[main] CDN 模块正常退出"),
                Ok(Err(e)) => error!("[main] CDN 模块异常退出: {e}"),
                Err(e) => error!("[main] CDN 模块 panic: {e}"),
            }
        }
        res = http_task => {
            match res {
                Ok(Ok(())) => info!("[main] HTTP 服务正常退出"),
                Ok(Err(e)) => error!("[main] HTTP 服务异常退出: {e}"),
                Err(e) => error!("[main] HTTP 服务 panic: {e}"),
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("[main] 收到 SIGINT（Ctrl+C），开始优雅关闭");
        }
    }

    // ================================================================
    // 优雅关闭
    // ================================================================
    shutdown(&root_cancel).await;
}

// ---------------------------------------------------------------------------
// 辅助函数
// ---------------------------------------------------------------------------

/// 创建 QUIC Endpoint（固定端口）。
async fn create_quic_endpoint(config: &Config) -> anyhow::Result<quinn::Endpoint> {
    let server_config = holepunch::tls::make_server_config()?;
    let client_config = holepunch::tls::make_client_config()?;

    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.set_nonblocking(true)?;

    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;

    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// 等待 Tunnel 就绪。
async fn wait_for_tunnel(tunnel: &TunnelHandle, cancel: &CancellationToken) -> bool {
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(30);

    while !tunnel.is_ready() {
        if cancel.is_cancelled() {
            return false;
        }
        if start.elapsed() > timeout {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    true
}



/// 注册到 Worker，返回 Worker 分配的 edge_id（首次注册时有效）。
async fn register_to_worker(
    config: &Config,
    token: &Arc<RwLock<String>>,
    candidates: &[types::Candidate],
    tunnel_url: &str,
) -> anyhow::Result<Option<String>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
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

    let token_guard = token.read().await;
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", *token_guard))
        .json(&body)
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("注册失败: {} {}", status, text);
    }

    // 解析响应体，提取 Worker 分配的 edge_id
    let body: serde_json::Value = resp.json().await?;
    let edge_id = body["edge_id"].as_str().map(|s| s.to_string());

    Ok(edge_id)
}

/// 优雅关闭。
async fn shutdown(root_cancel: &CancellationToken) {
    info!("[main] 触发所有模块关闭...");
    root_cancel.cancel();

    // 给子任务 5s 关闭时间
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    info!("[main] 优雅关闭完成");
}
