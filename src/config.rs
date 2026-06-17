//! # config.rs — 配置加载与 AppState
//!
//! 职责：
//! - 从 `config.toml` 及环境变量加载 `Config`
//! - 构建 `AppState`，注入所有共享句柄
//! - `AppState` 可直接 `Clone`（所有字段均为 Arc 或轻量值），
//!   axum 的 `State` 提取器可安全克隆

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use dashmap::DashMap;
use serde::Deserialize;
use tracing::{debug, info};

use crate::tunnel::TunnelHandle;
use crate::types::{
    CdnRules, ConnRegistry, HolePunchSender, ReloadSender, VirtualIpRegistry,
};

// ---------------------------------------------------------------------------
// Config — 应用配置
// ---------------------------------------------------------------------------

/// edge-agent 配置，优先从 `config.toml` 加载，环境变量可覆盖。
///
/// # 环境变量覆盖规则
/// | TOML 字段              | 环境变量                    |
/// |------------------------|-----------------------------|
/// | `worker_url`           | `EDGE_WORKER_URL`           |
/// | `auth_secret`          | `EDGE_AUTH_SECRET`          |
/// | `edge_id`              | `EDGE_EDGE_ID`              |
/// | `tunnel_token`         | `EDGE_TUNNEL_TOKEN`         |
/// | `cloudflared_path`     | `EDGE_CLOUDFLARED_PATH`     |
/// | `stun_server`          | `EDGE_STUN_SERVER`          |
/// | `cdn_manifest`         | `EDGE_CDN_MANIFEST`         |
/// | `data_dir`             | `EDGE_AGENT_DATA_DIR`       |
/// | `virtual_ip`           | `EDGE_VIRTUAL_IP`           |
/// | `group_name`           | `EDGE_GROUP_NAME`           |
/// | `group_password`       | `EDGE_GROUP_PASSWORD`       |
///
/// # 启动后注入字段
/// - `quic_conn_id`：main.rs 启动后第 1 步（Config 加载后）立即生成并写入，
///   见设计文档第 4.3a 节。
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    // ---- Worker 信令 ----
    /// Worker API 地址，如 `https://quic-p2p.example.workers.dev`
    pub worker_url: String,

    /// 换取 Bearer Token 的密钥（对应 Worker 的 AUTH_SECRET）
    pub auth_secret: String,

    /// 本节点唯一 ID（由 Worker 在注册时生成，持久化到 data_dir/edge_id）
    #[serde(skip)]
    pub edge_id: String,

    // ---- Tunnel ----
    /// cloudflared Tunnel Token
    pub tunnel_token: String,

    /// cloudflared 二进制路径，`None` 则自动在 PATH 中查找
    pub cloudflared_path: Option<PathBuf>,

    // ---- STUN ----
    /// STUN 服务器地址，默认 `stun.cloudflare.com:3478`
    pub stun_server: String,

    // ---- 文件路径 ----
    /// CDN 规则清单路径（TOML），默认 `{data_dir}/cdn_list.toml`
    pub cdn_manifest: PathBuf,

    /// 数据目录，平台相关默认值
    pub data_dir: PathBuf,

    // ---- 组网 & TUN（v0.8 新增） ----
    /// 本节点虚拟 IP，格式 `"10.0.0.1/24"`。
    /// validate() 校验 CIDR 合法性。
    pub virtual_ip: String,

    /// 组名称，注册时上报 Worker，非空必填。
    pub group_name: String,

    /// 组密码（明文），Worker 哈希后存储。
    /// 最小长度 8 位。
    pub group_password: String,

    // ---- 运行时生成字段（main.rs 在 Config 加载后设置） ----
    /// 本节点固定的 QUIC Connection ID，启动时随机生成一次，运行期间不变。
    /// 生成方式：`uuid::Uuid::new_v4().to_string()`（~36 字节）。
    /// 由 `main.rs` 第 1 步在 Config 加载后注入。
    #[serde(skip)]
    pub quic_conn_id: String,
}

/// `config.toml` 未填写时的默认值
impl Default for Config {
    fn default() -> Self {
        let data_dir = default_data_dir();

        Self {
            worker_url: "http://127.0.0.1:8787".into(),
            auth_secret: String::new(),
            edge_id: String::new(),
            tunnel_token: String::new(),
            cloudflared_path: None,
            stun_server: "stun.cloudflare.com:3478".into(),
            cdn_manifest: data_dir.join("cdn_list.toml"),
            data_dir,
            virtual_ip: String::new(),
            group_name: String::new(),
            group_password: String::new(),
            quic_conn_id: String::new(),
        }
    }
}

impl Config {
    /// 加载配置：读取 config.toml → 环境变量覆盖。
    ///
    /// `path` 为 `None` 时依次尝试：
    ///   1. `./config.toml`
    ///   2. `$EDGE_AGENT_DATA_DIR/config.toml`
    ///   3. `/etc/edge-agent/config.toml`
    pub fn load(path: Option<&PathBuf>) -> Result<Self> {
        let path = match path {
            Some(p) => p.clone(),
            None => find_config()?,
        };

        let mut config: Self = if path.exists() {
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("读取配置失败: {}", path.display()))?;
            toml::from_str(&content)
                .with_context(|| format!("解析配置失败: {}", path.display()))?
        } else {
            info!("未找到配置文件，使用默认值");
            Self::default()
        };

        // 环境变量覆盖
        apply_env_override(&mut config);

        // 校验必填字段
        config.validate()?;

        info!(
            "配置加载完成: edge_id={}, worker_url={}, data_dir={}",
            config.edge_id,
            config.worker_url,
            config.data_dir.display()
        );

        Ok(config)
    }

    /// 校验必填字段。
    fn validate(&self) -> Result<()> {
        if self.worker_url.is_empty() {
            bail!("worker_url 未设置（环境变量 EDGE_WORKER_URL 或 config.toml 中配置）");
        }
        if !self.worker_url.starts_with("http://") && !self.worker_url.starts_with("https://") {
            bail!("worker_url 格式错误，必须以 http:// 或 https:// 开头");
        }
        if self.auth_secret.is_empty() {
            bail!("auth_secret 未设置");
        }
        if self.tunnel_token.is_empty() {
            bail!("tunnel_token 未设置");
        }
        if self.virtual_ip.is_empty() {
            bail!("virtual_ip 未设置（格式如 10.0.0.1/24）");
        }
        if !self.virtual_ip.contains('/') {
            bail!(
                "virtual_ip 必须是 CIDR 格式（含掩码位），如 10.0.0.1/24，当前值: {}",
                self.virtual_ip
            );
        }
        if self.virtual_ip.parse::<ipnetwork::IpNetwork>().is_err() {
            bail!("virtual_ip 格式无效，应为 CIDR 格式如 10.0.0.1/24");
        }
        if self.group_name.is_empty() {
            bail!("group_name 未设置");
        }
        if self.group_password.len() < 8 {
            bail!("group_password 长度至少 8 位");
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AppState — 应用共享状态
// ---------------------------------------------------------------------------

/// edge-agent 的全局共享状态，注入 axum、打洞引擎、CDN 模块等。
///
/// 所有字段均为 `Arc`（或本身就是轻量句柄），
/// `Clone` 代价极低，axum 的 `State<AppState>` 提取器可直接使用。
#[derive(Debug, Clone)]
pub struct AppState {
    /// 只读配置
    pub config: Arc<Config>,

    /// 连接状态表（DashMap）
    pub conn_registry: ConnRegistry,

    /// CDN 规则表（读多写少）
    pub cdn_rules: CdnRules,

    /// 向打洞引擎投递任务的 channel Sender
    pub hp_sender: HolePunchSender,

    /// 向 CDN 模块投递指令的 channel Sender
    pub reload_sender: ReloadSender,

    /// cloudflared 子进程句柄
    pub tunnel: Arc<TunnelHandle>,

    /// virtual_ip → peer_id 映射表（v0.8 新增），用于 TUN 模块路由查找。
    /// `tun.rs` 通过 `state.vip_registry.clone()` 获取副本。
    pub vip_registry: VirtualIpRegistry,

    /// 当前 Bearer Token，由 `auth.rs` 定时续签刷新
    pub token: Arc<tokio::sync::RwLock<String>>,
}

impl AppState {
    /// 创建 `AppState`，注入所有共享句柄。
    ///
    /// # 参数
    /// * `config` — 已加载的配置
    /// * `token` — 共享 Bearer Token（Arc RwLock，auth.rs 续签时更新）
    /// * `tunnel` — TunnelHandle
    /// * `conn_registry` — 连接状态表（与 holepunch/tun 共享）
    /// * `hp_sender` — 打洞引擎 channel 的发送端
    /// * `reload_sender` — CDN 重载 channel 的发送端
    /// * `vip_registry` — virtual_ip 映射表
    pub fn new(
        config: Config,
        token: Arc<tokio::sync::RwLock<String>>,
        tunnel: Arc<TunnelHandle>,
        conn_registry: ConnRegistry,
        hp_sender: HolePunchSender,
        reload_sender: ReloadSender,
        vip_registry: VirtualIpRegistry,
    ) -> Self {
        Self {
            config: Arc::new(config),
            conn_registry,
            cdn_rules: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            hp_sender,
            reload_sender,
            tunnel,
            vip_registry,
            token,
    }
}

    /// 创建临时的 `AppState`（测试/尚未完全初始化时使用）。
    ///
    /// ⚠ **channel receiver 已被丢弃**：`hp_sender` 和 `reload_sender`
    /// 的接收端在函数返回时即被 drop，任何 `send()` 调用将返回 `SendError`。
    /// 仅用于无需实际投递消息的静态检查场景。
    pub fn new_ephemeral() -> Self {
        let (hp_tx, _hp_rx) = crate::types::new_hp_channel();
        let (reload_tx, _reload_rx) = crate::types::new_reload_channel();
        let tunnel = Arc::new(crate::tunnel::TunnelHandle::new_placeholder());
        let conn_registry: ConnRegistry = Arc::new(DashMap::new());
        let vip_registry: VirtualIpRegistry = Arc::new(DashMap::new());
        let token = Arc::new(tokio::sync::RwLock::new(String::new()));
        Self::new(
            Config::default(),
            token,
            tunnel,
            conn_registry,
            hp_tx,
            reload_tx,
            vip_registry,
        )
    }
}

// ---------------------------------------------------------------------------
// 辅助函数
// ---------------------------------------------------------------------------

/// 确定平台默认的数据目录。
///
/// | 平台    | 优先级                                      |
/// |---------|---------------------------------------------|
/// | Linux   | `$EDGE_AGENT_DATA_DIR` → `/etc/edge-agent` |
/// | Windows | `$EDGE_AGENT_DATA_DIR` → exe 同目录        |
/// | Android | `$EDGE_AGENT_DATA_DIR`（**必须设置**）     |
fn default_data_dir() -> PathBuf {
    // 环境变量优先
    if let Ok(dir) = std::env::var("EDGE_AGENT_DATA_DIR") {
        return PathBuf::from(dir);
    }

    // 平台回退默认值
    #[cfg(target_os = "android")]
    {
        panic!(
            "Android 上必须设置 EDGE_AGENT_DATA_DIR 环境变量，\
             例如 /data/data/<pkg>/files/edge-agent"
        );
    }

    #[cfg(not(target_os = "android"))]
    {
        // 优先使用 XDG 风格路径，否则 exe 同目录
        if let Some(exe_dir) = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        {
            // Windows：exe 同目录；Linux：/etc/edge-agent
            #[cfg(target_os = "windows")]
            {
                return exe_dir;
            }
            #[cfg(not(target_os = "windows"))]
            {
                let _ = exe_dir; // suppress unused warning
            }
        }
        PathBuf::from("/etc/edge-agent")
    }
}

/// 自动查找配置文件路径。
fn find_config() -> Result<PathBuf> {
    // 收集候选路径
    let mut candidates = Vec::new();
    candidates.push(PathBuf::from("./config.toml"));
    if let Ok(dir) = std::env::var("EDGE_AGENT_DATA_DIR") {
        candidates.push(PathBuf::from(dir).join("config.toml"));
    }
    candidates.push(PathBuf::from("/etc/edge-agent/config.toml"));

    for p in &candidates {
        if p.exists() {
            return Ok(p.clone());
        }
    }

    debug!(
        "未找到配置文件，已查找路径: {:?}，回退到默认值",
        candidates.iter().map(|p| p.display().to_string()).collect::<Vec<_>>()
    );

    // 都不存在则回退到 ./config.toml（load() 会用默认值）
    Ok(PathBuf::from("./config.toml"))
}

/// 用环境变量覆盖配置中的对应字段。
/// 注意：default_data_dir() 在 Default::default() 时已读过 EDGE_AGENT_DATA_DIR。
/// 这里再次读取是为了覆盖从 TOML 文件加载的 data_dir 值。
fn apply_env_override(config: &mut Config) {
    macro_rules! override_str {
        ($field:ident, $env:literal) => {
            if let Ok(val) = std::env::var($env) {
                if !val.is_empty() {
                    config.$field = val;
                }
            }
        };
    }

    override_str!(worker_url, "EDGE_WORKER_URL");
    override_str!(auth_secret, "EDGE_AUTH_SECRET");
    override_str!(edge_id, "EDGE_EDGE_ID");
    override_str!(tunnel_token, "EDGE_TUNNEL_TOKEN");
    override_str!(stun_server, "EDGE_STUN_SERVER");

    override_str!(virtual_ip, "EDGE_VIRTUAL_IP");
    override_str!(group_name, "EDGE_GROUP_NAME");
    override_str!(group_password, "EDGE_GROUP_PASSWORD");

    if let Ok(val) = std::env::var("EDGE_CLOUDFLARED_PATH") {
        if !val.is_empty() {
            config.cloudflared_path = Some(PathBuf::from(val));
        }
    }

    if let Ok(val) = std::env::var("EDGE_CDN_MANIFEST") {
        if !val.is_empty() {
            config.cdn_manifest = PathBuf::from(val);
        }
    }

    if let Ok(val) = std::env::var("EDGE_AGENT_DATA_DIR") {
        if !val.is_empty() {
            config.data_dir = PathBuf::from(val);
            // 除非用户显式设置了 EDGE_CDN_MANIFEST，否则同步更新 cdn_manifest
            if std::env::var("EDGE_CDN_MANIFEST").is_err() {
                config.cdn_manifest = config.data_dir.join("cdn_list.toml");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// edge_id 管理（由 Worker 生成并持久化）
// ---------------------------------------------------------------------------

use std::fs;

/// 从 data_dir/edge_id 文件加载 edge_id。
pub fn load_edge_id(data_dir: &std::path::Path) -> Option<String> {
    let path = data_dir.join("edge_id");
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

/// 将 edge_id 持久化到 data_dir/edge_id 文件。
pub fn save_edge_id(data_dir: &std::path::Path, edge_id: &str) -> anyhow::Result<()> {
    let path = data_dir.join("edge_id");
    fs::write(&path, edge_id)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let cfg = Config::default();
        assert_eq!(cfg.stun_server, "stun.cloudflare.com:3478");
        assert!(cfg.cloudflared_path.is_none());
        assert!(cfg.quic_conn_id.is_empty());
    }

    #[test]
    fn test_config_validate_ok() {
        let mut cfg = Config::default();
        cfg.worker_url = "https://worker.test".into();
        cfg.auth_secret = "secret-123".into();
        cfg.edge_id = "node-test".into();
        cfg.tunnel_token = "token-abc".into();
        cfg.virtual_ip = "10.0.0.1/24".into();
        cfg.group_name = "test-net".into();
        cfg.group_password = "password123".into();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_config_validate_fails_on_empty_fields() {
        let cfg = Config::default();
        let err = cfg.validate().unwrap_err();
        let msg = format!("{err}");
        // 第一个失败的检查是 worker_url
        assert!(msg.contains("worker_url"), "应提示 worker_url 缺失, 得到: {msg}");
    }

    #[test]
    fn test_app_state_ephemeral() {
        let state = AppState::new_ephemeral();
        assert_eq!(state.config.edge_id, "");
        assert_eq!(*state.token.try_read().unwrap(), "");
    }

    #[test]
    fn test_app_state_quic_conn_id_after_init() {
        // 模拟 main.rs 的启动流程：先加载 Config，再设置 quic_conn_id
        let mut cfg = Config::default();
        cfg.edge_id = "real-node".into();
        cfg.auth_secret = "s".into();
        cfg.worker_url = "https://w.test".into();
        cfg.tunnel_token = "t".into();
        cfg.quic_conn_id = uuid::Uuid::new_v4().to_string();

        let (hp_tx, _) = crate::types::new_hp_channel();
        let (reload_tx, _) = crate::types::new_reload_channel();
        let tunnel = Arc::new(crate::tunnel::TunnelHandle::new_placeholder());
        let conn_registry: crate::types::ConnRegistry = Arc::new(DashMap::new());
        let vip_registry: crate::types::VirtualIpRegistry = Arc::new(DashMap::new());
        let token = Arc::new(tokio::sync::RwLock::new("test-token".into()));
        let state = AppState::new(
            cfg,
            token,
            tunnel,
            conn_registry,
            hp_tx,
            reload_tx,
            vip_registry,
        );
        assert!(!state.config.quic_conn_id.is_empty());
        assert_eq!(*state.token.try_read().unwrap(), "test-token");
    }

    #[test]
    fn test_config_validate_bad_worker_url() {
        let mut cfg = Config::default();
        cfg.worker_url = "not-a-url".into();
        cfg.auth_secret = "s".into();
        cfg.edge_id = "n".into();
        cfg.tunnel_token = "t".into();
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("http://"),
            "应提示 URL 格式错误, 得到: {}",
            err
        );
    }

    #[test]
    fn test_env_override_str() {
        // 仅验证 apply_env_override 调用不 panic，不对字段值做断言（受环境变量影响）
        let mut cfg = Config::default();
        cfg.worker_url = "original".into();
        apply_env_override(&mut cfg);
    }
}
