//! 配置：单文件 TOML，一个 `data_dir` 对应一个网络归属。
//!
//! 这一份配置是**面向用户**的：`qp2p create` / `qp2p join` 把建好的网络写进来，
//! `qp2p up` 直接读它，用户不需要记任何参数、也不需要手工 curl 接口。

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// 加入密钥前缀，后面是 `<network_id>_<secret>`。
pub const TOKEN_PREFIX: &str = "qp2p1_";

/// 配置文件在数据目录里的名字。
pub const CONFIG_FILE: &str = "config.toml";

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("TOML 解析失败：{0}")]
    Parse(#[from] toml::de::Error),
    #[error("listen 不是合法地址：{0}")]
    BadListen(String),
    #[error("forward.listen 不是合法地址：{0}")]
    BadForwardListen(String),
    #[error("token 格式非法，应为 qp2p1_<network_id>_<secret>")]
    BadToken,
    #[error("network.id 为空")]
    EmptyNetworkId,
    #[error("forward.target 为空")]
    EmptyForwardTarget,
    #[error("worker 地址必须以 http:// 或 https:// 开头：{0}")]
    BadWorker(String),
    #[error("routes 里的网段不合法（要写成 192.168.1.0/24）：{0}")]
    BadRoute(String),
    #[error("读写配置失败 {path}：{source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("序列化配置失败：{0}")]
    Encode(#[from] toml::ser::Error),
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Config {
    /// 信令 Worker 的地址，例如 `https://p2p.example.com`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker: Option<String>,
    /// 管理密钥，只在建网/换密钥时用；不填则每次从 `--admin` 或环境变量取。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_secret: Option<String>,
    #[serde(default = "default_node_name")]
    pub node_name: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default = "default_stun")]
    pub stun: Vec<String>,
    #[serde(default = "default_listen")]
    pub listen: String,
    /// 虚拟网卡 MTU。命令行没给时用这里的值。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    /// 直连空闲多少秒自动断开（0/None = 不断）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle: Option<u64>,
    /// 虚拟网卡名。Windows 上就是适配器名。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev: Option<String>,
    /// 额外走隧道的网段，等价于命令行重复写 `--route`。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<String>,
    #[serde(default = "default_true")]
    pub upnp: bool,
    /// 信令传输方式：`auto`（默认，现在等同于 poll）、`ws`（长连接）、`poll`（轮询）。
    ///
    /// `ws` 需要服务端是绑定 Durable Object 的部署；连不上会直接报错，不会自动退回轮询
    /// （自动降级在下一步做）。不填时保持原有轮询行为，升级不影响现有使用者。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal_transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,
    #[serde(default, rename = "forward")]
    pub forwards: Vec<Forward>,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Network {
    pub id: String,
    pub token: String,
    /// 服务端分配的虚拟网段，例如 `10.64.0.0/16`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    /// 服务端上次分配给我的虚拟地址。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtual_ip: Option<String>,
    #[serde(default)]
    pub route: RouteMode,
    /// 本机对外通告的局域网网段
    #[serde(default)]
    pub advertise: Vec<String>,
    /// 只出不进
    #[serde(default)]
    pub deny_inbound: bool,
}

/// 手写 Debug：token 里的 secret 绝不能进日志。
impl std::fmt::Debug for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Network")
            .field("id", &self.id)
            .field("token", &"<redacted>")
            .field("cidr", &self.cidr)
            .field("virtual_ip", &self.virtual_ip)
            .field("route", &self.route)
            .field("advertise", &self.advertise)
            .field("deny_inbound", &self.deny_inbound)
            .finish()
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("worker", &self.worker)
            .field(
                "admin_secret",
                &self.admin_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("node_name", &self.node_name)
            .field("data_dir", &self.data_dir)
            .field("stun", &self.stun)
            .field("listen", &self.listen)
            .field("mtu", &self.mtu)
            .field("dev", &self.dev)
            .field("routes", &self.routes)
            .field("upnp", &self.upnp)
            .field("network", &self.network)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteMode {
    #[default]
    Tun,
    Forward,
    Off,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Forward {
    pub listen: String,
    pub peer: String,
    pub target: String,
    /// true = 对端监听、本机连出（`-R`）
    #[serde(default)]
    pub reverse: bool,
}

/// 老版本把节点名硬编码成 "qp2p"；读到这个占位值就当没设过。
pub const LEGACY_PLACEHOLDER_NAME: &str = "qp2p";

/// 默认节点名：本机真实主机名。
///
/// Windows 有 `COMPUTERNAME`，类 Unix 一般有 `HOSTNAME`，都没有再读
/// `/etc/hostname`。带域名的只取第一段（`pc.lan` → `pc`），因为这个名字会显示在
/// 管理页和别的成员的直连日志里，越短越好认。
fn default_node_name() -> String {
    machine_name()
}

/// 本机真实主机名（Windows 取 `COMPUTERNAME`，类 Unix 取 `HOSTNAME`，
/// 再不行读 `/etc/hostname`）。取不到时退回 `"qp2p"`。
pub fn machine_name() -> String {
    fn short(raw: &str) -> Option<String> {
        let name = raw.trim();
        let head = name.split('.').next().unwrap_or(name).trim();
        if head.is_empty() {
            None
        } else {
            Some(head.to_string())
        }
    }

    for key in ["COMPUTERNAME", "HOSTNAME"] {
        if let Ok(value) = std::env::var(key) {
            if let Some(name) = short(&value) {
                return name;
            }
        }
    }
    if let Ok(value) = std::fs::read_to_string("/etc/hostname") {
        if let Some(name) = short(&value) {
            return name;
        }
    }
    "qp2p".to_string()
}

fn default_data_dir() -> PathBuf {
    PathBuf::from(".")
}

/// 默认 STUN 服务器。
///
/// 不放 Google：`stun.l.google.com` 在部分地区不可达。Cloudflare 全球可用，
/// 再配两台国内公共服务（小米、哔哩哔哩）。探测是并行的，不可达的只是没有回应，
/// 不会拖慢启动；至少要有两台**不同 IP** 的回应才能判定 NAT 类型。
/// 公共服务没有 SLA，网络受限的环境建议在配置里加上自己的服务器（`stun = [...]`）。
fn default_stun() -> Vec<String> {
    vec![
        "stun.cloudflare.com:3478".to_string(),
        "stun.miwifi.com:3478".to_string(),
        "stun.chat.bilibili.com:3478".to_string(),
    ]
}

fn default_listen() -> String {
    format!("0.0.0.0:{}", crate::DEFAULT_PORT)
}

fn default_true() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            worker: None,
            admin_secret: None,
            node_name: default_node_name(),
            data_dir: default_data_dir(),
            stun: default_stun(),
            listen: default_listen(),
            mtu: None,
            idle: None,
            dev: None,
            routes: Vec::new(),
            upnp: true,
            signal_transport: None,
            network: None,
            forwards: Vec::new(),
        }
    }
}

impl Config {
    pub fn from_toml(source: &str) -> Result<Self, ConfigError> {
        let mut config: Self = toml::from_str(source)?;
        // 老配置里节点名是硬编码的占位值 "qp2p"，读到它就换成真实主机名，
        // 免得升级之后管理页上一排机器都叫 qp2p
        if config.node_name.trim().is_empty() || config.node_name == LEGACY_PLACEHOLDER_NAME {
            config.node_name = default_node_name();
        }
        config.validate()?;
        Ok(config)
    }

    /// 数据目录：`QP2P_HOME` > `~/.qp2p`（Windows 用 `USERPROFILE`）> 当前目录。
    pub fn default_dir() -> PathBuf {
        if let Some(dir) = std::env::var_os("QP2P_HOME") {
            return PathBuf::from(dir);
        }
        std::env::var_os("USERPROFILE")
            .or_else(|| std::env::var_os("HOME"))
            .map(|p| PathBuf::from(p).join(".qp2p"))
            .unwrap_or_else(|| PathBuf::from("."))
    }

    /// 读取配置；文件不存在时返回默认值（不是错误——首次使用本来就没有）。
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        Self::from_toml(&text)
    }

    /// 写入配置。里面有加入令牌，按私密文件写（0600）。
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| ConfigError::Io {
                path: dir.display().to_string(),
                source: e,
            })?;
        }
        let text = toml::to_string_pretty(self)?;
        let header = "# qp2p 本地配置（含加入令牌，勿分享）\n\
                      # 一般不需要手改：用 qp2p init / create / join 生成\n\n";
        crate::secret_file::write_private(path, format!("{header}{text}").as_bytes()).map_err(|e| {
            ConfigError::Io {
                path: path.display().to_string(),
                source: e,
            }
        })
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.listen
            .parse::<SocketAddr>()
            .map_err(|_| ConfigError::BadListen(self.listen.clone()))?;

        if let Some(worker) = &self.worker {
            let trimmed = worker.trim();
            if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
                return Err(ConfigError::BadWorker(worker.clone()));
            }
        }

        for route in &self.routes {
            route
                .parse::<crate::route::Cidr>()
                .map_err(|_| ConfigError::BadRoute(route.clone()))?;
        }

        if let Some(network) = &self.network {
            if network.id.trim().is_empty() {
                return Err(ConfigError::EmptyNetworkId);
            }
            parse_token(&network.token).ok_or(ConfigError::BadToken)?;
        }

        for forward in &self.forwards {
            forward
                .listen
                .parse::<SocketAddr>()
                .map_err(|_| ConfigError::BadForwardListen(forward.listen.clone()))?;
            if forward.target.trim().is_empty() {
                return Err(ConfigError::EmptyForwardTarget);
            }
        }

        Ok(())
    }
}

/// 拆出 `network_id` 与 `secret`。
pub fn parse_token(token: &str) -> Option<(&str, &str)> {
    let rest = token.strip_prefix(TOKEN_PREFIX)?;
    let (network_id, secret) = rest.split_once('_')?;
    if network_id.is_empty() || secret.is_empty() {
        return None;
    }
    Some((network_id, secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config_uses_defaults() {
        let config = Config::from_toml("").unwrap();
        assert_eq!(config.listen, format!("0.0.0.0:{}", crate::DEFAULT_PORT));
        assert!(config.upnp);
        assert!(config.network.is_none());
        assert_eq!(config.stun.len(), 3);
        assert!(
            config.stun.iter().all(|s| !s.contains("google")),
            "默认列表不应依赖在部分地区不可达的 Google"
        );
    }

    #[test]
    fn full_config_parses() {
        let source = r#"
node_name = "nas"
listen = "0.0.0.0:51820"

[network]
id = "home-3f9a"
token = "qp2p1_home-3f9a_secret"
route = "tun"
advertise = ["192.168.1.0/24"]

[[forward]]
listen = "127.0.0.1:8080"
peer = "nas"
target = "10.64.1.7:80"
"#;
        let config = Config::from_toml(source).unwrap();
        assert_eq!(config.node_name, "nas");
        let network = config.network.unwrap();
        assert_eq!(network.id, "home-3f9a");
        assert_eq!(network.route, RouteMode::Tun);
        assert_eq!(config.forwards.len(), 1);
        assert!(!config.forwards[0].reverse);
    }

    #[test]
    fn rejects_bad_listen() {
        let err = Config::from_toml("listen = \"not-an-addr\"").unwrap_err();
        assert!(matches!(err, ConfigError::BadListen(_)));
    }

    #[test]
    fn rejects_bad_token() {
        let source = r#"
[network]
id = "home"
token = "nope"
"#;
        assert!(matches!(
            Config::from_toml(source).unwrap_err(),
            ConfigError::BadToken
        ));
    }

    #[test]
    fn token_roundtrip() {
        let (id, secret) = parse_token("qp2p1_home-3f9a_abcdef").unwrap();
        assert_eq!(id, "home-3f9a");
        assert_eq!(secret, "abcdef");

        assert!(parse_token("qp2p1__x").is_none());
        assert!(parse_token("qp2p1_home_").is_none());
        assert!(parse_token("home_secret").is_none());
    }
}
