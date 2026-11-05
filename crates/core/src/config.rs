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
    #[serde(default = "default_true")]
    pub upnp: bool,
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

fn default_node_name() -> String {
    "qp2p".to_string()
}

fn default_data_dir() -> PathBuf {
    PathBuf::from(".")
}

fn default_stun() -> Vec<String> {
    vec![
        "stun.cloudflare.com:3478".to_string(),
        "stun.l.google.com:19302".to_string(),
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
            upnp: true,
            network: None,
            forwards: Vec::new(),
        }
    }
}

impl Config {
    pub fn from_toml(source: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(source)?;
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
        assert_eq!(config.stun.len(), 2);
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
