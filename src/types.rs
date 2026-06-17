//! # types.rs — 全局共享类型
//!
//! 纯数据定义文件，无业务逻辑，无副作用。
//! 所有模块可自由引入，不产生循环依赖。
//!
//! 包含：公共结构体、枚举、类型别名。
//! 打洞相关类型   → holepunch/ 模块消费
//! CDN 相关类型   → cdn/ 模块消费
//! HTTP 相关类型  → http/ 模块消费

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use dashmap::DashMap;
use quinn::Connection;
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use serde::de::{self, Deserializer};
use serde::ser::Serializer;

// ---------------------------------------------------------------------------
// 标识符别名
// ---------------------------------------------------------------------------

/// 节点 ID（对应 Worker D1 表中的 edge_id）
pub type PeerId = String;

/// QUIC Connection ID（固定 CID，打洞全程使用）
pub type ConnId = String;

/// 绝对 Unix 毫秒时间戳
pub type TimestampMs = u64;

/// 打洞时间窗口（毫秒）。
///
/// Worker 不下发此值，edge-agent 内部固定。
/// punch.rs 和 retry.rs 共用此常量。
pub const PUNCH_WINDOW_MS: u64 = 600;

// ---------------------------------------------------------------------------
// Candidate — 候选地址
// ---------------------------------------------------------------------------

/// QUIC 候选地址，标注地址类型以供优先级排序。
///
/// 序列化格式与 Worker worker.js 期望一致：
/// ```json
/// { "type": "host", "addr": "192.168.1.100:4433" }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// 地址类型：host（内网）或 srflx（STUN 探测的公网映射）
    pub addr_type: CandidateType,

    /// 地址，`SocketAddr` 强类型保证编译期合法。
    /// 序列化为 `"ip:port"` 字符串与 Worker 兼容。
    pub address: SocketAddr,
}

impl serde::Serialize for Candidate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("Candidate", 2)?;
        s.serialize_field("type", &self.addr_type)?;
        s.serialize_field("addr", &self.address.to_string())?;
        s.end()
    }
}

impl<'de> serde::Deserialize<'de> for Candidate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(field_identifier)]
        enum Field {
            #[serde(rename = "type")]
            Type,
            #[serde(rename = "addr")]
            Address,
        }

        struct CandidateVisitor;

        impl<'de> de::Visitor<'de> for CandidateVisitor {
            type Value = Candidate;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct Candidate")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Candidate, V::Error>
            where
                V: de::MapAccess<'de>,
            {
                let mut addr_type = None;
                let mut address = None;
                while let Some(key) = map.next_key::<Field>()? {
                    match key {
                        Field::Type => {
                            if addr_type.is_some() {
                                return Err(de::Error::duplicate_field("type"));
                            }
                            addr_type = Some(map.next_value::<CandidateType>()?);
                        }
                        Field::Address => {
                            if address.is_some() {
                                return Err(de::Error::duplicate_field("address"));
                            }
                            let s: String = map.next_value()?;
                            address = Some(
                                s.parse::<SocketAddr>()
                                    .map_err(|e| de::Error::custom(format!("invalid address: {e}")))?,
                            );
                        }
                    }
                }
                let addr_type = addr_type.ok_or_else(|| de::Error::missing_field("type"))?;
                let address = address.ok_or_else(|| de::Error::missing_field("address"))?;
                Ok(Candidate { addr_type, address })
            }
        }

        deserializer.deserialize_struct("Candidate", &["type", "addr"], CandidateVisitor)
    }
}

/// 候选地址类型
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CandidateType {
    /// 内网地址（本机网卡 IP）
    Host,
    /// STUN 探测所得的公网 NAT 映射地址
    Srflx,
}

// ---------------------------------------------------------------------------
// ConnState — 连接状态
// ---------------------------------------------------------------------------

/// 与某个对端节点的当前连接状态。
///
/// 存储在全局 `ConnRegistry`（DashMap）中，所有模块通过此表获取最新状态。
/// 上层业务**不允许缓存 Connection 句柄**，每次发送前应重新查询 registry。
#[derive(Debug, Clone)]
pub enum ConnState {
    /// 打洞进行中（Initial 包已发出，等待握手）
    Punching,

    /// QUIC 直连已建立，包含可用的 Connection 对象
    Direct(Connection),

    /// 打洞失败，回落 Tunnel 中继；后台重打洞循环正在运行
    Relay,

    /// 两条路径均不可用（预留，初始状态）
    Unavailable,
}

// ---------------------------------------------------------------------------
// HolePunchTask — 打洞任务
// ---------------------------------------------------------------------------

/// 从 HTTP `/notify` handler 投递给打洞引擎的一次打洞任务。
///
/// # 字段来源
/// | 字段          | A 侧（请求方）               | B 侧（被请求方）          |
/// |---------------|------------------------------|---------------------------|
/// | peer_id       | 来自 `/connect` 响应的 target | 来自 `/notify` 的 `from`  |
/// | candidates    | `/connect` 返回的 target_candidates（已排序） | `/notify` 的 `from_candidates` |
/// | conn_id       | `Some(target_conn_id)`       | `None`（B 用不到 A 的 CID）|
/// | peer_virtual_ip | `Some(target_virtual_ip)`  | `Some(from_virtual_ip)`   |
/// | punch_at      | `/connect` 响应的 `t`        | `/notify` 的 `t`          |
///
/// `punch_at` 是 Worker 计算好的绝对打洞时间戳（Unix ms），
/// `punch.rs` 负责时间对齐，本模块不做任何时间计算。
#[derive(Debug, Clone)]
pub struct HolePunchTask {
    /// 对端节点 ID
    pub peer_id: PeerId,

    /// 对端候选地址列表（已按 host → srflx 排序）
    pub candidates: Vec<Candidate>,

    /// 对端的 quic_conn_id。
    /// - A 侧：`Some(...)`，来自 `/connect` 响应的 `target_conn_id`
    /// - B 侧：`None`，来自 `/notify`（Worker 下发 null）
    pub conn_id: Option<ConnId>,

    /// 对端 virtual_ip（v0.8 新增）。
    /// - A 侧：`Some(...)`，来自 `/connect` 响应的 `target_virtual_ip`
    /// - B 侧：`Some(...)`，来自 `/notify` 推送的 `from_virtual_ip`
    /// 打洞成功后由 `punch.rs` 写入 `VirtualIpRegistry`。
    pub peer_virtual_ip: Option<IpAddr>,

    /// 绝对打洞时间戳（Unix 毫秒），来自 Worker 计算的 `t` 值
    pub punch_at: TimestampMs,
}

// ---------------------------------------------------------------------------
// ReloadCmd — CDN 热重载指令
// ---------------------------------------------------------------------------

/// 通过 mpsc channel 发送给 CDN 模块的指令。
#[derive(Debug, Clone)]
pub enum ReloadCmd {
    /// 触发 CDN 清单重新解析并更新规则表
    Reload,

    /// 优雅关闭 CDN 模块
    Shutdown,
}

// ---------------------------------------------------------------------------
// Rule — CDN 规则
// ---------------------------------------------------------------------------

/// CDN 转发/直连规则。解析自 `cdn_list.toml`，存储于 `CdnRules`。
///
/// 匹配逻辑（最长前缀匹配）在 `cdn::rules::match_path()` 中实现。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Rule {
    /// 路径前缀，如 `"/files/videos/"` 或 `"/files/assets/large/*.mp4"`
    pub path: String,

    /// 模式：`cdn`（302 跳转 CDN）或 `direct`（本地直接返回）
    pub mode: RuleMode,

    /// CDN 缓存 TTL（秒），仅 mode = "cdn" 时生效
    pub max_age: u64,

    /// 302 跳转目标 URL（仅 mode = Cdn 时生效）。
    /// 例如 `https://<tunnel-domain>/files/videos/`。
    ///
    /// **注意：mode = Cdn 时此字段必须为 Some，**
    /// **cdn::rules::parse() 解析时应校验，缺失则返回错误。**
    /// mode = Direct 时为 None，解析时忽略。
    pub cdn_url: Option<String>,

    /// 本地网络 CIDR 列表（可选）。
    /// 空列表时回退到 /24 自动检测。
    #[serde(default)]
    pub local_cidrs: Vec<String>,
}

/// 规则模式
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleMode {
    /// 返回 302 跳转到 Tunnel URL，走 CF CDN 缓存
    Cdn,
    /// 直接从本地磁盘读取并返回文件流
    Direct,
}

// ---------------------------------------------------------------------------
// 全局状态类型别名
// ---------------------------------------------------------------------------

/// 全局连接状态表。
///
/// - key: `PeerId`（对端节点 ID）
/// - value: `ConnState`（当前连接状态）
/// - 打洞引擎负责写入，HTTP 模块只读查询
pub type ConnRegistry = Arc<DashMap<PeerId, ConnState>>;

/// CDN 规则表（读多写少）。
///
/// - `cdn::mod` 模块在收到 `ReloadCmd::Reload` 时用写锁替换整个 Vec
/// - HTTP `/files/*` handler 用读锁查询，无锁竞争
pub type CdnRules = Arc<RwLock<Vec<Rule>>>;

/// 向打洞引擎投递任务的 mpsc Sender。
///
/// - Producer: `http::notify` handler（POST /notify 时 send）
/// - Consumer: `holepunch::mod` 引擎主循环（recv 后执行打洞）
pub type HolePunchSender = mpsc::Sender<HolePunchTask>;

/// 从打洞引擎接收任务的 mpsc Receiver。
pub type HolePunchReceiver = mpsc::Receiver<HolePunchTask>;

/// 向 CDN 模块投递指令的 mpsc Sender。
///
/// - Producer: `http::health` handler（POST /reload 时 send）
/// - Consumer: `cdn::mod` 主循环（recv 后重载配置）
pub type ReloadSender = mpsc::Sender<ReloadCmd>;

/// virtual_ip → peer_id 映射表（v0.8 新增）。
///
/// 打洞成功后由 `holepunch::punch.rs` 写入，
/// `tun.rs` 读取用于路由查找（IP 包 → 目标节点）。
pub type VirtualIpRegistry = Arc<DashMap<IpAddr, PeerId>>;

// ---------------------------------------------------------------------------
// 通道创建辅助函数（仅用于初始化，不含业务逻辑）
// ---------------------------------------------------------------------------

/// 创建打洞引擎通道。
///
/// buffer = 64：单节点同时最多 ~64 个并发打洞请求，
/// 超出时 sender 会 await，给 HTTP handler 自然背压。
pub fn new_hp_channel() -> (HolePunchSender, mpsc::Receiver<HolePunchTask>) {
    mpsc::channel(64)
}

/// 创建 CDN 重载指令通道。
pub fn new_reload_channel() -> (ReloadSender, mpsc::Receiver<ReloadCmd>) {
    mpsc::channel(16)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_candidate_serde() {
        let addr: SocketAddr = "203.0.113.5:4433".parse().unwrap();
        let c = Candidate {
            addr_type: CandidateType::Srflx,
            address: addr,
        };
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains(r#""type":"srflx""#));
        assert!(json.contains(r#""addr":"203.0.113.5:4433""#));

        let back: Candidate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.addr_type, CandidateType::Srflx);
        assert_eq!(back.address, addr);
    }

    #[test]
    fn test_candidate_invalid_address() {
        let bad = r#"{"type":"host","addr":"not-an-addr"}"#;
        let result = serde_json::from_str::<Candidate>(bad);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("invalid address"),
            "error message should indicate invalid address"
        );
    }

    #[test]
    fn test_hole_punch_task_defaults() {
        let task = HolePunchTask {
            peer_id: "node-a".into(),
            candidates: vec![Candidate {
                addr_type: CandidateType::Host,
                address: "10.0.0.1:4433".parse().unwrap(),
            }],
            conn_id: Some("fixed-cid-001".into()),
            peer_virtual_ip: Some("10.0.0.2".parse().unwrap()),
            punch_at: 1_700_000_000_000,
        };
        assert_eq!(task.peer_id, "node-a");
        assert!(task.conn_id.is_some());
    }

    #[test]
    fn test_rule_mode_serde() {
        assert_eq!(
            serde_json::from_str::<RuleMode>("\"cdn\"").unwrap(),
            RuleMode::Cdn
        );
        assert_eq!(
            serde_json::from_str::<RuleMode>("\"direct\"").unwrap(),
            RuleMode::Direct
        );
    }

    #[tokio::test]
    async fn test_channel_creation() {
        let (tx, mut rx) = new_hp_channel();
        let task = HolePunchTask {
            peer_id: "test".into(),
            candidates: vec![],
            conn_id: None,
            peer_virtual_ip: None,
            punch_at: 0,
        };
        tx.send(task).await.unwrap();
        let received = rx.recv().await.unwrap();
        assert_eq!(received.peer_id, "test");
    }

    #[test]
    fn test_reload_cmd_serde() {
        // Verify ReloadCmd derives Debug + Clone (not serde by design)
        let cmd = ReloadCmd::Reload;
        let cmd2 = cmd.clone();
        assert!(matches!(cmd2, ReloadCmd::Reload));
    }
}
