//! 信令 HTTP 客户端。
//!
//! 建网、换密钥、加入、注册、拉事件、撮合、下线——全部在这里。
//! 上层（CLI / 桌面 / 安卓）只调用这些方法，不需要知道 URL、签名串和错误码。
//!
//! 签名规则与 `signal/worker.js` 的 `verifySignedRequest` 一一对应：
//!
//! ```text
//! qp2p1|<op>|<network>|<ts>|<nonce>|<sha256(canonical_json(body without sig))>
//! ```
//!
//! 时间戳是毫秒且窗口只有 ±120 秒，所以本机时钟偏差会直接表现为
//! `bad_signature`。这里把这类错误翻译成人话，省得用户去猜。

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::config::{parse_token, TOKEN_PREFIX};
use crate::identity::{Identity, NodeId};
use crate::signal::canonical::{body_digest, signing_message};

/// 单次 HTTP 请求的超时。Worker 正常在几十毫秒内返回，超过就是网络问题。
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

/// 服务端返回的业务错误。
#[derive(Debug, Clone)]
pub struct SignalError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for SignalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 每条都带上"该怎么办"，而不是把服务端的英文错误码直接抛给用户
        let hint = match self.code.as_str() {
            "invalid_token" => "令牌格式应为 qp2p1_<网络>_<密钥>，请向建网的人要完整的令牌",
            "wrong_secret" => "加入密钥不正确：可能已被换掉（rotate），或者你被移出了这个网络",
            "network_not_found" => "服务端没有这个网络，确认 Worker 地址和令牌来自同一套部署",
            "target_not_found" => "对端不在这个网络里（可能已退出）",
            "target_offline" => "对端心跳已超时：它可能没在运行 qp2p up",
            "target_no_candidates" => "对端还没上报可直连的地址，稍等几秒再试",
            "network_full" => "这个网络的节点数到上限了（256），先清理不用的节点",
            "rate_limited" => "请求太频繁（每 IP 每分钟 240 次），等一下再试",
            "admin_secret_unset" => {
                "服务端没有配置 ADMIN_SECRET：Cloudflare → Worker → Settings → Variables 添加后重新部署"
            }
            "invalid_admin_secret" => "ADMIN_SECRET 不对，检查 Cloudflare 里的变量和本机保存的是否一致",
            "network_exists" => "网络已存在。要换密钥用 qp2p rotate，要看令牌用 qp2p token",
            "invalid_name" => "网络名只能用小写字母、数字和连字符，且以字母或数字开头",
            "invalid_join_key" => "密钥长度需在 16~128 字符之间",
            "invalid_cidr" => "网段只支持 10.x.0.0/16 形式",
            "bad_signature" => {
                "签名校验失败：最常见原因是本机时钟和真实时间差超过 2 分钟，请先校准时间"
            }
            "node_id_mismatch" => "身份文件和令牌不匹配：换一台机器或删掉 ~/.qp2p/identity.key 重来",
            "not_found" => {
                "服务端不认识这个接口：Worker 版本太旧，把 signal/worker.js（2.3.0）重新粘贴部署一次"
            }
            "confirm_required" => "删除网络不可撤销，需要在请求里带 confirm=<网络 id>（qp2p delete 会自动带）",
            _ => "",
        };

        if self.message.is_empty() && hint.is_empty() {
            return write!(f, "服务端返回 HTTP {}", self.status);
        }
        let detail = if self.message.is_empty() {
            String::new()
        } else {
            self.message.clone()
        };
        if hint.is_empty() {
            write!(f, "{detail}（HTTP {} / {}）", self.status, self.code)
        } else if detail.is_empty() {
            write!(f, "{hint}")
        } else if detail.contains(hint) {
            // 服务端的原话已经说清楚了，不必重复一遍
            write!(f, "{detail}")
        } else {
            write!(f, "{hint}\n服务端原话：{detail}")
        }
    }
}

impl std::error::Error for SignalError {}

/// 一个网络的元信息。
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkInfo {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub cidr: String,
}

/// 本节点在服务端登记的记录。
#[derive(Debug, Clone, Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    #[serde(default)]
    pub virtual_ip: String,
    #[serde(default)]
    pub name: String,
}

/// 同网络里的另一个节点。
#[derive(Debug, Clone, Deserialize)]
pub struct PeerInfo {
    pub node_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub virtual_ip: String,
    #[serde(default)]
    pub nat_type: String,
    #[serde(default)]
    pub tls_fp: String,
    #[serde(default)]
    pub candidates: Vec<String>,
    #[serde(default)]
    pub last_seen: i64,
    /// 服务端判定的在线状态。老版本 Worker 不返回这个字段：缺省按"在线"处理，
    /// 保持旧行为（照常尝试拨号），而不是把所有人都当成离线。
    #[serde(default = "default_online")]
    pub online: bool,
}

fn default_online() -> bool {
    true
}

impl PeerInfo {
    /// 候选地址转成可打洞的 SocketAddr，顺手丢掉解析不了的（服务端已经校验过一遍）。
    pub fn socket_addrs(&self) -> Vec<std::net::SocketAddr> {
        self.candidates
            .iter()
            .filter_map(|c| c.parse().ok())
            .collect()
    }

    /// 掉线多久了（秒）。服务端时间与本机可能有偏差，只用于展示。
    pub fn idle_secs(&self) -> i64 {
        let now = now_ms() as i64;
        ((now - self.last_seen).max(0)) / 1000
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegisterReply {
    pub network: NetworkInfo,
    pub node: NodeInfo,
    #[serde(default)]
    pub peers: Vec<PeerInfo>,
    #[serde(default)]
    pub durable: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConnectReply {
    #[serde(default)]
    pub t: i64,
    #[serde(default)]
    pub target_candidates: Vec<String>,
    #[serde(default)]
    pub target_virtual_ip: String,
    #[serde(default)]
    pub target_tls_fp: String,
}

impl ConnectReply {
    pub fn socket_addrs(&self) -> Vec<std::net::SocketAddr> {
        self.target_candidates
            .iter()
            .filter_map(|c| c.parse().ok())
            .collect()
    }
}

/// 一条待处理事件。`data` 里是原始字段（`from`、`candidates`、`virtual_ip`…）。
#[derive(Debug, Clone, Deserialize)]
pub struct Event {
    #[serde(default)]
    pub seq: i64,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(flatten)]
    pub data: Map<String, Value>,
}

impl Event {
    pub fn str(&self, key: &str) -> Option<&str> {
        self.data.get(key).and_then(Value::as_str)
    }

    pub fn strings(&self, key: &str) -> Vec<String> {
        self.data
            .get(key)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct EventsReply {
    #[serde(default)]
    pub cursor: i64,
    #[serde(default)]
    pub events: Vec<Event>,
}

/// 管理面看到的一个网络（`qp2p nets`）。
#[derive(Debug, Clone, Deserialize)]
pub struct AdminNetwork {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub cidr: String,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub nodes: i64,
    #[serde(default)]
    pub has_join_key: bool,
}

/// 建网 / 换密钥的结果。
#[derive(Debug, Clone, Deserialize)]
pub struct IssuedNetwork {
    pub network: NetworkInfo,
    pub token: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub warning: String,
}

/// 服务端自检结果（`qp2p init` 用来确认地址填对了）。
#[derive(Debug, Clone, Deserialize)]
pub struct Health {
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub storage: String,
    #[serde(default)]
    pub has_admin_secret: bool,
    #[serde(default)]
    pub warning: String,
    #[serde(default)]
    pub nodes: Option<i64>,
}

/// 信令客户端：一个实例绑定一个网络令牌。
#[derive(Clone)]
pub struct SignalClient {
    base: String,
    token: String,
    network_id: String,
    http: reqwest::Client,
}

impl std::fmt::Debug for SignalClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignalClient")
            .field("base", &self.base)
            .field("network_id", &self.network_id)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl SignalClient {
    pub fn new(worker: &str, token: &str) -> Result<Self> {
        let base = normalize_worker(worker)?;
        let (network_id, _) = parse_token(token.trim()).ok_or_else(|| {
            anyhow::anyhow!(
                "令牌格式不对：应为 {TOKEN_PREFIX}<网络>_<密钥>，你给的是 {:?}",
                preview(token)
            )
        })?;

        Ok(Self {
            http: build_http_for(&base)?,
            base,
            token: token.trim().to_string(),
            network_id: network_id.to_string(),
        })
    }

    /// 只做管理操作（建网 / 换密钥）的客户端：不需要加入令牌。
    pub fn admin(worker: &str) -> Result<Self> {
        let base = normalize_worker(worker)?;
        Ok(Self {
            http: build_http_for(&base)?,
            base,
            token: String::new(),
            network_id: String::new(),
        })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    // ---- 管理面（只有建网的人需要 ADMIN_SECRET） -------------------------

    /// 检查 Worker 是否可用。匿名探测，只拿得到 `ok`。
    ///
    /// 不需要令牌——`qp2p init` 就是要在还没有网络的时候先探一下。
    pub async fn health(&self) -> Result<Health> {
        health_of(&self.base, None).await
    }

    /// 建一个网络。密钥留空则让服务端生成随机的（更安全）。
    pub async fn create_network(
        &self,
        admin_secret: &str,
        name: &str,
        join_key: Option<&str>,
        cidr: Option<&str>,
    ) -> Result<IssuedNetwork> {
        let mut body = Map::new();
        body.insert("name".into(), Value::String(name.to_string()));
        if let Some(key) = join_key {
            body.insert("join_key".into(), Value::String(key.to_string()));
        }
        if let Some(cidr) = cidr {
            body.insert("cidr".into(), Value::String(cidr.to_string()));
        }

        let value = self
            .post_admin("/v1/admin/networks", admin_secret, Value::Object(body))
            .await?;
        parse_issued(value)
    }

    /// 换掉某个网络的加入密钥；旧令牌立刻失效，成员需要重新 join。
    pub async fn rotate_join_key(
        &self,
        admin_secret: &str,
        network_id: &str,
        join_key: Option<&str>,
    ) -> Result<IssuedNetwork> {
        let mut body = Map::new();
        if let Some(key) = join_key {
            body.insert("join_key".into(), Value::String(key.to_string()));
        }
        let path = format!("/v1/admin/networks/{network_id}/rotate");
        let value = self
            .post_admin(&path, admin_secret, Value::Object(body))
            .await?;
        parse_issued(value)
    }

    /// 列出所有网络（管理面）。
    pub async fn list_networks(&self, admin_secret: &str) -> Result<Vec<AdminNetwork>> {
        let url = format!("{}/v1/admin/networks", self.base);
        let res = self
            .http
            .get(&url)
            .header("x-admin-secret", admin_secret)
            .send()
            .await
            .with_context(|| format!("连不上 {url}（检查 Worker 地址和网络）"))?;
        let value = self.read(res).await?;
        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(default)]
            networks: Vec<AdminNetwork>,
        }
        Ok(serde_json::from_value::<Wrapper>(value)
            .context("服务端返回的网络列表格式不对")?
            .networks)
    }

    /// 删除网络（连同节点与事件）。返回清理掉的节点数。
    ///
    /// 服务端要求 `confirm` 与网络 id 一致，这里照做——这一步不可撤销。
    pub async fn delete_network(&self, admin_secret: &str, network_id: &str) -> Result<i64> {
        let url = format!("{}/v1/admin/networks/{}", self.base, network_id);
        let body = serde_json::json!({ "confirm": network_id });
        let res = self
            .http
            .delete(&url)
            .header("x-admin-secret", admin_secret)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(&body)?)
            .send()
            .await
            .with_context(|| format!("连不上 {url}（检查 Worker 地址和网络）"))?;
        let value = self.read(res).await?;
        Ok(value
            .get("removed_nodes")
            .and_then(Value::as_i64)
            .unwrap_or(0))
    }

    // ---- 数据面 ---------------------------------------------------------

    /// 注册（或刷新）本节点，返回服务端分配的虚拟地址和当前成员列表。
    pub async fn register(
        &self,
        identity: &Identity,
        name: &str,
        tls_fp: &str,
        candidates: &[String],
        nat_type: &str,
        virtual_ip: Option<std::net::Ipv4Addr>,
    ) -> Result<RegisterReply> {
        let node_id = identity.node_id();
        let mut body = Map::new();
        body.insert("node_id".into(), Value::String(node_id.to_string()));
        body.insert(
            "pubkey".into(),
            Value::String(hex::encode(identity.public_key())),
        );
        body.insert("name".into(), Value::String(name.to_string()));
        body.insert("tls_fp".into(), Value::String(tls_fp.to_string()));
        body.insert("nat_type".into(), Value::String(nat_type.to_string()));
        body.insert(
            "candidates".into(),
            Value::Array(candidates.iter().cloned().map(Value::String).collect()),
        );
        // 只在用户明确指定时带上：不指定就由服务端分配并在重连后保持不变
        if let Some(ip) = virtual_ip {
            body.insert("virtual_ip".into(), Value::String(ip.to_string()));
        }

        let value = self
            .post_signed("/v1/register", "register", identity, body)
            .await?;
        serde_json::from_value(value).context("服务端返回的注册结果格式不对")
    }

    /// 只加入、不要求候选地址；用来验证令牌、刷新在线状态、拿成员列表。
    pub async fn join(
        &self,
        identity: &Identity,
        name: &str,
        virtual_ip: Option<std::net::Ipv4Addr>,
    ) -> Result<RegisterReply> {
        let node_id = identity.node_id();
        let mut body = Map::new();
        body.insert("node_id".into(), Value::String(node_id.to_string()));
        body.insert(
            "pubkey".into(),
            Value::String(hex::encode(identity.public_key())),
        );
        body.insert("name".into(), Value::String(name.to_string()));
        // 空数组不会覆盖服务端已有的候选，只更新心跳
        body.insert("candidates".into(), Value::Array(Vec::new()));
        if let Some(ip) = virtual_ip {
            body.insert("virtual_ip".into(), Value::String(ip.to_string()));
        }

        let value = self.post_signed("/v1/join", "join", identity, body).await?;
        serde_json::from_value(value).context("服务端返回的加入结果格式不对")
    }

    /// 请求与某个节点撮合打洞：服务端把我们的候选推给它，并返回它的候选。
    pub async fn connect(&self, identity: &Identity, target: &NodeId) -> Result<ConnectReply> {
        let mut body = Map::new();
        body.insert("from".into(), Value::String(identity.node_id().to_string()));
        body.insert("target".into(), Value::String(target.to_string()));

        let value = self
            .post_signed("/v1/connect", "connect", identity, body)
            .await?;
        serde_json::from_value(value).context("服务端返回的撮合结果格式不对")
    }

    /// 拉取待处理事件（顺便当心跳）。
    pub async fn events(&self, identity: &Identity, since: i64) -> Result<EventsReply> {
        let ts = now_ms();
        let nonce = random_nonce();
        let node_id = identity.node_id().to_string();

        let mut body = Map::new();
        body.insert("node_id".into(), Value::String(node_id.clone()));
        body.insert("since".into(), Value::from(since));
        body.insert("ts".into(), Value::from(ts));
        body.insert("nonce".into(), Value::String(nonce.clone()));

        let digest = body_digest(&Value::Object(body)).context("事件请求无法规范化（内部错误）")?;
        let message = signing_message("events", &self.network_id, ts, &nonce, &digest);
        let sig = hex::encode(identity.sign(message.as_bytes()));

        let url = format!(
            "{}/v1/events?node_id={node_id}&since={since}&ts={ts}&nonce={nonce}&sig={sig}",
            self.base
        );
        let res = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .with_context(|| format!("拉取事件失败：连不上 {}", self.base))?;
        let value = self.read(res).await?;
        serde_json::from_value(value).context("服务端返回的事件格式不对")
    }

    /// 生成 WebSocket 握手地址（`wss://…/v1/ws?…&sig=…`）。
    ///
    /// 签名与 `/v1/events` 同规则，只是 op 换成 `ws`、摘要多一个 `caps` 字段：
    /// 摘要是 `canonicalJson({node_id, since, ts, nonce, caps})`，其中 **caps 是
    /// 排序后逗号拼接的字符串**——服务端按同样规则算，两边只需对一个字符串。
    /// 令牌不进 URL（会落进访问日志），由调用方用 `Authorization` 头发。
    pub fn ws_url(&self, identity: &Identity, since: i64, caps: &[&str]) -> Result<String> {
        let mut sorted: Vec<&str> = caps.to_vec();
        sorted.sort_unstable();
        let caps_str = sorted.join(",");

        let ts = now_ms();
        let nonce = random_nonce();
        let node_id = identity.node_id().to_string();

        let mut body = Map::new();
        body.insert("node_id".into(), Value::String(node_id.clone()));
        body.insert("since".into(), Value::from(since));
        body.insert("ts".into(), Value::from(ts));
        body.insert("nonce".into(), Value::String(nonce.clone()));
        body.insert("caps".into(), Value::String(caps_str.clone()));

        let digest = body_digest(&Value::Object(body)).context("握手请求无法规范化（内部错误）")?;
        let message = signing_message("ws", &self.network_id, ts, &nonce, &digest);
        let sig = hex::encode(identity.sign(message.as_bytes()));

        let ws_base = if let Some(rest) = self.base.strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = self.base.strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            anyhow::bail!("Worker 地址必须是 http(s) 开头");
        };

        Ok(format!(
            "{ws_base}/v1/ws?node_id={node_id}&since={since}&ts={ts}&nonce={nonce}&caps={caps_str}&sig={sig}"
        ))
    }

    /// 下线：把本节点从网络里删掉，别人就不会再尝试连它。
    pub async fn leave(&self, identity: &Identity) -> Result<()> {
        let mut body = Map::new();
        body.insert(
            "node_id".into(),
            Value::String(identity.node_id().to_string()),
        );
        body.insert(
            "pubkey".into(),
            Value::String(hex::encode(identity.public_key())),
        );
        self.post_signed("/v1/leave", "leave", identity, body)
            .await
            .map(|_| ())
    }

    // ---- 内部 -----------------------------------------------------------

    async fn post_admin(&self, path: &str, admin_secret: &str, body: Value) -> Result<Value> {
        let url = format!("{}{}", self.base, path);
        let res = self
            .http
            .post(&url)
            .header("x-admin-secret", admin_secret)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(&body)?)
            .send()
            .await
            .with_context(|| format!("连不上 {url}（检查 Worker 地址和网络）"))?;
        self.read(res).await
    }

    async fn post_signed(
        &self,
        path: &str,
        op: &str,
        identity: &Identity,
        mut body: Map<String, Value>,
    ) -> Result<Value> {
        let ts = now_ms();
        let nonce = random_nonce();
        body.insert("ts".into(), Value::from(ts));
        body.insert("nonce".into(), Value::String(nonce.clone()));

        // 签名覆盖除 sig 之外的整个请求体：ts/nonce 也在里面，改任何一项都会失效
        let digest = body_digest(&Value::Object(body.clone()))
            .context("请求体无法规范化（数字必须是 ±2^53 以内的整数）")?;
        let message = signing_message(op, &self.network_id, ts, &nonce, &digest);
        let sig = hex::encode(identity.sign(message.as_bytes()));
        body.insert("sig".into(), Value::String(sig));

        let url = format!("{}{}", self.base, path);
        let res = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(&Value::Object(body))?)
            .send()
            .await
            .with_context(|| format!("连不上 {url}（检查 Worker 地址和网络）"))?;
        self.read(res).await
    }

    async fn read(&self, res: reqwest::Response) -> Result<Value> {
        let status = res.status();
        let text = res
            .text()
            .await
            .context("读取服务端响应失败（连接被中断）")?;
        let parsed: Value = serde_json::from_str(&text).unwrap_or(Value::Null);

        let ok = parsed.get("ok").and_then(Value::as_bool);
        if status.is_success() && ok != Some(false) {
            return Ok(parsed);
        }

        // Worker 用 detail 字段；老版本/别处可能叫 message，两个都认
        let message = parsed
            .get("detail")
            .or_else(|| parsed.get("message"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| text.trim().chars().take(200).collect());

        Err(SignalError {
            status: status.as_u16(),
            code: parsed
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("http_error")
                .to_string(),
            message,
        }
        .into())
    }
}

fn parse_issued(value: Value) -> Result<IssuedNetwork> {
    serde_json::from_value(value).context("服务端返回的建网结果格式不对")
}

/// 按目标地址决定要不要走系统代理。
///
/// reqwest 会读 `HTTP_PROXY` / `HTTPS_PROXY`，这点对访问 workers.dev 是好事
/// （国内经常需要代理），但它对**回环和内网地址**也照样转发：
/// 本机联调会变成"请求发给代理再回环"，局域网自建的信令服务更是直接连不上。
/// 所以这两类地址显式绕过代理。
fn build_http_for(base: &str) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .user_agent(concat!("qp2p/", env!("CARGO_PKG_VERSION")));
    if is_local_target(base) {
        builder = builder.no_proxy();
    }
    builder.build().context("初始化 HTTP 客户端失败")
}

/// 目标是不是回环 / 私有网段（这类地址绝不该经过代理）。
fn is_local_target(base: &str) -> bool {
    let host = base
        .split("://")
        .nth(1)
        .unwrap_or(base)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");

    // 去掉端口，IPv6 字面量保留方括号里的内容
    let host = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or("").to_string()
    } else {
        host.split(':').next().unwrap_or("").to_string()
    };

    if host == "localhost" || host.ends_with(".localhost") || host == "::1" {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified()
        }
        Ok(std::net::IpAddr::V6(ip)) => ip.is_loopback() || ip.is_unspecified(),
        Err(_) => false,
    }
}

/// 探测一个 Worker 地址。
///
/// 不需要令牌。但服务端只对**带对管理密钥**的请求返回版本、存储、节点数这些
/// 部署详情，匿名请求只会拿到 `{"ok":true}`——它不该变成公开的资产清单。
pub async fn health_of(worker: &str, admin: Option<&str>) -> Result<Health> {
    let base = normalize_worker(worker)?;
    let url = format!("{base}/v1/health");
    let mut request = build_http_for(&base)?.get(&url);
    if let Some(secret) = admin {
        request = request.header("x-admin-secret", secret);
    }
    let res = request
        .send()
        .await
        .with_context(|| format!("连不上 {url}（检查地址、本机网络，或换一个能访问的域名）"))?;

    let status = res.status();
    let text = res.text().await.context("读取 health 响应失败")?;
    let value: Value = serde_json::from_str(&text).with_context(|| {
        format!("{url} 返回的不是 JSON（HTTP {status}），这个地址不是 qp2p 信令服务")
    })?;

    if let Some(error) = value.get("error").and_then(Value::as_str) {
        return Err(SignalError {
            status: status.as_u16(),
            code: error.to_string(),
            message: value
                .get("detail")
                .or_else(|| value.get("message"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        }
        .into());
    }

    serde_json::from_value(value).context("health 返回格式不对（Worker 版本太旧？）")
}

/// 统一成不带尾斜杠的基地址；顺手接受用户直接粘贴带 `/v1/...` 的地址。
pub fn normalize_worker(raw: &str) -> Result<String> {
    let text = raw.trim().trim_end_matches('/');
    if text.is_empty() {
        anyhow::bail!("Worker 地址不能为空");
    }
    let text = match text.find("/v1/") {
        Some(index) => &text[..index],
        None => text,
    };
    if !(text.starts_with("http://") || text.starts_with("https://")) {
        anyhow::bail!("Worker 地址要以 https:// 开头（例如 https://p2p.example.com）：{raw}");
    }
    Ok(text.trim_end_matches('/').to_string())
}

/// 从用户可能粘贴的各种形式里取出令牌：
/// 纯令牌、`https://worker/?token=...`、`qp2p join <token>` 都认。
pub fn extract_token(raw: &str) -> Option<String> {
    let text = raw.trim();
    let text = text.strip_prefix("qp2p join").unwrap_or(text).trim();

    // 只认"确实能被 parse_token 拆开"的串：`qp2p1_home` 这种少了密钥的不算
    let valid = |value: &str| parse_token(value).is_some();

    if valid(text) {
        return Some(text.to_string());
    }
    for marker in ["token=", "key="] {
        if let Some(index) = text.find(marker) {
            let rest = &text[index + marker.len()..];
            let value = rest.split(['&', '#', ' ']).next().unwrap_or(rest);
            if valid(value) {
                return Some(value.to_string());
            }
        }
    }
    None
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn random_nonce() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// 日志/报错里只露出令牌的头尾，避免整串进终端回滚缓冲。
fn preview(token: &str) -> String {
    let text = token.trim();
    if text.chars().count() <= 24 {
        return text.to_string();
    }
    let head: String = text.chars().take(12).collect();
    let tail: String = text.chars().skip(text.chars().count() - 4).collect();
    format!("{head}…{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_address_is_normalized() {
        assert_eq!(
            normalize_worker("https://p2p.example.com/").unwrap(),
            "https://p2p.example.com"
        );
        assert_eq!(
            normalize_worker("https://p2p.example.com/v1/health").unwrap(),
            "https://p2p.example.com"
        );
        assert!(normalize_worker("p2p.example.com").is_err());
        assert!(normalize_worker("  ").is_err());
    }

    #[test]
    fn token_is_extracted_from_every_shape_users_paste() {
        let token = "qp2p1_home_abcdef0123456789";
        assert_eq!(extract_token(token).as_deref(), Some(token));
        assert_eq!(
            extract_token("  qp2p1_home_abcdef0123456789  ").as_deref(),
            Some(token)
        );
        assert_eq!(
            extract_token("https://p2p.example.com/?token=qp2p1_home_abcdef0123456789&x=1")
                .as_deref(),
            Some(token)
        );
        assert_eq!(
            extract_token("qp2p join qp2p1_home_abcdef0123456789").as_deref(),
            Some(token)
        );
        assert!(extract_token("https://p2p.example.com/").is_none());
        assert!(extract_token("qp2p1_home").is_none());
    }

    #[test]
    fn local_targets_bypass_the_proxy() {
        for local in [
            "http://127.0.0.1:8787",
            "http://localhost:8787",
            "http://[::1]:8787",
            "http://192.168.1.10",
            "http://10.64.0.1:9000",
            "http://172.16.5.4",
        ] {
            assert!(is_local_target(local), "{local} 应当直连");
        }
        for remote in [
            "https://p2p.example.com",
            "https://p2p.coj.workers.dev",
            "http://8.8.8.8:80",
        ] {
            assert!(!is_local_target(remote), "{remote} 应当可以走代理");
        }
    }

    #[test]
    fn client_rejects_bad_token_early() {
        let err = SignalClient::new("https://x.example.com", "nope").unwrap_err();
        assert!(format!("{err:#}").contains("令牌格式"), "{err:#}");
    }

    #[test]
    fn error_messages_are_actionable() {
        let err = SignalError {
            status: 403,
            code: "bad_signature".into(),
            message: "ts 超出 ±120 秒窗口".into(),
        };
        let text = err.to_string();
        assert!(text.contains("时钟"), "{text}");
        assert!(text.contains("ts 超出"), "{text}");
    }

    #[test]
    fn peer_addresses_parse() {
        let peer = PeerInfo {
            node_id: "a".repeat(32),
            name: "x".into(),
            virtual_ip: "10.64.1.2".into(),
            nat_type: String::new(),
            tls_fp: String::new(),
            candidates: vec!["203.0.113.7:51820".into(), "bogus".into()],
            last_seen: 0,
            online: true,
        };
        assert_eq!(peer.socket_addrs().len(), 1);
    }
}
