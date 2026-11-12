//! WebSocket 客户端：事件推送与保活。
//!
//! 与 `SignalClient::events` 的关系：轮询是"我去问"，这里是"服务端推给我"。
//! 两者产出的 [`Event`] 完全同构，调用方不需要区别对待——差别只在延迟和请求数
//! （轮询每个节点每天约 1440 次请求，长连接约 260 次）。
//!
//! 保活做在 [`WsLink::next`] 内部：调用方只要一直读，ping 就会每 25 秒发一次，
//! 10 秒收不到 pong 就判成半开并返回 [`WsItem::Down`]。之所以不单独起任务，
//! 是因为一条连接被两处并发写会让帧交错的排查变得很难。

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::Value;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use super::client::{Event, SignalClient};
use crate::identity::Identity;

/// TCP + TLS + HTTP 升级三段的统一上限。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// 等 hello 的上限：超时说明服务端卡在验签或建 socket 上。
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// 服务端没下发 limits 时的兜底。
const DEFAULT_PING_EVERY: Duration = Duration::from_secs(25);
const DEFAULT_PONG_TIMEOUT: Duration = Duration::from_secs(10);

/// 握手被服务端以 HTTP 状态码拒绝。
///
/// 单独成一个错误类型，是为了让调用方能区分"网络抖一下"和"令牌已经废了"：
/// 后者再重试一万次也不会成功，必须停下来告诉用户。
#[derive(Debug, Clone)]
pub struct HandshakeRejected {
    pub status: u16,
    /// 服务端错误体（`{ok:false,error,detail}` 的原文，截断过）
    pub detail: String,
}

impl std::fmt::Display for HandshakeRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.detail.is_empty() {
            write!(f, "服务端拒绝握手（HTTP {}）", self.status)
        } else {
            write!(f, "服务端拒绝握手（HTTP {}）：{}", self.status, self.detail)
        }
    }
}

impl std::error::Error for HandshakeRejected {}

impl HandshakeRejected {
    /// 令牌不对 / 签名不对 / 密钥已轮换：重试没有意义。
    pub fn is_auth_failure(&self) -> bool {
        matches!(self.status, 401 | 403)
    }

    /// 服务端明确表示没有 Durable Object：直接退回轮询，不用等失败次数攒够。
    pub fn is_unsupported(&self) -> bool {
        self.status == 501
    }
}

/// 握手成功后服务端下发的第一条消息。
#[derive(Debug, Clone, Deserialize)]
pub struct Hello {
    #[serde(default)]
    pub v: u32,
    #[serde(default)]
    pub server_ms: u64,
    /// 服务端当前最大事件序号。
    #[serde(default)]
    pub cursor: i64,
    /// 数据代次：与本地记录的不同，说明服务端数据被重建过。
    #[serde(default)]
    pub epoch: String,
    #[serde(default)]
    pub limits: Limits,
}

/// 阈值由服务端下发，客户端不再各写一份。
#[derive(Debug, Clone, Deserialize)]
pub struct Limits {
    #[serde(default)]
    pub ping_every_ms: u64,
    #[serde(default)]
    pub pong_timeout_ms: u64,
    #[serde(default)]
    pub ws_grace_ms: u64,
    #[serde(default)]
    pub offline_ms: u64,
    #[serde(default)]
    pub heartbeat_ms: u64,
    #[serde(default)]
    pub max_nodes: i64,
    #[serde(default)]
    pub max_events: i64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            ping_every_ms: 25_000,
            pong_timeout_ms: 10_000,
            ws_grace_ms: 75_000,
            offline_ms: 150_000,
            heartbeat_ms: 55_000,
            max_nodes: 0,
            max_events: 0,
        }
    }
}

impl Limits {
    fn ping_every(&self) -> Duration {
        if self.ping_every_ms == 0 {
            DEFAULT_PING_EVERY
        } else {
            Duration::from_millis(self.ping_every_ms)
        }
    }

    fn pong_timeout(&self) -> Duration {
        if self.pong_timeout_ms == 0 {
            DEFAULT_PONG_TIMEOUT
        } else {
            Duration::from_millis(self.pong_timeout_ms)
        }
    }
}

/// 从连接上读出来的一件事。
#[derive(Debug, Clone)]
pub enum WsItem {
    /// 一条事件，与 HTTP `/v1/events` 返回的元素同构。
    Event(Event),
    /// `connect_ok` 的原始载荷（已把 `punch_at` 补回 `t`，与 HTTP `ConnectReply` 一致）。
    ConnectOk(Value),
    /// 撮合失败的应答。
    ConnectError {
        req: Option<i64>,
        error: String,
        detail: String,
    },
    /// 被踢下线（随后服务端会以 4401 关闭）。
    Kick(String),
    /// 补发结束，带上新的游标。
    ResumeOk(i64),
    /// 连接关闭。
    Closed { code: u16, reason: String },
    /// 连接坏了（半开、读失败、pong 超时），应按退避重连。
    Down(String),
}

type Sink = SplitSink<WebSocketStream<TlsStream<TcpStream>>, Message>;
type Source = SplitStream<WebSocketStream<TlsStream<TcpStream>>>;

/// 一条活着的信令长连接。
pub struct WsLink {
    tx: Sink,
    rx: Source,
    hello: Hello,
    /// 已处理到的最大序号，用来丢弃重复下发的事件。
    cursor: i64,
    /// 发 ping 的时刻；收到 pong 就清空，超时未清则判半开。
    ping_sent: Option<Instant>,
    pong_timeout: Duration,
    ticker: tokio::time::Interval,
}

impl std::fmt::Debug for WsLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsLink")
            .field("epoch", &self.hello.epoch)
            .field("cursor", &self.cursor)
            .finish()
    }
}

impl WsLink {
    /// 建立连接并等 hello。
    ///
    /// `since` 是本地已处理到的序号：非 0 时服务端会在 hello 之后直接补发，
    /// 不用客户端再发一次 `resume`。
    pub async fn open(
        client: &SignalClient,
        identity: &Identity,
        since: i64,
        caps: &[&str],
    ) -> Result<Self> {
        let url = client.ws_url(identity, since, caps)?;
        let uri: tokio_tungstenite::tungstenite::http::Uri = url
            .parse()
            .with_context(|| format!("握手地址不合法：{url}"))?;
        let host = uri
            .host()
            .ok_or_else(|| anyhow!("握手地址里没有主机名：{url}"))?
            .to_string();
        let port = uri.port_u16().unwrap_or(443);

        // TCP 与 TLS 都必须设上限：对端丢包时 connect 会挂在系统默认的 ~20 秒，
        // 而调用方（后台任务）在拿到结果前不会发任何通知，主循环会误以为
        // "连接是好的，只是没有事件"——静默失联比直接报错难查得多。
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, async {
            let tcp = TcpStream::connect((host.as_str(), port))
                .await
                .with_context(|| format!("连不上 {host}:{port}"))?;
            tcp.set_nodelay(true).ok();
            tls_connect(&host, tcp).await
        })
        .await
        .map_err(|_| {
            anyhow!(
                "连接 {host}:{port} 超时（{} 秒）",
                CONNECT_TIMEOUT.as_secs()
            )
        })??;

        let mut request = url
            .as_str()
            .into_client_request()
            .context("构造 WebSocket 握手请求失败")?;
        request.headers_mut().insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {}", client.token()))
                .context("令牌里有不能放进请求头的字符")?,
        );

        let (mut ws, _resp) = match tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio_tungstenite::client_async(request, stream),
        )
        .await
        {
            Err(_) => {
                return Err(anyhow!(
                    "WebSocket 握手超时（{} 秒）",
                    CONNECT_TIMEOUT.as_secs()
                ))
            }
            Ok(Ok(pair)) => pair,
            // 服务端在升级前就用 HTTP 状态码拒绝：保留状态码与响应体，别让
            // 调用方只看到一句"握手失败"（401 和 503 的处理方式完全不同）
            Ok(Err(tokio_tungstenite::tungstenite::Error::Http(resp))) => {
                let status = resp.status().as_u16();
                let detail = resp
                    .body()
                    .as_ref()
                    .and_then(|b| String::from_utf8(b.clone()).ok())
                    .unwrap_or_default();
                return Err(anyhow::Error::new(HandshakeRejected {
                    status,
                    detail: detail.chars().take(200).collect(),
                }));
            }
            Ok(Err(e)) => {
                return Err(anyhow::Error::new(e).context(format!("WebSocket 握手被拒（{host}）")))
            }
        };

        let hello = tokio::time::timeout(HELLO_TIMEOUT, read_hello(&mut ws))
            .await
            .map_err(|_| anyhow!("等 hello 超时（服务端没有回握手的确认消息）"))??;

        let mut ticker = tokio::time::interval_at(
            tokio::time::Instant::now() + hello.limits.ping_every(),
            hello.limits.ping_every(),
        );
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let pong_timeout = hello.limits.pong_timeout();
        // 服务端的游标可能比本地小（换引擎、数据被重建）：以服务端为准。
        // 否则本地游标永远大于真实 seq，重连补发永远是空的，只能靠重启自愈。
        let cursor = since.max(0).min(hello.cursor.max(0));
        let (tx, rx) = ws.split();

        Ok(Self {
            tx,
            rx,
            hello,
            cursor,
            ping_sent: None,
            pong_timeout,
            ticker,
        })
    }

    pub fn hello(&self) -> &Hello {
        &self.hello
    }

    /// 当前已处理到的序号。
    pub fn cursor(&self) -> i64 {
        self.cursor
    }

    /// 读下一件事。内部顺带保活：到点发 `ping`，超时没 `pong` 就判半开。
    pub async fn next(&mut self) -> WsItem {
        loop {
            // pong 的超时要单独等：只在 25 秒的心跳拍子上检查，会把半开检测
            // 从设计的 10 秒拖到最多 25 秒（补发一条 ping 之后的下一拍才发现）。
            let deadline = self.ping_sent.map(|t| t + self.pong_timeout);
            tokio::select! {
                biased;

                _ = sleep_until_opt(deadline) => {
                    return WsItem::Down(format!(
                        "{} 秒没收到 pong，连接可能已经半开",
                        self.pong_timeout.as_secs()
                    ));
                }

                frame = self.rx.next() => {
                    match frame {
                        Some(Ok(Message::Text(text))) => {
                            if text == "pong" {
                                self.ping_sent = None;
                                continue;
                            }
                            match serde_json::from_str::<Value>(&text) {
                                Ok(value) => {
                                    if let Some(item) = self.decode(value) {
                                        return item;
                                    }
                                }
                                // 认不出来的帧忽略，不要因为一条坏消息断开整条连接
                                Err(e) => tracing::debug!("[ws] 收到无法解析的帧：{e}"),
                            }
                        }
                        Some(Ok(Message::Close(frame))) => {
                            let (code, reason) = match frame {
                                Some(f) => (u16::from(f.code), f.reason.to_string()),
                                None => (1005, String::new()),
                            };
                            return WsItem::Closed { code, reason };
                        }
                        Some(Ok(Message::Ping(payload))) => {
                            // tungstenite 不会替我们回 pong，得自己写出去
                            if self.tx.send(Message::Pong(payload)).await.is_err() {
                                return WsItem::Down("回 pong 失败，连接已断".into());
                            }
                        }
                        Some(Ok(_)) => {}
                        Some(Err(e)) => return WsItem::Down(format!("读取失败：{e}")),
                        None => {
                            return WsItem::Closed {
                                code: 1006,
                                reason: "连接被对端关闭".into(),
                            }
                        }
                    }
                }

                _ = self.ticker.tick() => {
                    // 上一条 ping 还在等 pong：不重复发，超时由上面的 deadline 分支管
                    if self.ping_sent.is_some() {
                        continue;
                    }
                    if self.tx.send(Message::Text("ping".into())).await.is_err() {
                        return WsItem::Down("发送 ping 失败，连接已断".into());
                    }
                    self.ping_sent = Some(Instant::now());
                }
            }
        }
    }

    /// 请求撮合。`req` 由调用方分配，应答里会原样带回。
    pub async fn request_connect(&mut self, req: i64, target: &str) -> Result<()> {
        let payload = serde_json::json!({ "t": "connect", "req": req, "target": target });
        self.send_json(&payload).await
    }

    /// 请求补发 `since` 之后的事件。
    pub async fn request_resume(&mut self, since: i64) -> Result<()> {
        let payload = serde_json::json!({ "t": "resume", "since": since });
        self.send_json(&payload).await
    }

    /// 主动下线（服务端收到后直接按离线处理并回 1000）。
    pub async fn request_leave(&mut self) -> Result<()> {
        self.send_json(&serde_json::json!({ "t": "leave" })).await
    }

    async fn send_json(&mut self, value: &Value) -> Result<()> {
        let text = serde_json::to_string(value)?;
        self.tx
            .send(Message::Text(text))
            .await
            .context("发送失败，连接已断")
    }

    /// 正常关闭。
    pub async fn close(&mut self) {
        let _ = self.tx.send(Message::Close(None)).await;
        let _ = self.tx.flush().await;
    }

    /// 把一条下行消息翻译成 [`WsItem`]；返回 `None` 表示这条不需要上报。
    fn decode(&mut self, mut value: Value) -> Option<WsItem> {
        let kind = value.get("t").and_then(Value::as_str)?.to_string();

        match kind.as_str() {
            "event" => {
                let seq = value.get("seq").and_then(Value::as_i64).unwrap_or(0);
                // seq=0 是 peer_offline 这类不落库的即时消息，不参与去重
                if seq > 0 {
                    if seq <= self.cursor {
                        return None;
                    }
                    self.cursor = seq;
                }
                if let Some(obj) = value.as_object_mut() {
                    obj.remove("t");
                    // WS 侧载荷的打洞时间叫 punch_at（避免和消息类型字段重名），
                    // 转成 Event 时补回 t，让调用方看到的结构与 HTTP 完全一致
                    if let Some(punch_at) = obj.remove("punch_at") {
                        obj.insert("t".into(), punch_at);
                    }
                }
                serde_json::from_value::<Event>(value)
                    .ok()
                    .map(WsItem::Event)
            }
            "connect_ok" => {
                if let Some(obj) = value.as_object_mut() {
                    obj.remove("t");
                    if let Some(punch_at) = obj.remove("punch_at") {
                        obj.insert("t".into(), punch_at);
                    }
                }
                Some(WsItem::ConnectOk(value))
            }
            "error" => Some(WsItem::ConnectError {
                req: value.get("req").and_then(Value::as_i64),
                error: value
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
                detail: value
                    .get("detail")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            }),
            "kick" => Some(WsItem::Kick(
                value
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("被移出网络")
                    .to_string(),
            )),
            "resume_ok" => {
                let cursor = value
                    .get("cursor")
                    .and_then(Value::as_i64)
                    .unwrap_or(self.cursor);
                if cursor > self.cursor {
                    self.cursor = cursor;
                }
                Some(WsItem::ResumeOk(cursor))
            }
            _ => None,
        }
    }
}

/// 读第一条 `hello`。
async fn read_hello<S>(ws: &mut WebSocketStream<S>) -> Result<Hello>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        match ws.next().await {
            Some(Ok(Message::Text(text))) => {
                if text == "pong" {
                    continue;
                }
                let value: Value = match serde_json::from_str(&text) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                match value.get("t").and_then(Value::as_str) {
                    Some("hello") => {
                        return serde_json::from_value(value).context("hello 的字段解析失败")
                    }
                    // 握手后服务端会紧接着补发事件（since 非 0 时），先跳过
                    _ => continue,
                }
            }
            Some(Ok(_)) => {}
            Some(Err(e)) => return Err(anyhow!("握手后立刻出错：{e}")),
            None => return Err(anyhow!("服务端在发 hello 之前就关掉了连接")),
        }
    }
}

/// TLS 连接。用 ring 作为 crypto provider，与项目里其它 rustls 用法保持一致
/// （rustls 0.23 在同时启用多个 provider 时需要显式指定，否则运行时会 panic）。
async fn tls_connect(host: &str, tcp: TcpStream) -> Result<TlsStream<TcpStream>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("初始化 TLS 协议版本失败")?
    .with_root_certificates(roots)
    .with_no_client_auth();

    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .with_context(|| format!("{host} 不是合法的服务器名"))?;

    TlsConnector::from(Arc::new(config))
        .connect(server_name, tcp)
        .await
        .with_context(|| format!("与 {host} 建立 TLS 失败"))
}

/// 等到 `deadline`；没有 deadline 就永远挂着（交给 `select!` 的其它分支）。
///
/// 存在的理由：pong 超时是一个"从发出 ping 起算的绝对时刻"，而心跳是 25 秒一拍。
/// 若只在拍子上检查，最坏要等到下一拍才发现半开（实测 25 秒，设计写的是 10 秒）。
async fn sleep_until_opt(deadline: Option<Instant>) {
    match deadline {
        Some(t) => tokio::time::sleep_until(tokio::time::Instant::from_std(t)).await,
        None => std::future::pending::<()>().await,
    }
}
