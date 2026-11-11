//! Cloudflare API 的最小封装。
//!
//! 只包部署需要的几个调用，不做通用 SDK。所有失败都带上 Cloudflare 的
//! `errors[{code,message}]` —— 它的错误码比 HTTP 状态码有用得多
//! （比如 10021 是 metadata 结构不对、10090 是迁移被拒）。

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

const DEFAULT_BASE: &str = "https://api.cloudflare.com/client/v4";

pub struct Client {
    http: reqwest::Client,
    token: String,
    account: String,
    base: String,
}

impl Client {
    /// `base` 可以指向本地假服务端，便于对着模拟 API 跑测试。
    pub fn new(token: &str, account: &str, base: Option<&str>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("qp2p-deploy/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(90))
            .build()
            .context("初始化 HTTP 客户端失败")?;
        Ok(Self {
            http,
            token: token.to_string(),
            account: account.to_string(),
            base: base
                .unwrap_or(DEFAULT_BASE)
                .trim_end_matches('/')
                .to_string(),
        })
    }

    /// 统一解析 `{success, errors, result}`；429 与 5xx 退避重试 3 次。
    async fn call(&self, req: reqwest::RequestBuilder) -> Result<Value> {
        let mut delay = Duration::from_secs(1);
        let mut last = String::from("未知错误");

        for attempt in 0..3 {
            let Some(retry) = req.try_clone() else {
                bail!("这个请求无法重试（请求体不是可克隆的），请改用不支持重试的调用");
            };
            let res = retry
                .bearer_auth(&self.token)
                .send()
                .await
                .with_context(|| format!("连不上 Cloudflare API（{}）", self.base))?;

            let status = res.status();
            let body: Value = res.json().await.unwrap_or(Value::Null);

            if body.get("success").and_then(Value::as_bool) == Some(true) {
                return Ok(body.get("result").cloned().unwrap_or(Value::Null));
            }

            last = describe_errors(&body, status.as_u16());
            if (status.as_u16() == 429 || status.is_server_error()) && attempt < 2 {
                eprintln!("  · {last}，{} 秒后重试", delay.as_secs());
                tokio::time::sleep(delay).await;
                delay *= 2;
                continue;
            }
            break;
        }

        Err(anyhow!(last))
    }

    pub async fn verify_token(&self) -> Result<()> {
        let res = self
            .call(self.http.get(format!("{}/user/tokens/verify", self.base)))
            .await
            .context("令牌校验失败（检查令牌是否有效、有没有 Workers 权限）")?;
        let status = res.get("status").and_then(Value::as_str).unwrap_or("");
        if status != "active" {
            bail!("令牌状态是 {status:?}，不是 active");
        }
        Ok(())
    }

    pub async fn find_d1(&self, name: &str) -> Result<Option<String>> {
        let url = format!(
            "{}/accounts/{}/d1/database?name={}",
            self.base, self.account, name
        );
        let res = self.call(self.http.get(url)).await?;
        let hit = res
            .as_array()
            .and_then(|list| {
                list.iter()
                    .find(|db| db.get("name").and_then(Value::as_str) == Some(name))
            })
            .and_then(|db| db.get("uuid").and_then(Value::as_str));
        Ok(hit.map(str::to_string))
    }

    pub async fn create_d1(&self, name: &str) -> Result<String> {
        let url = format!("{}/accounts/{}/d1/database", self.base, self.account);
        let res = self
            .call(self.http.post(url).json(&json!({ "name": name })))
            .await
            .with_context(|| format!("创建 D1 数据库 {name} 失败"))?;
        res.get("uuid")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| anyhow!("创建 D1 后没拿到 uuid，返回：{res}"))
    }

    /// 按名字找库，没有才建。
    pub async fn ensure_d1(&self, name: &str) -> Result<String> {
        if let Some(id) = self.find_d1(name).await? {
            return Ok(id);
        }
        self.create_d1(name).await
    }

    /// 脚本是否存在（顺便确认令牌能读这个 Worker）。
    ///
    /// 用 `/settings` 而不是脚本本身：后者返回的是源码，不是 JSON。
    pub async fn script_exists(&self, name: &str) -> Result<bool> {
        let url = format!(
            "{}/accounts/{}/workers/scripts/{}/settings",
            self.base, self.account, name
        );
        match self.call(self.http.get(url)).await {
            Ok(_) => Ok(true),
            Err(e) => {
                let text = format!("{e:#}");
                if text.contains("10007") || text.contains("not found") || text.contains("404") {
                    Ok(false)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// 上传脚本。**这个调用不能重试**：multipart 请求体不可克隆。
    pub async fn upload(&self, name: &str, metadata: &Value, source: &str) -> Result<Value> {
        let form = reqwest::multipart::Form::new()
            .part(
                "metadata",
                reqwest::multipart::Part::text(metadata.to_string())
                    .mime_str("application/json")
                    .context("metadata 不是合法 JSON")?,
            )
            .part(
                "worker.js",
                reqwest::multipart::Part::text(source.to_string())
                    // 文件名必须与 main_module 一致，否则报 No such module
                    .file_name("worker.js")
                    .mime_str("application/javascript+module")
                    .context("脚本 part 的 content-type 不合法")?,
            );

        let url = format!(
            "{}/accounts/{}/workers/scripts/{}",
            self.base, self.account, name
        );
        let res = self
            .http
            .put(url)
            .bearer_auth(&self.token)
            .multipart(form)
            .send()
            .await
            .context("上传 Worker 失败（连不上 API）")?;

        let status = res.status();
        let body: Value = res.json().await.unwrap_or(Value::Null);
        if body.get("success").and_then(Value::as_bool) != Some(true) {
            bail!("上传被拒：{}", describe_errors(&body, status.as_u16()));
        }
        Ok(body.get("result").cloned().unwrap_or(Value::Null))
    }

    pub async fn enable_workers_dev(&self, name: &str) -> Result<()> {
        let url = format!(
            "{}/accounts/{}/workers/scripts/{}/subdomain",
            self.base, self.account, name
        );
        // 预览 URL 默认会开，这里显式关掉：多一个入口就多一份暴露面
        self.call(
            self.http
                .post(url)
                .json(&json!({ "enabled": true, "previews_enabled": false })),
        )
        .await
        .with_context(|| format!("启用 {name} 的 workers.dev 子域失败"))?;
        Ok(())
    }

    pub async fn subdomain(&self) -> Result<String> {
        let url = format!("{}/accounts/{}/workers/subdomain", self.base, self.account);
        let res = self.call(self.http.get(url)).await?;
        res.get("subdomain")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                anyhow!(
                    "这个账号还没有 workers.dev 子域，先去控制台 Workers 页面创建一个（我不会替你起名）"
                )
            })
    }

    pub async fn delete_script(&self, name: &str) -> Result<()> {
        let url = format!(
            "{}/accounts/{}/workers/scripts/{}",
            self.base, self.account, name
        );
        self.call(self.http.delete(url))
            .await
            .with_context(|| format!("删除 Worker {name} 失败"))?;
        Ok(())
    }

    pub async fn set_secret(&self, name: &str, key: &str, value: &str) -> Result<()> {
        let url = format!(
            "{}/accounts/{}/workers/scripts/{}/secrets",
            self.base, self.account, name
        );
        self.call(
            self.http
                .put(url)
                .json(&json!({ "name": key, "text": value, "type": "secret_text" })),
        )
        .await
        .with_context(|| format!("设置密钥 {key} 失败"))?;
        Ok(())
    }
}

fn describe_errors(body: &Value, status: u16) -> String {
    let mut out = String::new();
    if let Some(list) = body.get("errors").and_then(Value::as_array) {
        for e in list {
            let code = e.get("code").and_then(Value::as_i64).unwrap_or(0);
            let text = e.get("message").and_then(Value::as_str).unwrap_or("");
            if !out.is_empty() {
                out.push_str("；");
            }
            out.push_str(&format!("[{code}] {text}"));
        }
    }
    if out.is_empty() {
        format!("HTTP {status}")
    } else {
        format!("HTTP {status} {out}")
    }
}
