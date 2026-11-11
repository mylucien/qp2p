//! 部署后的冒烟：只读 `/v1/health`，确认版本、引擎与能力都对得上。

use anyhow::{bail, Context, Result};
use serde_json::Value;

#[derive(Debug)]
pub struct Report {
    pub version: String,
    pub engine: String,
    pub features: Vec<String>,
    pub storage: String,
}

pub async fn health(base: &str, admin: Option<&str>) -> Result<Report> {
    let url = format!("{}/v1/health", base.trim_end_matches('/'));
    let mut req = reqwest::Client::new()
        .get(&url)
        .timeout(std::time::Duration::from_secs(30));
    if let Some(secret) = admin {
        req = req.header("x-admin-secret", secret);
    }
    let res = req
        .send()
        .await
        .with_context(|| format!("连不上 {url}（子域没启用？或 Worker 还没生效）"))?;
    let status = res.status();
    let body: Value = res.json().await.unwrap_or(Value::Null);

    if body.get("ok").and_then(Value::as_bool) != Some(true) {
        bail!("{url} 返回 HTTP {status}：{}", body);
    }

    // 匿名访问只拿得到 {"ok":true}，其余字段缺省
    let text = |k: &str| {
        body.get(k)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    Ok(Report {
        version: text("version"),
        engine: text("engine"),
        storage: text("storage"),
        features: body
            .get("features")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
    })
}

impl Report {
    /// 没给管理密钥时只能确认"服务活着"，别冒充验证过版本。
    pub fn describe(&self) -> String {
        if self.version.is_empty() {
            "服务可达（没带管理密钥，看不到版本与引擎）".to_string()
        } else {
            format!(
                "版本 {} · 引擎 {} · 存储 {} · 能力 [{}]",
                self.version,
                self.engine,
                self.storage,
                self.features.join(", ")
            )
        }
    }
}
