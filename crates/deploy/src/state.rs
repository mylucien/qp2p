//! 本地部署状态：记住上次部署到哪一步。
//!
//! **只存非敏感信息**。令牌和密钥永不落盘——令牌丢了可以再建，
//! 密钥只在新生成时显示一次。

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct State {
    pub worker: String,
    pub account_id: String,
    pub subdomain: String,
    /// 上次成功部署的迁移标签；空表示从没成功过（下次会从头规划）
    pub migration_tag: String,
    pub updated_at: u64,
}

fn path() -> Result<PathBuf> {
    if let Ok(custom) = std::env::var("QP2P_DEPLOY_STATE") {
        return Ok(PathBuf::from(custom));
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .context("找不到家目录（HOME / USERPROFILE 都没设置）")?;
    Ok(PathBuf::from(home).join(".qp2p").join("deploy.json"))
}

pub fn load() -> Result<State> {
    let p = path()?;
    match std::fs::read_to_string(&p) {
        Ok(text) => serde_json::from_str(&text)
            .with_context(|| format!("{} 不是合法的部署状态，删掉它即可重建", p.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
        Err(e) => Err(e).with_context(|| format!("读不了 {}", p.display())),
    }
}

pub fn save(state: &State) -> Result<()> {
    let p = path()?;
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("建不了目录 {}", dir.display()))?;
    }
    std::fs::write(&p, serde_json::to_string_pretty(state)?)
        .with_context(|| format!("写不了 {}", p.display()))?;
    Ok(())
}

pub fn path_display() -> String {
    path().map(|p| p.display().to_string()).unwrap_or_default()
}
