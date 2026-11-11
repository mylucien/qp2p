//! 迁移链。
//!
//! **只允许追加**：已经发布过的步骤一个字都不能改，否则不同阶段部署的
//! 用户拿到的是两份互不兼容的历史。新增能力就往后面接一步。

#[derive(Debug, Clone)]
pub struct Step {
    pub tag: &'static str,
    /// 这一步要新建的 SQLite 类。DO 类名一旦发布就永久冻结。
    pub new_sqlite_classes: &'static [&'static str],
}

pub const CHAIN: &[Step] = &[Step {
    tag: "v1",
    new_sqlite_classes: &["NetworkRoom"],
}];

/// 链条上最新的标签。
pub fn latest_tag() -> &'static str {
    CHAIN.last().map(|s| s.tag).unwrap_or("")
}

/// 从 `current` 之后开始的步骤；`current` 为空表示全新部署。
///
/// 返回 `Err` 表示线上的标签不在这条链里——**不猜**，让人去看清楚再决定。
pub fn plan(current: Option<&str>) -> Result<Vec<&'static Step>, String> {
    let current = current.unwrap_or("").trim();
    if current.is_empty() {
        return Ok(CHAIN.iter().collect());
    }
    match CHAIN.iter().position(|s| s.tag == current) {
        Some(i) => Ok(CHAIN[i + 1..].iter().collect()),
        None => Err(current.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_current_runs_everything() {
        assert_eq!(plan(None).unwrap().len(), CHAIN.len());
        assert_eq!(plan(Some("")).unwrap().len(), CHAIN.len());
    }

    #[test]
    fn latest_current_runs_nothing() {
        assert!(plan(Some(latest_tag())).unwrap().is_empty());
    }

    #[test]
    fn unknown_tag_is_rejected_not_guessed() {
        let err = plan(Some("v99")).unwrap_err();
        assert_eq!(err, "v99");
    }
}
