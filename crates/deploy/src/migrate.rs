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

pub const CHAIN: &[Step] = &[
    Step {
        tag: "v1",
        new_sqlite_classes: &["NetworkRoom"],
    },
    // v2 不带新类，只推进标签。
    //
    // 原因：Durable Object 的**类实现**跟着部署版本走，而只有带 `migrations`
    // 的上传才会让 CF 生成新版本并重建 DO 实例。只改顶层 fetch 的上传（"没有
    // 待执行的迁移，只更新代码"）会让已有 DO 继续跑旧代码——2026-11-22 实测：
    // 修好 parseCandidates 并上传后，顶层 `/v1/health` 已是新版，但
    // `/v1/register`（DO 内处理）仍返回旧行为，光猫继续 400。
    //
    // 所以**每次改动 DO 内逻辑都必须往后接一个 tag**，哪怕没有新类。
    Step {
        tag: "v2",
        new_sqlite_classes: &[],
    },
];

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

    #[test]
    fn chain_can_advance_tag_without_new_classes() {
        // 只改 DO 内逻辑时要靠「空步骤」推进 tag，否则 CF 不会重建 DO 实例
        let steps = plan(Some("v1")).unwrap();
        assert_eq!(steps.last().map(|s| s.tag), Some(latest_tag()));
        assert!(
            steps.iter().any(|s| s.new_sqlite_classes.is_empty()),
            "链上应保留一步不带新类的，专门用来推动 DO 更新"
        );
    }
}
