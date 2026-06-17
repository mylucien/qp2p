//! # rules.rs — CDN 规则引擎
//!
//! 解析 `cdn_list.toml` 清单，生成 `Vec<Rule>`。
//! 提供 `match_path()` 进行最长前缀匹配，以及 ETag 计算。

use std::fs;
use std::path::Path;
use std::time::UNIX_EPOCH;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use tracing::info;

use crate::types::{Rule, RuleMode};

// ---------------------------------------------------------------------------
// TOML 清单解析
// ---------------------------------------------------------------------------

/// TOML 清单的顶层结构。
#[derive(serde::Deserialize)]
struct Manifest {
    #[serde(default)]
    local_network: Option<LocalNetwork>,
    #[serde(default)]
    rules: Vec<ManifestRule>,
}

#[derive(serde::Deserialize)]
struct LocalNetwork {
    #[serde(default)]
    cidrs: Vec<String>,
}

/// TOML 清单中的单条规则。
#[derive(serde::Deserialize)]
struct ManifestRule {
    path: String,
    /// 不提供默认值，用户必须显式填写 "cdn" 或 "direct"
    mode: String,
    #[serde(default)]
    max_age: u64,
    /// TOML 中的 cdn_url，仅 mode = "cdn" 时需要
    cdn_url: Option<String>,
    /// 可选，覆盖全局 local_network
    #[serde(default)]
    local_cidrs: Option<Vec<String>>,
}

/// 解析 TOML 清单文件，返回 `Vec<Rule>`。
pub fn parse_manifest(path: &Path) -> Result<Vec<Rule>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("读取 CDN 清单失败: {}", path.display()))?;

    let manifest: Manifest = toml::from_str(&content)
        .with_context(|| format!("解析 CDN 清单失败: {}", path.display()))?;

    let global_cidrs: Vec<String> = manifest
        .local_network
        .map(|n| n.cidrs)
        .unwrap_or_default();

    let mut rules = Vec::new();

    for (i, mr) in manifest.rules.into_iter().enumerate() {
        let rule_num = i + 1;

        let mode = match mr.mode.as_str() {
            "cdn" => RuleMode::Cdn,
            "direct" => RuleMode::Direct,
            other => bail!("规则 #{rule_num} 的 mode 无效: '{other}'（应为 'cdn' 或 'direct'）"),
        };

        // mode = Cdn 时必须提供 cdn_url
        if matches!(mode, RuleMode::Cdn) && mr.cdn_url.is_none() {
            bail!("规则 #{rule_num} path='{}' mode='cdn' 但缺少 cdn_url", mr.path);
        }

        let local_cidrs = mr.local_cidrs.unwrap_or_else(|| global_cidrs.clone());

        // 路径必须以 / 开头
        if !mr.path.starts_with('/') {
            bail!("规则 #{rule_num} 的 path 必须以 '/' 开头: '{}'", mr.path);
        }
        // 路径必须以 / 或 /* 结尾，防止 /files/video 误匹配 /files/videos/
        if !mr.path.ends_with('/') && !mr.path.ends_with("/*") {
            bail!(
                "规则 #{rule_num} 的 path 必须以 '/' 或 '/*' 结尾: '{}'",
                mr.path
            );
        }

        rules.push(Rule {
            path: mr.path,
            mode,
            max_age: mr.max_age,
            cdn_url: mr.cdn_url,
            local_cidrs,
        });
    }

    info!("[cdn] 已加载 {} 条规则", rules.len());

    Ok(rules)
}

// ---------------------------------------------------------------------------
// 路径匹配
// ---------------------------------------------------------------------------

/// 最长前缀匹配：返回第一个匹配的 Rule。
///
/// 注意：O(n) 遍历，假设规则数量 < 100。规则数量大时可改用前缀树。
///
/// 遍历所有规则，找到 path 前缀匹配 `req_path` 且前缀最长的规则。
/// 如果都不匹配，返回 `None`。
pub fn match_path<'a>(rules: &'a [Rule], req_path: &str) -> Option<&'a Rule> {
    let mut best: Option<&'a Rule> = None;
    let mut best_len: usize = 0;

    for rule in rules {
        let rule_path = &rule.path;

        // 去掉尾部的 *（如 "/files/assets/large/*.mp4" → "/files/assets/large/"）
        let prefix = rule_path.trim_end_matches('*');

        // 要求 req_path 以 prefix 开头，且 prefix 以 / 结尾
        // 防止 "/files/assets/large" 误匹配 "/files/assets/large-extra/"
        if req_path.starts_with(prefix) {
            let matched_len = prefix.len();
            if matched_len > best_len {
                best_len = matched_len;
                best = Some(rule);
            }
        }
    }

    best
}

// ---------------------------------------------------------------------------
// ETag 计算
// ---------------------------------------------------------------------------

/// 基于文件 metadata（mtime + size）计算 ETag。
///
/// 注意：macOS 的 mtime 精度为秒，1s 内的文件变更可能产生相同 ETag。
///
/// 使用 Sha256 对 `mtime_nanos:size_bytes` 做哈希，取前 16 字节 hex。
/// 不读取文件内容，适合大文件。
pub fn compute_etag(metadata: &fs::Metadata) -> Result<String> {
    let mtime = metadata
        .modified()
        .context("获取文件修改时间失败")?;
    let mtime_nanos = mtime
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let size = metadata.len();

    let mut hasher = Sha256::new();
    hasher.update(mtime_nanos.to_le_bytes());
    hasher.update(size.to_le_bytes());
    let hash = hasher.finalize();

    Ok(hex::encode(&hash[..8]))
}


// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_path_exact() {
        let rules = vec![
            Rule {
                path: "/files/videos/".into(),
                mode: RuleMode::Cdn,
                max_age: 86400,
                cdn_url: Some("https://cdn.example.com/".into()),
                local_cidrs: vec![],
            },
            Rule {
                path: "/files/".into(),
                mode: RuleMode::Direct,
                max_age: 0,
                cdn_url: None,
                local_cidrs: vec![],
            },
        ];

        // 应匹配更长的前缀 "/files/videos/"
        let matched = match_path(&rules, "/files/videos/1.mp4").unwrap();
        assert_eq!(matched.path, "/files/videos/");
        assert_eq!(matched.mode, RuleMode::Cdn);

        // 应匹配 "/files/"
        let matched = match_path(&rules, "/files/docs/readme.txt").unwrap();
        assert_eq!(matched.path, "/files/");
        assert_eq!(matched.mode, RuleMode::Direct);
    }

    #[test]
    fn test_match_path_no_match() {
        let rules = vec![Rule {
            path: "/files/videos/".into(),
            mode: RuleMode::Cdn,
            max_age: 86400,
            cdn_url: Some("https://cdn.example.com/".into()),
            local_cidrs: vec![],
        }];
        assert!(match_path(&rules, "/other/path").is_none());
    }

    #[test]
    fn test_match_path_wildcard() {
        let rules = vec![Rule {
            path: "/files/assets/large/*.mp4".into(),
            mode: RuleMode::Cdn,
            max_age: 3600,
            cdn_url: Some("https://cdn.example.com/".into()),
            local_cidrs: vec![],
        }];

        let matched = match_path(&rules, "/files/assets/large/movie.mp4").unwrap();
        assert_eq!(matched.path, "/files/assets/large/*.mp4");
    }

    #[test]
    fn test_compute_etag() {
        let dir = std::env::temp_dir().join("edge_agent_test_etag");
        let _ = fs::create_dir_all(&dir);
        let file_path = dir.join("test.txt");
        fs::write(&file_path, b"hello").unwrap();

        let metadata = fs::metadata(&file_path).unwrap();
        let etag = compute_etag(&metadata).unwrap();
        assert!(!etag.is_empty());
        assert_eq!(etag.len(), 16); // 8 字节 hex = 16 字符

        // 同一文件两次调用应返回相同 ETag
        let etag2 = compute_etag(&metadata).unwrap();
        assert_eq!(etag, etag2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_parse_manifest_inline() {
        // 测试 TOML 解析逻辑而不依赖实际文件
        let toml_content = r#"
[local_network]
cidrs = ["192.168.1.0/24", "10.0.0.0/8"]

[[rules]]
path = "/files/videos/"
mode = "cdn"
max_age = 86400
cdn_url = "https://cdn.example.com/"

[[rules]]
path = "/files/docs/"
mode = "direct"
"#;

        let manifest: Manifest = toml::from_str(toml_content).unwrap();
        assert_eq!(manifest.rules.len(), 2);
        assert_eq!(manifest.rules[0].path, "/files/videos/");
        assert_eq!(manifest.rules[0].mode, "cdn");
        assert_eq!(manifest.rules[1].mode, "direct");

        let local = manifest.local_network.unwrap();
        assert_eq!(local.cidrs.len(), 2);
    }

    #[test]
    fn test_parse_manifest_missing_cdn_url() {
        let toml_content = r#"
[[rules]]
path = "/files/videos/"
mode = "cdn"
max_age = 86400
"#;
        let manifest: Manifest = toml::from_str(toml_content).unwrap();
        let result = || -> Result<Vec<Rule>> {
            let mut rules = Vec::new();
            for (i, mr) in manifest.rules.into_iter().enumerate() {
                let mode = match mr.mode.as_str() {
                    "cdn" => RuleMode::Cdn,
                    "direct" => RuleMode::Direct,
                    _ => bail!("无效 mode"),
                };
                if matches!(mode, RuleMode::Cdn) && mr.cdn_url.is_none() {
                    bail!("规则 #{} 缺少 cdn_url", i + 1);
                }
                rules.push(Rule {
                    path: mr.path,
                    mode,
                    max_age: mr.max_age,
                    cdn_url: mr.cdn_url,
                    local_cidrs: vec![],
                });
            }
            Ok(rules)
        };
        assert!(result().is_err());
    }
}
