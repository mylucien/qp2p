//! 信令请求的签名规范。
//!
//! 与 `signal/worker.js` 的 `canonicalJson` 逐字节一致：键按字典序排序、无空白、
//! 非 ASCII 转义成 `\uXXXX`。签名串是
//!
//! ```text
//! qp2p1|<op>|<network>|<ts>|<nonce>|<sha256(canonical_json(body without sig))>
//! ```
//!
//! 这里不手挑字段：`tls_fp`、`candidates`、`name` 任何一个漏签，攻击者都能拿一份
//! 合法报文改掉它重放。测试里的向量与 JS 侧共用，任何一边改了序列化都会被抓住。
//!
//! ## 数字规则（两端必须一致）
//!
//! 只允许 `±(2^53 - 1)` 以内的**整数**，其余一律拒绝而不是各自格式化：
//! JS 的 `Number` 是 f64，`1.0` 会被写成 `1`、`9007199254740993` 会丢精度，
//! 而 Rust 会原样输出 `1.0` 和 `9007199254740993`——两边摘要不同，
//! 表现为难以排查的 `bad_signature`。拒绝比"尽量对齐"可靠。
//!
//! 因此客户端必须用整数类型（`u64`/`i64`）写数字字段，不要用 `f64`，
//! 即使数值是 `1.0` 也会被拒绝。
//!
//! **注意这不是对称的**：JS 侧 `JSON.parse("1.0")` 得到的和 `1` 是同一个值，
//! 根本无法区分，所以 Worker 收到 `1.0` 会按 `1` 处理并正常放行。这里是"签名方严格、
//! 校验方宽松"。将来若在 Rust 里实现请求校验，遇到整数值的浮点应按整数格式化，
//! 否则会把 JS 客户端合法签出的请求拒掉（目前唯一的校验方是 Worker）。
//!
//! ## 键排序
//!
//! 按 Unicode 码点升序（等价于 UTF-8 字节序）。JS 默认的 `sort()` 按 UTF-16
//! 码元排序，遇到 BMP 之上的字符时顺序会不同，所以 JS 侧用了专门的比较函数。

use serde_json::{Number, Value};
use sha2::{Digest, Sha256};

pub const SIGN_PREFIX: &str = "qp2p1";

/// JS 的 `Number.MAX_SAFE_INTEGER`。
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalError {
    #[error("不支持的数字 {0}：只允许 ±(2^53-1) 以内的整数（浮点数请改用整数或字符串）")]
    UnsupportedNumber(String),
}

/// 规范化 JSON：与 JS 的 `canonicalJson` 输出完全一致。
///
/// 遇到非整数或超出安全范围的数字时返回错误，而不是输出一个 JS 对不上的字符串。
pub fn canonical_json(value: &Value) -> Result<String, CanonicalError> {
    Ok(match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => canonical_number(n)?,
        Value::String(s) => quote_json(s),
        Value::Array(items) => {
            let inner = items
                .iter()
                .map(canonical_json)
                .collect::<Result<Vec<_>, _>>()?;
            format!("[{}]", inner.join(","))
        }
        Value::Object(map) => {
            // String 的 Ord 是字节序，对 UTF-8 而言等价于码点序
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let inner = keys
                .iter()
                .map(|k| Ok(format!("{}:{}", quote_json(k), canonical_json(&map[*k])?)))
                .collect::<Result<Vec<_>, CanonicalError>>()?;
            format!("{{{}}}", inner.join(","))
        }
    })
}

fn canonical_number(n: &Number) -> Result<String, CanonicalError> {
    // as_i64 对 f64 表示（哪怕是 1.0）返回 None，正好把浮点挡在外面；
    // 超过 i64::MAX 的 u64 同样得到 None。
    match n.as_i64() {
        Some(i) if (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&i) => Ok(i.to_string()),
        _ => Err(CanonicalError::UnsupportedNumber(n.to_string())),
    }
}

/// 字符串转义规则：`"`、`\`、控制符转义；非 ASCII 一律 `\uXXXX`。
fn quote_json(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let code = c as u32;
                if code > 0xffff {
                    let rest = code - 0x10000;
                    let hi = 0xd800 + (rest >> 10);
                    let lo = 0xdc00 + (rest & 0x3ff);
                    out.push_str(&format!("\\u{hi:04x}\\u{lo:04x}"));
                } else {
                    out.push_str(&format!("\\u{code:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// 去掉 `sig` 之后的请求体摘要（hex）。
pub fn body_digest(body: &Value) -> Result<String, CanonicalError> {
    let mut stripped = body.clone();
    if let Some(map) = stripped.as_object_mut() {
        map.remove("sig");
    }
    let canonical = canonical_json(&stripped)?;
    Ok(hex::encode(Sha256::digest(canonical.as_bytes())))
}

/// 拼出真正被签名的字符串。
pub fn signing_message(op: &str, network_id: &str, ts: u64, nonce: &str, digest: &str) -> String {
    format!("{SIGN_PREFIX}|{op}|{network_id}|{ts}|{nonce}|{digest}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// 由 JS 侧（signal/vec.mjs 同款脚本）生成的向量，两边必须一致。
    const VECTOR_BODY: &str = r#"{
        "node_id": "0123456789abcdef0123456789abcdef",
        "pubkey": "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
        "name": "bob",
        "candidates": ["203.0.113.7:51820", "198.51.100.9:51820"],
        "tls_fp": "abababababababababababababababababababababababababababababababab",
        "ts": 1730000000000,
        "nonce": "0011223344556677"
    }"#;

    const VECTOR_CANONICAL: &str = concat!(
        r#"{"candidates":["203.0.113.7:51820","198.51.100.9:51820"],"name":"bob","#,
        r#""node_id":"0123456789abcdef0123456789abcdef","nonce":"0011223344556677","#,
        r#""pubkey":"03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8","#,
        r#""tls_fp":"abababababababababababababababababababababababababababababababab","#,
        r#""ts":1730000000000}"#
    );

    const VECTOR_DIGEST: &str = "8ce0e74da4065e5a28a4c781c105f14b78e0e30033245a09adf464c706abf486";
    const VECTOR_MESSAGE: &str = concat!(
        "qp2p1|register|home-lab|1730000000000|0011223344556677|",
        "8ce0e74da4065e5a28a4c781c105f14b78e0e30033245a09adf464c706abf486"
    );
    const VECTOR_SIGNATURE: &str = concat!(
        "1eb65cc470a0689bdf6f3508219644c1b1a875d7037a141f834798d33b44040f",
        "3108a8fa5c3dfd69eae6e0772239b6295c3b33439724665752c4ad012f6f4809"
    );
    const VECTOR_PUBKEY: &str = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";

    fn vector_body() -> Value {
        serde_json::from_str(VECTOR_BODY).expect("向量 JSON 合法")
    }

    #[test]
    fn canonical_json_matches_js() {
        assert_eq!(canonical_json(&vector_body()).unwrap(), VECTOR_CANONICAL);
    }

    #[test]
    fn body_digest_matches_js() {
        assert_eq!(body_digest(&vector_body()).unwrap(), VECTOR_DIGEST);
    }

    /// sig 字段本身不参与摘要，加了也不影响。
    #[test]
    fn signature_field_is_excluded_from_digest() {
        let mut body = vector_body();
        body.as_object_mut()
            .unwrap()
            .insert("sig".into(), Value::String("00".repeat(64)));
        assert_eq!(body_digest(&body).unwrap(), VECTOR_DIGEST);
    }

    #[test]
    fn signing_message_matches_js() {
        let digest = body_digest(&vector_body()).unwrap();
        let message = signing_message(
            "register",
            "home-lab",
            1730000000000,
            "0011223344556677",
            &digest,
        );
        assert_eq!(message, VECTOR_MESSAGE);
    }

    /// Ed25519 是确定性签名：同一把种子签同一条消息，两边必然逐字节相同。
    #[test]
    fn deterministic_signature_matches_js() {
        let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
        let key = SigningKey::from_bytes(&seed);
        assert_eq!(hex::encode(key.verifying_key().to_bytes()), VECTOR_PUBKEY);

        let signature = key.sign(VECTOR_MESSAGE.as_bytes());
        assert_eq!(hex::encode(signature.to_bytes()), VECTOR_SIGNATURE);
    }

    #[test]
    fn non_ascii_is_escaped() {
        let value = serde_json::json!({ "name": "家里" });
        assert_eq!(
            canonical_json(&value).unwrap(),
            r#"{"name":"\u5bb6\u91cc"}"#
        );
    }

    #[test]
    fn nested_objects_are_sorted() {
        let value = serde_json::json!({ "b": { "z": 1, "a": 2 }, "a": [1, 2] });
        assert_eq!(
            canonical_json(&value).unwrap(),
            r#"{"a":[1,2],"b":{"a":2,"z":1}}"#
        );
    }

    // ---- 数字规则：与 signal/worker.js 的 canonicalJson 同一组边界 ----------

    fn canon(text: &str) -> Result<String, CanonicalError> {
        canonical_json(&serde_json::from_str::<Value>(text).expect("测试 JSON 合法"))
    }

    #[test]
    fn safe_integers_are_accepted() {
        assert_eq!(canon(r#"{"a":0}"#).unwrap(), r#"{"a":0}"#);
        assert_eq!(canon(r#"{"a":-1}"#).unwrap(), r#"{"a":-1}"#);
        assert_eq!(
            canon(r#"{"a":9007199254740991}"#).unwrap(),
            r#"{"a":9007199254740991}"#
        );
        assert_eq!(
            canon(r#"{"a":-9007199254740991}"#).unwrap(),
            r#"{"a":-9007199254740991}"#
        );
    }

    /// 这几组在修复前 Rust 与 JS 输出不同（1.0 / 精度丢失），现在两边都拒绝。
    #[test]
    fn unsafe_or_non_integer_numbers_are_rejected() {
        for text in [
            r#"{"a":1.0}"#,
            r#"{"a":1.5}"#,
            r#"{"a":1e21}"#,
            r#"{"a":1e2}"#,
            r#"{"a":9007199254740992}"#,
            r#"{"a":9007199254740993}"#,
            r#"{"a":-9007199254740992}"#,
            r#"{"a":18446744073709551615}"#,
            // serde_json 把 -0 解析成浮点 -0.0；JS 侧用 Object.is(v, -0) 同样拒绝
            r#"{"a":-0}"#,
        ] {
            assert!(
                matches!(canon(text), Err(CanonicalError::UnsupportedNumber(_))),
                "应当拒绝：{text}"
            );
        }
    }

    #[test]
    fn rejection_reaches_nested_values_and_digest() {
        assert!(canon(r#"{"a":[1,{"b":2.5}]}"#).is_err());
        let body: Value = serde_json::from_str(r#"{"ts":1730000000000,"extra":0.5}"#).unwrap();
        assert!(body_digest(&body).is_err());
    }

    /// 键按码点升序：U+FFFD 在 U+1F600 之前。
    /// JS 默认 sort() 按 UTF-16 码元比较（0xD83D < 0xFFFD），会得到相反顺序。
    #[test]
    fn keys_are_sorted_by_code_point() {
        let value = serde_json::json!({ "\u{1F600}": 1, "\u{FFFD}": 2, "a": 3 });
        assert_eq!(
            canonical_json(&value).unwrap(),
            r#"{"a":3,"\ufffd":2,"\ud83d\ude00":1}"#
        );
    }
}
