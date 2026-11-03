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

use serde_json::Value;
use sha2::{Digest, Sha256};

pub const SIGN_PREFIX: &str = "qp2p1";

/// 规范化 JSON：与 JS 的 `canonicalJson` 输出完全一致。
pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => quote_json(s),
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", inner.join(","))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let inner: Vec<String> = keys
                .iter()
                .map(|k| format!("{}:{}", quote_json(k), canonical_json(&map[*k])))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
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
pub fn body_digest(body: &Value) -> String {
    let mut stripped = body.clone();
    if let Some(map) = stripped.as_object_mut() {
        map.remove("sig");
    }
    let canonical = canonical_json(&stripped);
    hex::encode(Sha256::digest(canonical.as_bytes()))
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
        assert_eq!(canonical_json(&vector_body()), VECTOR_CANONICAL);
    }

    #[test]
    fn body_digest_matches_js() {
        assert_eq!(body_digest(&vector_body()), VECTOR_DIGEST);
    }

    /// sig 字段本身不参与摘要，加了也不影响。
    #[test]
    fn signature_field_is_excluded_from_digest() {
        let mut body = vector_body();
        body.as_object_mut()
            .unwrap()
            .insert("sig".into(), Value::String("00".repeat(64)));
        assert_eq!(body_digest(&body), VECTOR_DIGEST);
    }

    #[test]
    fn signing_message_matches_js() {
        let digest = body_digest(&vector_body());
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
        assert_eq!(canonical_json(&value), r#"{"name":"\u5bb6\u91cc"}"#);
    }

    #[test]
    fn nested_objects_are_sorted() {
        let value = serde_json::json!({ "b": { "z": 1, "a": 2 }, "a": [1, 2] });
        assert_eq!(canonical_json(&value), r#"{"a":[1,2],"b":{"a":2,"z":1}}"#);
    }
}
