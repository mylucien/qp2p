//! 生成上传用的 metadata。
//!
//! 两个反复踩到的坑写死在这里：
//! 1. `migrations` 必须是**对象**（`{new_tag, steps}`），传数组会报
//!    `10021 cannot unmarshal array into ActorMigrations`；
//! 2. multipart 里脚本的 filename 必须等于 `main_module`，否则
//!    `No such module: worker.js`。

use serde_json::{json, Value};

use crate::migrate;

/// 与线上保持一致，不要随手改——改了等于换运行时。
pub const COMPATIBILITY_DATE: &str = "2026-11-03";
pub const MAIN_MODULE: &str = "worker.js";

pub struct Options<'a> {
    pub d1_id: &'a str,
    /// 是否绑定 Durable Object。`false` 用于紧急回退到 legacy 数据面。
    pub with_room: bool,
    /// 首次部署要带密钥明文；升级时传 `None`，靠 `keep_bindings` 保住已有密钥。
    pub admin_secret: Option<&'a str>,
    /// 这次要执行的迁移步骤；空表示只改代码。
    pub steps: &'a [&'a migrate::Step],
}

pub fn metadata(opts: &Options<'_>) -> Value {
    let mut bindings = vec![json!({
        "type": "d1",
        "name": "DB",
        "id": opts.d1_id,
    })];

    if opts.with_room {
        bindings.push(json!({
            "type": "durable_object_namespace",
            "name": "ROOM",
            "class_name": "NetworkRoom",
        }));
    }

    if let Some(secret) = opts.admin_secret {
        bindings.push(json!({
            "type": "secret_text",
            "name": "ADMIN_SECRET",
            "text": secret,
        }));
    }

    let mut meta = json!({
        "main_module": MAIN_MODULE,
        "compatibility_date": COMPATIBILITY_DATE,
        "bindings": bindings,
    });

    // 不带新密钥时必须显式声明"保留 secret 类型"，否则升级会把 ADMIN_SECRET 抹掉
    if opts.admin_secret.is_none() {
        meta["keep_bindings"] = json!(["secret_text"]);
    }

    if !opts.steps.is_empty() {
        let classes: Vec<&str> = opts
            .steps
            .iter()
            .flat_map(|s| s.new_sqlite_classes.iter().copied())
            .collect();
        meta["migrations"] = json!({
            "new_tag": opts.steps.last().map(|s| s.tag).unwrap_or(migrate::latest_tag()),
            "steps": [ if classes.is_empty() {
                json!({})
            } else {
                json!({ "new_sqlite_classes": classes })
            } ],
        });
    }

    meta
}

/// 打印前的脱敏：密钥只留长度。
pub fn redacted(meta: &Value) -> Value {
    let mut copy = meta.clone();
    if let Some(list) = copy.get_mut("bindings").and_then(Value::as_array_mut) {
        for b in list.iter_mut() {
            if b.get("type").and_then(Value::as_str) == Some("secret_text") {
                let len = b
                    .get("text")
                    .and_then(Value::as_str)
                    .map(|s| s.chars().count())
                    .unwrap_or(0);
                b["text"] = json!(format!("<{len} 字符，已脱敏>"));
            }
        }
    }
    copy
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step() -> &'static migrate::Step {
        &migrate::CHAIN[0]
    }

    #[test]
    fn first_deploy_has_secret_and_migration() {
        let meta = metadata(&Options {
            d1_id: "db-1",
            with_room: true,
            admin_secret: Some("s3cret"),
            steps: &[step()],
        });
        assert!(meta.get("keep_bindings").is_none());
        let bindings = meta["bindings"].as_array().unwrap();
        assert!(bindings
            .iter()
            .any(|b| b["type"] == "secret_text" && b["text"] == "s3cret"));
        assert!(bindings
            .iter()
            .any(|b| b["type"] == "durable_object_namespace"));
        assert_eq!(meta["migrations"]["new_tag"], "v1");
    }

    #[test]
    fn upgrade_keeps_secret_and_omits_migrations() {
        let meta = metadata(&Options {
            d1_id: "db-1",
            with_room: true,
            admin_secret: None,
            steps: &[],
        });
        assert_eq!(meta["keep_bindings"], json!(["secret_text"]));
        assert!(meta.get("migrations").is_none());
        let bindings = meta["bindings"].as_array().unwrap();
        assert!(!bindings.iter().any(|b| b["type"] == "secret_text"));
    }

    #[test]
    fn no_room_drops_the_binding() {
        let meta = metadata(&Options {
            d1_id: "db-1",
            with_room: false,
            admin_secret: None,
            steps: &[],
        });
        let bindings = meta["bindings"].as_array().unwrap();
        assert!(!bindings
            .iter()
            .any(|b| b["type"] == "durable_object_namespace"));
    }

    #[test]
    fn secret_is_redacted_for_display() {
        let meta = metadata(&Options {
            d1_id: "db-1",
            with_room: true,
            admin_secret: Some("abcdef"),
            steps: &[],
        });
        let shown = redacted(&meta);
        let text = shown["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["type"] == "secret_text")
            .map(|b| b["text"].as_str().unwrap().to_string())
            .unwrap();
        assert!(!text.contains("abcdef"));
        assert!(text.contains('6'));
    }
}
