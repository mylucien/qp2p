//! qp2p 信令部署器。
//!
//! 做成独立二进制而不是塞进 `qp2p`：持有 Cloudflare API 令牌的代码
//! 不应该和带 root/TUN 权限的 VPN 客户端待在一起。
//!
//! ```text
//! qp2p-deploy init            建 D1 → 首次上传 → 启用 workers.dev → 冒烟
//! qp2p-deploy up              升级：按迁移链补步骤，保留已有密钥
//! qp2p-deploy status          看本地记录 + 探一次线上
//! qp2p-deploy rotate-admin    重设 ADMIN_SECRET
//! qp2p-deploy destroy         删 Worker（DO 数据随之销毁）
//! ```
//!
//! 令牌从 `CLOUDFLARE_API_TOKEN` 读，账号从 `CLOUDFLARE_ACCOUNT_ID` 读；
//! **两者都不落盘**。

mod cf;
mod manifest;
mod migrate;
mod state;
mod verify;

use std::fmt;
use std::process::exit;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde_json::Value;

/// Worker 源码在编译期内嵌：部署出去的代码和本地跑过的版本永远一致。
const WORKER_SOURCE: &str = include_str!("../../../signal/worker.js");
const DEFAULT_WORKER: &str = "qp2p";
const DEFAULT_DB: &str = "qp2p";

const USAGE: &str = "\
qp2p-deploy — 部署 / 升级 qp2p 信令 Worker

用法：
  qp2p-deploy init [--worker 名字] [--db 名字] [--dry-run]
  qp2p-deploy up   [--worker 名字] [--tag v1] [--no-room] [--dry-run]
  qp2p-deploy status [--worker 名字]
  qp2p-deploy rotate-admin [--worker 名字]
  qp2p-deploy destroy [--worker 名字]

环境变量：
  CLOUDFLARE_API_TOKEN    必需（Workers Scripts:Edit + D1:Edit）
  CLOUDFLARE_ACCOUNT_ID   必需
  QP2P_DEPLOY_STATE       可选，覆盖状态文件位置

退出码：0 成功 / 2 参数错 / 3 API 错 / 4 迁移被拒 / 5 冒烟失败
";

/// 带退出码的致命错误。
#[derive(Debug)]
struct Fatal {
    code: i32,
    msg: String,
}

impl fmt::Display for Fatal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for Fatal {}

fn fatal(code: i32, msg: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Fatal {
        code,
        msg: msg.into(),
    })
}

struct Args {
    cmd: String,
    worker: String,
    db: String,
    tag: Option<String>,
    no_room: bool,
    dry_run: bool,
}

fn parse_args() -> Result<Args> {
    let mut argv = std::env::args().skip(1);
    let cmd = argv.next().unwrap_or_else(|| "help".to_string());
    let mut args = Args {
        cmd,
        worker: DEFAULT_WORKER.to_string(),
        db: DEFAULT_DB.to_string(),
        tag: None,
        no_room: false,
        dry_run: false,
    };

    while let Some(flag) = argv.next() {
        match flag.as_str() {
            "--worker" => args.worker = next_value(&mut argv, "--worker")?,
            "--db" => args.db = next_value(&mut argv, "--db")?,
            "--tag" => args.tag = Some(next_value(&mut argv, "--tag")?),
            "--no-room" => args.no_room = true,
            "--dry-run" => args.dry_run = true,
            "-h" | "--help" => args.cmd = "help".to_string(),
            other => bail!("不认识的参数 {other}"),
        }
    }
    Ok(args)
}

fn next_value(argv: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    argv.next()
        .with_context(|| format!("{flag} 后面要跟一个值"))
}

fn env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("请先设置环境变量 {name}"))
}

fn client_from_env() -> Result<cf::Client> {
    let token = env("CLOUDFLARE_API_TOKEN")?;
    let account = env("CLOUDFLARE_ACCOUNT_ID")?;
    cf::Client::new(&token, &account, None)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn new_secret() -> String {
    // 48 位十六进制，与 worker 里 ADMIN_SECRET 的用法一致
    hex::encode(rand::random::<[u8; 24]>())
}

fn workers_dev_url(worker: &str, subdomain: &str) -> String {
    if subdomain.is_empty() {
        String::new()
    } else {
        format!("https://{worker}.{subdomain}.workers.dev")
    }
}

/// 上传后服务端要几秒才生效，冒烟给几次机会。
async fn smoke_with_retry(url: &str, secret: &str) -> Result<verify::Report> {
    let mut last = String::new();
    for attempt in 0..5 {
        match verify::health(url, Some(secret)).await {
            Ok(report) => return Ok(report),
            Err(e) => {
                last = format!("{e:#}");
                if attempt < 4 {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }
    Err(fatal(5, format!("冒烟失败：{last}")))
}

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("参数错误：{e:#}\n\n{USAGE}");
            exit(2);
        }
    };

    let outcome = match args.cmd.as_str() {
        "init" => cmd_init(&args).await,
        "up" => cmd_up(&args).await,
        "status" => cmd_status(&args).await,
        "rotate-admin" => cmd_rotate_admin(&args).await,
        "destroy" => cmd_destroy(&args).await,
        "help" | "-h" | "--help" => {
            print!("{USAGE}");
            Ok(())
        }
        other => Err(fatal(2, format!("不认识的命令 {other}"))),
    };

    match outcome {
        Ok(()) => exit(0),
        Err(e) => {
            eprintln!("\n✗ {e:#}");
            let code = e.downcast_ref::<Fatal>().map(|f| f.code).unwrap_or(1);
            exit(code);
        }
    }
}

async fn cmd_init(args: &Args) -> Result<()> {
    let cf = client_from_env()?;

    println!("① 校验令牌");
    cf.verify_token().await.map_err(api)?;
    println!("   ok");

    println!("② 准备 D1 数据库 {}", args.db);
    let d1 = cf.ensure_d1(&args.db).await.map_err(api)?;
    println!("   {d1}");

    let secret = new_secret();
    let steps = migrate::plan(None).map_err(|t| {
        fatal(
            4,
            format!("迁移链不认识标签 {t}；不猜，先检查 crates/deploy/src/migrate.rs"),
        )
    })?;
    let meta = manifest::metadata(&manifest::Options {
        d1_id: &d1,
        with_room: !args.no_room,
        admin_secret: Some(&secret),
        steps: &steps,
    });

    if args.dry_run {
        println!("\n--dry-run：只打印将要上传的 metadata（密钥已脱敏）");
        println!(
            "{}",
            serde_json::to_string_pretty(&manifest::redacted(&meta))?
        );
        return Ok(());
    }

    println!("③ 上传 Worker {}", args.worker);
    let uploaded = cf
        .upload(&args.worker, &meta, WORKER_SOURCE)
        .await
        .map_err(api)?;
    let tag = uploaded
        .get("migration_tag")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    println!("④ 启用 workers.dev（预览 URL 保持关闭）");
    cf.enable_workers_dev(&args.worker).await.map_err(api)?;
    let subdomain = cf.subdomain().await.unwrap_or_default();
    let url = workers_dev_url(&args.worker, &subdomain);

    println!("⑤ 冒烟");
    let report = smoke_with_retry(&url, &secret).await?;
    println!("   {}", report.describe());

    state::save(&state::State {
        worker: args.worker.clone(),
        account_id: std::env::var("CLOUDFLARE_ACCOUNT_ID").unwrap_or_default(),
        subdomain: subdomain.clone(),
        migration_tag: tag.clone(),
        updated_at: now_secs(),
    })?;

    println!("\n✓ 部署完成");
    println!("  地址     : {url}");
    println!("  管理页   : {url}/admin");
    println!("  迁移标签 : {tag}");
    println!("\n  ADMIN_SECRET（只显示这一次，丢了只能 rotate-admin 重设）");
    println!("  {secret}");
    println!("\n下一步：想用自定义域名就在控制台给这个 Worker 加一条路由。");
    Ok(())
}

async fn cmd_up(args: &Args) -> Result<()> {
    let cf = client_from_env()?;
    cf.verify_token().await.map_err(api)?;

    if !cf.script_exists(&args.worker).await.map_err(api)? {
        return Err(fatal(
            2,
            format!("Worker {} 还不存在，首次部署请用 init", args.worker),
        ));
    }

    let mut st = state::load()?;
    // 优先用命令行给的标签；其次本地记录。都没有当作全新，从头规划。
    let current = args
        .tag
        .clone()
        .or_else(|| Some(st.migration_tag.clone()).filter(|t| !t.is_empty()));

    let steps = migrate::plan(current.as_deref()).map_err(|t| {
        fatal(
            4,
            format!("线上的迁移标签 {t} 不在链里。用 --tag 显式指定当前标签，核对后再升级"),
        )
    })?;

    let d1 = cf.ensure_d1(&args.db).await.map_err(api)?;

    // 升级一律不带密钥明文，靠 keep_bindings 保住已有的
    let meta = manifest::metadata(&manifest::Options {
        d1_id: &d1,
        with_room: !args.no_room,
        admin_secret: None,
        steps: &steps,
    });

    if args.dry_run {
        println!("当前标签 : {}", current.as_deref().unwrap_or("<无>"));
        println!("待执行   : {}", steps.len());
        println!("\n--dry-run：将要上传的 metadata");
        println!(
            "{}",
            serde_json::to_string_pretty(&manifest::redacted(&meta))?
        );
        return Ok(());
    }

    if steps.is_empty() {
        println!("没有待执行的迁移，只更新代码");
    } else {
        println!("要执行 {} 个迁移步骤", steps.len());
    }

    let uploaded = cf
        .upload(&args.worker, &meta, WORKER_SOURCE)
        .await
        .map_err(api)?;
    let tag = uploaded
        .get("migration_tag")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let subdomain = if st.subdomain.is_empty() {
        cf.subdomain().await.unwrap_or_default()
    } else {
        st.subdomain.clone()
    };
    let url = workers_dev_url(&args.worker, &subdomain);

    if !url.is_empty() {
        // 升级后没有密钥明文，冒烟只能确认"服务活着"
        match verify::health(&url, None).await {
            Ok(report) => println!("冒烟: {}", report.describe()),
            Err(e) => eprintln!("冒烟未能完成（不影响部署）：{e:#}"),
        }
    }

    st.worker = args.worker.clone();
    st.subdomain = subdomain;
    st.migration_tag = if tag.is_empty() {
        st.migration_tag.clone()
    } else {
        tag.clone()
    };
    st.updated_at = now_secs();
    state::save(&st)?;

    println!("\n✓ 已升级到标签 {tag}");
    println!("  已有密钥、D1 与 DO 数据都保留；节点下一次请求就落到新代码。");
    Ok(())
}

async fn cmd_status(args: &Args) -> Result<()> {
    let st = state::load()?;
    let worker = if st.worker.is_empty() {
        args.worker.clone()
    } else {
        st.worker.clone()
    };

    println!("状态文件 : {}", state::path_display());
    println!("Worker   : {worker}");
    println!(
        "账号     : {}",
        if st.account_id.is_empty() {
            "<未知>"
        } else {
            &st.account_id
        }
    );

    // 本地没有记录是常态（手工上传过、换了机器、或者别人部署的），
    // 这时别急着说"从未部署"——去线上问一句脚本在不在、子域是什么。
    let mut subdomain = st.subdomain.clone();
    let mut remote: Option<bool> = None;
    if st.migration_tag.is_empty() || subdomain.is_empty() {
        if let Ok(cf) = client_from_env() {
            remote = cf.script_exists(&worker).await.ok();
            if subdomain.is_empty() {
                if let Ok(s) = cf.subdomain().await {
                    subdomain = s;
                }
            }
        }
    }

    println!(
        "上次标签 : {}",
        if !st.migration_tag.is_empty() {
            st.migration_tag.clone()
        } else {
            match remote {
                Some(true) => "<本地无记录，线上已存在>".to_string(),
                Some(false) => "<线上不存在>".to_string(),
                None => "<本地无记录>".to_string(),
            }
        }
    );

    let url = workers_dev_url(&worker, &subdomain);
    if url.is_empty() {
        println!("线上     : 查不到子域，跳过探测（可指定 --worker 或跑一次 init/up）");
        return Ok(());
    }
    match verify::health(&url, None).await {
        Ok(report) => println!("线上     : {}（{url}）", report.describe()),
        Err(e) => {
            println!("线上     : 探测失败 —— {e:#}");
            // 绑了自定义域名的部署，workers.dev 这条路本来就不通，别让人以为挂了
            println!(
                "           绑了自定义域名的话这是正常的，改用你自己的域名访问 /v1/health 验证"
            );
        }
    }
    Ok(())
}

async fn cmd_rotate_admin(args: &Args) -> Result<()> {
    let cf = client_from_env()?;
    cf.verify_token().await.map_err(api)?;

    let secret = new_secret();
    cf.set_secret(&args.worker, "ADMIN_SECRET", &secret)
        .await
        .map_err(api)?;

    println!("✓ 已重设 ADMIN_SECRET（只显示这一次）");
    println!("  {secret}");
    println!("\n成员不受影响：加入密钥是每个网络自己的，与管理密钥无关。");
    Ok(())
}

async fn cmd_destroy(args: &Args) -> Result<()> {
    let cf = client_from_env()?;
    cf.verify_token().await.map_err(api)?;

    println!(
        "删除 Worker {}（它下面的 Durable Object 数据会一起销毁）",
        args.worker
    );
    cf.delete_script(&args.worker).await.map_err(api)?;

    let mut st = state::load()?;
    st.migration_tag.clear();
    st.updated_at = now_secs();
    let _ = state::save(&st);

    println!(
        "✓ 已删除。D1 数据库 {} 仍在，需要时到控制台手动删。",
        args.db
    );
    Ok(())
}

/// Cloudflare API 失败统一归到退出码 3，并保留原始错误链。
fn api(e: anyhow::Error) -> anyhow::Error {
    fatal(3, format!("{e:#}"))
}
