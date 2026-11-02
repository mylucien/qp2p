//! qp2p 命令行前端。
//!
//! 现阶段（P3）提供三条命令：`punch`（纯打洞）、`forward`（打洞 + 端口映射）、
//! `doctor`（自检）。信令面接上之后，`--peer` 会换成节点名。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use qp2p_core::{link, Engine, Role};

const HELP: &str = "\
qp2p — 私有打洞组网

用法：
  qp2p punch   --bind <addr> --peer <addr> [--dialer] [--stun <host:port>]...
  qp2p forward --bind <addr> --peer <addr> [--dialer] --listen <addr> --target <addr>
  qp2p doctor  [--bind <addr>] [--stun <host:port>]...
  qp2p -V | --version

说明：
  --bind     本地 UDP 监听地址，默认 0.0.0.0:51820
  --peer     对端 UDP 地址，必须填对端实际可达的 IP:端口
  --dialer   本端主动发起 QUIC 握手（node_id 较小的一方）
  --listen   本机 TCP 监听地址，收到的连接转发到 --target
  --target   对端侧要访问的目标地址
  --stun     可重复；用同一个 UDP socket 探测公网映射
";

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "qp2p=info".into()),
        )
        .with_target(false)
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build();

    let result = match runtime {
        Ok(rt) => rt.block_on(run(&args)),
        Err(e) => Err(anyhow::anyhow!("初始化运行时失败: {e}")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("错误：{e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        None | Some("-h") | Some("--help") => {
            print!("{HELP}");
            Ok(())
        }
        Some("-V") | Some("--version") => {
            println!(
                "qp2p {} (protocol {})",
                env!("CARGO_PKG_VERSION"),
                qp2p_core::PROTOCOL_VERSION
            );
            Ok(())
        }
        Some("punch") => cmd_punch(&args[1..]).await,
        Some("forward") => cmd_forward(&args[1..]).await,
        Some("doctor") => cmd_doctor(&args[1..]).await,
        Some(other) => {
            print!("{HELP}");
            bail!("未知命令：{other}")
        }
    }
}

#[derive(Default)]
struct Flags {
    values: HashMap<String, Vec<String>>,
}

impl Flags {
    fn parse(args: &[String]) -> Result<Self> {
        let mut flags = Flags::default();
        let mut iter = args.iter().peekable();
        while let Some(arg) = iter.next() {
            let Some(key) = arg.strip_prefix("--") else {
                bail!("无法识别的参数：{arg}");
            };
            let value = match iter.peek() {
                Some(next) if !next.starts_with("--") => iter.next().cloned().unwrap_or_default(),
                _ => "true".to_string(),
            };
            flags.values.entry(key.to_string()).or_default().push(value);
        }
        Ok(flags)
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.values
            .get(key)
            .and_then(|v| v.last())
            .map(String::as_str)
    }

    fn many(&self, key: &str) -> Vec<String> {
        self.values.get(key).cloned().unwrap_or_default()
    }

    fn flag(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }

    fn addr(&self, key: &str, default: Option<&str>) -> Result<SocketAddr> {
        let raw = self
            .get(key)
            .or(default)
            .with_context(|| format!("缺少 --{key}"))?;
        raw.parse()
            .with_context(|| format!("--{key} 不是合法地址：{raw}"))
    }
}

async fn cmd_doctor(args: &[String]) -> Result<()> {
    let flags = Flags::parse(args)?;
    let bind = flags.addr("bind", Some("0.0.0.0:51820"))?;
    let stun = flags.many("stun");

    println!(
        "qp2p {} (protocol {})",
        env!("CARGO_PKG_VERSION"),
        qp2p_core::PROTOCOL_VERSION
    );
    println!("bind: {bind}");
    if stun.is_empty() {
        println!("stun: 未配置（跨 NAT 打洞前建议至少配一个）");
    } else {
        println!("stun: {}", stun.join(", "));
    }

    let engine = Engine::bind(bind, &stun).await.context("绑定失败")?;
    println!("udp  local: {}", engine.local_addr());
    match engine.srflx() {
        Some(addr) => println!("udp  公网: {addr}"),
        None => println!("udp  公网: 未知（STUN 未配置或不可达）"),
    }
    for candidate in engine.candidates() {
        println!("candidate {candidate}");
    }
    Ok(())
}

async fn cmd_punch(args: &[String]) -> Result<()> {
    let flags = Flags::parse(args)?;
    let (engine, peer, role) = prepare(&flags).await?;

    println!("本端 UDP: {}", engine.local_addr());
    for candidate in engine.candidates() {
        println!("candidate {candidate}");
    }
    println!("对端 UDP: {peer}  角色: {role:?}");

    let conn = engine
        .punch(peer, role, Duration::from_secs(2))
        .await
        .context("打洞失败")?;
    println!(
        "直连已建立 rtt={:?} peer={}",
        conn.rtt(),
        conn.remote_address()
    );

    if role == Role::Listener {
        let conn_for_flows = conn.clone();
        tokio::spawn(async move {
            let _ = link::serve_flows(conn_for_flows).await;
        });
    }

    tokio::signal::ctrl_c().await.context("等待中断信号失败")?;
    println!("收到中断，退出");
    Ok(())
}

async fn cmd_forward(args: &[String]) -> Result<()> {
    let flags = Flags::parse(args)?;
    let (engine, peer, role) = prepare(&flags).await?;
    let listen = flags.addr("listen", None)?;
    let target = flags.addr("target", None)?;

    println!("本端 UDP: {}", engine.local_addr());
    println!("对端 UDP: {peer}  角色: {role:?}");
    println!("映射: {listen} → {target}（经对端）");

    let conn = engine
        .punch(peer, role, Duration::from_secs(2))
        .await
        .context("打洞失败")?;
    println!("直连已建立 rtt={:?}", conn.rtt());

    if role == Role::Listener {
        let conn_for_flows = conn.clone();
        tokio::spawn(async move {
            let _ = link::serve_flows(conn_for_flows).await;
        });
    }

    let forward_conn = conn.clone();
    let forward =
        tokio::spawn(async move { link::forward_listen(forward_conn, listen, target).await });
    println!("开始转发，Ctrl+C 退出");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => println!("收到中断，退出"),
        res = forward => println!("转发任务结束：{res:?}"),
    }
    Ok(())
}

async fn prepare(flags: &Flags) -> Result<(Engine, SocketAddr, Role)> {
    let bind = flags.addr("bind", Some("0.0.0.0:51820"))?;
    let peer = flags.addr("peer", None)?;
    if peer.port() == 0 {
        bail!("--peer 端口不能为 0");
    }
    let role = if flags.flag("dialer") {
        Role::Dialer
    } else {
        Role::Listener
    };
    let engine = Engine::bind(bind, &flags.many("stun"))
        .await
        .context("绑定 UDP 失败")?;
    Ok((engine, peer, role))
}
