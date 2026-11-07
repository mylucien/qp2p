//! qp2p 命令行前端。
//!
//! 面向用户只有三条命令：`init`（填信令地址）、`create`/`join`（建网/入网）、
//! `up`（上线组网）。令牌、签名、事件轮询、打洞重试全部在客户端内部完成，
//! 用户不需要碰任何 HTTP 接口。
//!
//! 另外保留 `punch`/`forward`/`tun`/`doctor`：它们绕过信令面，
//! 用于手工验证两个地址之间能不能打通。

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use qp2p_core::config::{parse_token, Config, Network};
use qp2p_core::identity::Identity;
use qp2p_core::link::tun::MeshLinks;
use qp2p_core::signal::client::{extract_token, normalize_worker, SignalClient};
use qp2p_core::{link, Engine, Role};
use tokio::sync::RwLock;

#[cfg(windows)]
mod gui;
#[cfg(windows)]
mod win_gui;

const HELP: &str = "\
qp2p — 私有组网，没有公网 IP 也能直连

Windows 上双击 qp2p.exe（或直接敲 qp2p 不带参数）就是打开图形界面。
下面这些是命令行用法，看完加 --help 可以随时再翻。

第一次使用（只有一台机器要建网）：
  qp2p init https://你的-worker.workers.dev    # 填信令地址，顺便检查部署
  qp2p create home                             # 建网络，自动生成并保存加入密钥
  qp2p up                                      # 上线

其它机器加入：
  qp2p join qp2p1_home_xxxxxxxx                # 用建网时打印的令牌
  qp2p join <令牌> --ip 10.78.0.20             # 顺便指定自己的虚拟地址
  qp2p up

图形界面（仅 Windows）：
  qp2p                 不带参数就是打开图形界面（双击 exe 等价）
  qp2p gui             同上，显式写法（关掉即收进托盘，右键菜单可连接/断开/退出）

日常命令：
  qp2p status          看本机地址、在线成员、谁连上了
  qp2p token           重新显示加入令牌（发给别人）
  qp2p rotate          换新令牌，旧令牌立刻失效
  qp2p leave           从网络里注销本机
  qp2p config          查看本机保存的配置（MTU、网卡名、路由、STUN…）
  qp2p config set mtu 1280     改一项并保存，下次 up 直接生效
  qp2p up -h           看组网的详细选项

管理员（需要 ADMIN_SECRET，只有建网的人有）：
  qp2p nets            列出这台 Worker 上的所有网络
  qp2p rotate          换准入密码，旧令牌立刻失效
  qp2p delete <网络>   删除网络（连带成员和事件），需加 --yes 确认

调试/兼容命令（不需要信令服务器）：
  qp2p punch   --bind <addr> --peer <addr> [--dialer] (--peer-id <id> | --any-peer)
  qp2p forward --bind <addr> --peer <addr> [--dialer] (--peer-id <id> | --any-peer)
               --listen <addr> --target <addr> [--serve <addr>]...
  qp2p tun     --bind <addr> --peer <addr> [--dialer] (--peer-id <id> | --any-peer)
  qp2p doctor  [--bind <addr>] [--stun <host:port>]...
  qp2p -V | --version

通用选项：
  --data-dir <dir>  身份、证书、配置的存放目录，默认 ~/.qp2p
  --worker <url>    临时指定信令地址（默认用已保存的）
  --admin <secret>  管理密钥，建网/换密钥时用；也可用环境变量 QP2P_ADMIN_SECRET
";

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "qp2p=warn,qp2p_core=warn".into()),
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

/// 双击启动时系统会给我们单独开一个控制台窗口；从已有终端里启动时，
/// 控制台里还挂着那个 shell 进程。只有"里面只有自己"才藏，免得把用户的终端一起藏了。
#[cfg(windows)]
fn hide_own_console() -> bool {
    use windows_sys::Win32::System::Console::{GetConsoleProcessList, GetConsoleWindow};

    unsafe {
        let hwnd = GetConsoleWindow();
        if hwnd.is_null() {
            return false;
        }
        let mut pids = [0u32; 4];
        let count = GetConsoleProcessList(pids.as_mut_ptr(), pids.len() as u32);
        if count != 1 {
            return false;
        }
        windows_sys::Win32::UI::WindowsAndMessaging::ShowWindow(
            hwnd,
            windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE,
        );
        true
    }
}

async fn run(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        // 双击 exe（无参数）直接进图形界面：双击时系统会给一个自己的控制台窗口，
        // 顺手藏掉，别让黑框留在界面后面
        #[cfg(windows)]
        None => {
            let hidden = hide_own_console();
            let result = cmd_gui(&[]);
            if hidden {
                if let Err(e) = &result {
                    win_gui::alert(&format!("{e:#}"));
                }
            }
            result
        }
        #[cfg(not(windows))]
        None => {
            print!("{HELP}");
            Ok(())
        }
        Some("-h") | Some("--help") | Some("help") => {
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
        Some("init") => cmd_init(&args[1..]).await,
        Some("create") | Some("new") => cmd_create(&args[1..]).await,
        Some("join") => cmd_join(&args[1..]).await,
        Some("up") => cmd_up(&args[1..]).await,
        Some("gui") | Some("ui") => cmd_gui(&args[1..]),
        Some("status") | Some("peers") => cmd_status(&args[1..]).await,
        Some("token") => cmd_token(&args[1..]),
        Some("rotate") => cmd_rotate(&args[1..]).await,
        Some("leave") | Some("down") => cmd_leave(&args[1..]).await,
        Some("config") => cmd_config(&args[1..]),
        Some("nets") => cmd_nets(&args[1..]).await,
        Some("delete") | Some("rm") => cmd_delete(&args[1..]).await,
        Some("doctor") => cmd_doctor(&args[1..]).await,
        Some("punch") => cmd_punch(&args[1..]).await,
        Some("forward") => cmd_forward(&args[1..]).await,
        Some("tun") => cmd_tun(&args[1..]).await,
        Some(other) => {
            print!("{HELP}");
            bail!("未知命令：{other}")
        }
    }
}

#[derive(Default)]
struct Flags {
    values: HashMap<String, Vec<String>>,
    positional: Vec<String>,
}

impl Flags {
    fn parse(args: &[String]) -> Result<Self> {
        let mut flags = Flags::default();
        let mut iter = args.iter().peekable();
        while let Some(arg) = iter.next() {
            if arg == "-h" {
                flags
                    .values
                    .entry("help".to_string())
                    .or_default()
                    .push("true".into());
                continue;
            }
            let Some(key) = arg.strip_prefix("--") else {
                flags.positional.push(arg.clone());
                continue;
            };
            // --help 之类的开关没有值
            if key == "help" || key == "h" {
                flags
                    .values
                    .entry("help".to_string())
                    .or_default()
                    .push("true".into());
                continue;
            }
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

    fn addrs(&self, key: &str) -> Result<Vec<SocketAddr>> {
        self.many(key)
            .iter()
            .map(|raw| {
                raw.parse::<SocketAddr>()
                    .with_context(|| format!("--{key} 不是合法地址：{raw}"))
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// 本地配置
// ---------------------------------------------------------------------------

fn config_path(flags: &Flags) -> PathBuf {
    data_dir(flags)
        .unwrap_or_else(Config::default_dir)
        .join(qp2p_core::config::CONFIG_FILE)
}

fn load_config(flags: &Flags) -> Result<(Config, PathBuf)> {
    let path = config_path(flags);
    let config = Config::load(&path).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok((config, path))
}

fn save_config(config: &Config, path: &std::path::Path) -> Result<()> {
    config
        .save(path)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("保存配置失败：{}", path.display()))
}

/// 信令地址：命令行 > 配置文件。
fn worker_of(config: &Config, flags: &Flags) -> Result<String> {
    flags
        .get("worker")
        .map(str::to_string)
        .or_else(|| config.worker.clone())
        .map(|w| normalize_worker(&w))
        .transpose()?
        .context(
            "还没设置信令地址。先运行：\n  qp2p init https://你的-worker.workers.dev\n\
             （就是你部署 signal/worker.js 得到的那个地址）",
        )
}

/// 管理密钥：命令行 > 环境变量 > 配置文件。
fn admin_of(config: &Config, flags: &Flags) -> Option<String> {
    flags
        .get("admin")
        .map(str::to_string)
        .or_else(|| std::env::var("QP2P_ADMIN_SECRET").ok())
        .or_else(|| config.admin_secret.clone())
        .filter(|s| !s.trim().is_empty())
}

/// 本机名：`--name` > 配置 > 系统主机名。
fn node_name(config: &Config, flags: &Flags) -> String {
    flags
        .get("name")
        .map(str::to_string)
        .or_else(|| {
            let name = config.node_name.trim();
            if name.is_empty() || name == qp2p_core::config::LEGACY_PLACEHOLDER_NAME {
                None
            } else {
                Some(name.to_string())
            }
        })
        .unwrap_or_else(qp2p_core::config::machine_name)
}

fn data_dir(flags: &Flags) -> Option<PathBuf> {
    if let Some(raw) = flags.get("data-dir") {
        return Some(PathBuf::from(raw));
    }
    // 默认给一个稳定目录：身份、证书、配置都在里面，重启后 node_id 不变
    Some(Config::default_dir())
}

fn load_identity(flags: &Flags) -> Result<Identity> {
    Identity::load_or_create(data_dir(flags).as_deref()).context("读取本机身份失败")
}

// ---------------------------------------------------------------------------
// init / create / join
// ---------------------------------------------------------------------------

async fn cmd_init(args: &[String]) -> Result<()> {
    let flags = Flags::parse(args)?;
    let raw = flags
        .positional
        .first()
        .map(String::as_str)
        .or(flags.get("worker"))
        .context("用法：qp2p init https://你的-worker.workers.dev")?;
    let worker = normalize_worker(raw)?;

    println!("检查 {worker} …");
    let health = qp2p_core::signal::client::health_of(&worker)
        .await
        .context("这个地址不是可用的 qp2p 信令服务")?;

    if !health.ok {
        bail!(
            "服务端自检没通过（storage={}）。{}",
            health.storage,
            if health.storage == "d1" {
                "多半是 D1 表还没建好：重新部署一次 Worker，表会在首次请求时自动创建"
            } else {
                "看 Worker 的日志/部署状态"
            }
        );
    }

    println!("✓ Worker 可用");
    println!("  版本    : {}", health.version);
    println!(
        "  存储    : {}",
        if health.storage == "d1" {
            "D1（多地域一致）"
        } else {
            "内存（只存在单个实例里，重启就丢）"
        }
    );
    if !health.warning.is_empty() {
        println!("  注意    : {}", health.warning);
    }
    if health.has_admin_secret {
        println!("  管理密钥: 已配置");
    } else {
        println!("  管理密钥: 未配置");
        println!("            → Cloudflare → Worker → Settings → Variables 添加 ADMIN_SECRET 后重新部署，");
        println!("              否则建不了网络（成员加入不需要它）");
    }

    let (mut config, path) = load_config(&flags)?;
    config.worker = Some(worker.clone());
    if let Some(admin) = flags.get("admin") {
        config.admin_secret = Some(admin.to_string());
        println!("  已保存 ADMIN_SECRET 到本机配置");
    }
    save_config(&config, &path)?;

    println!("\n已写入 {}", path.display());
    println!("下一步：qp2p create home");
    Ok(())
}

async fn cmd_create(args: &[String]) -> Result<()> {
    let flags = Flags::parse(args)?;
    let name = flags
        .positional
        .first()
        .map(String::as_str)
        .context("用法：qp2p create <网络名>（例如 qp2p create home）")?
        .to_string();
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        bail!("网络名只能用小写字母、数字和连字符：{name}");
    }

    let (mut config, path) = load_config(&flags)?;
    let worker = worker_of(&config, &flags)?;
    let admin = admin_of(&config, &flags).context(
        "建网需要管理密钥（ADMIN_SECRET）。三种给法任选一种：\n\
         1) qp2p init <地址> --admin <密钥>   （推荐，会保存下来）\n\
         2) qp2p create home --admin <密钥>\n\
         3) 设置环境变量 QP2P_ADMIN_SECRET",
    )?;

    let client = SignalClient::admin(&worker)?;
    println!("正在 {worker} 上创建网络 {name} …");
    let issued = client
        .create_network(&admin, &name, flags.get("key"), flags.get("cidr"))
        .await?;

    config.worker = Some(worker.clone());
    config.network = Some(Network {
        id: issued.network.id.clone(),
        token: issued.token.clone(),
        cidr: Some(issued.network.cidr.clone()),
        virtual_ip: None,
        route: Default::default(),
        advertise: Vec::new(),
        deny_inbound: false,
    });
    save_config(&config, &path)?;

    if !issued.warning.is_empty() {
        println!("\n注意：{}", issued.warning);
    }

    println!(
        "\n✓ 网络已创建：{}（{}）",
        issued.network.name, issued.network.cidr
    );
    println!("\n加入令牌（发给其它机器，一条命令就能加入）：");
    println!("\n    qp2p join {}\n", issued.token);
    println!("本机已经保存好令牌，直接运行：qp2p up");
    println!(
        "（令牌也会写进 {}，用 qp2p token 可以再显示）",
        path.display()
    );
    Ok(())
}

async fn cmd_join(args: &[String]) -> Result<()> {
    let flags = Flags::parse(args)?;
    let raw = flags
        .positional
        .first()
        .map(String::as_str)
        .or(flags.get("token"))
        .context("用法：qp2p join qp2p1_<网络>_<密钥>")?;

    let token = extract_token(raw).with_context(|| {
        format!(
            "这看起来不是加入令牌。它应该以 qp2p1_ 开头，形如 qp2p1_home_3f9a…（你给的是 {:?}）",
            raw.chars().take(32).collect::<String>()
        )
    })?;
    let (network_id, _) = parse_token(&token).expect("extract_token 只返回合法令牌");

    let (mut config, path) = load_config(&flags)?;
    // 允许直接粘贴 `https://worker/?token=...`：从链接里取 worker 地址
    let worker = match flags.get("worker") {
        Some(w) => normalize_worker(w)?,
        None => {
            if raw.trim_start().starts_with("http") {
                let origin = raw
                    .trim()
                    .split(['?', '#'])
                    .next()
                    .unwrap_or(raw)
                    .trim_end_matches('/')
                    .to_string();
                normalize_worker(&origin)?
            } else {
                worker_of(&config, &flags)?
            }
        }
    };

    let client = SignalClient::new(&worker, &token)?;
    let identity = load_identity(&flags)?;
    let name = node_name(&config, &flags);

    // 想固定地址就自己给；不给由服务端分配，之后重连也保持不变
    let requested_ip: Option<Ipv4Addr> = match flags.get("ip").or(flags.get("tun-addr")) {
        Some(raw) => Some(
            raw.parse()
                .with_context(|| format!("--ip 不是合法 IPv4：{raw}"))?,
        ),
        None => None,
    };

    println!("正在加入 {network_id}（{worker}）…");
    let reply = client
        .join(&identity, &name, requested_ip)
        .await
        .context("加入失败")?;

    config.worker = Some(worker.clone());
    config.network = Some(Network {
        id: reply.network.id.clone(),
        token: token.clone(),
        cidr: Some(reply.network.cidr.clone()),
        virtual_ip: Some(reply.node.virtual_ip.clone()),
        route: Default::default(),
        advertise: Vec::new(),
        deny_inbound: false,
    });
    save_config(&config, &path)?;

    println!(
        "\n✓ 已加入 {}（{}）",
        reply.network.name, reply.network.cidr
    );
    println!("  本机  : {name}  {}", reply.node.virtual_ip);
    println!("  成员  : {} 个在线/历史节点", reply.peers.len());
    println!("\n已保存到 {}", path.display());
    println!("下一步：qp2p up");
    Ok(())
}

// ---------------------------------------------------------------------------
// status / token / rotate / leave
// ---------------------------------------------------------------------------

fn active_network(config: &Config) -> Result<Network> {
    config
        .network
        .clone()
        .context("本机还没加入任何网络。\n  建网：qp2p create <名字>\n  加入：qp2p join <令牌>")
}

async fn cmd_status(args: &[String]) -> Result<()> {
    let flags = Flags::parse(args)?;
    let (config, path) = load_config(&flags)?;
    let network = active_network(&config)?;
    let worker = worker_of(&config, &flags)?;
    let client = SignalClient::new(&worker, &network.token)?;
    let identity = load_identity(&flags)?;
    let name = node_name(&config, &flags);

    println!("qp2p {}", env!("CARGO_PKG_VERSION"));
    println!("信令服务 : {worker}");
    println!(
        "网络     : {}  {}",
        network.id,
        network.cidr.clone().unwrap_or_default()
    );
    println!("本机名称 : {name}");
    println!("node_id  : {}", identity.node_id());
    println!("配置     : {}", path.display());

    // join 只刷新在线状态，不需要候选地址，也不会影响正在跑的 up
    let reply = client.join(&identity, &name, None).await?;
    println!(
        "虚拟地址 : {}（网段 {}）",
        reply.node.virtual_ip, reply.network.cidr
    );
    if !reply.durable {
        println!("注意     : 服务端没绑 D1，状态只存在单个实例里，可能看到不完整的成员");
    }

    let mut peers = reply.peers;
    peers.sort_by(|a, b| a.virtual_ip.cmp(&b.virtual_ip));

    println!("\n成员（{} 个，不算本机）：", peers.len());
    if peers.is_empty() {
        println!("  还没有其它节点。把令牌发给别人：qp2p token");
    } else {
        println!(
            "  {:<16} {:<16} {:<7} 可直连地址",
            "名称", "虚拟地址", "状态"
        );
        for peer in &peers {
            let state = if peer.online {
                "在线".to_string()
            } else {
                format!("离线{}", human_age(peer.idle_secs()))
            };
            println!(
                "  {:<16} {:<16} {:<7} {}",
                truncate(&peer.name, 16),
                peer.virtual_ip,
                state,
                peer.candidates.len()
            );
        }
        println!("\n提示：qp2p up 会把在线成员全部自动连上，不需要逐个点名。");
    }
    Ok(())
}

fn cmd_token(args: &[String]) -> Result<()> {
    let flags = Flags::parse(args)?;
    let (config, _) = load_config(&flags)?;
    let network = active_network(&config)?;
    println!("{}", network.token);
    Ok(())
}

async fn cmd_rotate(args: &[String]) -> Result<()> {
    let flags = Flags::parse(args)?;
    let (mut config, path) = load_config(&flags)?;
    let network = active_network(&config)?;
    let worker = worker_of(&config, &flags)?;
    let admin = admin_of(&config, &flags)
        .context("换密钥需要管理密钥（ADMIN_SECRET），见 qp2p create 的说明")?;

    // 可以显式指定要改哪个网络；不指定就改本机所在的那个
    let target_id = flags
        .get("network")
        .map(str::to_string)
        .unwrap_or_else(|| network.id.clone());
    let client = SignalClient::admin(&worker)?;
    let issued = client
        .rotate_join_key(&admin, &target_id, flags.get("key"))
        .await?;

    // 只有改的就是本机这个网络时才更新本机令牌，别把别人的网络写进自己配置
    if target_id == network.id {
        let mut updated = network.clone();
        updated.token = issued.token.clone();
        updated.cidr = Some(issued.network.cidr.clone());
        config.network = Some(updated);
        save_config(&config, &path)?;
    } else {
        println!(
            "注意：改的是网络「{target_id}」，本机所在的「{}」没有变化",
            network.id
        );
    }

    if !issued.warning.is_empty() {
        println!("注意：{}", issued.warning);
    }
    println!("✓ 已换新令牌，旧令牌立刻失效");
    println!("\n新的加入令牌：\n\n    qp2p join {}\n", issued.token);
    println!("正在运行的节点：已经建立的直连不会立刻断，但它们刷新注册会被拒（约 1 分钟后），");
    println!("所以要新增成员，把新令牌发给它们重新 join 一次。新机器一律用新令牌。");
    Ok(())
}

async fn cmd_leave(args: &[String]) -> Result<()> {
    let flags = Flags::parse(args)?;
    let (config, _) = load_config(&flags)?;
    let network = active_network(&config)?;
    let worker = worker_of(&config, &flags)?;
    let identity = load_identity(&flags)?;
    let client = SignalClient::new(&worker, &network.token)?;

    match client.leave(&identity).await {
        Ok(()) => println!("✓ 已从网络 {} 注销本机", network.id),
        Err(e) => println!("注销请求没成功（服务端可能已经把本机当成离线清掉了）：{e}"),
    }
    println!("本机令牌仍在，随时可以 qp2p up 重新上线。");
    Ok(())
}

// ---------------------------------------------------------------------------
// 本机配置：查看 / 修改 / 撤销
// ---------------------------------------------------------------------------

fn cmd_config(args: &[String]) -> Result<()> {
    let flags = Flags::parse(args)?;
    let (mut config, path) = load_config(&flags)?;

    match flags
        .positional
        .first()
        .map(String::as_str)
        .unwrap_or("list")
    {
        "list" | "show" => {
            print_config(&config, &path);
            Ok(())
        }
        "set" => {
            let key = flags
                .positional
                .get(1)
                .map(String::as_str)
                .context("用法：qp2p config set <项> <值>，例如 qp2p config set mtu 1280")?;
            let value = flags
                .positional
                .get(2)
                .map(String::as_str)
                .or_else(|| flags.get("value"))
                .context("缺少值：qp2p config set mtu 1280")?;
            set_config(&mut config, key, value)?;
            save_config(&config, &path)?;
            println!("✓ 已保存 {key} = {value}");
            println!("  写到 {}", path.display());
            Ok(())
        }
        "unset" => {
            let key = flags
                .positional
                .get(1)
                .map(String::as_str)
                .context("用法：qp2p config unset <项>")?;
            unset_config(&mut config, key)?;
            save_config(&config, &path)?;
            println!("✓ 已清除 {key}，回到默认值");
            Ok(())
        }
        other => bail!("config 只支持 list / set / unset，不认识 {other}"),
    }
}

fn print_config(config: &Config, path: &std::path::Path) {
    let show = |value: Option<&str>, default: &str| match value {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => format!("{default}（默认）"),
    };

    println!("配置文件 : {}", path.display());
    println!(
        "信令服务 : {}",
        config
            .worker
            .as_deref()
            .unwrap_or("未设置（qp2p init <地址>）")
    );
    println!(
        "管理密钥 : {}",
        if config.admin_secret.is_some() {
            "已保存（建网/换密码用）"
        } else {
            "未保存"
        }
    );
    println!(
        "本机名称 : {}",
        show(Some(config.node_name.as_str()), "主机名")
    );
    println!("UDP 监听 : {}", config.listen);
    println!("虚拟网卡 : {}", show(config.dev.as_deref(), "qp2p0"));
    println!(
        "MTU      : {}",
        config
            .mtu
            .map(|v| v.to_string())
            .unwrap_or_else(|| "1400（默认）".into())
    );
    println!(
        "额外路由 : {}",
        if config.routes.is_empty() {
            "无".to_string()
        } else {
            config.routes.join(", ")
        }
    );
    println!("STUN     : {}", config.stun.join(", "));
    match &config.network {
        Some(net) => {
            println!(
                "网络     : {}  {}",
                net.id,
                net.cidr.as_deref().unwrap_or("（未知网段）")
            );
            println!(
                "虚拟地址 : {}",
                net.virtual_ip.as_deref().unwrap_or("由服务端分配")
            );
            println!("加入令牌 : {}", mask_token(&net.token));
        }
        None => println!("网络     : 未加入（qp2p create / qp2p join）"),
    }
    println!("\n改一项：qp2p config set <项> <值>   撤销：qp2p config unset <项>");
    println!("可用项：worker / admin_secret / node_name / listen / mtu / dev / stun / routes / ip");
}

fn set_config(config: &mut Config, key: &str, value: &str) -> Result<()> {
    match key {
        "worker" => config.worker = Some(normalize_worker(value)?),
        "admin_secret" => config.admin_secret = Some(value.to_string()),
        "node_name" | "name" => config.node_name = value.to_string(),
        "listen" | "bind" => {
            value
                .parse::<SocketAddr>()
                .with_context(|| format!("listen 不是合法地址：{value}"))?;
            config.listen = value.to_string();
        }
        "mtu" => {
            let mtu: u16 = value
                .parse()
                .with_context(|| format!("mtu 不是数字：{value}"))?;
            if mtu < 576 {
                bail!("MTU 太小（{mtu}），隧道内层至少 576");
            }
            config.mtu = Some(mtu);
        }
        "dev" => config.dev = Some(value.to_string()),
        "idle" => {
            let secs: u64 = value
                .parse()
                .with_context(|| format!("idle 不是数字：{value}"))?;
            config.idle = if secs == 0 { None } else { Some(secs) };
        }
        "stun" => {
            let list = split_list(value);
            if list.is_empty() {
                bail!("stun 不能为空，例如 qp2p config set stun stun.cloudflare.com:3478");
            }
            config.stun = list;
        }
        "routes" | "route" => {
            let list = split_list(value);
            for raw in &list {
                raw.parse::<qp2p_core::route::Cidr>()
                    .with_context(|| format!("不是合法网段：{raw}"))?;
            }
            config.routes = list;
        }
        "ip" | "virtual_ip" => {
            let network = config
                .network
                .as_mut()
                .context("还没加入网络，先 qp2p join <令牌>")?;
            let ip: Ipv4Addr = value
                .parse()
                .with_context(|| format!("不是合法 IPv4：{value}"))?;
            if let Some(cidr_text) = network.cidr.as_deref() {
                let cidr: qp2p_core::route::Cidr = cidr_text
                    .parse()
                    .with_context(|| format!("网络网段不合法：{cidr_text}"))?;
                if !cidr.contains(ip) {
                    bail!("{ip} 不在本网络网段 {cidr} 里");
                }
            }
            network.virtual_ip = Some(ip.to_string());
        }
        other => bail!(
            "不认识的配置项：{other}\n\
             可用：worker / admin_secret / node_name / listen / mtu / dev / stun / routes / ip"
        ),
    }
    Ok(())
}

fn unset_config(config: &mut Config, key: &str) -> Result<()> {
    match key {
        "worker" => config.worker = None,
        "admin_secret" => config.admin_secret = None,
        "node_name" | "name" => config.node_name = String::new(),
        "listen" => config.listen = format!("0.0.0.0:{}", qp2p_core::DEFAULT_PORT),
        "mtu" => config.mtu = None,
        "idle" => config.idle = None,
        "dev" => config.dev = None,
        "stun" => config.stun = Config::default().stun,
        "routes" | "route" => config.routes.clear(),
        "ip" | "virtual_ip" => {
            if let Some(network) = config.network.as_mut() {
                network.virtual_ip = None;
            }
        }
        other => bail!("不认识的配置项：{other}"),
    }
    Ok(())
}

fn split_list(text: &str) -> Vec<String> {
    text.split([',', ' '])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// 令牌只露头尾，避免截图/录屏时整串泄漏。
fn mask_token(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    if chars.len() <= 16 {
        return token.to_string();
    }
    let head: String = chars.iter().take(12).collect();
    let tail: String = chars.iter().skip(chars.len() - 4).collect();
    format!("{head}…{tail}")
}

// ---------------------------------------------------------------------------
// 管理面：列网络 / 删网络
// ---------------------------------------------------------------------------

async fn cmd_nets(args: &[String]) -> Result<()> {
    let flags = Flags::parse(args)?;
    let (config, _) = load_config(&flags)?;
    let worker = worker_of(&config, &flags)?;
    let admin = admin_of(&config, &flags)
        .context("列网络需要管理密钥（ADMIN_SECRET）：\n  qp2p init <地址> --admin <密钥>")?;

    let client = SignalClient::admin(&worker)?;
    let networks = client.list_networks(&admin).await?;

    if networks.is_empty() {
        println!("{worker} 上还没有网络。建一个：qp2p create home");
        return Ok(());
    }

    println!("{worker} 上的网络（{} 个）：\n", networks.len());
    println!(
        "  {:<18} {:<20} {:>6}  {:<8} 备注",
        "名称", "网段", "成员", "准入密码"
    );
    for net in &networks {
        let me = config
            .network
            .as_ref()
            .map(|n| n.id == net.id)
            .unwrap_or(false);
        println!(
            "  {:<18} {:<20} {:>6}  {:<8} {}",
            truncate(&net.name, 18),
            net.cidr,
            net.nodes,
            if net.has_join_key {
                "已设置"
            } else {
                "旧版"
            },
            if me { "本机所在" } else { "" }
        );
    }
    println!("\n换准入密码：qp2p rotate --network <名称>");
    println!("删网络    ：qp2p delete <名称> --yes");
    Ok(())
}

async fn cmd_delete(args: &[String]) -> Result<()> {
    let flags = Flags::parse(args)?;
    let (mut config, path) = load_config(&flags)?;
    let worker = worker_of(&config, &flags)?;

    let name = flags
        .positional
        .first()
        .cloned()
        .or_else(|| config.network.as_ref().map(|n| n.id.clone()))
        .context("用法：qp2p delete <网络名> [--yes]")?;

    if !flags.flag("yes") {
        println!("将删除网络「{name}」：成员、事件、加入密钥一并清除，不可恢复。");
        println!("确认无误后加 --yes 再执行一次：\n\n    qp2p delete {name} --yes\n");
        return Ok(());
    }

    let admin = admin_of(&config, &flags)
        .context("删除网络需要管理密钥（ADMIN_SECRET）：\n  qp2p init <地址> --admin <密钥>")?;
    let client = SignalClient::admin(&worker)?;
    let removed = client.delete_network(&admin, &name).await?;

    println!("✓ 已删除网络 {name}，清理 {removed} 个节点");
    if config.network.as_ref().map(|n| n.id.as_str()) == Some(name.as_str()) {
        config.network = None;
        save_config(&config, &path)?;
        println!("本机配置里的网络已清除，可以 qp2p join 新令牌");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// up：上线组网
// ---------------------------------------------------------------------------

/// 图形界面入口：只有 Windows 有原生窗口，其它平台明确告知。
fn cmd_gui(args: &[String]) -> Result<()> {
    #[cfg(windows)]
    {
        gui::run(args)
    }
    #[cfg(not(windows))]
    {
        let _ = args;
        bail!("图形界面只有 Windows 版有。这台机器请用命令行：\n  qp2p join <令牌>   加入网络\n  qp2p up            上线（需要 root）")
    }
}

async fn cmd_up(args: &[String]) -> Result<()> {
    let flags = Flags::parse(args)?;
    if flags.flag("help") {
        print!("{HELP}");
        println!(
            "\nup 的选项：\n  \
             --name <名字>     本机在成员列表里显示的名字\n  \
             --punch-only      只打洞不建虚拟网卡（不需要 root，用来验证能不能连通）\n  \
             --bind <addr>     UDP 监听地址，默认 0.0.0.0:51820\n  \
             --stun <host:port> 可重复，覆盖默认的 STUN 服务器\n  \
             --dev <名字>      虚拟网卡名，默认 qp2p0\n  \
             --mtu <n>         虚拟网卡 MTU，默认 1400\n  \
             --route <网段>    额外让某个网段走隧道，可重复\n  \
             --save            把这次给的 --name/--mtu/--dev/--route/--bind/--stun 存进配置\n  \
             --data-dir <dir>  身份目录，默认 ~/.qp2p\n\n             没给的选项会沿用 qp2p config 里保存的值。\n"
        );
        return Ok(());
    }

    let (mut config, config_path) = load_config(&flags)?;
    let network = active_network(&config)?;
    let worker = worker_of(&config, &flags)?;
    let client = SignalClient::new(&worker, &network.token)?;
    let name = node_name(&config, &flags);
    let bind = flags.addr("bind", Some(&config.listen))?;
    let stun = if flags.many("stun").is_empty() {
        config.stun.clone()
    } else {
        flags.many("stun")
    };
    // 取值顺序：命令行 > 配置文件 > 默认值。用户改过一次就该一直生效。
    let mtu: u16 = match flags.get("mtu") {
        Some(raw) => raw.parse().context("--mtu 不是数字")?,
        None => config.mtu.unwrap_or(1400),
    };
    let dev = flags
        .get("dev")
        .map(str::to_string)
        .or_else(|| config.dev.clone())
        .unwrap_or_else(|| "qp2p0".to_string());
    let routes = if flags.many("route").is_empty() {
        config.routes.clone()
    } else {
        flags.many("route")
    };

    println!("qp2p {} · 网络 {}", env!("CARGO_PKG_VERSION"), network.id);
    println!("信令 {worker}");

    let engine = Engine::bind_in(bind, &stun, data_dir(&flags).as_deref())
        .await
        .context("绑定 UDP 失败（端口被占用？用 --bind 换一个）")?;
    let node_id = engine.node_id();
    let identity = engine.identity().clone();
    let tls_fp = engine.tls_fp();

    println!("本机 {name}  node_id={node_id}");
    if let Some(srflx) = engine.srflx() {
        println!("公网映射 {srflx}");
    } else {
        println!("公网映射 未知（STUN 不可达，只能靠内网或 UPnP 建连）");
    }

    let candidates = qp2p_core::session::candidate_strings(&engine);
    let nat_type = qp2p_core::session::nat_type(&engine);
    // 配置里存的就是用户上次要求的地址（join --ip 或 config set ip），
    // 每次都带上：服务端会校验并原样保留，用户改配置后也能立刻切过去。
    let wanted_ip: Option<Ipv4Addr> = network.virtual_ip.as_deref().and_then(|s| s.parse().ok());
    let reply = match client
        .register(&identity, &name, &tls_fp, &candidates, nat_type, wanted_ip)
        .await
    {
        Ok(reply) => reply,
        Err(e) if qp2p_core::session::token_rejected(&e) => bail!(
            "加入令牌已失效（网络被删除，或管理员执行了 qp2p rotate）。\n\
             找管理员要新令牌，然后重新 qp2p join <新令牌>"
        ),
        Err(e) => return Err(e).context("向信令服务器注册失败"),
    };

    let virtual_ip: Ipv4Addr = reply
        .node
        .virtual_ip
        .parse()
        .with_context(|| format!("服务端给的虚拟地址不合法：{}", reply.node.virtual_ip))?;

    println!(
        "虚拟地址 {virtual_ip}/{}（{}）",
        cidr_prefix(&reply.network.cidr),
        reply.network.name
    );
    if reply.peers.is_empty() {
        println!("成员 目前只有你一个，把令牌发给别的机器：qp2p token");
    } else {
        let online = reply.peers.iter().filter(|p| p.online).count();
        println!("成员 {} 个（在线 {}）", reply.peers.len(), online);
    }
    if !reply.durable {
        println!("注意 服务端没绑 D1，多地域部署时可能互相看不见");
    }

    // 记下服务端给的网段和地址，status 不用再问一遍
    if config.network.as_ref().map(|n| n.cidr.clone()) != Some(Some(reply.network.cidr.clone()))
        || config.network.as_ref().and_then(|n| n.virtual_ip.clone())
            != Some(virtual_ip.to_string())
    {
        if let Some(entry) = config.network.as_mut() {
            entry.cidr = Some(reply.network.cidr.clone());
            entry.virtual_ip = Some(virtual_ip.to_string());
        }
        let _ = save_config(&config, &config_path);
    }

    // 把这次命令行里的选择固化下来：下次直接 qp2p up 就带同样的参数
    if flags.flag("save") {
        config.node_name = name.clone();
        config.mtu = Some(mtu);
        config.dev = Some(dev.clone());
        config.routes = routes.clone();
        config.listen = bind.to_string();
        if !stun.is_empty() {
            config.stun = stun.clone();
        }
        save_config(&config, &config_path)?;
        println!(
            "已把这次的选择保存到 {}（下次 up 直接沿用）",
            config_path.display()
        );
    }

    let net_cidr: Option<qp2p_core::route::Cidr> = reply.network.cidr.parse().ok();

    // 虚拟网卡：默认开；建不起来就降级成"只打洞"，不让整条命令失败
    let want_tun = !(flags.flag("punch-only") || flags.flag("no-tun"));
    let mut mesh: Option<Arc<MeshLinks>> = None;
    if want_tun {
        match open_tun(&dev, &routes, &reply.network.cidr, virtual_ip, mtu) {
            Ok(links) => {
                println!("虚拟网卡 {dev} 已就绪：可以 ping 其它成员的虚拟地址");
                mesh = Some(links);
            }
            Err(e) => {
                // {e:#} 打完整错误链：Display 只露最外层 context，
                // LoadLibrary 的真实错误码（126/193/5…）全被吞了，没法排查
                println!("虚拟网卡创建失败：{e:#}");
                println!("已降级为「只打洞」模式：能看到谁连上了，但 ping 不通对端。");
                println!("Linux 需要 sudo（或 CAP_NET_ADMIN），Windows 需要管理员，并让 wintun.dll 和 qp2p.exe 放在一起。");
            }
        }
    }

    let engine = Arc::new(RwLock::new(engine));
    // 会话循环在 core 里：CLI 和 Android 共用同一套打洞/退避/事件应答逻辑
    let session = qp2p_core::session::Session::new(
        qp2p_core::session::SessionConfig {
            client: client.clone(),
            identity: identity.clone(),
            node_id: node_id.clone(),
            name: name.clone(),
            net: net_cidr,
            wanted_ip,
            // --idle <秒>：直连空闲这么久就断开（省电/省流量）。命令行优先，其次配置。
            idle_timeout: flags
                .get("idle")
                .and_then(|v| v.parse::<u64>().ok())
                .or(config.idle)
                .filter(|secs| *secs > 0)
                .map(Duration::from_secs),
            peers: reply.peers.clone(),
        },
        engine.clone(),
        mesh.clone(),
        qp2p_core::session::Notify::new(|msg: &str| println!("{msg}")),
    );
    let mut task = tokio::spawn(session.run());

    println!("\n已上线（Ctrl+C 退出）。直连建立时会打印对端名字和延迟。");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => println!("\n收到中断，正在退出…"),
        _ = &mut task => println!("信令循环意外结束"),
    }
    task.abort();

    if let Some(mesh) = &mesh {
        let count = mesh.peer_count().await;
        if count > 0 {
            println!("已断开 {count} 条直连");
        }
    }
    if let Err(e) = client.leave(&identity).await {
        println!("（下线通知没发出去，服务端会在 2 分钟后把它当成离线：{e}）");
    }
    engine.write().await.shutdown().await;
    Ok(())
}

/// 建虚拟网卡并启动数据面，返回连接表。
fn open_tun(
    dev: &str,
    routes: &[String],
    network_cidr: &str,
    virtual_ip: Ipv4Addr,
    mtu: u16,
) -> Result<Arc<MeshLinks>> {
    let cidr: qp2p_core::route::Cidr = network_cidr
        .parse()
        .with_context(|| format!("服务端给的网段不合法：{network_cidr}"))?;

    let config = qp2p_core::route::TunConfig {
        name: dev.to_string(),
        address: virtual_ip,
        prefix: cidr.prefix,
        mtu,
    };
    let device = qp2p_core::route::open(&config)?;

    for raw in routes {
        let extra: qp2p_core::route::Cidr = raw
            .parse()
            .with_context(|| format!("--route 不是合法网段：{raw}"))?;
        qp2p_core::route::add_route(&config.name, &extra)
            .with_context(|| format!("添加路由 {extra} 失败"))?;
        println!("路由 {extra} → {}", config.name);
    }

    let link = qp2p_core::route::spawn_io(device, mtu);
    let links = MeshLinks::new(link.to_tun.clone());
    let runner = links.clone();
    tokio::spawn(async move {
        if let Err(e) = link::tun::run_mesh(runner, link.from_tun, virtual_ip, mtu).await {
            tracing::warn!("[tun] 数据面退出: {e:#}");
        }
    });
    Ok(links)
}

/// 取网段前缀长度，格式不对时回落到默认值。
fn cidr_prefix(cidr: &str) -> u8 {
    cidr.split_once('/')
        .and_then(|(_, p)| p.parse().ok())
        .unwrap_or(qp2p_core::DEFAULT_NETWORK_PREFIX_LEN)
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    text.chars().take(max.saturating_sub(1)).collect::<String>() + "…"
}

fn human_age(secs: i64) -> String {
    if secs < 60 {
        return String::new();
    }
    if secs < 3600 {
        return format!("{} 分钟", secs / 60);
    }
    format!("{} 小时", secs / 3600)
}

// ---------------------------------------------------------------------------
// 以下是不经过信令面的直连调试命令
// ---------------------------------------------------------------------------

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

    let engine = Engine::bind_in(bind, &stun, data_dir(&flags).as_deref())
        .await
        .context("绑定失败")?;
    println!("node_id: {}", engine.node_id());
    println!("pubkey : {}", engine.public_key_hex());
    println!("udp  local: {}", engine.local_addr());
    match engine.srflx() {
        Some(addr) => println!("udp  公网: {addr}"),
        None => println!("udp  公网: 未知（STUN 未配置或不可达）"),
    }
    match engine.upnp() {
        Some(addr) => println!("udp  UPnP: {addr}"),
        None => println!("udp  UPnP: 不可用（路由器未开启或无 IGD）"),
    }
    for candidate in engine.candidates() {
        println!("candidate {candidate}");
    }
    Ok(())
}

async fn cmd_punch(args: &[String]) -> Result<()> {
    let flags = Flags::parse(args)?;
    let (mut engine, peers, role) = prepare(&flags).await?;

    println!("本端 UDP: {}", engine.local_addr());
    println!("本端 node_id: {}", engine.node_id());
    println!("本端 tls_fp : {}", engine.tls_fp());
    for candidate in engine.candidates() {
        println!("candidate {candidate}");
    }
    println!("对端候选: {} 个  角色: {role:?}", peers.len());

    let conn = engine
        .punch_with_retry(role, || peers.clone(), 2)
        .await
        .context("打洞失败")?;
    println!(
        "直连已建立 rtt={:?} peer={}",
        conn.rtt(),
        conn.remote_address()
    );

    // 两端都接流：单向只让 listener 接会导致反方向流量永远挂住
    let allowed = std::sync::Arc::new(Vec::new());
    let serve_conn = conn.clone();
    tokio::spawn(async move {
        let _ = link::serve_flows(serve_conn, allowed).await;
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => println!("收到中断，退出"),
        reason = conn.closed() => println!("连接已关闭（{reason}），退出"),
    }

    // 显式收尾：删掉路由器上的 UPnP 映射。Drop 里 spawn 的任务在运行时关闭时跑不完。
    engine.shutdown().await;
    Ok(())
}

/// TUN 模式：把整台机器接进虚拟网段，能直接 ping / 访问对端网段。
///
/// 和 `forward` 的区别：`forward` 是"一个本地端口 ↔ 一个对端地址"，不需要任何权限；
/// `tun` 要建虚拟网卡（Linux 需 root/CAP_NET_ADMIN，Windows 需管理员 + wintun.dll），
/// 换来的是透明访问——不用为每个目标配一条映射。
async fn cmd_tun(args: &[String]) -> Result<()> {
    let flags = Flags::parse(args)?;
    let (mut engine, peers, role) = prepare(&flags).await?;

    let net_text = flags.get("net").unwrap_or("10.64.0.0/16");
    let net: qp2p_core::route::Cidr = net_text
        .parse()
        .with_context(|| format!("--net 不是合法网段：{net_text}"))?;

    let address = match flags.get("tun-addr") {
        Some(raw) => raw
            .parse::<std::net::Ipv4Addr>()
            .with_context(|| format!("--tun-addr 不是合法 IPv4：{raw}"))?,
        // 由 node_id 派生：同一个身份每次拿到同一个地址，不用手工分配、也不会撞车
        None => qp2p_core::identity::derive_virtual_ip(&engine.node_id(), net.base, net.prefix, 0),
    };
    if !net.contains(address) {
        bail!("--tun-addr {address} 不在 --net {net} 里");
    }

    let mtu: u16 = flags
        .get("mtu")
        .unwrap_or("1400")
        .parse()
        .context("--mtu 不是数字")?;

    println!("本端 node_id: {}", engine.node_id());
    println!("虚拟地址   : {address}/{}", net.prefix);
    println!("对端候选   : {} 个  角色: {role:?}", peers.len());

    let conn = engine
        .punch_with_retry(role, || peers.clone(), 2)
        .await
        .context("打洞失败")?;
    println!("直连已建立 rtt={:?}", conn.rtt());

    let config = qp2p_core::route::TunConfig {
        name: flags.get("dev").unwrap_or("qp2p0").to_string(),
        address,
        prefix: net.prefix,
        mtu,
    };
    let device = qp2p_core::route::open(&config).with_context(|| {
        format!(
            "创建虚拟网卡 {} 失败（Linux 需要 root；Windows 需要管理员并把 wintun.dll 放在 exe 旁边）",
            config.name
        )
    })?;
    // 访问对端背后的局域网：把那些网段指到这条隧道上
    for raw in flags.many("route") {
        let cidr: qp2p_core::route::Cidr = raw
            .parse()
            .with_context(|| format!("--route 不是合法网段：{raw}"))?;
        qp2p_core::route::add_route(&config.name, &cidr)
            .with_context(|| format!("添加路由 {cidr} 失败"))?;
        println!("路由已添加: {cidr} → {}", config.name);
    }

    let link = qp2p_core::route::spawn_io(device, mtu);
    println!("隧道已启动：可以 ping 对端的虚拟地址，Ctrl+C 退出");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => println!("收到中断，退出"),
        result = link::tun::run(conn.clone(), link, address) => {
            result.context("TUN 转发结束")?;
        }
    }

    engine.shutdown().await;
    Ok(())
}

async fn cmd_forward(args: &[String]) -> Result<()> {
    let flags = Flags::parse(args)?;
    let (mut engine, peers, role) = prepare(&flags).await?;
    let listen = flags.addr("listen", None)?;
    let target = flags.addr("target", None)?;

    println!("本端 UDP: {}", engine.local_addr());
    println!("本端 node_id: {}", engine.node_id());
    println!("本端 tls_fp : {}", engine.tls_fp());
    println!("对端候选: {} 个  角色: {role:?}", peers.len());
    println!("映射: {listen} → {target}（连由对端发起）");

    // 白名单是本端愿意替对端连的地址，不能拿自己的 --target 顶替：
    // --target 是对端要连的地址，方向正好相反，两边 target 不同时必然全被拒。
    let mut allow = flags.addrs("serve")?;
    allow.extend(flags.addrs("allow-target")?);
    allow.sort();
    allow.dedup();
    if allow.is_empty() {
        println!("警告：未配置 --serve，本端会拒绝对端的一切入站请求");
    } else {
        let text: Vec<String> = allow.iter().map(ToString::to_string).collect();
        println!("允许对端访问: {}", text.join(", "));
    }

    let conn = engine
        .punch_with_retry(role, || peers.clone(), 2)
        .await
        .context("打洞失败")?;
    println!("直连已建立 rtt={:?}", conn.rtt());

    let allowed = std::sync::Arc::new(allow);

    let serve_conn = conn.clone();
    let serve_allowed = allowed.clone();
    tokio::spawn(async move {
        let _ = link::serve_flows(serve_conn, serve_allowed).await;
    });

    let forward_conn = conn.clone();
    let mut forward =
        tokio::spawn(async move { link::forward_listen(forward_conn, listen, target).await });
    println!("开始转发，Ctrl+C 退出");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => println!("收到中断，退出"),
        reason = conn.closed() => println!("连接已关闭（{reason}），退出"),
        res = &mut forward => match res {
            Ok(Ok(())) => println!("转发任务结束"),
            Ok(Err(e)) => println!("转发任务失败：{e:#}"),
            Err(e) => println!("转发任务异常：{e}"),
        },
    }

    forward.abort();
    engine.shutdown().await;
    Ok(())
}

/// 对端身份策略。
///
/// 认证只证明"对面持有某把密钥"，不证明"对面是你想连的那个人"：不限定身份时，
/// 任何人现生成一把密钥都能通过认证、并访问 `--serve` 白名单里的地址。
/// 所以默认必须明说要连谁；确实不想限定，要显式写 `--any-peer`。
#[derive(Debug, PartialEq, Eq)]
enum PeerPolicy {
    Pinned(qp2p_core::identity::NodeId),
    Any,
}

fn peer_policy(flags: &Flags) -> Result<PeerPolicy> {
    let pinned = flags.get("peer-id");
    let any = flags.flag("any-peer");

    match (pinned, any) {
        (Some(_), true) => bail!("--peer-id 和 --any-peer 互相矛盾，只能选一个"),
        (Some(raw), false) => {
            let id = qp2p_core::identity::NodeId::parse(raw)
                .with_context(|| format!("--peer-id 格式不对（要 32 位十六进制）：{raw}"))?;
            Ok(PeerPolicy::Pinned(id))
        }
        (None, true) => Ok(PeerPolicy::Any),
        (None, false) => bail!(
            "缺少 --peer-id：不限定对端身份时，任何人生成一把密钥都能通过认证，\n\
             并访问 --serve 里的地址。请在对端运行 `qp2p doctor` 取它的 node_id；\n\
             确实要放开（仅限可信网络试验），请显式加 --any-peer"
        ),
    }
}

async fn prepare(flags: &Flags) -> Result<(Engine, Vec<SocketAddr>, Role)> {
    // 先校验策略：错了就立刻报，别等绑定端口、STUN、UPnP 折腾完才发现
    let policy = peer_policy(flags)?;
    let bind = flags.addr("bind", Some("0.0.0.0:51820"))?;
    let peers = flags.addrs("peer")?;
    if peers.is_empty() {
        bail!("至少需要一个 --peer");
    }
    if peers.iter().any(|p| p.port() == 0) {
        bail!("--peer 端口不能为 0");
    }
    let role = if flags.flag("dialer") {
        Role::Dialer
    } else {
        Role::Listener
    };
    let mut engine = Engine::bind_in(bind, &flags.many("stun"), data_dir(flags).as_deref())
        .await
        .context("绑定 UDP 失败")?;

    // 打洞成功后双方会交换身份并互相验签，并且签名绑定本条 TLS 会话
    match policy {
        PeerPolicy::Pinned(id) => engine.expect_peer(Some(id)),
        PeerPolicy::Any => {
            tracing::warn!("已指定 --any-peer：不限定对端身份，任何持有合法密钥的节点都能通过认证")
        }
    }

    if let Some(fp) = flags.get("peer-fp") {
        engine
            .expect_peer_fp(Some(fp))
            .with_context(|| format!("--peer-fp 不合法：{fp}"))?;
    }

    Ok((engine, peers, role))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "00112233445566778899aabbccddeeff";

    fn flags(args: &[&str]) -> Flags {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        Flags::parse(&args).expect("参数合法")
    }

    #[test]
    fn peer_id_is_required_by_default() {
        let err = peer_policy(&flags(&["--peer", "1.2.3.4:5"])).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("--peer-id"), "{text}");
        assert!(text.contains("--any-peer"), "{text}");
    }

    #[test]
    fn peer_id_pins_the_identity() {
        let policy = peer_policy(&flags(&["--peer-id", ID])).unwrap();
        match policy {
            PeerPolicy::Pinned(id) => assert_eq!(id.as_str(), ID),
            PeerPolicy::Any => panic!("应当是 Pinned"),
        }
    }

    #[test]
    fn any_peer_must_be_explicit() {
        assert_eq!(
            peer_policy(&flags(&["--any-peer"])).unwrap(),
            PeerPolicy::Any
        );
        // 开关后面紧跟别的选项也要认
        assert_eq!(
            peer_policy(&flags(&["--any-peer", "--dialer"])).unwrap(),
            PeerPolicy::Any
        );
    }

    #[test]
    fn conflicting_or_malformed_peer_id_is_rejected() {
        assert!(peer_policy(&flags(&["--peer-id", ID, "--any-peer"])).is_err());
        assert!(peer_policy(&flags(&["--peer-id", "not-hex"])).is_err());
        assert!(peer_policy(&flags(&["--peer-id", "abcd"])).is_err());
    }

    #[test]
    fn positional_arguments_are_kept() {
        let parsed = flags(&["https://p2p.example.com", "--admin", "s3cret"]);
        assert_eq!(parsed.positional, vec!["https://p2p.example.com"]);
        assert_eq!(parsed.get("admin"), Some("s3cret"));
    }

    #[test]
    fn cidr_prefix_falls_back_when_missing() {
        assert_eq!(cidr_prefix("10.64.0.0/16"), 16);
        assert_eq!(
            cidr_prefix("garbage"),
            qp2p_core::DEFAULT_NETWORK_PREFIX_LEN
        );
    }
}
