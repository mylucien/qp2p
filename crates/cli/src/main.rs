//! qp2p 命令行前端。
//!
//! 现阶段（P3）提供三条命令：`punch`（纯打洞）、`forward`（打洞 + 端口映射）、
//! `doctor`（自检）。信令面接上之后，`--peer` 会换成节点名。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use qp2p_core::{link, Engine, Role};

const HELP: &str = "\
qp2p — 私有打洞组网

用法：
  qp2p punch   --bind <addr> --peer <addr> [--dialer] (--peer-id <id> | --any-peer) [--stun <host:port>]...
  qp2p forward --bind <addr> --peer <addr> [--dialer] (--peer-id <id> | --any-peer) --listen <addr> --target <addr>
  qp2p tun     --bind <addr> --peer <addr> [--dialer] (--peer-id <id> | --any-peer)
               [--net 10.64.0.0/16] [--tun-addr <ipv4>] [--mtu 1400] [--dev qp2p0]
  qp2p doctor  [--bind <addr>] [--stun <host:port>]...
  qp2p -V | --version

说明：
  --bind     本地 UDP 监听地址，默认 0.0.0.0:51820
  --peer     对端 UDP 地址，可重复；所有候选会并行打洞
  --dialer   本端主动发起 QUIC 握手（node_id 较小的一方）
  --listen   本机 TCP 监听地址，收到的连接经隧道送到对端的 --target
  --target   对端要去连的地址（由对端发起 TCP 连接，不是本机连它）
  --serve    本机允许对端访问的地址，可重复；不填则拒绝一切入站
             （通常填对端的 --target，两边要对称）
  --peer-id  要求对端必须是指定的 node_id（32 位十六进制），在对端运行 `qp2p doctor` 可查到
             必须二选一：--peer-id 或 --any-peer，否则拒绝启动
  --any-peer 不限定对端身份：任何人生成一把密钥都能通过认证，并访问 --serve 里的地址
             只建议在完全可信的网络里做试验时用
  --peer-fp  要求对端 TLS 证书指纹一致（64 位十六进制），不符时握手就失败
  --data-dir 身份与证书的存放目录，默认 ~/.qp2p；同一目录重启后 node_id 不变
  --net      虚拟网段，默认 10.64.0.0/16（tun 模式）
  --tun-addr 本机虚拟地址；不填则由 node_id 派生（tun 模式）
  --mtu      虚拟网卡 MTU，默认 1400（tun 模式）
  --dev      虚拟网卡名，默认 qp2p0（Linux 最长 15 字节；Windows 需要管理员）
  --route    额外让某个网段走隧道，可重复（例：--route 192.168.1.0/24）
  --allow-target  --serve 的别名，保留兼容
  --stun     可重复；支持域名，用同一个 UDP socket 探测公网映射
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
        Some("tun") => cmd_tun(&args[1..]).await,
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

    let engine = Engine::bind_in(bind, &stun, data_dir(&flags)?.as_deref())
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
    let mut engine = Engine::bind_in(bind, &flags.many("stun"), data_dir(flags)?.as_deref())
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

/// 身份目录：默认 `~/.qp2p`，可用 `--data-dir` 覆盖。
fn data_dir(flags: &Flags) -> Result<Option<std::path::PathBuf>> {
    if let Some(raw) = flags.get("data-dir") {
        return Ok(Some(std::path::PathBuf::from(raw)));
    }
    let base = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"));
    Ok(base.map(|p| std::path::PathBuf::from(p).join(".qp2p")))
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
}
