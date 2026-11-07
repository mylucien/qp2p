//! `qp2p gui`：本地配置界面。
//!
//! 不引入任何 GUI 依赖：起一个只监听 127.0.0.1 的迷你 HTTP 服务，把内置页面
//! 交给系统浏览器打开。好处是单文件、无运行时依赖、中文渲染由浏览器负责；
//! "连接"按钮实际是拉起本进程的 `up` 子命令，日志通过管道回传，断开就是 kill。
//!
//! 安全边界：只绑 127.0.0.1，并且校验 Host 头，防止 DNS rebinding 从网页里
//! 反过来操控本机隧道。

use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use qp2p_core::config::{parse_token, Config, Network};

const PAGE: &str = include_str!("gui.html");
const MAX_LOG: usize = 600;

pub(crate) struct Shared {
    child: Option<Child>,
    log: VecDeque<String>,
    /// 名称 → (虚拟地址, 延迟)
    links: BTreeMap<String, (String, String)>,
    status: String,
    warn: Option<String>,
    config: Config,
    config_path: PathBuf,
    data_dir: PathBuf,
}

pub(crate) type State = Arc<Mutex<Shared>>;

pub fn run(args: &[String]) -> Result<()> {
    let flags = crate::Flags::parse(args)?;
    let data_dir = crate::data_dir(&flags).context("没有可用的数据目录")?;
    let config_path = crate::config_path(&flags);
    std::fs::create_dir_all(&data_dir).ok();

    let config = Config::load(&config_path).map_err(|e| anyhow::anyhow!("{e}"))?;
    let state: State = Arc::new(Mutex::new(Shared {
        child: None,
        log: VecDeque::new(),
        links: BTreeMap::new(),
        status: "未连接".to_string(),
        warn: None,
        config,
        config_path,
        data_dir,
    }));

    let port = flags
        .get("port")
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(0);
    let listener = bind_local(port)?;
    let addr = listener.local_addr()?;
    let port = addr.port();
    let url = format!("http://127.0.0.1:{port}/");

    println!("qp2p 配置界面：{url}");
    println!("（关掉浏览器不会断开；托盘图标右键可连接/断开/退出）");

    {
        let state = state.clone();
        std::thread::spawn(move || serve(listener, state));
    }
    open_browser(&url);

    #[cfg(windows)]
    {
        if let Err(e) = crate::tray::run(state.clone(), port) {
            eprintln!("[gui] 托盘不可用：{e:#}（界面仍可通过 {url} 访问，Ctrl+C 退出）");
            loop {
                std::thread::sleep(Duration::from_secs(3600));
            }
        }
        return Ok(());
    }

    #[cfg(not(windows))]
    {
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }
}

/// 托盘悬停提示：状态 + 直连条数。
pub(crate) fn status_text(state: &State) -> String {
    let guard = state.lock().expect("state 锁中毒");
    let links = guard.links.len();
    if links > 0 {
        format!("qp2p · {} · {} 条直连", guard.status, links)
    } else {
        format!("qp2p · {}", guard.status)
    }
}

fn serve(listener: TcpListener, state: State) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state = state.clone();
                std::thread::spawn(move || {
                    if let Err(e) = handle(stream, state) {
                        eprintln!("[gui] 请求处理失败: {e:#}");
                    }
                });
            }
            Err(e) => eprintln!("[gui] accept 失败: {e}"),
        }
    }
}

fn bind_local(preferred: u16) -> Result<TcpListener> {
    if preferred != 0 {
        return TcpListener::bind(("127.0.0.1", preferred))
            .with_context(|| format!("端口 {preferred} 被占用"));
    }
    for port in 17878..17888 {
        if let Ok(l) = TcpListener::bind(("127.0.0.1", port)) {
            return Ok(l);
        }
    }
    TcpListener::bind(("127.0.0.1", 0)).context("绑定本地端口失败")
}

fn open_browser(url: &str) {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}

// ---------------------------------------------------------------------------
// 极简 HTTP
// ---------------------------------------------------------------------------

fn handle(mut stream: TcpStream, state: State) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];

    // 读到头部结束
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 64 * 1024 {
            break;
        }
    }
    if buf.is_empty() {
        return Ok(());
    }

    let head_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(buf.len());
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or("").to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();

    // DNS rebinding 防护：只接受本机 Host
    let mut host_ok = false;
    let mut content_length = 0usize;
    for line in head.lines().skip(1) {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("host:")
            && (lower.contains("127.0.0.1") || lower.contains("localhost"))
        {
            host_ok = true;
        }
        if let Some(rest) = lower.strip_prefix("content-length:") {
            content_length = rest.trim().parse().unwrap_or(0);
        }
    }
    if !host_ok {
        return respond(
            &mut stream,
            403,
            "text/plain; charset=utf-8",
            b"forbidden host",
        );
    }
    let mut body = buf[head_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }

    let route = path.split('?').next().unwrap_or("/").to_string();

    if method == "GET" && (route == "/" || route == "/index.html") {
        return respond(
            &mut stream,
            200,
            "text/html; charset=utf-8",
            PAGE.as_bytes(),
        );
    }
    if method == "GET" && route == "/favicon.ico" {
        return respond(&mut stream, 204, "text/plain", b"");
    }
    if route == "/api/state" {
        let payload = state_json(&state);
        return respond_json(&mut stream, 200, &payload.to_string());
    }
    if method == "POST" {
        let value: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let result = match route.as_str() {
            "/api/config" => save_config(&state, &value),
            "/api/connect" => save_config(&state, &value).and_then(|_| spawn_up(&state)),
            "/api/disconnect" => stop_child(&state),
            "/api/open-dir" => open_dir(&state),
            "/api/quit" => {
                let _ = stop_child(&state);
                respond_ok(&mut stream, &json!({ "ok": true, "bye": true }))?;
                std::process::exit(0);
            }
            _ => Err(anyhow::anyhow!("未知接口 {route}")),
        };
        match result {
            Ok(msg) => {
                let payload = json!({ "ok": true, "message": msg, "state": state_json(&state) });
                return respond_json(&mut stream, 200, &payload.to_string());
            }
            Err(e) => {
                let payload =
                    json!({ "ok": false, "error": format!("{e:#}"), "state": state_json(&state) });
                return respond_json(&mut stream, 200, &payload.to_string());
            }
        }
    }

    respond(&mut stream, 404, "text/plain; charset=utf-8", b"not found")
}

fn respond(stream: &mut TcpStream, code: u16, ctype: &str, body: &[u8]) -> Result<()> {
    let head = format!(
        "HTTP/1.1 {code} X\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\ncache-control: no-store\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

fn respond_json(stream: &mut TcpStream, code: u16, body: &str) -> Result<()> {
    respond(
        stream,
        code,
        "application/json; charset=utf-8",
        body.as_bytes(),
    )
}

fn respond_ok(stream: &mut TcpStream, value: &Value) -> Result<()> {
    respond_json(stream, 200, &value.to_string())
}

// ---------------------------------------------------------------------------
// 状态与配置
// ---------------------------------------------------------------------------

fn state_json(state: &State) -> Value {
    let mut guard = state.lock().expect("state 锁中毒");
    refresh_child(&mut guard);

    let net = guard.config.network.as_ref();
    json!({
        "running": guard.child.is_some(),
        "status": guard.status.clone(),
        "warn": guard.warn.clone(),
        "log": guard.log.iter().collect::<Vec<_>>(),
        "links": guard.links.iter().map(|(name, pair)| {
            json!({ "name": name, "ip": pair.0, "rtt": pair.1 })
        }).collect::<Vec<_>>(),
        "config": {
            "worker": guard.config.worker.clone().unwrap_or_default(),
            "token": net.map(|n| n.token.clone()).unwrap_or_default(),
            "name": guard.config.node_name.clone(),
            "ip": net.and_then(|n| n.virtual_ip.clone()).unwrap_or_default(),
            "mtu": guard.config.mtu.unwrap_or(1400),
            "idle": guard.config.idle.unwrap_or(0),
            "data_dir": guard.data_dir.display().to_string(),
        }
    })
}

fn save_config(state: &State, body: &Value) -> Result<String> {
    let mut guard = state.lock().expect("state 锁中毒");
    let mut config = guard.config.clone();

    if let Some(worker) = body.get("worker").and_then(Value::as_str) {
        let worker = worker.trim().trim_end_matches('/');
        if worker.is_empty() {
            bail!("信令地址不能为空");
        }
        if !worker.starts_with("http://") && !worker.starts_with("https://") {
            bail!("信令地址要以 https:// 开头");
        }
        config.worker = Some(worker.to_string());
    }

    if let Some(token) = body.get("token").and_then(Value::as_str) {
        let token = token.trim();
        if token.is_empty() {
            bail!("加入令牌不能为空");
        }
        let (network_id, secret) = parse_token(token)
            .with_context(|| format!("令牌格式应为 qp2p1_<网络>_<密钥>，收到：{token}"))?;
        let mut net = config.network.clone().unwrap_or(Network {
            id: network_id.to_string(),
            token: String::new(),
            cidr: None,
            virtual_ip: None,
            route: Default::default(),
            advertise: Vec::new(),
            deny_inbound: false,
        });
        net.id = network_id.to_string();
        net.token = format!("qp2p1_{network_id}_{secret}");
        config.network = Some(net);
    }

    if let Some(name) = body.get("name").and_then(Value::as_str) {
        let name = name.trim();
        if !name.is_empty() {
            config.node_name = name.to_string();
        }
    }

    if let Some(ip) = body.get("ip").and_then(Value::as_str) {
        let ip = ip.trim();
        if !ip.is_empty() {
            ip.parse::<Ipv4Addr>()
                .with_context(|| format!("虚拟地址不合法：{ip}"))?;
        }
        if let Some(net) = config.network.as_mut() {
            net.virtual_ip = if ip.is_empty() {
                None
            } else {
                Some(ip.to_string())
            };
        }
    }

    if let Some(mtu) = body.get("mtu").and_then(Value::as_u64) {
        if !(576..=1500).contains(&mtu) {
            bail!("MTU 需要在 576~1500 之间");
        }
        config.mtu = Some(mtu as u16);
    }

    if let Some(idle) = body.get("idle").and_then(Value::as_u64) {
        config.idle = if idle == 0 { None } else { Some(idle) };
    }

    config
        .save(&guard.config_path)
        .map_err(|e| anyhow::anyhow!("保存配置失败：{e}"))?;
    guard.config = config;
    Ok("已保存".to_string())
}

pub(crate) fn spawn_up(state: &State) -> Result<String> {
    let mut guard = state.lock().expect("state 锁中毒");
    if guard.child.is_some() {
        return Ok("已经在运行".to_string());
    }
    let net = guard.config.network.clone().context("先填加入令牌")?;
    if net.token.is_empty() {
        bail!("先填加入令牌");
    }
    if guard.config.worker.is_none() {
        bail!("先填信令地址");
    }
    guard
        .config
        .save(&guard.config_path)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let exe = std::env::current_exe().context("拿不到自身路径")?;
    let mut cmd = Command::new(exe);
    cmd.arg("up")
        .arg("--data-dir")
        .arg(&guard.data_dir)
        .arg("--name")
        .arg(&guard.config.node_name);
    if let Some(mtu) = guard.config.mtu {
        cmd.arg("--mtu").arg(mtu.to_string());
    }
    if let Some(idle) = guard.config.idle {
        cmd.arg("--idle").arg(idle.to_string());
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW：别弹一个黑框出来抢焦点
        cmd.creation_flags(0x0800_0000);
    }

    let mut child = cmd.spawn().context("启动 up 子进程失败")?;
    guard.log.clear();
    guard.links.clear();
    guard.warn = None;
    guard.status = "正在连接…".to_string();

    if let Some(out) = child.stdout.take() {
        spawn_reader(state.clone(), out);
    }
    if let Some(err) = child.stderr.take() {
        spawn_reader(state.clone(), err);
    }
    guard.child = Some(child);
    Ok("已发起连接".to_string())
}

fn spawn_reader<R: Read + Send + 'static>(state: State, reader: R) {
    std::thread::spawn(move || {
        let buf = BufReader::new(reader);
        for line in buf.lines() {
            let Ok(line) = line else { break };
            let mut guard = state.lock().expect("state 锁中毒");
            push_log(&mut guard, &line);
            parse_line(&mut guard, &line);
        }
    });
}

fn push_log(guard: &mut Shared, line: &str) {
    if guard.log.len() >= MAX_LOG {
        guard.log.pop_front();
    }
    guard.log.push_back(line.to_string());
}

fn parse_line(guard: &mut Shared, line: &str) {
    if line.contains("虚拟网卡") && line.contains("已就绪") {
        guard.status = "已连接".to_string();
        guard.warn = None;
        return;
    }
    if line.contains("已降级为") {
        guard.status = "仅打洞（没有虚拟网卡）".to_string();
        guard.warn = Some(line.to_string());
        return;
    }
    if line.contains("直连已建立") {
        if let Some(rest) = line.split('：').nth(1) {
            let name = rest.split(" (").next().unwrap_or(rest).trim().to_string();
            let ip = rest
                .split('(')
                .nth(1)
                .and_then(|s| s.split(')').next())
                .unwrap_or("")
                .to_string();
            let rtt = rest.split("rtt=").nth(1).unwrap_or("").trim().to_string();
            guard.links.insert(name, (ip, rtt));
        }
        return;
    }
    if line.contains("加入令牌已失效") {
        guard.status = "令牌失效".to_string();
        guard.warn = Some(line.to_string());
        return;
    }
    if line.contains("会话已停止") || line.contains("收到中断") {
        guard.status = "已断开".to_string();
    }
}

fn refresh_child(guard: &mut Shared) {
    let Some(child) = guard.child.as_mut() else {
        return;
    };
    match child.try_wait() {
        Ok(Some(status)) => {
            guard.child = None;
            guard.links.clear();
            if guard.status == "正在连接…" || guard.status == "已连接" {
                guard.status = format!("已退出（{status}）");
            }
        }
        Ok(None) => {}
        Err(e) => {
            guard.child = None;
            guard.status = format!("子进程异常：{e}");
        }
    }
}

pub(crate) fn stop_child(state: &State) -> Result<String> {
    let mut guard = state.lock().expect("state 锁中毒");
    match guard.child.take() {
        Some(mut child) => {
            let _ = child.kill();
            let _ = child.wait();
            guard.links.clear();
            guard.status = "已断开".to_string();
            Ok("已断开".to_string())
        }
        None => Ok("本来就没在运行".to_string()),
    }
}

fn open_dir(state: &State) -> Result<String> {
    let dir = {
        let guard = state.lock().expect("state 锁中毒");
        guard.data_dir.clone()
    };
    #[cfg(windows)]
    {
        Command::new("explorer").arg(&dir).spawn().ok();
    }
    #[cfg(not(windows))]
    {
        Command::new("xdg-open").arg(&dir).spawn().ok();
    }
    Ok(format!("已打开 {}", dir.display()))
}
