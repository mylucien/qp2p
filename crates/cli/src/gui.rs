//! `qp2p gui` 的界面状态（仅 Windows 使用）。
//!
//! 这里只负责"配置 + 子进程 + 状态快照"这块与界面无关的逻辑：
//! 起停 `up` 子进程、把日志/直连/告警维护成可以随时读的快照。
//! 真正的窗口和托盘在 `win_gui`，Linux 上没有图形界面，直接用命令行。

use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead, BufReader, Read};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use qp2p_core::config::{parse_token, Config, Network};

const MAX_LOG: usize = 600;

pub(crate) struct Shared {
    child: Option<Child>,
    log: VecDeque<String>,
    /// 累计写入的日志行数（只增不减）：原生界面靠它算"还有哪几行没显示"，
    /// 环形缓冲满了之后也不会漏
    log_total: u64,
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
    let state = build_state(&flags)?;
    crate::win_gui::run(state)
}

fn build_state(flags: &crate::Flags) -> Result<State> {
    let data_dir = crate::data_dir(flags).context("没有可用的数据目录")?;
    let config_path = crate::config_path(flags);
    std::fs::create_dir_all(&data_dir).ok();

    let config = Config::load(&config_path).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(Arc::new(Mutex::new(Shared {
        child: None,
        log: VecDeque::new(),
        log_total: 0,
        links: BTreeMap::new(),
        status: "未连接".to_string(),
        warn: None,
        config,
        config_path,
        data_dir,
    })))
}

// ---------------------------------------------------------------------------
// 原生界面（Windows）取数接口
// ---------------------------------------------------------------------------

pub(crate) struct FormValues {
    pub worker: String,
    pub token: String,
    pub name: String,
    pub ip: String,
    pub mtu: u16,
    pub idle: u64,
}

pub(crate) fn form_values(state: &State) -> FormValues {
    let guard = state.lock().expect("state 锁中毒");
    let net = guard.config.network.as_ref();
    FormValues {
        worker: guard.config.worker.clone().unwrap_or_default(),
        token: net.map(|n| n.token.clone()).unwrap_or_default(),
        name: guard.config.node_name.clone(),
        ip: net.and_then(|n| n.virtual_ip.clone()).unwrap_or_default(),
        mtu: guard.config.mtu.unwrap_or(1400),
        idle: guard.config.idle.unwrap_or(0),
    }
}

/// 表单 → 配置：校验、保存都复用 `save_config`，两条路径行为一致。
pub(crate) fn apply_form(
    state: &State,
    worker: &str,
    token: &str,
    name: &str,
    ip: &str,
    mtu: u64,
    idle: u64,
) -> Result<String> {
    let body = json!({
        "worker": worker,
        "token": token,
        "name": name,
        "ip": ip,
        "mtu": mtu,
        "idle": idle,
    });
    save_config(state, &body)
}

pub(crate) fn is_running(state: &State) -> bool {
    let mut guard = state.lock().expect("state 锁中毒");
    refresh_child(&mut guard);
    guard.child.is_some()
}

/// 一次界面刷新的快照。
pub(crate) struct Tick {
    pub running: bool,
    pub status: String,
    pub warn: Option<String>,
    /// (名字, 虚拟地址, 延迟)
    pub links: Vec<(String, String, String)>,
    /// 累计行数（单调）；和 `log` 的最后 N 行对应
    pub log_total: u64,
    pub log: Vec<String>,
}

pub(crate) fn tick(state: &State) -> Tick {
    let mut guard = state.lock().expect("state 锁中毒");
    refresh_child(&mut guard);
    Tick {
        running: guard.child.is_some(),
        status: guard.status.clone(),
        warn: guard.warn.clone(),
        links: guard
            .links
            .iter()
            .map(|(name, pair)| (name.clone(), pair.0.clone(), pair.1.clone()))
            .collect(),
        log_total: guard.log_total,
        log: guard.log.iter().cloned().collect(),
    }
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
    guard.log_total += 1;
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

pub(crate) fn open_dir(state: &State) -> Result<String> {
    let dir = {
        let guard = state.lock().expect("state 锁中毒");
        guard.data_dir.clone()
    };
    Command::new("explorer").arg(&dir).spawn().ok();
    Ok(format!("已打开 {}", dir.display()))
}
