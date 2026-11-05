//! Android 外壳：JNI 入口。
//!
//! 分成两步是 Android 的硬约束：`VpnService.Builder.establish()` 需要**先知道**
//! 本机的虚拟地址和网段才能建接口，而这两个值是注册时服务端给的。所以：
//!
//! 1. `prepare(config)`：建端点、注册、拿到 `{node_id, virtual_ip, cidr}`，先不算流量。
//! 2. Kotlin 用这些值建 VpnService，拿到 tun 的 fd，调 `start(fd)` 开始收发。
//! 3. 用户点断开 → `stop()` 置停止位，`start` 那一侧在 3 秒内退出。
//!
//! 打洞、退避、事件轮询全部复用 `qp2p_core::session`，和桌面端同一套逻辑。

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
use tokio::sync::RwLock;

use qp2p_core::identity::{Identity, NodeId};
use qp2p_core::link::tun::MeshLinks;
use qp2p_core::route::Cidr;
use qp2p_core::signal::client::{PeerInfo, SignalClient};
use qp2p_core::{link, Engine};

fn default_mtu() -> u16 {
    1280
}

fn default_stun() -> Vec<String> {
    vec![
        "stun.cloudflare.com:3478".to_string(),
        "stun.l.google.com:19302".to_string(),
    ]
}

/// Kotlin 传进来的启动参数。
#[derive(Debug, Clone, Deserialize)]
pub struct StartConfig {
    pub worker: String,
    pub token: String,
    #[serde(default)]
    pub name: String,
    /// 身份文件目录，一般就是 `context.filesDir`
    #[serde(default)]
    pub data_dir: Option<String>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    #[serde(default)]
    pub stun: Vec<String>,
    /// UDP 绑定地址，默认让系统挑端口
    #[serde(default)]
    pub bind: Option<String>,
}

/// `prepare` 返回给 Kotlin 的信息，用来构建 VpnService。
#[derive(Debug, Clone, Serialize)]
pub struct PreparedInfo {
    pub node_id: String,
    pub virtual_ip: String,
    pub cidr: String,
    pub prefix: u8,
    pub mtu: u16,
    pub name: String,
}

struct Prepared {
    rt: Runtime,
    engine: Arc<RwLock<Engine>>,
    client: SignalClient,
    identity: Identity,
    node_id: NodeId,
    name: String,
    net: Option<Cidr>,
    virtual_ip: Ipv4Addr,
    peers: Vec<PeerInfo>,
    mtu: u16,
}

static PREPARED: OnceLock<Mutex<Option<Prepared>>> = OnceLock::new();
static STOP: OnceLock<Arc<AtomicBool>> = OnceLock::new();

fn prepared_slot() -> &'static Mutex<Option<Prepared>> {
    PREPARED.get_or_init(|| Mutex::new(None))
}

fn stop_flag() -> Arc<AtomicBool> {
    STOP.get_or_init(|| Arc::new(AtomicBool::new(false)))
        .clone()
}

/// 写 Android 日志（logcat 标签 `qp2p`）。桌面编译时退化成 stderr。
fn log(message: &str) {
    #[cfg(target_os = "android")]
    {
        // 用 c_char 而不是 i8：Android 的 NDK 在 aarch64 上也是 i8，但这样写不依赖假设
        extern "C" {
            fn __android_log_write(
                prio: i32,
                tag: *const std::ffi::c_char,
                text: *const std::ffi::c_char,
            ) -> i32;
        }
        if let Ok(text) = std::ffi::CString::new(message.replace('\0', " ")) {
            // priority 4 = INFO
            unsafe {
                __android_log_write(4, c"qp2p".as_ptr(), text.as_ptr());
            }
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        eprintln!("[qp2p] {message}");
    }
}

impl PreparedInfo {
    fn from_prepared(p: &Prepared, cidr: &Cidr) -> Self {
        Self {
            node_id: p.node_id.to_string(),
            virtual_ip: p.virtual_ip.to_string(),
            cidr: cidr.to_string(),
            prefix: cidr.prefix,
            mtu: p.mtu,
            name: p.name.clone(),
        }
    }
}

/// 第一步：注册并拿到本机地址。不产生任何流量。
pub fn prepare(config: StartConfig) -> Result<PreparedInfo> {
    let data_dir = config.data_dir.as_deref().map(std::path::Path::new);
    let bind: SocketAddr = config
        .bind
        .as_deref()
        .unwrap_or("0.0.0.0:0")
        .parse()
        .context("bind 地址不合法")?;
    let stun = if config.stun.is_empty() {
        default_stun()
    } else {
        config.stun.clone()
    };
    let mtu = if config.mtu < 576 { 1280 } else { config.mtu };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("创建 tokio 运行时失败")?;

    let client = SignalClient::new(&config.worker, &config.token)?;
    let name = config.name.clone();

    let (engine, reply) = rt.block_on(async {
        let engine = Engine::bind_in(bind, &stun, data_dir)
            .await
            .context("绑定 UDP 失败")?;
        let identity = engine.identity().clone();
        let node_id = engine.node_id().to_string();
        let display = if name.trim().is_empty() {
            node_id[..8].to_string()
        } else {
            name.trim().to_string()
        };
        let candidates = qp2p_core::session::candidate_strings(&engine);
        let nat = qp2p_core::session::nat_type(&engine);
        let reply = client
            .register(
                &identity,
                &display,
                &engine.tls_fp(),
                &candidates,
                nat,
                None,
            )
            .await
            .context("向信令服务器注册失败（令牌过期或网络已删除？）")?;
        Ok::<_, anyhow::Error>((engine, reply))
    })?;

    let virtual_ip: Ipv4Addr = reply
        .node
        .virtual_ip
        .parse()
        .with_context(|| format!("服务端给的虚拟地址不合法：{}", reply.node.virtual_ip))?;
    let cidr: Cidr = reply
        .network
        .cidr
        .parse()
        .with_context(|| format!("服务端给的网段不合法：{}", reply.network.cidr))?;

    let node_id = engine.node_id();
    let identity = engine.identity().clone();
    let display = reply.node.name.clone();

    let prepared = Prepared {
        rt,
        engine: Arc::new(RwLock::new(engine)),
        client,
        identity,
        node_id,
        name: display,
        net: Some(cidr),
        virtual_ip,
        peers: reply.peers.clone(),
        mtu,
    };
    let info = PreparedInfo::from_prepared(&prepared, &cidr);

    log(&format!(
        "已注册：{} {} / {}",
        info.name, info.virtual_ip, info.cidr
    ));
    *prepared_slot().lock().expect("prepared 锁中毒") = Some(prepared);
    Ok(info)
}

/// 第二步：接管 VpnService 的 tun fd，开始收发。阻塞到 `stop()`。
pub fn start(fd: i32) -> Result<()> {
    let prepared = prepared_slot()
        .lock()
        .expect("prepared 锁中毒")
        .take()
        .context("还没有 prepare，先调用 prepare()")?; // 只有一次机会，取走即用

    let Prepared {
        rt,
        engine,
        client,
        identity,
        node_id,
        name,
        net,
        virtual_ip,
        peers,
        mtu,
    } = prepared;

    let stop = stop_flag();
    stop.store(false, Ordering::SeqCst);

    rt.block_on(async {
        // Android 上没有 root，网卡由 VpnService 建好，这里只接管描述符
        let device = tun_device(fd)?;
        let tun_link = qp2p_core::route::spawn_io(device, mtu);
        let mesh = MeshLinks::new(tun_link.to_tun.clone());

        {
            let runner = mesh.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    link::tun::run_mesh(runner, tun_link.from_tun, virtual_ip, mtu).await
                {
                    log(&format!("数据面退出：{e:#}"));
                }
            });
        }

        let session = qp2p_core::session::Session::new_with_stop(
            qp2p_core::session::SessionConfig {
                client: client.clone(),
                identity: identity.clone(),
                node_id: node_id.clone(),
                name,
                net,
                wanted_ip: Some(virtual_ip),
                peers,
            },
            engine.clone(),
            Some(mesh.clone()),
            qp2p_core::session::Notify::new(|msg: &str| log(msg)),
            stop.clone(),
        );
        session.run().await;

        log("会话结束，正在退出");
        if let Err(e) = client.leave(&identity).await {
            log(&format!("下线通知没发出去：{e}"));
        }
        let mut guard = engine.write().await;
        guard.shutdown().await;
        Ok::<(), anyhow::Error>(())
    })
}

/// 把 tun 描述符包成设备。非 Android 平台编译时保留一个明确的错误。
fn tun_device(fd: i32) -> Result<Box<dyn qp2p_core::route::TunDevice>> {
    #[cfg(target_os = "android")]
    {
        qp2p_core::route::from_fd(fd)
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = fd;
        anyhow::bail!("tun fd 只在 Android 上有意义")
    }
}

/// 停止会话。可以重复调用。
pub fn stop() {
    stop_flag().store(true, Ordering::SeqCst);
}

/// 是否已经有 prepare 过的会话在等 tun fd。
pub fn is_prepared() -> bool {
    prepared_slot().lock().map(|s| s.is_some()).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// JNI 门面：Kotlin 侧的 com.qp2p.Native 对应这里
// ---------------------------------------------------------------------------

#[cfg(target_os = "android")]
mod jni_bridge {
    use super::*;
    use jni::objects::{JClass, JString};
    use jni::sys::{jint, jstring};
    use jni::JNIEnv;

    fn reply(env: &mut JNIEnv, text: &str) -> jstring {
        match env.new_string(text) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }

    fn err_json(message: &str) -> String {
        serde_json::json!({ "error": message }).to_string()
    }

    /// `Native.prepare(configJson)` → 成功返回里面的 JSON，失败返回 `{"error": "..."}`。
    #[no_mangle]
    pub extern "system" fn Java_com_qp2p_Native_prepare<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        config: JString<'local>,
    ) -> jstring {
        let text: String = match env.get_string(&config) {
            Ok(s) => s.into(),
            Err(e) => return reply(&mut env, &err_json(&format!("读不到配置：{e}"))),
        };
        let parsed: StartConfig = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => return reply(&mut env, &err_json(&format!("配置格式不对：{e}"))),
        };
        match prepare(parsed) {
            Ok(info) => {
                let json = serde_json::to_string(&info)
                    .unwrap_or_else(|e| err_json(&format!("序列化失败：{e}")));
                reply(&mut env, &json)
            }
            Err(e) => reply(&mut env, &err_json(&format!("{e:#}"))),
        }
    }

    /// `Native.start(fd)`：阻塞到断开。成功返回 null，失败返回错误信息。
    #[no_mangle]
    pub extern "system" fn Java_com_qp2p_Native_start<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        fd: jint,
    ) -> jstring {
        match start(fd) {
            Ok(()) => std::ptr::null_mut(),
            Err(e) => reply(&mut env, &format!("{e:#}")),
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_qp2p_Native_stop<'local>(
        _env: JNIEnv<'local>,
        _class: JClass<'local>,
    ) {
        stop();
    }

    #[no_mangle]
    pub extern "system" fn Java_com_qp2p_Native_isPrepared<'local>(
        _env: JNIEnv<'local>,
        _class: JClass<'local>,
    ) -> jni::sys::jboolean {
        is_prepared() as jni::sys::jboolean
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_accepts_minimal_json() {
        let cfg: StartConfig =
            serde_json::from_str(r#"{"worker":"https://w.dev","token":"qp2p1_a_b"}"#).unwrap();
        assert_eq!(cfg.mtu, 1280, "Android 默认用 1280，兼容移动网络");
        assert!(cfg.name.is_empty());
        assert!(cfg.stun.is_empty());
    }

    #[test]
    fn config_keeps_explicit_values() {
        let cfg: StartConfig = serde_json::from_str(
            r#"{"worker":"https://w.dev","token":"t","name":"phone","mtu":1400,"stun":["s:3478"]}"#,
        )
        .unwrap();
        assert_eq!(cfg.mtu, 1400);
        assert_eq!(cfg.name, "phone");
        assert_eq!(cfg.stun, vec!["s:3478".to_string()]);
    }
}
