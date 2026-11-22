//! TLS 身份与配置。
//!
//! 证书与节点身份一起落盘：`node_id` 和 `tls_fp` 在重启后不变，否则钉扎和
//! "记住这台机器"都无从谈起。目录里三份文件：
//!
//! - `identity.key`：32 字节种子（十六进制），身份的唯一来源（见 identity.rs）
//! - `tls.crt.der` / `tls.key.der`：自签证书，`tls_fp = sha256(cert_der)`
//!
//! QUIC 默认仍是"连接建立后互换身份、应用层验签"（见 `peer::auth`）；
//! 证书指纹留给需要 TLS 层钉扎的场景：`client_config(Some(fp))`。

use std::fs;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};

pub const ALPN: &[u8] = b"qp2p/1";
pub const SERVER_NAME: &str = "qp2p.local";

const CERT_FILE: &str = "tls.crt.der";
const KEY_FILE: &str = "tls.key.der";

/// 本机有没有 AES 硬件加速。
///
/// ring 在 aarch64 上要求 AES + PMULL 同时具备才走硬件路径（GCM 的 GHASH
/// 靠 PMULL 加速），而 ARMv8 的现实实现里两者基本同进同退：Cortex-A53 /
/// A55 / A72 / A76 要么都有、要么都没有。x86 侧同理，有 AES-NI 的机器
/// 几乎都有 PCLMULQDQ。这里按主流情况判断；万一误判，代价只是选错套件，
/// 不影响正确性。
fn has_aes_hw() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("aes")
    }
    #[cfg(target_arch = "x86_64")]
    {
        std::arch::is_x86_feature_detected!("aes")
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        true
    }
}

/// TLS 套件提供者：没有 AES 硬件时把 ChaCha20 提到最前。
///
/// rustls 的默认顺序是 AES-256-GCM 第一。在没有 AES 指令的 ARM 上，ring
/// 会落到 NEON 比特切片的软件实现，比同样走 NEON 的 ChaCha20 慢数倍。
/// `sort_by_key` 是稳定排序，其余套件的相对顺序保持不变。
fn provider() -> rustls::crypto::CryptoProvider {
    let mut provider = default_provider();
    if !has_aes_hw() {
        tracing::info!("[tls] 本机无 AES 硬件加速，优先 ChaCha20-Poly1305");
        prefer_chacha(&mut provider);
    }
    provider
}

/// 把 ChaCha20-Poly1305 挪到第一位，其余套件相对顺序不变。
///
/// 单独抽出来是为了能测排序本身——`has_aes_hw()` 依赖运行环境，
/// 而排序逻辑与硬件无关。
fn prefer_chacha(provider: &mut rustls::crypto::CryptoProvider) {
    provider.cipher_suites.sort_by_key(|suite| {
        if suite.suite() == rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 {
            0
        } else {
            1
        }
    });
}

/// `initial_rtt` 为 None 时用 quinn 的默认值（333 ms，QUIC 规范的保守值）。
///
/// 局域网直连的真实 RTT 只有 1~10 ms，用 333 ms 起步会让初始 pacing 和
/// PTO 都过于保守，建连后头几百毫秒跑不满。第一个 RTT 样本到手后
/// quinn 会自己校正，所以这个值只影响建连初期。
fn transport(initial_rtt: Option<Duration>) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    transport.max_concurrent_bidi_streams(256u32.into());
    transport.max_concurrent_uni_streams(0u32.into());

    // 单流 2 MB：40 ms RTT 下单流上限从 250 Mbps 提到 400 Mbps。
    // 这是"愿意为这条流缓冲多少"，不是预分配，空闲时不占内存。
    transport.stream_receive_window((2 * 1024 * 1024u32).into());
    // 连接级总上限 16 MB：兜住 256 条流的理论最坏值（256 × 2 MB = 512 MB）。
    // 按 8 条满窗流设计；每对端一份，10 个对端最坏 160 MB。
    transport.receive_window((16 * 1024 * 1024u32).into());

    // 初始 MTU 1280：IPv6 的最小 MTU，也是多数 VPN / 隧道 / 部分蜂窝网络
    // 能过的值。用 1400 时，路径实际只支持 1280 的链路上每个大包都会丢，
    // 要等黑洞检测（连续 3 次可疑丢包 burst）才退回 min_mtu——期间小包
    // （ACK、PING）仍能通，所以不会触发 8 秒判死，只是吞吐卡几秒，每条
    // 新连接都要重来一遍。
    //
    // quinn 的 MTU 发现会自己往上爬到路径 MTU，1280 只是起步值；握手包
    // 固定 pad 到 1200，不受这里影响，所以调低不增加连不上的风险。
    transport.initial_mtu(1280);
    transport.min_mtu(1200);

    if let Some(rtt) = initial_rtt {
        transport.initial_rtt(rtt);
    }

    let tune = tuning();
    if tune.ack_threshold > 0 {
        let mut ack = quinn::AckFrequencyConfig::default();
        ack.ack_eliciting_threshold(quinn::VarInt::from_u32(tune.ack_threshold));
        // max_ack_delay 刻意不动：调大它会让丢包重传判定变慢，
        // 对直播这种低延迟场景是负作用。只减少 ACK 数量。
        transport.ack_frequency_config(Some(ack));
    }

    transport
}

/// 本机的 TLS 证书与私钥。
pub struct TlsIdentity {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

impl TlsIdentity {
    /// 从磁盘加载；没有就生成一份写回去。`None` 表示不落盘（测试用）。
    ///
    /// 证书和私钥是两个文件，中间崩溃会留下"只有一个"的状态。旧实现遇到
    /// 这种情况会补写缺的那个，而补写的是一对新密钥：结果磁盘上是**旧证书 +
    /// 新私钥**，`with_single_cert` 从此永远失败，只能手删文件。
    ///
    /// 现在两条路都堵死：只剩一个就整对重建；两个都在则真的配一次，
    /// 配不上（历史遗留的坏状态）也整对重建。
    pub fn load_or_create(dir: Option<&Path>) -> Result<Self> {
        let Some(dir) = dir else {
            return Self::generate();
        };

        fs::create_dir_all(dir).with_context(|| format!("创建数据目录失败：{}", dir.display()))?;

        let cert_path = dir.join(CERT_FILE);
        let key_path = dir.join(KEY_FILE);
        let (has_cert, has_key) = (cert_path.exists(), key_path.exists());

        if has_cert && has_key {
            let loaded = Self::load(dir)?;
            if loaded.is_paired() {
                return Ok(loaded);
            }
            tracing::warn!(
                "[tls] {} 里的证书与私钥不匹配（多半是上次写入中途崩溃留下的），重建一对新的",
                dir.display()
            );
        } else if has_cert || has_key {
            tracing::warn!("[tls] {} 里证书/私钥只剩一个，清理后重建", dir.display());
        }

        if has_cert || has_key {
            let _ = fs::remove_file(&cert_path);
            let _ = fs::remove_file(&key_path);
        }

        let generated = Self::generate()?;
        // 返回 false 表示另一个进程抢先写了，下面以磁盘上的为准
        let _mine = generated.persist(dir)?;
        let loaded = Self::load(dir)?;
        if !loaded.is_paired() {
            anyhow::bail!(
                "{} 里的 TLS 证书与私钥不匹配，且无法自动修复；删掉这两个文件后重试",
                dir.display()
            );
        }
        Ok(loaded)
    }

    /// 证书与私钥是不是一对。真的构建一次服务端配置，失败就是配不上。
    fn is_paired(&self) -> bool {
        self.server_config().is_ok()
    }

    fn generate() -> Result<Self> {
        let cert = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])
            .context("生成自签证书失败")?;
        Ok(Self {
            cert: CertificateDer::from(cert.cert),
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der())),
        })
    }

    fn load(dir: &Path) -> Result<Self> {
        let cert = fs::read(dir.join(CERT_FILE)).context("读取证书失败")?;
        let key = fs::read(dir.join(KEY_FILE)).context("读取私钥失败")?;
        Ok(Self {
            cert: CertificateDer::from(cert),
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        })
    }

    /// 落盘。返回 false 表示证书或私钥已经存在（另一个进程抢先了）。
    fn persist(&self, dir: &Path) -> Result<bool> {
        let key_der = match &self.key {
            PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der().to_vec(),
            _ => anyhow::bail!("只支持 PKCS#8 私钥"),
        };
        let cert_new = crate::secret_file::create_private(&dir.join(CERT_FILE), self.cert.as_ref())
            .with_context(|| format!("写入证书失败：{}", dir.display()))?;
        let key_new = crate::secret_file::create_private(&dir.join(KEY_FILE), &key_der)
            .with_context(|| format!("写入私钥失败：{}", dir.display()))?;
        Ok(cert_new && key_new)
    }

    /// 证书指纹（sha256 hex），用于钉扎与人工核对。
    pub fn fingerprint(&self) -> String {
        hex::encode(Sha256::digest(self.cert.as_ref()))
    }

    pub fn cert_der(&self) -> &[u8] {
        self.cert.as_ref()
    }

    pub fn server_config(&self) -> Result<quinn::ServerConfig> {
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("TLS 1.3 不可用")?
            .with_no_client_auth()
            .with_single_cert(vec![self.cert.clone()], self.key.clone_key())
            .context("加载自签证书失败")?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        // 本机没有 AES 硬件时强制自己的套件偏好：否则客户端 offer 的
        // AES-256 顺序会被照单全收，本机就得软件解密。本机有 AES 时保持
        // false（尊重客户端偏好）——反过来强制 AES 反而会拖慢没有 AES
        // 指令的对端。
        tls.ignore_client_order = !has_aes_hw();

        let crypto = QuicServerConfig::try_from(tls).context("构建 QUIC 服务端配置失败")?;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        config.transport_config(Arc::new(transport(None)));
        Ok(config)
    }
}

/// 链路调优参数。
///
/// 放在进程级全局槽里，是为了不把配置一路穿到每个 TLS 构造函数——
/// `transport()` 被 `client_config` / `server_config` 两条路径共用，
/// 而它们的调用点遍布引擎、测试和 Android 外壳。一个进程只有一个
/// 有效配置，正好适合全局设置一次。
///
/// **没有拥塞控制选项**：曾经提供过 `congestion = "bbr"`，2026-11-22 实测
/// 在 4G + 家用路由器上会让连接每分钟被自己摘一次。根因在 quinn 的 BBR
/// 实现（初始窗口 200 包 ≈ 240 KB、Startup 阶段 `cwnd += bytes_acked` 无上限、
/// `app_limited` 时永远退不出 Startup），不是配置问题，所以整条路径删除，
/// 固定用 Cubic。详见 DESIGN.md「数据面调优」。
#[derive(Clone, Copy, Debug)]
pub struct LinkTuning {
    /// 请求对端每 N 个 ack-eliciting 包回一次 ACK；0 表示保持 quinn 默认。
    pub ack_threshold: u32,
    /// Linux 的 `SO_BUSY_POLL`（微秒）；0 表示关闭。
    ///
    /// 收包在中断上下文之外忙轮询，能把唤醒延迟压掉几十微秒。
    /// 代价是烧 CPU，弱核上可能反而更慢，所以默认关。
    pub busy_poll_us: u32,
}

impl Default for LinkTuning {
    fn default() -> Self {
        Self {
            // 放宽 ACK 阈值是纯收益，默认开：每 10 个包回一次，
            // 而 max_ack_delay 保持默认，不拖慢丢包判定
            ack_threshold: 10,
            // 忙轮询要显式配置才开
            busy_poll_us: 0,
        }
    }
}

static TUNING: OnceLock<LinkTuning> = OnceLock::new();

/// 设置链路调优。重复调用只有第一次生效——配置在进程生命周期内不变。
pub fn configure(tuning: LinkTuning) {
    let _ = TUNING.set(tuning);
}

fn tuning() -> LinkTuning {
    TUNING.get().copied().unwrap_or_default()
}

/// 当前生效的链路调优。没调用过 [`configure`] 时就是默认值。
pub fn current_tuning() -> LinkTuning {
    tuning()
}

/// 客户端配置。`pin` 为 Some 时校验证书指纹，否则跳过校验
/// （身份认证由 `peer::auth` 在连接建立后完成）。
pub fn client_config(pin: Option<[u8; 32]>) -> Result<quinn::ClientConfig> {
    client_config_with(pin, None)
}

/// 同上，但可以指定 `initial_rtt`（毫秒）。内网候选走这个版本。
pub fn client_config_with(
    pin: Option<[u8; 32]>,
    initial_rtt_ms: Option<u64>,
) -> Result<quinn::ClientConfig> {
    let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> = match pin {
        Some(expected) => Arc::new(PinnedVerify { expected }),
        None => Arc::new(SkipVerify),
    };

    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("TLS 1.3 不可用")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let crypto = QuicClientConfig::try_from(tls).context("构建 QUIC 客户端配置失败")?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(transport(
        initial_rtt_ms.map(Duration::from_millis),
    )));
    Ok(config)
}

/// 只信这一张证书：指纹不符直接让握手失败。
#[derive(Debug)]
struct PinnedVerify {
    expected: [u8; 32],
}

impl rustls::client::danger::ServerCertVerifier for PinnedVerify {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let digest = Sha256::digest(end_entity.as_ref());
        if digest.as_slice() == self.expected {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "证书指纹不匹配：期望 {}，实际 {}",
                hex::encode(self.expected),
                hex::encode(digest)
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_signature(message, cert, dss, false)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_signature(message, cert, dss, true)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        supported_schemes()
    }
}

#[derive(Debug)]
struct SkipVerify;

impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_signature(message, cert, dss, false)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_signature(message, cert, dss, true)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        supported_schemes()
    }
}

fn verify_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &rustls::DigitallySignedStruct,
    tls13: bool,
) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
    let provider = default_provider();
    let algorithms = &provider.signature_verification_algorithms;
    if tls13 {
        rustls::crypto::verify_tls13_signature(message, cert, dss, algorithms)
    } else {
        rustls::crypto::verify_tls12_signature(message, cert, dss, algorithms)
    }
}

fn supported_schemes() -> Vec<rustls::SignatureScheme> {
    default_provider()
        .signature_verification_algorithms
        .supported_schemes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("qp2p-tls-{tag}-{}", std::process::id()))
    }

    #[test]
    fn fingerprint_is_stable_across_reload() {
        let dir = temp_dir("stable");
        let _ = fs::remove_dir_all(&dir);
        let first = TlsIdentity::load_or_create(Some(&dir)).unwrap();
        let second = TlsIdentity::load_or_create(Some(&dir)).unwrap();
        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_eq!(first.cert_der(), second.cert_der());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ephemeral_identity_differs_each_time() {
        let a = TlsIdentity::load_or_create(None).unwrap();
        let b = TlsIdentity::load_or_create(None).unwrap();
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn configs_build_for_both_pinning_modes() {
        let mine = TlsIdentity::load_or_create(None).unwrap();
        let pinned: [u8; 32] = hex::decode(mine.fingerprint()).unwrap().try_into().unwrap();
        assert!(client_config(Some(pinned)).is_ok());
        assert!(client_config(None).is_ok());
        assert!(mine.server_config().is_ok());
    }

    #[test]
    fn chacha_moves_to_front() {
        let mut p = default_provider();
        prefer_chacha(&mut p);
        assert_eq!(
            p.cipher_suites[0].suite(),
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            "无 AES 时 ChaCha20 必须排第一"
        );
    }

    #[test]
    fn prefer_chacha_keeps_other_suites_in_order() {
        let original: Vec<_> = default_provider()
            .cipher_suites
            .iter()
            .map(|s| s.suite())
            .collect();
        let mut p = default_provider();
        prefer_chacha(&mut p);
        let after: Vec<_> = p.cipher_suites.iter().map(|s| s.suite()).collect();

        let mut expected: Vec<_> = original
            .iter()
            .copied()
            .filter(|s| *s != rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)
            .collect();
        expected.insert(0, rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256);
        assert_eq!(after, expected, "其余套件的相对顺序不能变");
    }
}
