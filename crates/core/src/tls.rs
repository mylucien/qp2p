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
use std::sync::Arc;
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

fn transport() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    transport.max_concurrent_bidi_streams(256u32.into());
    transport.max_concurrent_uni_streams(0u32.into());
    transport
}

/// 本机的 TLS 证书与私钥。
pub struct TlsIdentity {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

impl TlsIdentity {
    /// 从磁盘加载；没有就生成一份写回去。`None` 表示不落盘（测试用）。
    pub fn load_or_create(dir: Option<&Path>) -> Result<Self> {
        let Some(dir) = dir else {
            return Self::generate();
        };

        fs::create_dir_all(dir).with_context(|| format!("创建数据目录失败：{}", dir.display()))?;

        let cert_path = dir.join(CERT_FILE);
        let key_path = dir.join(KEY_FILE);

        if cert_path.exists() && key_path.exists() {
            return Self::load(dir);
        }

        let generated = Self::generate()?;
        if generated.persist(dir)? {
            Ok(generated)
        } else {
            // 另一个进程抢先写了证书/私钥：以磁盘上的为准，避免"证书是 A 的、私钥是 B 的"
            Self::load(dir)
        }
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
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("TLS 1.3 不可用")?
            .with_no_client_auth()
            .with_single_cert(vec![self.cert.clone()], self.key.clone_key())
            .context("加载自签证书失败")?;
        tls.alpn_protocols = vec![ALPN.to_vec()];

        let crypto = QuicServerConfig::try_from(tls).context("构建 QUIC 服务端配置失败")?;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        config.transport_config(Arc::new(transport()));
        Ok(config)
    }
}

/// 客户端配置。`pin` 为 Some 时校验证书指纹，否则跳过校验
/// （身份认证由 `peer::auth` 在连接建立后完成）。
pub fn client_config(pin: Option<[u8; 32]>) -> Result<quinn::ClientConfig> {
    let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> = match pin {
        Some(expected) => Arc::new(PinnedVerify { expected }),
        None => Arc::new(SkipVerify),
    };

    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("TLS 1.3 不可用")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let crypto = QuicClientConfig::try_from(tls).context("构建 QUIC 客户端配置失败")?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(transport()));
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
}
