//! # tls.rs — TLS 配置（punch / retry 共用）
//!
//! QUIC (quinn) 强制要求 TLS，P2P 直连场景无 CA，
//! 采用自签证书 + 跳过服务端验证。
//!
//! 安全说明：跳过证书验证只影响身份认证（无法验证对端是谁），
//! 不影响传输加密（数据仍然加密）。P2P 场景的节点身份由
//! Worker Token 机制保证，因此跳过 TLS 验证是可接受的设计权衡。

use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// 生成 quinn ServerConfig，内含 rcgen 随机自签证书。
///
/// 每次启动重新生成，无需持久化。
pub fn make_server_config() -> Result<quinn::ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec!["edge-agent.local".into()])
        .context("生成自签证书失败")?;

    let cert_der: CertificateDer = cert.cert.into();
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
        cert.key_pair.serialize_der(),
    ));

    let tls_config = rustls::ServerConfig::builder_with_provider(
        default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .context("TLS 1.3 协议不可用")?
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .context("加载自签证书失败")?;

    let quic_config = QuicServerConfig::try_from(tls_config)
        .context("构建 QuicServerConfig 失败")?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));
    // 保留 connection migration（默认 true），用于重打洞成功后无缝切回直连

    Ok(server_config)
}

/// 生成 quinn ClientConfig，跳过服务端证书验证。
pub fn make_client_config() -> Result<quinn::ClientConfig> {
    let tls_config = rustls::ClientConfig::builder_with_provider(
        default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .context("TLS 1.3 协议不可用")?
    .dangerous()
    .with_custom_certificate_verifier(SkipVerify::new())
    .with_no_client_auth();

    let quic_config = QuicClientConfig::try_from(tls_config)
        .context("构建 QuicClientConfig 失败")?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_config));
    client_config.transport_config(Arc::new(transport_config()));

    Ok(client_config)
}

/// 传输配置：调优以适配 P2P 打洞场景
fn transport_config() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_uni_streams(1000u32.into());
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    transport.datagram_receive_buffer_size(Some(65536));
    transport
}

// ---------------------------------------------------------------------------
// 跳过证书验证
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct SkipVerify;

impl SkipVerify {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

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
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_creation() {
        let config = make_server_config().unwrap();
        let _ = config; // 构建成功即通过
    }

    #[test]
    fn test_client_config_creation() {
        let config = make_client_config().unwrap();
        let _ = config; // 构建成功即通过
    }
}
