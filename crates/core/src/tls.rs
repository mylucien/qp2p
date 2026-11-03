//! TLS 配置。
//!
//! 当前阶段使用自签证书 + 跳过校验，证书钉扎要等信令面能交换指纹后接上
//! （DESIGN D3）。ALPN 固定为 `qp2p/1`，避免和浏览器流量混淆。

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

pub const ALPN: &[u8] = b"qp2p/1";
pub const SERVER_NAME: &str = "qp2p.local";

fn transport() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    transport.max_concurrent_bidi_streams(256u32.into());
    transport.max_concurrent_uni_streams(0u32.into());
    transport
}

pub fn server_config() -> Result<quinn::ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])
        .context("生成自签证书失败")?;
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("TLS 1.3 不可用")?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .context("加载自签证书失败")?;
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let crypto = QuicServerConfig::try_from(tls).context("构建 QUIC 服务端配置失败")?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::new(transport()));
    Ok(config)
}

pub fn client_config() -> Result<quinn::ClientConfig> {
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("TLS 1.3 不可用")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify::new()))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let crypto = QuicClientConfig::try_from(tls).context("构建 QUIC 客户端配置失败")?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(transport()));
    Ok(config)
}

/// TODO(P4)：信令面能交换 TLS 公钥指纹后，换成钉扎校验器。
#[derive(Debug)]
struct SkipVerify;

impl SkipVerify {
    fn new() -> Self {
        Self
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
