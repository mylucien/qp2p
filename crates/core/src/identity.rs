//! 节点身份：Ed25519 密钥、node_id 派生、虚拟地址派生。
//!
//! 旧版把节点身份锚在 cloudflared 打印在 stderr 里的 URL 上，
//! 重启换 URL 就换身份。这里改为从密钥派生，稳定且可验证。

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// node_id 的十六进制字符数（取 SHA-256 前 16 字节）。
pub const NODE_ID_HEX_LEN: usize = 32;

/// 节点标识：`hex(sha256(pubkey))[..32]`。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(String);

impl NodeId {
    pub fn from_pubkey(pubkey: &[u8; 32]) -> Self {
        let digest = Sha256::digest(pubkey);
        let hex = hex::encode(digest);
        Self(hex[..NODE_ID_HEX_LEN].to_string())
    }

    pub fn parse(value: &str) -> Option<Self> {
        if value.len() != NODE_ID_HEX_LEN || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        Some(Self(value.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for NodeId {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(())
    }
}

/// 节点身份（私钥）。Debug 只暴露 node_id，不泄露密钥。
#[derive(Clone)]
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// 序列化为 32 字节种子，落盘时记得 0600。
    pub fn to_seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn node_id(&self) -> NodeId {
        NodeId::from_pubkey(&self.public_key())
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }

    pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        match VerifyingKey::from_bytes(public_key) {
            Ok(key) => key
                .verify_strict(message, &Signature::from_bytes(signature))
                .is_ok(),
            Err(_) => false,
        }
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("node_id", &self.node_id().to_string())
            .finish()
    }
}

/// 由 node_id 派生虚拟地址。
///
/// `network` 是网络基址，`prefix_len` 是掩码长度；同一网络内
/// `salt` 用于碰撞后的重算（由信令面下发）。
pub fn derive_virtual_ip(
    node_id: &NodeId,
    network: Ipv4Addr,
    prefix_len: u8,
    salt: u32,
) -> Ipv4Addr {
    let prefix = prefix_len.clamp(8, 30) as u32;
    let host_bits = 32 - prefix;
    let mask: u32 = (1u32 << host_bits) - 1;

    let mut hasher = Sha256::new();
    hasher.update(node_id.as_str().as_bytes());
    hasher.update(salt.to_be_bytes());
    let digest = hasher.finalize();

    let raw = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    // | 2 避开网络地址；命中广播地址时回退一格
    let mut host = (raw & mask) | 2;
    if host == mask {
        host ^= 1;
    }

    let base = u32::from(network) & !mask;
    Ipv4Addr::from(base | host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_stable_across_restarts() {
        let id = Identity::generate();
        let seed = id.to_seed();
        let restored = Identity::from_seed(&seed);
        assert_eq!(id.node_id(), restored.node_id());
    }

    #[test]
    fn node_id_matches_public_key_hash() {
        let id = Identity::generate();
        let expected = NodeId::from_pubkey(&id.public_key());
        assert_eq!(id.node_id(), expected);
        assert_eq!(id.node_id().as_str().len(), NODE_ID_HEX_LEN);
    }

    #[test]
    fn signatures_verify_and_tampering_fails() {
        let id = Identity::generate();
        let msg = b"punch at 1730000000000";
        let sig = id.sign(msg);

        assert!(Identity::verify(&id.public_key(), msg, &sig));
        assert!(!Identity::verify(&id.public_key(), b"other", &sig));

        let other = Identity::generate();
        assert!(!Identity::verify(&other.public_key(), msg, &sig));
    }

    #[test]
    fn node_id_parse_rejects_bad_input() {
        assert!(NodeId::parse("3f9a").is_none());
        assert!(NodeId::parse(&"z".repeat(NODE_ID_HEX_LEN)).is_none());
        assert!(NodeId::parse(&"a".repeat(NODE_ID_HEX_LEN)).is_some());
    }

    #[test]
    fn virtual_ip_is_inside_network_and_stable() {
        let id = Identity::generate();
        let net = Ipv4Addr::new(10, 64, 0, 0);
        let a = derive_virtual_ip(&id.node_id(), net, 16, 0);
        let b = derive_virtual_ip(&id.node_id(), net, 16, 0);
        assert_eq!(a, b);
        assert_eq!(a.octets()[0..2], [10, 64]);
        assert_ne!(a, Ipv4Addr::new(10, 64, 0, 0));
        assert_ne!(a, Ipv4Addr::new(10, 64, 255, 255));
    }

    #[test]
    fn salt_changes_address_on_collision() {
        let id = Identity::generate();
        let net = Ipv4Addr::new(10, 64, 0, 0);
        let a = derive_virtual_ip(&id.node_id(), net, 16, 0);
        let b = derive_virtual_ip(&id.node_id(), net, 16, 1);
        assert_ne!(a, b);
    }

    #[test]
    fn different_nodes_get_different_addresses() {
        let net = Ipv4Addr::new(10, 64, 0, 0);
        let a = derive_virtual_ip(&Identity::generate().node_id(), net, 16, 0);
        let b = derive_virtual_ip(&Identity::generate().node_id(), net, 16, 0);
        assert_ne!(a, b);
    }

    /// 与 signal/worker.js 的 deriveVirtualIp 共用一组向量，两边算法一旦跑偏就会被抓出来。
    #[test]
    fn virtual_ip_matches_signaling_vectors() {
        let net = Ipv4Addr::new(10, 64, 0, 0);
        let cases = [
            (
                "0123456789abcdef0123456789abcdef",
                ["10.64.158.142", "10.64.193.155", "10.64.30.74"],
            ),
            (
                "ffffffffffffffffffffffffffffffff",
                ["10.64.159.126", "10.64.129.186", "10.64.197.198"],
            ),
            (
                "3f9a1b2c3d4e5f60718293a4b5c6d7e8",
                ["10.64.128.239", "10.64.71.59", "10.64.251.83"],
            ),
        ];

        for (id, expected) in cases {
            let node = NodeId::parse(id).expect("合法 node_id");
            for (salt, want) in [0u32, 1, 7].iter().zip(expected) {
                let got = derive_virtual_ip(&node, net, 16, *salt).to_string();
                assert_eq!(got, want, "node={id} salt={salt}");
            }
        }
    }
}
