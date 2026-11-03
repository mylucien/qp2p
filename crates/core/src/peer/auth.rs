//! 连接建立后的对端认证（应用层握手）。
//!
//! QUIC 这一层目前是自签证书 + 跳过校验，任何能到达 UDP 端口的人都能把
//! 握手做完；而 `serve_flows` 会服务"打洞胜出的那条连接"，所以光有打洞
//! 不能说明对面是谁。
//!
//! 这里在 QUIC 之上做一次带 nonce 的双向挑战应答：双方各自用身份私钥签名，
//! 签名里同时绑定对方和自己的 node_id，因此
//!
//! - 复放一张旧的认证帧没用（nonce 是本次连接现生成的）
//! - 反射攻击没用（签名顺序里两边的 id 不能互换）
//! - 想冒充某个已知 node_id，必须先拿到它的私钥
//!
//! 只花两个往返，一条流搞定。之所以不走 TLS 证书钉扎：身份本来就是一把
//! Ed25519 密钥，再引入"证书 → 指纹 → 钉扎"要多一层持久化和分发，
//! 得到的保证是同一个。将来若要在 TLS 层也隐身（抗 DPI 或挡握手 DoS），
//! 再把证书绑到这把密钥上、复用同一套指纹即可。

use std::time::Duration;

use anyhow::{bail, Context, Result};
use quinn::{Connection, RecvStream, SendStream};
use serde::{Deserialize, Serialize};

use crate::identity::{Identity, NodeId};

/// 认证协议版本，改字段就换一个。
const AUTH_VERSION: u8 = 1;
/// 单步超时。握手是本地往返，超过这个时间基本就是出问题了。
const STEP_TIMEOUT: Duration = Duration::from_secs(5);
/// 单帧上限，防止对端塞一个巨大的 JSON。
const MAX_FRAME: usize = 4096;

const AUTH_TAG: &str = "QP2P-AUTH-1";

#[derive(Debug, Serialize, Deserialize)]
struct Hello {
    v: u8,
    node_id: String,
    pubkey: String,
    nonce: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Proof {
    v: u8,
    node_id: String,
    /// 对 `AUTH_TAG|signer|peer|my_nonce|peer_nonce` 的签名
    sig: String,
}

/// 认证结果：确认过的对端身份。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    pub node_id: NodeId,
    pub pubkey: [u8; 32],
}

/// dialer 侧：开一条流发起认证，并校验对端。
pub async fn authenticate_dialer(
    conn: &Connection,
    identity: &Identity,
    expected: Option<&NodeId>,
) -> Result<PeerIdentity> {
    let (mut send, mut recv) = tokio::time::timeout(STEP_TIMEOUT, conn.open_bi())
        .await
        .context("打开认证流超时")?
        .context("打开认证流失败")?;

    let my_nonce = random_nonce();

    // 1. 我先亮身份（含 nonce）
    let hello = Hello {
        v: AUTH_VERSION,
        node_id: identity.node_id().as_str().to_string(),
        pubkey: hex::encode(identity.public_key()),
        nonce: my_nonce.clone(),
    };
    write_frame(&mut send, &hello).await?;

    // 2. 对端回身份 + 对双方 nonce 的签名
    let peer_hello: Hello = read_frame(&mut recv).await?;
    let peer = check_hello(&peer_hello)?;

    let proof: Proof = read_frame(&mut recv).await?;
    let peer_nonce = peer_hello.nonce.clone();
    verify_proof(
        &proof,
        &peer,
        &peer.node_id,
        &identity.node_id(),
        &peer_nonce,
        &my_nonce,
    )?;

    // 3. 我回签，证明我也持有私钥
    let message = auth_message(
        identity.node_id().as_str(),
        peer.node_id.as_str(),
        &my_nonce,
        &peer_nonce,
    );
    let my_proof = Proof {
        v: AUTH_VERSION,
        node_id: identity.node_id().as_str().to_string(),
        sig: hex::encode(identity.sign(message.as_bytes())),
    };
    write_frame(&mut send, &my_proof).await?;
    let _ = send.finish();

    check_expected(&peer.node_id, expected)?;
    Ok(peer)
}

/// listener 侧：接受认证流，回签并校验对端。
pub async fn authenticate_listener(
    conn: &Connection,
    identity: &Identity,
    expected: Option<&NodeId>,
) -> Result<PeerIdentity> {
    let (mut send, mut recv) = tokio::time::timeout(STEP_TIMEOUT, conn.accept_bi())
        .await
        .context("等待认证流超时")?
        .context("接受认证流失败")?;

    // 1. 对端先亮身份
    let peer_hello: Hello = read_frame(&mut recv).await?;
    let peer = check_hello(&peer_hello)?;
    let peer_nonce = peer_hello.nonce.clone();

    // 2. 我回身份 + 签名（绑定两个 nonce 和两边的 node_id）
    let my_nonce = random_nonce();
    let reply = Hello {
        v: AUTH_VERSION,
        node_id: identity.node_id().as_str().to_string(),
        pubkey: hex::encode(identity.public_key()),
        nonce: my_nonce.clone(),
    };
    write_frame(&mut send, &reply).await?;

    let message = auth_message(
        identity.node_id().as_str(),
        peer.node_id.as_str(),
        &my_nonce,
        &peer_nonce,
    );
    let my_proof = Proof {
        v: AUTH_VERSION,
        node_id: identity.node_id().as_str().to_string(),
        sig: hex::encode(identity.sign(message.as_bytes())),
    };
    write_frame(&mut send, &my_proof).await?;

    // 3. 对端回签，证明它确实持有那把私钥
    let peer_proof: Proof = read_frame(&mut recv).await?;
    verify_proof(
        &peer_proof,
        &peer,
        &peer.node_id,
        &identity.node_id(),
        &peer_nonce,
        &my_nonce,
    )?;
    let _ = send.finish();

    check_expected(&peer.node_id, expected)?;
    Ok(peer)
}

fn auth_message(signer: &str, peer: &str, my_nonce: &str, peer_nonce: &str) -> String {
    format!("{AUTH_TAG}|{signer}|{peer}|{my_nonce}|{peer_nonce}")
}

fn check_hello(hello: &Hello) -> Result<PeerIdentity> {
    if hello.v != AUTH_VERSION {
        bail!("认证协议版本不匹配：{} != {AUTH_VERSION}", hello.v);
    }

    let pubkey = hex::decode(&hello.pubkey).context("pubkey 不是合法十六进制")?;
    let pubkey: [u8; 32] = pubkey
        .try_into()
        .map_err(|_| anyhow::anyhow!("pubkey 长度必须是 32 字节"))?;

    let claimed = NodeId::parse(&hello.node_id).context("node_id 格式非法")?;
    let derived = NodeId::from_pubkey(&pubkey);
    if derived != claimed {
        bail!("node_id 与公钥不匹配（可能被冒充）");
    }

    Ok(PeerIdentity {
        node_id: claimed,
        pubkey,
    })
}

fn verify_proof(
    proof: &Proof,
    peer: &PeerIdentity,
    signer: &NodeId,
    receiver: &NodeId,
    signer_nonce: &str,
    receiver_nonce: &str,
) -> Result<()> {
    if proof.v != AUTH_VERSION {
        bail!("认证协议版本不匹配");
    }
    if proof.node_id != signer.as_str() {
        bail!("签名里的 node_id 与握手声明不一致");
    }

    let sig = hex::decode(&proof.sig).context("签名不是合法十六进制")?;
    let sig: [u8; 64] = sig
        .try_into()
        .map_err(|_| anyhow::anyhow!("签名长度必须是 64 字节"))?;

    let message = auth_message(
        signer.as_str(),
        receiver.as_str(),
        signer_nonce,
        receiver_nonce,
    );
    if !Identity::verify(&peer.pubkey, message.as_bytes(), &sig) {
        bail!("对端认证签名校验失败（密钥不对，或 nonce 被篡改）");
    }
    Ok(())
}

fn check_expected(peer: &NodeId, expected: Option<&NodeId>) -> Result<()> {
    if let Some(want) = expected {
        if want != peer {
            bail!("对端身份不符：期望 {want}，实际 {peer}");
        }
    }
    Ok(())
}

fn random_nonce() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

async fn write_frame<T: Serialize>(send: &mut SendStream, value: &T) -> Result<()> {
    let body = serde_json::to_vec(value).context("序列化认证帧失败")?;
    if body.len() > MAX_FRAME {
        bail!("认证帧过大：{}", body.len());
    }
    let len = u16::try_from(body.len()).context("认证帧过长")?;
    tokio::time::timeout(STEP_TIMEOUT, async {
        send.write_all(&len.to_be_bytes()).await?;
        send.write_all(&body).await
    })
    .await
    .context("写认证帧超时")?
    .context("写认证帧失败")
}

async fn read_frame<T: for<'de> Deserialize<'de>>(recv: &mut RecvStream) -> Result<T> {
    let mut len = [0u8; 2];
    tokio::time::timeout(STEP_TIMEOUT, recv.read_exact(&mut len))
        .await
        .context("读认证帧长度超时")?
        .context("读认证帧长度失败")?;

    let len = usize::from(u16::from_be_bytes(len));
    if len == 0 || len > MAX_FRAME {
        bail!("认证帧长度非法：{len}");
    }

    let mut body = vec![0u8; len];
    tokio::time::timeout(STEP_TIMEOUT, recv.read_exact(&mut body))
        .await
        .context("读认证帧超时")?
        .context("读认证帧失败")?;

    serde_json::from_slice(&body).context("解析认证帧失败")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_message_binds_both_ids_and_nonces() {
        let a = auth_message("alice", "bob", "n1", "n2");
        assert_eq!(a, "QP2P-AUTH-1|alice|bob|n1|n2");
        // 换任何一段都必须得到不同的签名内容
        assert_ne!(a, auth_message("bob", "alice", "n1", "n2"));
        assert_ne!(a, auth_message("alice", "bob", "n2", "n1"));
    }

    #[test]
    fn hello_rejects_forged_node_id() {
        let id = Identity::generate();
        let other = Identity::generate();

        let ok = Hello {
            v: AUTH_VERSION,
            node_id: id.node_id().as_str().to_string(),
            pubkey: hex::encode(id.public_key()),
            nonce: "00".into(),
        };
        assert!(check_hello(&ok).is_ok());

        // 用别人的公钥配自己的 node_id
        let forged = Hello {
            v: AUTH_VERSION,
            node_id: id.node_id().as_str().to_string(),
            pubkey: hex::encode(other.public_key()),
            nonce: "00".into(),
        };
        assert!(check_hello(&forged).is_err());
    }

    #[test]
    fn proof_from_wrong_key_is_rejected() {
        let me = Identity::generate();
        let peer = Identity::generate();
        let attacker = Identity::generate();

        let message = auth_message(
            peer.node_id().as_str(),
            me.node_id().as_str(),
            "peer-nonce",
            "my-nonce",
        );
        let bad = Proof {
            v: AUTH_VERSION,
            node_id: peer.node_id().as_str().to_string(),
            sig: hex::encode(attacker.sign(message.as_bytes())),
        };

        let identity = PeerIdentity {
            node_id: peer.node_id(),
            pubkey: peer.public_key(),
        };
        assert!(verify_proof(
            &bad,
            &identity,
            &peer.node_id(),
            &me.node_id(),
            "peer-nonce",
            "my-nonce"
        )
        .is_err());
    }

    #[test]
    fn proof_for_other_session_nonce_is_rejected() {
        let me = Identity::generate();
        let peer = Identity::generate();

        // 上一轮会话的签名帧，换到新 nonce 下应当失效
        let stale = auth_message(peer.node_id().as_str(), me.node_id().as_str(), "old", "old");
        let proof = Proof {
            v: AUTH_VERSION,
            node_id: peer.node_id().as_str().to_string(),
            sig: hex::encode(peer.sign(stale.as_bytes())),
        };

        let identity = PeerIdentity {
            node_id: peer.node_id(),
            pubkey: peer.public_key(),
        };
        assert!(verify_proof(
            &proof,
            &identity,
            &peer.node_id(),
            &me.node_id(),
            "new",
            "new"
        )
        .is_err());
    }
}
