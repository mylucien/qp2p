//! 连接建立后的对端认证（应用层握手）。
//!
//! QUIC 这一层默认是自签证书 + 跳过校验，任何能到达 UDP 端口的人都能把
//! 握手做完；而 `serve_flows` 会服务"打洞胜出的那条连接"，所以光有打洞
//! 不能说明对面是谁。
//!
//! 这里在 QUIC 之上做一次带 nonce 的双向挑战应答：双方各自用身份私钥签名，
//! 签名里同时绑定对方和自己的 node_id，以及**这条 TLS 会话的导出值**，因此
//!
//! - 复放一张旧的认证帧没用（nonce 是本次连接现生成的）
//! - 反射攻击没用（签名顺序里两边的 id 不能互换）
//! - 想冒充某个已知 node_id，必须先拿到它的私钥
//! - **中继 / 中间人没用**：TLS 不校验证书，路径上的人可以终结两段 QUIC 再
//!   逐帧转发认证帧；但两段 TLS 会话的导出值不同，转发过去的签名在对面
//!   必然校验失败（通道绑定，RFC 5705 / RFC 9266 同一思路）
//!
//! 最后一条是关键：只有"身份签名"而没有"会话绑定"，认证只能证明对面有那把
//! 钥匙，证明不了自己正在和它直接通话。这一点不能靠"反正身份是 Ed25519
//! 密钥"省掉，也不等价于证书钉扎——钉扎是在 TLS 层拒绝陌生证书，通道绑定是
//! 在应用层证明"签名的人就是 TLS 对面的人"，两者任选其一都能挡住中继，
//! 默认路径上只有通道绑定是始终生效的。
//!
//! 一条流、三个消息往返：身份 + 双向签名 + 两侧各自的结论。
//! 最后一步是刻意加上的——少了它，先返回的一侧会在对端还等着读的时候
//! 就把端点丢掉，对端看到的只是一句"closed by peer"。

use std::time::Duration;

use anyhow::{bail, Context, Result};
use quinn::{Connection, RecvStream, SendStream};
use serde::{Deserialize, Serialize};

use crate::identity::{Identity, NodeId};

/// 认证协议版本，改字段就换一个。
const AUTH_VERSION: u8 = 3;
/// 单步超时。握手是本地往返，超过这个时间基本就是出问题了。
const STEP_TIMEOUT: Duration = Duration::from_secs(5);
/// 单帧上限，防止对端塞一个巨大的 JSON。
const MAX_FRAME: usize = 4096;

const AUTH_TAG: &str = "QP2P-AUTH-3";

/// TLS keying material exporter 的标签与上下文。
/// 两端必须一致；改了就要同时升 `AUTH_VERSION` 和 `AUTH_TAG`。
const BINDING_LABEL: &[u8] = b"EXPORTER-qp2p-auth-v3";
const BINDING_LEN: usize = 32;

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
    /// 对 `AUTH_TAG|signer|peer|my_nonce|peer_nonce|binding` 的签名
    sig: String,
}

/// listener 对本次认证的最终裁决。
///
/// 少了这一帧，dialer 发完自己的签名就返回成功：即使 listener 因为身份不符
/// 把连接关掉，dialer 侧还是打印"认证通过"，然后在第一次开流时才莫名其妙地失败。
#[derive(Debug, Serialize, Deserialize)]
struct Verdict {
    ok: bool,
    #[serde(default)]
    reason: String,
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

    let binding = channel_binding(conn)?;
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
        &binding,
    )?;

    // 3. 我回签，证明我也持有私钥
    let message = auth_message(
        identity.node_id().as_str(),
        peer.node_id.as_str(),
        &my_nonce,
        &peer_nonce,
        &binding,
    );
    let my_proof = Proof {
        v: AUTH_VERSION,
        node_id: identity.node_id().as_str().to_string(),
        sig: hex::encode(identity.sign(message.as_bytes())),
    };
    write_frame(&mut send, &my_proof).await?;

    // 4. 等 listener 的最终裁决：它可能因为自己的 --peer-id 不匹配而拒了我
    let verdict: Verdict = read_frame(&mut recv)
        .await
        .context("对端没有给出认证结论（连接可能已被拒绝后关闭）")?;

    // 5. 我这边也要给出结论，并且必须在返回前发出去：
    //    listener 等它才敢收尾，否则它一返回、端点被丢弃，
    //    刚写的裁决帧会连同连接一起消失，我这边就成了"对端没说结论"
    let outcome = if verdict.ok {
        check_expected(&peer.node_id, expected)
    } else {
        Err(anyhow::anyhow!("对端拒绝了本次连接：{}", verdict.reason))
    };
    let ack = match &outcome {
        Ok(()) => Verdict {
            ok: true,
            reason: String::new(),
        },
        Err(e) => Verdict {
            ok: false,
            reason: format!("{e:#}"),
        },
    };
    let _ = write_frame(&mut send, &ack).await;
    let _ = send.finish();

    outcome?;
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

    let binding = channel_binding(conn)?;

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
        &binding,
    );
    let my_proof = Proof {
        v: AUTH_VERSION,
        node_id: identity.node_id().as_str().to_string(),
        sig: hex::encode(identity.sign(message.as_bytes())),
    };
    write_frame(&mut send, &my_proof).await?;

    // 3. 对端回签，证明它确实持有那把私钥
    let peer_proof: Proof = read_frame(&mut recv).await?;
    let outcome = verify_proof(
        &peer_proof,
        &peer,
        &peer.node_id,
        &identity.node_id(),
        &peer_nonce,
        &my_nonce,
        &binding,
    )
    .and_then(|()| check_expected(&peer.node_id, expected));

    // 4. 无论通过还是拒绝，都给出结论再关流：
    //    dialer 靠这一帧区分"真的通过了"和"对端已经把我关了"
    let verdict = match &outcome {
        Ok(()) => Verdict {
            ok: true,
            reason: String::new(),
        },
        Err(e) => Verdict {
            ok: false,
            reason: format!("{e:#}"),
        },
    };
    let _ = write_frame(&mut send, &verdict).await;

    // 5. 等对端的结论。必须等到它，否则我们会在对方还等着读取时就返回：
    //    调用方一旦返回就会丢弃端点，裁决帧连同连接一起消失，
    //    对方只能看到"closed by peer"，拿不到拒绝原因。
    //    顺带把"对方接受了我"和"对方拒绝了我"也变成两侧一致的结果。
    let peer_verdict: Verdict = read_frame(&mut recv).await.unwrap_or(Verdict {
        ok: false,
        reason: "对端没有给出结论".to_string(),
    });
    let _ = send.finish();

    outcome?;
    if !peer_verdict.ok {
        bail!("对端拒绝了本次连接：{}", peer_verdict.reason);
    }
    Ok(peer)
}

/// 导出这条 TLS 会话独有的绑定值（十六进制）。
///
/// 同一条 TLS 会话的两端会得到相同的值，不同会话（比如中间人的两段）一定不同。
fn channel_binding(conn: &Connection) -> Result<String> {
    let mut out = [0u8; BINDING_LEN];
    conn.export_keying_material(&mut out, BINDING_LABEL, b"")
        .map_err(|e| anyhow::anyhow!("导出 TLS 会话绑定值失败：{e:?}"))?;
    Ok(hex::encode(out))
}

fn auth_message(
    signer: &str,
    peer: &str,
    my_nonce: &str,
    peer_nonce: &str,
    binding: &str,
) -> String {
    format!("{AUTH_TAG}|{signer}|{peer}|{my_nonce}|{peer_nonce}|{binding}")
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
    binding: &str,
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
        binding,
    );
    if !Identity::verify(&peer.pubkey, message.as_bytes(), &sig) {
        bail!("对端认证签名校验失败（密钥不对、nonce 被篡改，或 TLS 会话被中继）");
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

    fn identity_of(id: &Identity) -> PeerIdentity {
        PeerIdentity {
            node_id: id.node_id(),
            pubkey: id.public_key(),
        }
    }

    #[test]
    fn auth_message_binds_ids_nonces_and_session() {
        let a = auth_message("alice", "bob", "n1", "n2", "s1");
        assert_eq!(a, "QP2P-AUTH-3|alice|bob|n1|n2|s1");
        // 换任何一段都必须得到不同的签名内容
        assert_ne!(a, auth_message("bob", "alice", "n1", "n2", "s1"));
        assert_ne!(a, auth_message("alice", "bob", "n2", "n1", "s1"));
        assert_ne!(a, auth_message("alice", "bob", "n1", "n2", "s2"));
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

    fn signed_proof(signer: &Identity, receiver: &Identity, sn: &str, rn: &str, b: &str) -> Proof {
        let message = auth_message(
            signer.node_id().as_str(),
            receiver.node_id().as_str(),
            sn,
            rn,
            b,
        );
        Proof {
            v: AUTH_VERSION,
            node_id: signer.node_id().as_str().to_string(),
            sig: hex::encode(signer.sign(message.as_bytes())),
        }
    }

    fn check(proof: &Proof, signer: &Identity, receiver: &Identity, binding: &str) -> Result<()> {
        verify_proof(
            proof,
            &identity_of(signer),
            &signer.node_id(),
            &receiver.node_id(),
            "peer-nonce",
            "my-nonce",
            binding,
        )
    }

    #[test]
    fn proof_from_right_key_and_session_is_accepted() {
        let me = Identity::generate();
        let peer = Identity::generate();
        let proof = signed_proof(&peer, &me, "peer-nonce", "my-nonce", "session-A");
        assert!(check(&proof, &peer, &me, "session-A").is_ok());
    }

    #[test]
    fn proof_from_wrong_key_is_rejected() {
        let me = Identity::generate();
        let peer = Identity::generate();
        let attacker = Identity::generate();

        // 攻击者拿自己的密钥签，却声称自己是 peer
        let mut bad = signed_proof(&attacker, &me, "peer-nonce", "my-nonce", "session-A");
        bad.node_id = peer.node_id().as_str().to_string();
        assert!(check(&bad, &peer, &me, "session-A").is_err());
    }

    #[test]
    fn proof_for_other_session_nonce_is_rejected() {
        let me = Identity::generate();
        let peer = Identity::generate();

        // 上一轮会话的签名帧，换到新 nonce 下应当失效
        let stale = signed_proof(&peer, &me, "old", "old", "session-A");
        assert!(check(&stale, &peer, &me, "session-A").is_err());
    }

    /// 通道绑定：中间人把 D↔M 会话里签好的帧原样转给另一段 TLS 会话，
    /// 对面用自己那条会话的导出值验签，必然失败。
    #[test]
    fn proof_relayed_into_another_tls_session_is_rejected() {
        let me = Identity::generate();
        let peer = Identity::generate();

        let proof = signed_proof(&peer, &me, "peer-nonce", "my-nonce", "session-peer-side");
        assert!(check(&proof, &peer, &me, "session-peer-side").is_ok());
        assert!(check(&proof, &peer, &me, "session-my-side").is_err());
    }
}
