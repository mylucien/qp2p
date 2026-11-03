//! 候选地址：来源分类、优先级、去重、线上格式。
//!
//! 线上格式与信令面保持一致：
//! `{"type":"srflx","addr":"203.0.113.5:51820"}`

use std::cmp::Ordering;
use std::fmt;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// 候选地址来源。枚举顺序即优先级：内网 > UPnP 映射 > STUN 映射。
///
/// UPnP 排在 srflx 前面，因为它是一个**确定存在**的端口转发；
/// srflx 只是某个 NAT 给我们看到的映射，能否被对端打进来还要看过滤行为。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CandidateKind {
    /// 本机网卡地址，同一局域网内可直接用
    Host,
    /// UPnP / NAT-PMP 主动申请的端口映射
    Upnp,
    /// STUN 观测到的公网映射
    Srflx,
}

impl CandidateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Upnp => "upnp",
            Self::Srflx => "srflx",
        }
    }
}

/// 一个可尝试的候选地址。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub kind: CandidateKind,
    pub addr: SocketAddr,
}

impl Candidate {
    pub fn new(kind: CandidateKind, addr: SocketAddr) -> Self {
        Self { kind, addr }
    }

    pub fn priority(&self) -> u8 {
        self.kind as u8
    }

    /// 是否值得拿去尝试：排除未指定地址、回环地址和端口 0。
    pub fn is_usable(&self) -> bool {
        let ip = self.addr.ip();
        !ip.is_unspecified() && !ip.is_loopback() && self.addr.port() != 0
    }
}

impl fmt::Display for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.kind.as_str(), self.addr)
    }
}

impl Serialize for Candidate {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            #[serde(rename = "type")]
            kind: CandidateKind,
            #[serde(rename = "addr")]
            addr: &'a str,
        }
        let addr = self.addr.to_string();
        Wire {
            kind: self.kind,
            addr: &addr,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Candidate {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(rename = "type")]
            kind: CandidateKind,
            #[serde(rename = "addr")]
            addr: String,
        }
        let wire = Wire::deserialize(deserializer)?;
        let addr = wire
            .addr
            .parse::<SocketAddr>()
            .map_err(|e| serde::de::Error::custom(format!("非法地址 {:?}: {e}", wire.addr)))?;
        Ok(Self {
            kind: wire.kind,
            addr,
        })
    }
}

/// 过滤掉不可用地址，按优先级排序并去重。
///
/// 排序规则：先按来源（host → srflx → upnp），同来源按地址字典序，
/// 保证同样的输入永远得到同样的输出，便于测试与日志比对。
pub fn normalize(candidates: Vec<Candidate>) -> Vec<Candidate> {
    let mut usable: Vec<Candidate> = candidates
        .into_iter()
        .filter(Candidate::is_usable)
        .collect();
    usable.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.addr.cmp(&b.addr)));
    usable.dedup_by(|a, b| a.kind == b.kind && a.addr == b.addr);
    usable
}

/// 只保留最高优先级的一类候选（内网可达时不必打洞）。
pub fn best_tier(candidates: &[Candidate]) -> Vec<Candidate> {
    let Some(first) = candidates.first() else {
        return Vec::new();
    };
    let kind = first.kind;
    candidates
        .iter()
        .filter(|c| c.kind == kind)
        .cloned()
        .collect()
}

impl PartialOrd for Candidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Candidate {
    fn cmp(&self, other: &Self) -> Ordering {
        self.kind
            .cmp(&other.kind)
            .then_with(|| self.addr.cmp(&other.addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(kind: CandidateKind, addr: &str) -> Candidate {
        Candidate::new(kind, addr.parse().unwrap())
    }

    #[test]
    fn serde_roundtrip_matches_wire_format() {
        let cand = c(CandidateKind::Srflx, "203.0.113.5:51820");
        let json = serde_json::to_string(&cand).unwrap();
        assert_eq!(json, r#"{"type":"srflx","addr":"203.0.113.5:51820"}"#);

        let back: Candidate = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cand);
    }

    #[test]
    fn serde_rejects_bad_address() {
        let err =
            serde_json::from_str::<Candidate>(r#"{"type":"host","addr":"nope"}"#).unwrap_err();
        assert!(err.to_string().contains("非法地址"), "{err}");
    }

    #[test]
    fn normalize_sorts_by_kind_then_addr() {
        let input = vec![
            c(CandidateKind::Upnp, "203.0.113.9:1000"),
            c(CandidateKind::Srflx, "203.0.113.5:51820"),
            c(CandidateKind::Host, "192.168.1.20:51820"),
            c(CandidateKind::Host, "192.168.1.10:51820"),
        ];
        let out = normalize(input);
        let kinds: Vec<_> = out.iter().map(|x| x.kind).collect();
        assert_eq!(
            kinds,
            vec![
                CandidateKind::Host,
                CandidateKind::Host,
                CandidateKind::Upnp,
                CandidateKind::Srflx
            ]
        );
        assert_eq!(out[0].addr.ip().to_string(), "192.168.1.10");
    }

    #[test]
    fn normalize_dedups_and_drops_unusable() {
        let input = vec![
            c(CandidateKind::Host, "192.168.1.10:51820"),
            c(CandidateKind::Host, "192.168.1.10:51820"),
            c(CandidateKind::Host, "0.0.0.0:51820"),
            c(CandidateKind::Host, "127.0.0.1:51820"),
            c(CandidateKind::Srflx, "203.0.113.5:0"),
        ];
        let out = normalize(input);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].addr.ip().to_string(), "192.168.1.10");
    }

    #[test]
    fn best_tier_keeps_only_top_priority() {
        let input = normalize(vec![
            c(CandidateKind::Host, "192.168.1.10:51820"),
            c(CandidateKind::Srflx, "203.0.113.5:51820"),
        ]);
        let tier = best_tier(&input);
        assert_eq!(tier.len(), 1);
        assert_eq!(tier[0].kind, CandidateKind::Host);
    }

    #[test]
    fn display_is_readable() {
        assert_eq!(
            c(CandidateKind::Host, "192.168.1.10:51820").to_string(),
            "host 192.168.1.10:51820"
        );
    }
}
