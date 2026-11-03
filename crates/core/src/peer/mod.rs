//! 对端连接管理。
//!
//! 当前只有状态机（P1）；连接表、打洞执行器与引擎在 P2/P3 接入。

pub mod auth;
pub mod fsm;
pub mod punch;

pub use auth::PeerIdentity;
pub use fsm::{
    backoff_ms, role_for, Effect, Event, FailureReason, PeerFsm, PeerState, BACKOFF_LADDER_MS,
    MAX_RETRIES,
};

/// 打洞角色：由 node_id 字典序决定，避免双方同时发起 QUIC 握手。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// 主动发起 QUIC 握手的一方
    Dialer,
    /// 只发探针、等待入站的一方
    Listener,
}
