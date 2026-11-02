//! 每个对端一个状态机。
//!
//! 纯函数：不碰网络、不读时钟、不写日志。时间只从参数进来，
//! 因此可以用虚拟时钟覆盖所有分支，包括重试耗尽和连接抖动。
//!
//! 旧版把网络调用、全局表写入和取消令牌缠在 `punch.rs` 里，
//! 除了跑真网络几乎无法测试——这里彻底拆开。

use super::Role;
use crate::identity::NodeId;

/// 首次尝试之后最多重试次数。
pub const MAX_RETRIES: u8 = 3;

/// 重试退避阶梯（毫秒）。抖动由调用方添加，保持状态机可测。
pub const BACKOFF_LADDER_MS: [u64; 3] = [30_000, 60_000, 120_000];

pub fn backoff_ms(retry: u8) -> u64 {
    let index = retry as usize;
    BACKOFF_LADDER_MS[index.min(BACKOFF_LADDER_MS.len() - 1)]
}

/// 按 node_id 决定谁主动发起 QUIC 握手。
///
/// QUIC 没有同时打开，两侧都当客户端只会得到两条连接
/// 和一堆没人取走的 accept。
pub fn role_for(me: &NodeId, peer: &NodeId) -> Role {
    if me.as_str() < peer.as_str() {
        Role::Dialer
    } else {
        Role::Listener
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerState {
    /// 空闲，没有连接意图
    Idle,
    /// 已向信令面请求撮合，等对端候选地址
    Requesting,
    /// 打洞进行中
    Punching { attempt: u8, deadline_ms: u64 },
    /// 直连已建立
    Direct { since_ms: u64 },
    /// 本次失败，等待重试时刻
    Backoff { retry: u8, wake_at_ms: u64 },
    /// 放弃
    Failed { reason: FailureReason },
}

impl PeerState {
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Direct { .. })
    }

    /// 供界面显示的状态短名。
    pub fn label(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Requesting => "requesting",
            Self::Punching { .. } => "punching",
            Self::Direct { .. } => "direct",
            Self::Backoff { .. } => "backoff",
            Self::Failed { .. } => "failed",
        }
    }
}

/// 失败原因，同时也是 `qp2p doctor` 的诊断依据。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReason {
    /// 双方都没有可用候选（常见于完全对称 NAT + 未开 UPnP）
    NoCandidates,
    /// 窗口内没打通
    PunchTimeout,
    /// 信令面拿不到对端信息
    Unreachable,
    /// 对端拒绝（分组不匹配、密钥错误）
    Rejected,
    /// 对端离线
    Offline,
}

impl FailureReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoCandidates => "no_candidates",
            Self::PunchTimeout => "punch_timeout",
            Self::Unreachable => "unreachable",
            Self::Rejected => "rejected",
            Self::Offline => "offline",
        }
    }

    /// 给用户看的一句话解释。
    pub fn hint(self) -> &'static str {
        match self {
            Self::NoCandidates => "没有可用候选地址：对端可能处于对称 NAT，且未开启 UPnP",
            Self::PunchTimeout => "打洞超时：双方 NAT 都不允许对方先发包，或包被防火墙丢弃",
            Self::Unreachable => "信令面没有返回对端候选，检查 Worker 是否可用",
            Self::Rejected => "对端拒绝连接：网络密钥不匹配或已被移出网络",
            Self::Offline => "对端离线：最后活跃时间超过阈值",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// 用户或上层要连这个对端
    WantConnect,
    /// 信令面返回了对端候选
    CandidatesReady {
        count: usize,
    },
    /// 信令面明确表示没有候选
    NoCandidates,
    /// 时间对齐完成，进入打洞窗口
    PunchStarted {
        attempt: u8,
        deadline_ms: u64,
    },
    /// QUIC 握手完成，路径可用
    PathReady {
        now_ms: u64,
    },
    /// 窗口结束仍未打通
    PunchTimedOut,
    /// 已建立的连接断了
    ConnLost,
    /// 退避到期
    RetryDue,
    Rejected,
    PeerOffline,
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// 向信令面发起撮合
    RequestPunch {
        attempt: u8,
    },
    /// 发裸 UDP 探针开自己这侧的孔
    SendProbe,
    /// 发起 QUIC 握手
    Dial,
    /// 安排一次唤醒
    ScheduleWake {
        after_ms: u64,
    },
    /// 取消已安排的唤醒
    CancelWake,
    ReportConnected,
    ReportDisconnected,
    ReportFailed {
        reason: FailureReason,
    },
}

pub struct PeerFsm {
    role: Role,
    state: PeerState,
}

impl PeerFsm {
    pub fn new(role: Role) -> Self {
        Self {
            role,
            state: PeerState::Idle,
        }
    }

    pub fn state(&self) -> &PeerState {
        &self.state
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn step(&mut self, event: Event, now_ms: u64) -> Vec<Effect> {
        let state = self.state.clone();

        match (state, event) {
            (_, Event::Shutdown) => {
                self.state = PeerState::Idle;
                vec![Effect::CancelWake]
            }

            (PeerState::Idle, Event::WantConnect)
            | (PeerState::Failed { .. }, Event::WantConnect) => {
                self.state = PeerState::Requesting;
                vec![Effect::RequestPunch { attempt: 0 }]
            }

            (PeerState::Direct { .. }, Event::WantConnect) => vec![Effect::ReportConnected],

            (PeerState::Requesting, Event::CandidatesReady { count: 0 }) => {
                self.state = PeerState::Failed {
                    reason: FailureReason::NoCandidates,
                };
                vec![Effect::ReportFailed {
                    reason: FailureReason::NoCandidates,
                }]
            }
            (PeerState::Requesting, Event::CandidatesReady { .. }) => Vec::new(),

            (PeerState::Requesting, Event::NoCandidates) => {
                self.state = PeerState::Failed {
                    reason: FailureReason::NoCandidates,
                };
                vec![Effect::ReportFailed {
                    reason: FailureReason::NoCandidates,
                }]
            }

            (
                PeerState::Requesting,
                Event::PunchStarted {
                    attempt,
                    deadline_ms,
                },
            ) => {
                self.state = PeerState::Punching {
                    attempt,
                    deadline_ms,
                };
                // 两侧都发探针开孔；只有 dialer 发起 QUIC 握手
                let mut effects = vec![Effect::SendProbe];
                if self.role == Role::Dialer {
                    effects.push(Effect::Dial);
                }
                effects
            }

            (PeerState::Requesting, Event::PunchTimedOut) => {
                self.state = PeerState::Failed {
                    reason: FailureReason::Unreachable,
                };
                vec![Effect::ReportFailed {
                    reason: FailureReason::Unreachable,
                }]
            }

            (PeerState::Punching { .. }, Event::PathReady { now_ms }) => {
                self.state = PeerState::Direct { since_ms: now_ms };
                vec![Effect::CancelWake, Effect::ReportConnected]
            }

            (PeerState::Punching { attempt, .. }, Event::PunchTimedOut) => {
                if attempt >= MAX_RETRIES {
                    self.state = PeerState::Failed {
                        reason: FailureReason::PunchTimeout,
                    };
                    vec![Effect::ReportFailed {
                        reason: FailureReason::PunchTimeout,
                    }]
                } else {
                    let wait = backoff_ms(attempt);
                    self.state = PeerState::Backoff {
                        retry: attempt + 1,
                        wake_at_ms: now_ms.saturating_add(wait),
                    };
                    vec![Effect::ScheduleWake { after_ms: wait }]
                }
            }

            (PeerState::Backoff { retry, .. }, Event::RetryDue) => {
                self.state = PeerState::Requesting;
                vec![Effect::RequestPunch { attempt: retry }]
            }

            (PeerState::Direct { .. }, Event::ConnLost) => {
                self.state = PeerState::Requesting;
                vec![
                    Effect::ReportDisconnected,
                    Effect::RequestPunch { attempt: 0 },
                ]
            }

            (_, Event::Rejected) => {
                self.state = PeerState::Failed {
                    reason: FailureReason::Rejected,
                };
                vec![Effect::ReportFailed {
                    reason: FailureReason::Rejected,
                }]
            }

            (_, Event::PeerOffline) => {
                self.state = PeerState::Failed {
                    reason: FailureReason::Offline,
                };
                vec![Effect::ReportFailed {
                    reason: FailureReason::Offline,
                }]
            }

            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fsm(role: Role) -> PeerFsm {
        PeerFsm::new(role)
    }

    #[test]
    fn dialer_happy_path() {
        let mut f = fsm(Role::Dialer);
        assert_eq!(f.state(), &PeerState::Idle);

        assert_eq!(
            f.step(Event::WantConnect, 0),
            vec![Effect::RequestPunch { attempt: 0 }]
        );
        assert_eq!(f.state(), &PeerState::Requesting);

        assert!(f.step(Event::CandidatesReady { count: 2 }, 0).is_empty());

        assert_eq!(
            f.step(
                Event::PunchStarted {
                    attempt: 0,
                    deadline_ms: 500
                },
                0
            ),
            vec![Effect::SendProbe, Effect::Dial]
        );
        assert_eq!(
            f.state(),
            &PeerState::Punching {
                attempt: 0,
                deadline_ms: 500
            }
        );

        assert_eq!(
            f.step(Event::PathReady { now_ms: 900 }, 900),
            vec![Effect::CancelWake, Effect::ReportConnected]
        );
        assert_eq!(f.state(), &PeerState::Direct { since_ms: 900 });
        assert!(f.state().is_connected());
    }

    #[test]
    fn listener_does_not_dial() {
        let mut f = fsm(Role::Listener);
        f.step(Event::WantConnect, 0);
        f.step(Event::CandidatesReady { count: 1 }, 0);
        assert_eq!(
            f.step(
                Event::PunchStarted {
                    attempt: 0,
                    deadline_ms: 10
                },
                0
            ),
            vec![Effect::SendProbe]
        );
    }

    #[test]
    fn retries_with_backoff_then_gives_up() {
        let mut f = fsm(Role::Dialer);
        f.step(Event::WantConnect, 0);
        f.step(Event::CandidatesReady { count: 1 }, 0);

        // 第 0 次尝试超时 → 30s 退避
        assert_eq!(
            f.step(
                Event::PunchStarted {
                    attempt: 0,
                    deadline_ms: 100
                },
                0
            ),
            vec![Effect::SendProbe, Effect::Dial]
        );
        assert_eq!(
            f.step(Event::PunchTimedOut, 1_000),
            vec![Effect::ScheduleWake { after_ms: 30_000 }]
        );
        assert_eq!(
            f.state(),
            &PeerState::Backoff {
                retry: 1,
                wake_at_ms: 31_000
            }
        );

        // 退避到期 → 重新撮合
        assert_eq!(
            f.step(Event::RetryDue, 31_000),
            vec![Effect::RequestPunch { attempt: 1 }]
        );

        // 第 1 次超时 → 60s
        f.step(
            Event::PunchStarted {
                attempt: 1,
                deadline_ms: 2_000,
            },
            31_000,
        );
        assert_eq!(
            f.step(Event::PunchTimedOut, 32_000),
            vec![Effect::ScheduleWake { after_ms: 60_000 }]
        );

        // 第 2 次超时 → 120s
        f.step(Event::RetryDue, 92_000);
        f.step(
            Event::PunchStarted {
                attempt: 2,
                deadline_ms: 93_000,
            },
            92_000,
        );
        assert_eq!(
            f.step(Event::PunchTimedOut, 94_000),
            vec![Effect::ScheduleWake { after_ms: 120_000 }]
        );

        // 第 3 次超时 → 放弃
        f.step(Event::RetryDue, 214_000);
        f.step(
            Event::PunchStarted {
                attempt: 3,
                deadline_ms: 215_000,
            },
            214_000,
        );
        assert_eq!(
            f.step(Event::PunchTimedOut, 216_000),
            vec![Effect::ReportFailed {
                reason: FailureReason::PunchTimeout
            }]
        );
    }

    #[test]
    fn no_candidates_fails_fast() {
        let mut f = fsm(Role::Dialer);
        f.step(Event::WantConnect, 0);
        let effects = f.step(Event::NoCandidates, 0);
        assert_eq!(
            effects,
            vec![Effect::ReportFailed {
                reason: FailureReason::NoCandidates
            }]
        );
        assert_eq!(
            f.state(),
            &PeerState::Failed {
                reason: FailureReason::NoCandidates
            }
        );
    }

    #[test]
    fn conn_lost_reconnects_immediately() {
        let mut f = fsm(Role::Dialer);
        f.state = PeerState::Direct { since_ms: 1 };
        assert_eq!(
            f.step(Event::ConnLost, 10),
            vec![
                Effect::ReportDisconnected,
                Effect::RequestPunch { attempt: 0 }
            ]
        );
        assert_eq!(f.state(), &PeerState::Requesting);
    }

    #[test]
    fn shutdown_resets() {
        let mut f = fsm(Role::Dialer);
        f.state = PeerState::Punching {
            attempt: 1,
            deadline_ms: 5,
        };
        assert_eq!(f.step(Event::Shutdown, 6), vec![Effect::CancelWake]);
        assert_eq!(f.state(), &PeerState::Idle);
    }

    #[test]
    fn role_is_deterministic() {
        let a = NodeId::parse(&"a".repeat(32)).unwrap();
        let b = NodeId::parse(&"b".repeat(32)).unwrap();
        assert_eq!(role_for(&a, &b), Role::Dialer);
        assert_eq!(role_for(&b, &a), Role::Listener);
    }

    #[test]
    fn failure_reasons_are_actionable() {
        assert!(FailureReason::PunchTimeout.hint().contains("打洞超时"));
        assert_eq!(FailureReason::NoCandidates.as_str(), "no_candidates");
    }
}
