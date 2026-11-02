//! 引擎：端点生命周期与打洞入口。
//!
//! 外壳（CLI / 桌面 / Android）都只和这一层打交道。

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use quinn::Connection;
use tokio::time::Instant;

use crate::candidate::Candidate;
use crate::peer::{punch, Role};
use crate::socket;

/// 打洞前给对端的准备时间：双方都要先拿到对端地址。
const ALIGN_DELAY: Duration = Duration::from_millis(300);

pub struct Engine {
    endpoint: quinn::Endpoint,
    local_addr: SocketAddr,
    srflx: Option<SocketAddr>,
    candidates: Vec<Candidate>,
}

impl Engine {
    /// 绑定端口、做 STUN 探测、创建端点。
    pub async fn bind(bind_addr: SocketAddr, stun_servers: &[String]) -> Result<Self> {
        let bound = socket::bind(bind_addr, stun_servers, Duration::from_secs(3)).await?;
        Ok(Self {
            endpoint: bound.endpoint,
            local_addr: bound.local_addr,
            srflx: bound.srflx,
            candidates: bound.candidates,
        })
    }

    pub fn endpoint(&self) -> &quinn::Endpoint {
        &self.endpoint
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// STUN 观测到的公网映射。
    pub fn srflx(&self) -> Option<SocketAddr> {
        self.srflx
    }

    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }

    /// 与对端打洞。
    pub async fn punch(
        &self,
        peer: SocketAddr,
        role: Role,
        window: Duration,
    ) -> Result<Connection, punch::PunchError> {
        let start = Instant::now() + ALIGN_DELAY;
        punch::execute(&self.endpoint, peer, role, start, window).await
    }

    /// 等待所有连接结束（外壳常驻用）。
    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await;
    }
}
