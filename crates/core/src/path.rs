//! 时钟偏移估计与打洞窗口调度。
//!
//! 打洞需要双方在同一瞬间发包，但不能假设两台机器的墙钟一致
//! （旧版直接做毫秒减法，还用 ±30s 硬拒绝把没配 NTP 的设备判死）。
//! 这里只估计"服务端时间 - 本地时间"的偏移，再把服务端下发的
//! 绝对时刻换算成本地时钟。

use std::time::Duration;

/// 指数加权移动平均系数：新样本权重。
const EWMA_ALPHA: f64 = 0.3;

#[derive(Debug, Clone)]
pub struct ClockOffset {
    offset_ms: f64,
    samples: u32,
    best_rtt_ms: f64,
}

impl Default for ClockOffset {
    fn default() -> Self {
        Self::new()
    }
}

impl ClockOffset {
    pub const fn new() -> Self {
        Self {
            offset_ms: 0.0,
            samples: 0,
            best_rtt_ms: f64::MAX,
        }
    }

    /// 用一次请求/响应样本更新偏移。
    ///
    /// `send_ms` / `recv_ms` 是本地单调时间，`server_ms` 是响应里的服务端时间。
    pub fn observe(&mut self, send_ms: u64, recv_ms: u64, server_ms: u64) {
        let rtt = recv_ms.saturating_sub(send_ms) as f64;
        let midpoint = send_ms as f64 + rtt / 2.0;
        let sample = server_ms as f64 - midpoint;

        if self.samples == 0 {
            self.offset_ms = sample;
        } else {
            self.offset_ms = EWMA_ALPHA * sample + (1.0 - EWMA_ALPHA) * self.offset_ms;
        }
        self.samples = self.samples.saturating_add(1);
        self.best_rtt_ms = self.best_rtt_ms.min(rtt);
    }

    /// 当前估计的偏移（服务端时间减去本地时间）。
    pub fn offset_ms(&self) -> f64 {
        self.offset_ms
    }

    pub fn samples(&self) -> u32 {
        self.samples
    }

    /// 见过的最小 RTT，用来判断样本质量。
    pub fn best_rtt_ms(&self) -> Option<f64> {
        (self.samples > 0).then_some(self.best_rtt_ms)
    }

    /// 把服务端绝对时刻换算成本地时钟。
    pub fn server_to_local(&self, server_ms: u64) -> u64 {
        (server_ms as f64 - self.offset_ms).max(0.0).round() as u64
    }

    /// 距离某个服务端时刻还有多久；已过则为 0。
    pub fn wait_until(&self, server_deadline_ms: u64, local_now_ms: u64) -> Duration {
        let local_deadline = self.server_to_local(server_deadline_ms);
        Duration::from_millis(local_deadline.saturating_sub(local_now_ms))
    }
}

/// 一次打洞尝试的时间窗。
///
/// 窗口内按固定间隔重发，而不是只赌一个时刻——这是从 n2n 的
/// 周期性 REGISTER 学来的，用来抵消时钟误差和 UDP 丢包。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PunchSchedule {
    start_ms: u64,
    window_ms: u64,
    interval_ms: u64,
}

impl PunchSchedule {
    pub const DEFAULT_WINDOW_MS: u64 = 800;
    pub const DEFAULT_INTERVAL_MS: u64 = 120;

    pub fn new(start_ms: u64, window_ms: u64, interval_ms: u64) -> Self {
        Self {
            start_ms,
            window_ms,
            interval_ms: interval_ms.max(1),
        }
    }

    pub fn start_ms(&self) -> u64 {
        self.start_ms
    }

    pub fn deadline_ms(&self) -> u64 {
        self.start_ms.saturating_add(self.window_ms)
    }

    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms > self.deadline_ms()
    }

    /// 窗口内一共发几次。
    pub fn tick_count(&self) -> u64 {
        self.window_ms / self.interval_ms + 1
    }

    /// 第 n 次发包的时刻；超出窗口返回 None。
    pub fn tick_at(&self, n: u64) -> Option<u64> {
        let at = self
            .start_ms
            .saturating_add(n.saturating_mul(self.interval_ms));
        (at <= self.deadline_ms()).then_some(at)
    }

    /// 现在该不该发下一个包。
    pub fn is_due(&self, last_sent_ms: Option<u64>, now_ms: u64) -> bool {
        if now_ms < self.start_ms || self.is_expired(now_ms) {
            return false;
        }
        match last_sent_ms {
            None => true,
            Some(last) => now_ms >= last.saturating_add(self.interval_ms),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_converges_towards_known_skew() {
        let mut clock = ClockOffset::new();
        // 本地比服务端慢 5000ms
        for i in 0..20u64 {
            let send = 1_000_000 + i * 1000;
            let rtt = 40;
            let server = send + 5000 + rtt / 2;
            clock.observe(send, send + rtt, server);
        }
        assert!(
            (clock.offset_ms() - 5000.0).abs() < 5.0,
            "{}",
            clock.offset_ms()
        );
        assert_eq!(clock.samples(), 20);
        assert_eq!(clock.best_rtt_ms(), Some(40.0));
    }

    #[test]
    fn server_deadline_maps_to_local_clock() {
        let mut clock = ClockOffset::new();
        clock.observe(1000, 1040, 6020); // 偏移 5000
        assert_eq!(clock.server_to_local(10_000), 5000);
        assert_eq!(clock.wait_until(10_000, 4000), Duration::from_millis(1000));
        assert_eq!(clock.wait_until(10_000, 6000), Duration::ZERO);
    }

    #[test]
    fn offset_never_goes_negative_from_rounding() {
        let mut clock = ClockOffset::new();
        clock.observe(0, 0, 0);
        assert_eq!(clock.server_to_local(0), 0);
    }

    #[test]
    fn schedule_counts_ticks_inside_window() {
        let s = PunchSchedule::new(1000, 800, 120);
        assert_eq!(s.tick_count(), 7);
        assert_eq!(s.deadline_ms(), 1800);
        assert_eq!(s.tick_at(0), Some(1000));
        assert_eq!(s.tick_at(6), Some(1720));
        assert_eq!(s.tick_at(7), None);
    }

    #[test]
    fn schedule_due_logic() {
        let s = PunchSchedule::new(1000, 800, 120);
        assert!(!s.is_due(None, 999));
        assert!(s.is_due(None, 1000));
        assert!(!s.is_due(Some(1000), 1100));
        assert!(s.is_due(Some(1000), 1120));
        assert!(!s.is_due(None, 1801));
    }

    #[test]
    fn zero_interval_is_clamped() {
        let s = PunchSchedule::new(0, 100, 0);
        assert_eq!(s.tick_count(), 101);
    }
}
