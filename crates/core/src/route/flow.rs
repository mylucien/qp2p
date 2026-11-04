//! 流表：一条 IP 五元组对应一条 QUIC 双向流。
//!
//! TUN 模式下每个新连接开一条流，之后双向复用；空闲久了回收，
//! 否则长跑的进程会把流配额吃光（quinn 默认 256 条）。

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// 一条流的键。ICMP 与分片包的端口记 0，按"同一对主机一条流"处理。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub proto: u8,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub sport: u16,
    pub dport: u16,
}

impl FlowKey {
    pub fn new(proto: u8, src: Ipv4Addr, dst: Ipv4Addr, ports: Option<(u16, u16)>) -> Self {
        let (sport, dport) = ports.unwrap_or((0, 0));
        Self {
            proto,
            src,
            dst,
            sport,
            dport,
        }
    }
}

struct Entry<V> {
    value: V,
    last_used: Instant,
}

/// 带空闲回收和容量上限的流表。
pub struct FlowTable<V> {
    entries: HashMap<FlowKey, Entry<V>>,
    idle: Duration,
    capacity: usize,
}

impl<V> FlowTable<V> {
    pub fn new(idle: Duration, capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            idle,
            capacity: capacity.max(1),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 取一条流并刷新它的活跃时间。
    pub fn get_mut(&mut self, key: &FlowKey, now: Instant) -> Option<&mut V> {
        let entry = self.entries.get_mut(key)?;
        entry.last_used = now;
        Some(&mut entry.value)
    }

    pub fn contains(&self, key: &FlowKey) -> bool {
        self.entries.contains_key(key)
    }

    /// 插入一条新流。满了就先淘汰最久没用的那条，并把它返回给调用方去关闭。
    pub fn insert(&mut self, key: FlowKey, value: V, now: Instant) -> Option<(FlowKey, V)> {
        if !self.entries.contains_key(&key) && self.entries.len() >= self.capacity {
            if let Some(evicted) = self.evict_oldest() {
                self.entries.insert(
                    key,
                    Entry {
                        value,
                        last_used: now,
                    },
                );
                return Some(evicted);
            }
        }
        self.entries.insert(
            key,
            Entry {
                value,
                last_used: now,
            },
        );
        None
    }

    fn evict_oldest(&mut self) -> Option<(FlowKey, V)> {
        let oldest = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.last_used)
            .map(|(k, _)| *k)?;
        let entry = self.entries.remove(&oldest)?;
        Some((oldest, entry.value))
    }

    /// 回收空闲超时的流，返回它们的键和值（调用方负责 close/reset）。
    pub fn sweep(&mut self, now: Instant) -> Vec<(FlowKey, V)> {
        let idle = self.idle;
        let expired: Vec<FlowKey> = self
            .entries
            .iter()
            .filter(|(_, e)| now.duration_since(e.last_used) >= idle)
            .map(|(k, _)| *k)
            .collect();

        expired
            .into_iter()
            .filter_map(|k| self.entries.remove(&k).map(|e| (k, e.value)))
            .collect()
    }

    /// 撤销某条流（收到对端 reset / 出错时）。
    pub fn remove(&mut self, key: &FlowKey) -> Option<V> {
        self.entries.remove(key).map(|e| e.value)
    }

    /// 把所有流取出来（连接断开时统一收尾）。
    pub fn drain(&mut self) -> Vec<(FlowKey, V)> {
        self.entries.drain().map(|(k, e)| (k, e.value)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(port: u16) -> FlowKey {
        FlowKey::new(
            6,
            Ipv4Addr::new(10, 64, 1, 2),
            Ipv4Addr::new(10, 64, 3, 4),
            Some((port, 80)),
        )
    }

    #[test]
    fn same_tuple_hits_same_flow() {
        let mut t: FlowTable<u32> = FlowTable::new(Duration::from_secs(60), 8);
        let now = Instant::now();
        t.insert(key(1000), 1, now);
        assert_eq!(t.get_mut(&key(1000), now), Some(&mut 1));
        assert!(!t.contains(&key(1001)), "不同源端口是不同流");
    }

    #[test]
    fn idle_flows_are_swept() {
        let mut t: FlowTable<u32> = FlowTable::new(Duration::from_secs(60), 8);
        let now = Instant::now();
        t.insert(key(1), 1, now);
        t.insert(key(2), 2, now);

        // 只碰第二条，第一条应当被回收
        t.get_mut(&key(2), now + Duration::from_secs(50));
        let gone = t.sweep(now + Duration::from_secs(61));
        assert_eq!(gone.len(), 1, "只应回收闲置的那条：{gone:?}");
        assert!(!t.contains(&key(1)));
        assert!(t.contains(&key(2)));
    }

    #[test]
    fn capacity_evicts_oldest() {
        let mut t: FlowTable<u32> = FlowTable::new(Duration::from_secs(60), 2);
        let now = Instant::now();
        t.insert(key(1), 1, now);
        t.insert(key(2), 2, now + Duration::from_millis(10));
        // 满了：最久没用的 k1 被挤掉
        let evicted = t.insert(key(3), 3, now + Duration::from_millis(20));
        assert_eq!(evicted.map(|(k, _)| k), Some(key(1)));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn inserting_existing_key_does_not_evict() {
        let mut t: FlowTable<u32> = FlowTable::new(Duration::from_secs(60), 1);
        let now = Instant::now();
        t.insert(key(1), 1, now);
        let evicted = t.insert(key(1), 9, now);
        assert!(evicted.is_none());
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn drain_returns_everything() {
        let mut t: FlowTable<u32> = FlowTable::new(Duration::from_secs(60), 8);
        let now = Instant::now();
        t.insert(key(1), 1, now);
        t.insert(key(2), 2, now);
        assert_eq!(t.drain().len(), 2);
        assert!(t.is_empty());
    }
}
