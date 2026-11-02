//! qp2p-core — 打洞内核。
//!
//! 设计见仓库根目录 `DESIGN.md`。本 crate 不依赖任何前端：
//! CLI、Windows 桌面、Android 通过各自的外壳复用同一份实现。
//!
//! 阶段说明（P1）：只有纯逻辑层——候选地址、STUN 编解码、时钟偏移、
//! 打洞状态机、节点身份。全部无网络、无 I/O 副作用，可完整单测。

pub mod candidate;
pub mod config;
pub mod identity;
pub mod path;
pub mod peer;
pub mod stun;

/// 信令与探针的协议版本，握手时交换。
pub const PROTOCOL_VERSION: u16 = 1;

/// 默认 UDP 端口（QUIC 与 STUN 共用一个 socket）。
pub const DEFAULT_PORT: u16 = 51820;

/// 每个网络分配到的虚拟网段前缀长度。
pub const DEFAULT_NETWORK_PREFIX_LEN: u8 = 16;
