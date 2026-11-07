//! qp2p-core — 打洞内核。
//!
//! 设计见仓库根目录 `DESIGN.md`。本 crate 不依赖任何前端：
//! CLI、Windows 桌面、Android 通过各自的外壳复用同一份实现。
//!
//! 当前进度：
//! - P1 纯逻辑：候选地址、STUN 编解码、时钟偏移、状态机、身份
//! - P2 端点与打洞：单 socket + 同 socket STUN + 角色化打洞
//! - P3 数据面：QUIC 流复用 + 双向端口映射

pub mod candidate;
pub mod config;
pub mod engine;
pub mod identity;
pub mod link;
pub mod path;
pub mod peer;
pub mod route;
pub mod secret_file;
pub mod session;
pub mod signal;
pub mod socket;
pub mod stun;
pub mod stun_watch;
pub mod tls;
pub mod upnp;

/// 信令与探针的协议版本，握手时交换。
pub const PROTOCOL_VERSION: u16 = 1;

/// 默认 UDP 端口（QUIC 与 STUN 共用一个 socket）。
pub const DEFAULT_PORT: u16 = 51820;

/// 每个网络分配到的虚拟网段前缀长度。
pub const DEFAULT_NETWORK_PREFIX_LEN: u8 = 16;

pub use engine::Engine;
pub use peer::Role;
