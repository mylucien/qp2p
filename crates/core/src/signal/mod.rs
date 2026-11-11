//! 信令面：签名规范、HTTP 客户端与 WebSocket 长连接。

pub mod canonical;
pub mod client;
pub mod ws;

pub use client::{SignalClient, SignalError};
pub use ws::{WsItem, WsLink};
