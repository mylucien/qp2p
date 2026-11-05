//! 信令面：签名规范与 HTTP 客户端。

pub mod canonical;
pub mod client;

pub use client::{SignalClient, SignalError};
