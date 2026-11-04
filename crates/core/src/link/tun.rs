//! TUN 模式的数据面：把 IP 包按五元组复用到 QUIC 双向流上。
//!
//! 线上格式：流的第一字节是类型 `2`（区别于 TCP 端口映射的 `1`），
//! 之后是 `[len:u16][IP 包]` 的帧序列。这里用「一条流一条流」而不是
//! datagram，是因为 QUIC datagram 受路径 MTU 限制（约 1150），
//! 内层 MTU 会被压得很低，TCP MSS 跟着难看。
//!
//! 代价是单条流内的队头阻塞——但每条 TCP 连接各自一条流，互不影响。

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use quinn::{Connection, ReadExactError, RecvStream, SendStream};
use tokio::sync::mpsc;

use crate::route::{flow::FlowKey, flow::FlowTable, ip, TunLink};

/// 流类型：IP 包。
const KIND_IP: u8 = 2;
/// 空闲多久回收一条流。
const FLOW_IDLE: Duration = Duration::from_secs(120);
/// 同时存在的流上限，与 quinn 的 `max_concurrent_bidi_streams` 对齐。
const FLOW_CAPACITY: usize = 200;
const READ_BUF: usize = 4096;

/// 跑起来：把内核交给我们的包送出去，把对端送来的包写回内核。
///
/// `local` 是本机的虚拟地址，用来判断 ICMP echo 要不要就地应答——
/// 远端不开 `ip_forward` 也能 ping 通，这是用户判断"连没连上"的第一反应。
pub async fn run(conn: Connection, link: TunLink, local: Ipv4Addr) -> Result<()> {
    let TunLink {
        mut from_tun,
        to_tun,
        mtu,
    } = link;

    let inbound = {
        let conn = conn.clone();
        let to_tun = to_tun.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_inbound(conn, to_tun).await {
                tracing::debug!("[tun] 接收循环结束: {e:#}");
            }
        })
    };

    let mut flows: FlowTable<SendStream> = FlowTable::new(FLOW_IDLE, FLOW_CAPACITY);
    let mut last_sweep = Instant::now();

    loop {
        tokio::select! {
            packet = from_tun.recv() => {
                let Some(packet) = packet else { break };
                if let Err(e) = dispatch(&conn, &mut flows, &to_tun, local, &packet, mtu).await {
                    tracing::debug!("[tun] 转发失败: {e:#}");
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                if last_sweep.elapsed() >= Duration::from_secs(5) {
                    last_sweep = Instant::now();
                    for (key, mut send) in flows.sweep(Instant::now()) {
                        tracing::trace!("[tun] 回收空闲流 {key:?}");
                        let _ = send.reset(0u32.into());
                    }
                }
            }
            _ = conn.closed() => {
                tracing::info!("[tun] 连接已断开");
                break;
            }
        }
    }

    for (_, mut send) in flows.drain() {
        let _ = send.reset(0u32.into());
    }
    inbound.abort();
    Ok(())
}

async fn dispatch(
    conn: &Connection,
    flows: &mut FlowTable<SendStream>,
    to_tun: &mpsc::Sender<Vec<u8>>,
    local: Ipv4Addr,
    packet: &[u8],
    mtu: usize,
) -> Result<()> {
    let Some(parsed) = ip::parse(packet) else {
        return Ok(());
    };

    // 1. 打自己的 ping 就地应答，不打扰对端
    if parsed.dst == local && ip::is_echo_request(&parsed) {
        if let Some(reply) = ip::echo_reply(&parsed) {
            let _ = to_tun.send(reply).await;
        }
        return Ok(());
    }

    if packet.len() > mtu {
        bail!("包比 MTU 大（{} > {mtu}），内核本应分片", packet.len());
    }

    // 2. 已有流就复用
    let key = FlowKey::new(parsed.proto, parsed.src, parsed.dst, parsed.ports);
    let now = Instant::now();
    if flows.contains(&key) {
        let send = flows.get_mut(&key, now).expect("刚判断过存在");
        if write_frame(send, packet).await.is_ok() {
            return Ok(());
        }
        // 写失败说明这条流已经废了，删掉后下面重开一条
        flows.remove(&key);
    }

    // 3. 新开一条流
    let (mut send, mut recv) = conn.open_bi().await.context("打开双向流失败")?;
    send.write_all(&[KIND_IP]).await.context("写流类型失败")?;
    write_frame(&mut send, packet).await?;

    // 对端可能主动关流：等它，顺便把错误暴露到日志
    tokio::spawn(async move {
        let mut buf = [0u8; 64];
        let _ = recv.read(&mut buf).await;
    });

    if let Some((old, mut old_send)) = flows.insert(key, send, now) {
        let _ = old_send.reset(0u32.into());
        tracing::debug!("[tun] 流表满，淘汰 {old:?}");
    }
    Ok(())
}

async fn write_frame(send: &mut SendStream, packet: &[u8]) -> Result<()> {
    let len = u16::try_from(packet.len()).context("单个 IP 包超过 64KB")?;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(packet).await?;
    Ok(())
}

/// 接收方向：对端每开一条流就是一个新 flow。
async fn serve_inbound(conn: Connection, to_tun: mpsc::Sender<Vec<u8>>) -> Result<()> {
    loop {
        let (send, mut recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::debug!("[tun] 不再接受流: {e}");
                return Ok(());
            }
        };
        let to_tun = to_tun.clone();
        tokio::spawn(async move {
            if let Err(e) = pump_stream(&mut recv, to_tun).await {
                tracing::trace!("[tun] 流结束: {e:#}");
            }
            drop(send);
        });
    }
}

async fn pump_stream(recv: &mut RecvStream, to_tun: mpsc::Sender<Vec<u8>>) -> Result<()> {
    let mut kind = [0u8; 1];
    recv.read_exact(&mut kind).await.context("读流类型失败")?;
    if kind[0] != KIND_IP {
        bail!("不是 IP 流（类型 {}）", kind[0]);
    }

    loop {
        let mut len = [0u8; 2];
        match recv.read_exact(&mut len).await {
            Ok(()) => {}
            // 读到 0 字节就是正常结束：对端把这条流关了
            Err(ReadExactError::FinishedEarly(0)) => return Ok(()),
            Err(e) => return Err(e).context("读帧长度失败"),
        }
        let len = usize::from(u16::from_be_bytes(len));
        if len == 0 || len > READ_BUF * 16 {
            bail!("帧长度非法：{len}");
        }
        let mut buf = vec![0u8; len];
        recv.read_exact(&mut buf).await.context("读帧失败")?;
        if to_tun.send(buf).await.is_err() {
            return Ok(());
        }
    }
}
