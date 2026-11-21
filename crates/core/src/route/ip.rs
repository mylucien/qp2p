//! IPv4 报文的最小解析。
//!
//! TUN 模式转的是**原始 IP 包**，所以这里只需要认出五元组和 ICMP echo，
//! 不做任何校验和/分片重组——分片交给两端内核，我们原样透传。

use std::net::Ipv4Addr;

/// IPv4 头最小长度。
pub const IPV4_HEADER_LEN: usize = 20;

/// 传输层协议号。
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// ICMP 类型。
pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_ECHO_REPLY: u8 = 0;

/// 从 IP 包里能拿到的转发信息。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpPacket<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: u8,
    /// TCP/UDP 的源/目的端口；ICMP 或分片包为 None。
    pub ports: Option<(u16, u16)>,
    /// 原始字节（含 IP 头）。
    pub raw: &'a [u8],
}

/// 解析 IPv4 包。不是 IPv4、长度不够、或头长非法都返回 None。
///
/// 分片包（MF 置位或分片偏移非 0）**不解析端口**：后续分片里没有传输层头，
/// 拿第一个分片的端口当整条流的端口会在乱序时出错。调用方按
/// `(proto, src, dst, 0, 0)` 归并分片，让内核去重组。
pub fn parse(buf: &[u8]) -> Option<IpPacket<'_>> {
    if buf.len() < IPV4_HEADER_LEN {
        return None;
    }
    let version = buf[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = usize::from(buf[0] & 0x0f) * 4;
    if ihl < IPV4_HEADER_LEN || buf.len() < ihl {
        return None;
    }

    let total_len = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
    if total_len < ihl || total_len > buf.len() {
        return None;
    }
    let raw = &buf[..total_len];

    let proto = buf[9];
    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);

    let frag = u16::from_be_bytes([buf[6], buf[7]]);
    let more_fragments = frag & 0x2000 != 0;
    let offset = frag & 0x1fff;
    let fragmented = more_fragments || offset != 0;

    let ports = if fragmented {
        None
    } else if (proto == PROTO_TCP || proto == PROTO_UDP) && raw.len() >= ihl + 4 {
        Some((
            u16::from_be_bytes([raw[ihl], raw[ihl + 1]]),
            u16::from_be_bytes([raw[ihl + 2], raw[ihl + 3]]),
        ))
    } else {
        None
    };

    Some(IpPacket {
        src,
        dst,
        proto,
        ports,
        raw,
    })
}

/// IPv4 头长度。带 options 的包 IHL 会大于 5，必须按它算传输层起点。
fn header_len(raw: &[u8]) -> Option<usize> {
    let ihl = usize::from(raw.first()? & 0x0f) * 4;
    if ihl < IPV4_HEADER_LEN || raw.len() < ihl {
        return None;
    }
    Some(ihl)
}

/// 这是不是一个 ICMP echo request。用于"对端直接应答 ping"。
pub fn is_echo_request(packet: &IpPacket<'_>) -> bool {
    if packet.proto != PROTO_ICMP {
        return false;
    }
    let Some(ihl) = header_len(packet.raw) else {
        return false;
    };
    // echo 头至少 8 字节：type/code/checksum/id/seq
    packet.raw.len() >= ihl + 8 && packet.raw[ihl] == ICMP_ECHO_REQUEST
}

/// 按 IPv4 规则把一个超过 `mtu` 的包切开，返回每一片的完整报文（含 IP 头）。
///
/// 只在"本该不发生"的情况下用到：TUN 的 MTU 建的时候已经夹到 1424，
/// 内核不会再交来更大的包。但配置被外部改动过、或设备带上 GSO 时仍可能
/// 出现超大包，直接丢的后果是"能 ping 通、大流量全废"，所以切开送出去。
///
/// 以下情况返回 `None`，由调用方决定丢包：
/// - 不需要分片（`packet.len() <= mtu`）
/// - 已经是分片（MF 置位或偏移非 0）：再切要重算偏移，而且这种包本该已 ≤ MTU
/// - `mtu` 装不下一个 8 字节片段（偏移字段以 8 字节为单位，小于这个没法切）
///
/// 每片复制原包头（含 options），只改总长度、分片字段和头校验和。
/// 分片后端口信息丢失，这些片会归到 `(proto, src, dst, 0, 0)` 那条流——
/// 只影响"配置错误"这个兜底路径，正常流量不会走到。
pub fn fragment(packet: &[u8], mtu: usize) -> Option<Vec<Vec<u8>>> {
    if packet.len() <= mtu || packet.first()? >> 4 != 4 {
        return None;
    }
    let ihl = header_len(packet)?;

    let frag = u16::from_be_bytes([packet[6], packet[7]]);
    // MF 或非零偏移都说明这已经是一片，不能二次切
    if frag & 0x3fff != 0 {
        return None;
    }

    let declared = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    let total = declared.min(packet.len());
    if total <= ihl {
        return None;
    }

    // 除最后一片外，每片载荷必须是 8 的倍数
    let chunk = ((mtu - ihl) / 8) * 8;
    if chunk == 0 {
        return None;
    }

    let payload = &packet[ihl..total];
    let mut pieces = Vec::with_capacity(payload.len() / chunk + 1);
    let mut offset = 0usize;
    while offset < payload.len() {
        let end = (offset + chunk).min(payload.len());
        let mut piece = Vec::with_capacity(ihl + (end - offset));
        piece.extend_from_slice(&packet[..ihl]);
        piece.extend_from_slice(&payload[offset..end]);

        let more = end < payload.len();
        // 保留原保留位，清掉 DF（已经分了，再带 DF 会被中间设备丢），
        // 其余按本片重写
        let field =
            (frag & 0x8000) | if more { 0x2000 } else { 0 } | u16::try_from(offset / 8).ok()?;
        piece[6..8].copy_from_slice(&field.to_be_bytes());
        let len = u16::try_from(piece.len()).ok()?;
        piece[2..4].copy_from_slice(&len.to_be_bytes());

        // 长度和分片字段都变了，头校验和必须重算
        piece[10..12].fill(0);
        let sum = checksum(&piece[..ihl]);
        piece[10..12].copy_from_slice(&sum.to_be_bytes());

        pieces.push(piece);
        offset = end;
    }
    Some(pieces)
}

/// 把 ICMP echo request 翻成 echo reply（交换地址、改类型、重算校验和）。
///
/// 远端不开 `ip_forward` 也能 ping 通，这是判断"连没连上"的第一反应。
pub fn echo_reply(packet: &IpPacket<'_>) -> Option<Vec<u8>> {
    if !is_echo_request(packet) {
        return None;
    }
    let mut out = packet.raw.to_vec();
    // 按 IHL 索引，不再假设头是 20 字节：带 options 的包用固定偏移会写错位置
    let ihl = header_len(&out)?;
    if out.len() < ihl + 8 {
        return None;
    }

    // 交换源/目的
    let (src, dst) = (out[12..16].to_vec(), out[16..20].to_vec());
    out[12..16].copy_from_slice(&dst);
    out[16..20].copy_from_slice(&src);

    out[ihl] = ICMP_ECHO_REPLY;

    // 重算两处校验和：必须先把旧值清零，否则算出来的是"旧值参与后的结果"
    out[10..12].fill(0);
    let ip_sum = checksum(&out[..ihl]);
    out[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    out[ihl + 2..ihl + 4].fill(0);
    let icmp_sum = checksum(&out[ihl..]);
    out[ihl + 2..ihl + 4].copy_from_slice(&icmp_sum.to_be_bytes());

    Some(out)
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// 组装一个 ICMP echo request，给 `qp2p tun --ping` 这类自检用。
pub fn build_echo_request(src: Ipv4Addr, dst: Ipv4Addr, id: u16, seq: u16) -> Vec<u8> {
    let payload = b"qp2p-ping";
    let mut pkt = vec![0u8; IPV4_HEADER_LEN + 8 + payload.len()];
    pkt[0] = 0x45;
    let total = pkt.len() as u16;
    pkt[2..4].copy_from_slice(&total.to_be_bytes());
    pkt[8] = 64; // ttl
    pkt[9] = PROTO_ICMP;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());

    let icmp = IPV4_HEADER_LEN;
    pkt[icmp] = ICMP_ECHO_REQUEST;
    pkt[icmp + 4..icmp + 6].copy_from_slice(&id.to_be_bytes());
    pkt[icmp + 6..icmp + 8].copy_from_slice(&seq.to_be_bytes());
    pkt[icmp + 8..].copy_from_slice(payload);

    let ip_sum = checksum(&pkt[..IPV4_HEADER_LEN]);
    pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    let icmp_sum = checksum(&pkt[icmp..]);
    pkt[icmp + 2..icmp + 4].copy_from_slice(&icmp_sum.to_be_bytes());
    pkt
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_packet(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let mut p = vec![0u8; IPV4_HEADER_LEN + 20];
        p[0] = 0x45;
        let total = p.len() as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p[8] = 64;
        p[9] = PROTO_TCP;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p
    }

    #[test]
    fn parses_tcp_five_tuple() {
        let pkt = tcp_packet([10, 64, 1, 2], [10, 64, 3, 4], 51000, 80);
        let p = parse(&pkt).expect("应当解析成功");
        assert_eq!(p.src, Ipv4Addr::new(10, 64, 1, 2));
        assert_eq!(p.dst, Ipv4Addr::new(10, 64, 3, 4));
        assert_eq!(p.proto, PROTO_TCP);
        assert_eq!(p.ports, Some((51000, 80)));
        assert_eq!(p.raw.len(), pkt.len());
    }

    #[test]
    fn truncated_packet_is_rejected() {
        let pkt = tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1, 2);
        assert!(parse(&pkt[..10]).is_none());
        // 头部声明长度大于实际长度
        let mut bad = pkt.clone();
        bad[2..4].copy_from_slice(&1000u16.to_be_bytes());
        assert!(parse(&bad).is_none());
    }

    #[test]
    fn options_increase_header_length() {
        let mut pkt = vec![0u8; 24 + 20];
        pkt[0] = 0x46; // IHL=6 -> 24 字节
        let total = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&total.to_be_bytes());
        pkt[9] = PROTO_UDP;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        pkt[24..26].copy_from_slice(&5353u16.to_be_bytes());
        pkt[26..28].copy_from_slice(&53u16.to_be_bytes());

        let p = parse(&pkt).expect("带选项的包也要能解析");
        assert_eq!(p.ports, Some((5353, 53)));
    }

    #[test]
    fn fragments_have_no_ports() {
        let mut pkt = tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1, 2);
        pkt[6..8].copy_from_slice(&0x2000u16.to_be_bytes()); // MF
        assert_eq!(parse(&pkt).unwrap().ports, None);
    }

    #[test]
    fn echo_request_gets_a_valid_reply() {
        let req = build_echo_request(
            Ipv4Addr::new(10, 64, 0, 2),
            Ipv4Addr::new(10, 64, 0, 3),
            0x1234,
            7,
        );
        let parsed = parse(&req).expect("请求可解析");
        assert!(is_echo_request(&parsed));

        let reply = echo_reply(&parsed).expect("应当能生成应答");
        let back = parse(&reply).expect("应答可解析");
        assert_eq!(back.src, parsed.dst, "源/目的要交换");
        assert_eq!(back.dst, parsed.src);
        assert!(!is_echo_request(&back), "应答不能再被当成请求");
        assert_eq!(back.raw[IPV4_HEADER_LEN], ICMP_ECHO_REPLY);
        // 校验和必须能被接收端验过：把整包按 16 位求和应当得到 0
        assert_eq!(checksum(&reply[..IPV4_HEADER_LEN]), 0);
        assert_eq!(checksum(&reply[IPV4_HEADER_LEN..]), 0);
    }

    #[test]
    fn non_echo_is_not_answered() {
        let pkt = tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1, 2);
        assert!(echo_reply(&parse(&pkt).unwrap()).is_none());
    }

    // --- 超 MTU 分片 -----------------------------------------------------

    fn big_packet(total: usize, frag_field: u16) -> Vec<u8> {
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        let len = total as u16;
        p[2..4].copy_from_slice(&len.to_be_bytes());
        p[6..8].copy_from_slice(&frag_field.to_be_bytes());
        p[8] = 64;
        p[9] = PROTO_UDP;
        p[12..16].copy_from_slice(&[10, 64, 0, 2]);
        p[16..20].copy_from_slice(&[10, 64, 0, 9]);
        let sum = checksum(&p[..IPV4_HEADER_LEN]);
        p[10..12].copy_from_slice(&sum.to_be_bytes());
        p
    }

    #[test]
    fn oversized_packet_is_split_on_eight_byte_boundaries() {
        // DF 置位的 1500 字节包，按 1424 切
        let pkt = big_packet(1500, 0x4000);
        let pieces = fragment(&pkt, 1424).expect("1500 超过 1424，应当分片");
        // 每片载荷 1400（8 的倍数），1480 字节载荷正好两片
        assert_eq!(pieces.len(), 2);
        assert_eq!(pieces[0].len(), IPV4_HEADER_LEN + 1400);
        assert_eq!(pieces[1].len(), IPV4_HEADER_LEN + 80);
        assert_eq!(
            usize::from(u16::from_be_bytes([pieces[0][2], pieces[0][3]])),
            pieces[0].len(),
            "总长度必须与实际长度一致"
        );

        let f0 = u16::from_be_bytes([pieces[0][6], pieces[0][7]]);
        assert_eq!(f0 & 0x2000, 0x2000, "第一片还有后续，MF 要置位");
        assert_eq!(f0 & 0x1fff, 0, "第一片偏移为 0");
        assert_eq!(f0 & 0x4000, 0, "分了片就不能再带 DF");

        let f1 = u16::from_be_bytes([pieces[1][6], pieces[1][7]]);
        assert_eq!(f1 & 0x2000, 0, "最后一片不该再置 MF");
        assert_eq!(f1 & 0x1fff, 1400 / 8, "第二片偏移按 8 字节为单位");

        // 每片的头校验和都必须能被接收端验过
        for (i, piece) in pieces.iter().enumerate() {
            assert_eq!(
                checksum(&piece[..IPV4_HEADER_LEN]),
                0,
                "第 {i} 片的头校验和不对"
            );
            // 载荷要首尾相接、字节不变
            let expect = if i == 0 {
                &pkt[IPV4_HEADER_LEN..IPV4_HEADER_LEN + 1400]
            } else {
                &pkt[IPV4_HEADER_LEN + 1400..]
            };
            assert_eq!(&piece[IPV4_HEADER_LEN..], expect);
        }
    }

    #[test]
    fn fragment_declines_when_it_cannot_help() {
        let small = big_packet(1000, 0);
        assert!(fragment(&small, 1424).is_none(), "没超限不该分片");

        // 已经是分片：MF 置位
        let already = big_packet(1500, 0x2000);
        assert!(fragment(&already, 1424).is_none(), "不能二次分片");

        // MTU 小到装不下一个 8 字节片段
        let pkt = big_packet(1500, 0);
        assert!(fragment(&pkt, 24).is_none());
    }
}
