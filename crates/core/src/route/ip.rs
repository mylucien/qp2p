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

/// 这是不是一个 ICMP echo request。用于"对端直接应答 ping"。
pub fn is_echo_request(packet: &IpPacket<'_>) -> bool {
    packet.proto == PROTO_ICMP
        && packet.raw.len() > IPV4_HEADER_LEN + 1
        && packet.raw[IPV4_HEADER_LEN] == ICMP_ECHO_REQUEST
}

/// 把 ICMP echo request 翻成 echo reply（交换地址、改类型、重算校验和）。
///
/// 远端不开 `ip_forward` 也能 ping 通，这是判断"连没连上"的第一反应。
pub fn echo_reply(packet: &IpPacket<'_>) -> Option<Vec<u8>> {
    if !is_echo_request(packet) {
        return None;
    }
    let mut out = packet.raw.to_vec();
    let ihl = usize::from(out[0] & 0x0f) * 4;

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
}
