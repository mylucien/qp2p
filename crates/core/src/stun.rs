//! STUN Binding（RFC 5389 的最小子集）。
//!
//! 只做两件事：构造 Binding Request、解析 XOR-MAPPED-ADDRESS。
//! 关键约束：探测必须走 QUIC 用的**同一个** UDP socket，
//! 否则拿到的映射与 QUIC 五元组无关（旧版正是在这里出的错）。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use thiserror::Error;

pub const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

/// STUN 头部长度（不含属性）。
pub const HEADER_LEN: usize = 20;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StunError {
    #[error("消息过短：{0} 字节")]
    TooShort(usize),
    #[error("不是 Binding Response：0x{0:04x}")]
    NotBindingResponse(u16),
    #[error("magic cookie 不匹配")]
    BadCookie,
    #[error("未找到 XOR-MAPPED-ADDRESS")]
    NoMappedAddress,
    #[error("属性格式非法")]
    BadAttribute,
    #[error("不支持的地址族：0x{0:02x}")]
    UnsupportedFamily(u8),
}

/// 构造 Binding Request。txid 由调用方生成，必须与响应校验时一致。
pub fn build_binding_request(txid: [u8; 12]) -> [u8; HEADER_LEN] {
    let mut msg = [0u8; HEADER_LEN];
    msg[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    msg[2..4].copy_from_slice(&0u16.to_be_bytes());
    msg[4..8].copy_from_slice(&MAGIC_COOKIE);
    msg[8..20].copy_from_slice(&txid);
    msg
}

/// 是否是 STUN 报文（用于 PunchSocket 分流）。
///
/// STUN 报文前两位固定为 `00`，而 QUIC 短报文首字节 ≥ 0x40、
/// 长报文 ≥ 0x80，自定义探针以 0x00 0x51 开头，故不冲突。
pub fn is_stun(buf: &[u8]) -> bool {
    buf.len() >= HEADER_LEN && buf[0] & 0xC0 == 0x00 && buf[4..8] == MAGIC_COOKIE
}

/// 解析 Binding Response，取出服务端观测到的映射地址。
pub fn parse_binding_response(buf: &[u8]) -> Result<SocketAddr, StunError> {
    if buf.len() < HEADER_LEN {
        return Err(StunError::TooShort(buf.len()));
    }

    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != BINDING_RESPONSE {
        return Err(StunError::NotBindingResponse(msg_type));
    }
    if buf[4..8] != MAGIC_COOKIE {
        return Err(StunError::BadCookie);
    }

    let body_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let end = (HEADER_LEN + body_len).min(buf.len());

    let mut pos = HEADER_LEN;
    while pos + 4 <= end {
        let attr_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let attr_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;

        let value_end = pos + attr_len;
        if value_end > end {
            return Err(StunError::BadAttribute);
        }
        if attr_type == ATTR_XOR_MAPPED_ADDRESS {
            return parse_xor_mapped(&buf[pos..value_end]);
        }

        // 属性值按 4 字节对齐填充
        pos = value_end + (4 - attr_len % 4) % 4;
    }

    Err(StunError::NoMappedAddress)
}

fn parse_xor_mapped(value: &[u8]) -> Result<SocketAddr, StunError> {
    if value.len() < 4 {
        return Err(StunError::BadAttribute);
    }
    let family = value[1];
    let port = u16::from_be_bytes([value[2], value[3]])
        ^ u16::from_be_bytes([MAGIC_COOKIE[0], MAGIC_COOKIE[1]]);

    match family {
        0x01 => {
            if value.len() < 8 {
                return Err(StunError::BadAttribute);
            }
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&value[4..8]);
            for (byte, mask) in octets.iter_mut().zip(MAGIC_COOKIE.iter()) {
                *byte ^= mask;
            }
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        other => Err(StunError::UnsupportedFamily(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response_with_xor_mapped(ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        buf.extend_from_slice(&12u16.to_be_bytes());
        buf.extend_from_slice(&MAGIC_COOKIE);
        buf.extend_from_slice(&[0u8; 12]);
        buf.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        buf.extend_from_slice(&8u16.to_be_bytes());
        buf.push(0x00);
        buf.push(0x01);
        buf.extend_from_slice(&(port ^ 0x2112).to_be_bytes());
        for (i, byte) in ip.iter().enumerate() {
            buf.push(byte ^ MAGIC_COOKIE[i]);
        }
        buf
    }

    #[test]
    fn request_layout_is_rfc_compliant() {
        let req = build_binding_request([7u8; 12]);
        assert_eq!(req.len(), 20);
        assert_eq!(&req[0..2], &[0x00, 0x01]);
        assert_eq!(&req[2..4], &[0x00, 0x00]);
        assert_eq!(&req[4..8], &MAGIC_COOKIE);
        assert_eq!(&req[8..20], &[7u8; 12]);
    }

    #[test]
    fn parses_ipv4_mapping() {
        let buf = response_with_xor_mapped([203, 0, 113, 5], 51820);
        let addr = parse_binding_response(&buf).unwrap();
        assert_eq!(addr.port(), 51820);
        assert_eq!(addr.ip().to_string(), "203.0.113.5");
    }

    #[test]
    fn rejects_short_message() {
        assert_eq!(
            parse_binding_response(&[0u8; 10]).unwrap_err(),
            StunError::TooShort(10)
        );
    }

    #[test]
    fn rejects_wrong_type() {
        let mut buf = response_with_xor_mapped([1, 2, 3, 4], 1);
        buf[1] = 0x02;
        assert!(matches!(
            parse_binding_response(&buf),
            Err(StunError::NotBindingResponse(_))
        ));
    }

    #[test]
    fn rejects_bad_cookie() {
        let mut buf = response_with_xor_mapped([1, 2, 3, 4], 1);
        buf[4] = 0x00;
        assert_eq!(
            parse_binding_response(&buf).unwrap_err(),
            StunError::BadCookie
        );
    }

    #[test]
    fn reports_missing_attribute() {
        let mut buf = response_with_xor_mapped([1, 2, 3, 4], 1);
        // 把属性类型改成 MAPPED-ADDRESS，使 XOR-MAPPED-ADDRESS 缺失
        buf[20] = 0x00;
        buf[21] = 0x01;
        assert_eq!(
            parse_binding_response(&buf).unwrap_err(),
            StunError::NoMappedAddress
        );
    }

    #[test]
    fn rejects_ipv6_as_unsupported() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        buf.extend_from_slice(&24u16.to_be_bytes());
        buf.extend_from_slice(&MAGIC_COOKIE);
        buf.extend_from_slice(&[0u8; 12]);
        buf.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        buf.extend_from_slice(&20u16.to_be_bytes());
        buf.push(0x00);
        buf.push(0x02);
        buf.extend_from_slice(&1000u16.to_be_bytes());
        buf.extend_from_slice(&[0u8; 16]);
        assert_eq!(
            parse_binding_response(&buf).unwrap_err(),
            StunError::UnsupportedFamily(0x02)
        );
    }

    #[test]
    fn stun_detection_does_not_collide_with_quic() {
        let stun = response_with_xor_mapped([1, 2, 3, 4], 1);
        assert!(is_stun(&stun));
        assert!(!is_stun(&[
            0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]));
        assert!(!is_stun(&[
            0x00, b'Q', b'P', b'2', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]));
    }
}
