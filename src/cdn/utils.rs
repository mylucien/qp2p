//! # utils.rs — 公共 IP 工具函数
//!
//! `parse_client_ip()` 从 HTTP 请求头中提取真实客户端 IP，
//! `is_local_ip()` 判断 IP 是否属于本地网络 CIDR 列表。
//! 两个函数由 `files.rs` 和 `rules.rs` 共用。

use std::net::{IpAddr, ToSocketAddrs};

use axum::http::HeaderMap;

// ---------------------------------------------------------------------------
// parse_client_ip
// ---------------------------------------------------------------------------

/// 从 HTTP 请求头中提取真实客户端 IP。
///
/// 按以下优先级依次尝试：
/// 1. `CF-Connecting-IP`（Cloudflare 注入）
/// 2. `X-Forwarded-For` 第一个 IP（cloudflared 注入）
/// 3. `X-Real-IP`
///
/// 所有头部缺失时返回 `None`（视为本地请求）。
pub fn parse_client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    // CF-Connecting-IP
    if let Some(val) = headers.get("CF-Connecting-IP") {
        if let Ok(ip_str) = val.to_str() {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }

    // X-Forwarded-For：取第一个 IP（最靠近客户端）
    if let Some(val) = headers.get("X-Forwarded-For") {
        if let Ok(s) = val.to_str() {
            if let Some(first) = s.split(',').next().map(|s| s.trim()) {
                if let Ok(ip) = first.parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }

    // X-Real-IP
    if let Some(val) = headers.get("X-Real-IP") {
        if let Ok(ip_str) = val.to_str() {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// is_local_ip
// ---------------------------------------------------------------------------

/// 判断 IP 是否属于本地网络 CIDR 列表。
///
/// `cidrs` 为空时回退到 /24 自动检测：比较 IP 的前 24 位是否与本机任意
/// 非 loopback IPv4 地址的前 24 位匹配。
pub fn is_local_ip(ip: IpAddr, cidrs: &[String]) -> bool {
    // 显示 CIDR 列表优先
    for cidr_str in cidrs {
        if let Ok(network) = cidr_str.parse::<ipnetwork::IpNetwork>() {
            if network.contains(ip) {
                return true;
            }
        }
    }

    // 明确配置了空列表时不做自动检测（用户意图是全部走 CDN）
    // 但用户可能只是想用默认行为。这里约定：只要 vec 非空就只检查 vec，
    // 空 vec 才回退到自动检测。
    // 由于 Rule.local_cidrs 有 #[serde(default)]，未配置时为空 Vec。

    // 回退：/24 自动检测
    if cidrs.is_empty() {
        return is_same_subnet_24(ip);
    }

    false
}

/// 回退检测：/24 子网匹配。
///
/// 遍历本机非 loopback IPv4 地址，比较目标 IP 的前 24 位是否匹配。
/// 当前在 Windows 上返回 false（所有请求走 CDN），待步骤 15 实现。
fn is_same_subnet_24(ip: IpAddr) -> bool {
    #[cfg(windows)]
    {
        // Windows 接口枚举待实现（步骤 15），暂时返回 false
        let _ = ip;
        return false;
    }

    #[cfg(not(windows))]
    {
        let target_prefix = match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                [octets[0], octets[1], octets[2]]
            }
            IpAddr::V6(_) => return false,
        };
        get_local_ipv4_prefixes().iter().any(|prefix| *prefix == target_prefix)
    }
}

/// 获取本机所有非 loopback IPv4 地址的前 24 位前缀。
fn get_local_ipv4_prefixes() -> Vec<[u8; 3]> {
    let mut prefixes = Vec::new();

    // 通过主机名解析获取本机 IPv4 地址（跨平台替代 nix::ifaddrs）
    if let Ok(hostname) = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")) {
        if let Ok(addrs) = (hostname + ":0").to_socket_addrs() {
            for addr in addrs {
                if let std::net::IpAddr::V4(ip) = addr.ip() {
                    if !ip.is_loopback() {
                        let octets = ip.octets();
                        prefixes.push([octets[0], octets[1], octets[2]]);
                    }
                }
            }
        }
    }

    prefixes
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_client_ip_cf() {
        let mut headers = HeaderMap::new();
        headers.insert("CF-Connecting-IP", "203.0.113.5".parse().unwrap());
        assert_eq!(
            parse_client_ip(&headers),
            Some("203.0.113.5".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn test_parse_client_ip_xff() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Forwarded-For",
            "203.0.113.5, 10.0.0.1, 192.168.1.1".parse().unwrap(),
        );
        assert_eq!(
            parse_client_ip(&headers),
            Some("203.0.113.5".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn test_parse_client_ip_x_real() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Real-IP", "10.0.0.5".parse().unwrap());
        assert_eq!(
            parse_client_ip(&headers),
            Some("10.0.0.5".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn test_parse_client_ip_empty() {
        let headers = HeaderMap::new();
        assert_eq!(parse_client_ip(&headers), None);
    }

    #[test]
    fn test_is_local_ip_cidr_match() {
        let cidrs = vec!["192.168.1.0/24".into()];
        assert!(is_local_ip("192.168.1.100".parse().unwrap(), &cidrs));
        assert!(!is_local_ip("10.0.0.1".parse().unwrap(), &cidrs));
    }

    #[test]
    fn test_is_local_ip_multiple_cidrs() {
        let cidrs = vec!["10.0.0.0/8".into(), "172.16.0.0/12".into()];
        assert!(is_local_ip("10.1.2.3".parse().unwrap(), &cidrs));
        assert!(is_local_ip("172.16.0.1".parse().unwrap(), &cidrs));
        assert!(!is_local_ip("8.8.8.8".parse().unwrap(), &cidrs));
    }
}
