//! UPnP-IGD 端口预映射（借鉴 n2n：打洞前先敲路由器的门）。
//!
//! 全部是 best-effort：任何一步失败都只是少了几个候选，不影响后续打洞。
//! NAT-PMP 暂未实现（需要默认网关地址，跨平台获取要额外平台代码）。

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use anyhow::{bail, Context, Result};

const SSDP_ADDR: &str = "239.255.255.250:1900";
const SEARCH_TARGET: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";

/// 申请一个 UDP 端口映射，返回对外地址。
pub async fn map_udp_port(local_ip: Ipv4Addr, port: u16, timeout: Duration) -> Result<SocketAddr> {
    let location = tokio::task::spawn_blocking(move || discover(timeout))
        .await
        .context("SSDP 任务失败")??;

    // 只和局域网网关打交道：LOCATION 指向公网说明这不是可信的 IGD 响应
    let location_host = host_of(&location).context("LOCATION 缺少主机名")?;
    if !is_private_host(&location_host) {
        bail!("拒绝非内网的 LOCATION: {location}");
    }

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .no_proxy()
        .build()
        .context("构建 HTTP 客户端失败")?;

    let xml = client
        .get(&location)
        .send()
        .await
        .with_context(|| format!("拉取设备描述失败: {location}"))?
        .text()
        .await
        .context("读取设备描述失败")?;

    let (control_url, service) = parse_control(&xml, &location)?;
    if host_of(&control_url).as_deref() != Some(location_host.as_str()) {
        bail!("controlURL 主机与 LOCATION 不一致: {control_url}");
    }
    let external_ip = get_external_ip(&client, &control_url, &service).await?;
    add_mapping(&client, &control_url, &service, local_ip, port).await?;

    Ok(SocketAddr::new(external_ip.into(), port))
}

/// SSDP 发现：发 M-SEARCH，取第一个响应的 LOCATION。
fn discover(timeout: Duration) -> Result<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").context("绑定 SSDP socket 失败")?;
    socket
        .set_read_timeout(Some(timeout))
        .context("设置 SSDP 超时失败")?;

    let request = format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: {SSDP_ADDR}\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: {SEARCH_TARGET}\r\n\r\n"
    );
    socket
        .send_to(request.as_bytes(), SSDP_ADDR)
        .context("发送 M-SEARCH 失败")?;

    let mut buf = [0u8; 2048];
    let n = socket.recv(&mut buf).context("没有收到 SSDP 响应")?;
    let text = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();

    // 只接受 InternetGatewayDevice 的响应，避免把无关设备当网关
    if !text.contains("internetgatewaydevice") {
        bail!("SSDP 响应不是 IGD");
    }

    let original = String::from_utf8_lossy(&buf[..n]);
    for line in original.lines() {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim().eq_ignore_ascii_case("location") {
                return Ok(value.trim().to_string());
            }
        }
    }
    bail!("SSDP 响应中没有 LOCATION")
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let host_port = rest.split('/').next()?;
    Some(host_port.split(':').next()?.to_string())
}

fn is_private_host(host: &str) -> bool {
    if host == "localhost" {
        return true;
    }
    match host.parse::<Ipv4Addr>() {
        Ok(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        Err(_) => false,
    }
}

/// 从设备描述里挑出 WAN*Connection 服务的 controlURL。
fn parse_control(xml: &str, location: &str) -> Result<(String, String)> {
    for service in xml.split("<service>").skip(1) {
        let service = service.split("</service>").next().unwrap_or("");
        let service_type = tag(service, "serviceType").unwrap_or_default();
        if !service_type.contains("WANIPConnection") && !service_type.contains("WANPPPConnection") {
            continue;
        }
        let control = tag(service, "controlURL").context("服务缺少 controlURL")?;
        return Ok((join_url(location, &control), service_type));
    }
    bail!("设备描述里没有 WANIPConnection 服务")
}

fn join_url(base: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        return path.to_string();
    }
    let origin = match base.find("://") {
        Some(i) => match base[i + 3..].find('/') {
            Some(j) => &base[..i + 3 + j],
            None => base,
        },
        None => base,
    };
    format!(
        "{origin}{}",
        if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        }
    )
}

fn tag(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim().to_string())
}

async fn soap(
    client: &reqwest::Client,
    control_url: &str,
    service: &str,
    action: &str,
    body: &str,
) -> Result<String> {
    let envelope = format!(
        r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body><u:{action} xmlns:u="{service}">{body}</u:{action}></s:Body></s:Envelope>"#
    );

    let response = client
        .post(control_url)
        .header("Content-Type", "text/xml; charset=\"utf-8\"")
        .header("SOAPAction", format!("\"{service}#{action}\""))
        .body(envelope)
        .send()
        .await
        .with_context(|| format!("SOAP {action} 请求失败"))?;

    if !response.status().is_success() {
        bail!("SOAP {action} 返回 {}", response.status());
    }
    response.text().await.context("读取 SOAP 响应失败")
}

async fn get_external_ip(
    client: &reqwest::Client,
    control_url: &str,
    service: &str,
) -> Result<Ipv4Addr> {
    let body = soap(client, control_url, service, "GetExternalIPAddress", "").await?;
    let value = tag(&body, "NewExternalIPAddress").context("响应缺少 NewExternalIPAddress")?;
    value
        .parse()
        .with_context(|| format!("公网地址格式非法: {value}"))
}

async fn add_mapping(
    client: &reqwest::Client,
    control_url: &str,
    service: &str,
    local_ip: Ipv4Addr,
    port: u16,
) -> Result<()> {
    // 有些路由器不支持非零租约，失败后用 0（永久）再试一次
    if let Err(e) = add_mapping_with_lease(client, control_url, service, local_ip, port, 3600).await
    {
        tracing::debug!("[upnp] 非零租约失败，改用永久映射: {e}");
        add_mapping_with_lease(client, control_url, service, local_ip, port, 0).await?;
    }
    Ok(())
}

async fn add_mapping_with_lease(
    client: &reqwest::Client,
    control_url: &str,
    service: &str,
    local_ip: Ipv4Addr,
    port: u16,
    lease: u32,
) -> Result<()> {
    let body = format!(
        "<NewRemoteHost></NewRemoteHost>\
         <NewExternalPort>{port}</NewExternalPort>\
         <NewProtocol>UDP</NewProtocol>\
         <NewInternalPort>{port}</NewInternalPort>\
         <NewInternalClient>{local_ip}</NewInternalClient>\
         <NewEnabled>1</NewEnabled>\
         <NewPortMappingDescription>qp2p</NewPortMappingDescription>\
         <NewLeaseDuration>{lease}</NewLeaseDuration>"
    );
    soap(client, control_url, service, "AddPortMapping", &body).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_wan_service_control_url() {
        let xml = r#"
<root><device><serviceList>
<service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><controlURL>/l3</controlURL></service>
<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl/IPConn</controlURL></service>
</serviceList></device></root>"#;
        let (url, service) = parse_control(xml, "http://192.168.1.1:5000/rootDesc.xml").unwrap();
        assert_eq!(url, "http://192.168.1.1:5000/ctl/IPConn");
        assert!(service.contains("WANIPConnection"));
    }

    #[test]
    fn resolves_relative_control_url() {
        assert_eq!(
            join_url("http://10.0.0.1:49152/desc.xml", "ctl/IPConn"),
            "http://10.0.0.1:49152/ctl/IPConn"
        );
        assert_eq!(
            join_url("http://10.0.0.1:49152/desc.xml", "/ctl/IPConn"),
            "http://10.0.0.1:49152/ctl/IPConn"
        );
    }

    #[test]
    fn missing_service_is_an_error() {
        assert!(parse_control("<root></root>", "http://x/y").is_err());
    }
}
