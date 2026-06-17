//! # files.rs — GET /files/* handler
//!
//! CDN 感知的文件分发端点。
//! - 匹配 CDN 规则后，命中 CDN 模式且请求方非本地网络 → 302 跳转
//! - 命中 Direct 模式或本地网络 → 直接返回文件流
//! - 支持 ETag / If-None-Match 协商缓存（304 Not Modified）
//! - 支持 Last-Modified / If-Modified-Since 协商缓存

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use tokio::fs;
use tracing::warn;

use crate::cdn::rules;
use crate::cdn::utils;
use crate::config::AppState;
use crate::types::RuleMode;

// ---------------------------------------------------------------------------
// 错误响应
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn error_response(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(ErrorResponse { error: msg.into() })).into_response()
}

// ---------------------------------------------------------------------------
// handler
// ---------------------------------------------------------------------------

/// GET /files/*path
pub async fn files_handler(
    State(state): State<AppState>,
    req: Request,
) -> Response {
    // 提取请求路径
    let uri = req.uri().clone();
    let path = uri.path().to_string();

    // 提取真实客户端 IP
    let client_ip = utils::parse_client_ip(req.headers());

    // 读 CDN 规则
    let rules_guard = state.cdn_rules.read().await;

    // 路径匹配
    let matched = rules::match_path(&rules_guard, &path)
        .cloned(); // clone 后释放读锁
    drop(rules_guard); // 尽快释放读锁

    match matched {
        Some(rule) => {
            match rule.mode {
                RuleMode::Direct => {
                    // Direct 模式：直接返回本地文件
                    serve_local_file(
                        &state.config.data_dir,
                        &path,
                        req.headers(),
                        rule.max_age,
                    )
                    .await
                }
                RuleMode::Cdn => {
                    // CDN 模式：检查是否本地网络
                    let is_local = client_ip
                        .map(|ip| utils::is_local_ip(ip, &rule.local_cidrs))
                        .unwrap_or(true); // 无 IP 视为本地

                    if is_local {
                        serve_local_file(&state.config.data_dir, &path, req.headers(), rule.max_age).await
                    } else {
                        // 302 跳转到 CDN
                        cdn_redirect(rule.cdn_url.as_deref(), &path, rule.max_age)
                    }
                }
            }
        }
        None => {
            // 未匹配规则：404
            error_response(StatusCode::NOT_FOUND, "路径未匹配任何规则")
        }
    }
}

// ---------------------------------------------------------------------------
// 本地文件服务
// ---------------------------------------------------------------------------

/// 从本地磁盘读取文件并返回。
/// 支持 ETag 和 Last-Modified 协商缓存。
async fn serve_local_file(
    data_dir: &std::path::Path,
    req_path: &str,
    req_headers: &HeaderMap,
    max_age: u64,
) -> Response {
    // 构建文件路径
    let relative = req_path
        .strip_prefix("/files/")
        .unwrap_or(req_path.strip_prefix('/').unwrap_or(req_path));

    if relative.is_empty() {
        return error_response(StatusCode::NOT_FOUND, "路径为空");
    }
    // 防御性检查：拒绝路径遍历序列
    if relative.contains("..") {
        return error_response(StatusCode::NOT_FOUND, "非法路径");
    }

    // 路径安全性校验：join 后判断最终路径是否在允许的基目录内
    let base_dir = data_dir.join("files");
    let file_path = base_dir.join(relative);

    // 路径安全性校验：先打开文件，再从 fd 获取 metadata，避免 TOCTOU
    let (file, metadata) = match fs::File::open(&file_path).await {
        Ok(f) => {
            match f.metadata().await {
                Ok(m) => {
                    if m.is_dir() {
                        return error_response(StatusCode::NOT_FOUND, "路径是目录");
                    }
                    (f, m)
                }
                Err(e) => {
                    warn!("[files] 读取文件 metadata 失败: {file_path:?}: {e}");
                    return error_response(StatusCode::INTERNAL_SERVER_ERROR, "读取文件失败");
                }
            }
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                return error_response(StatusCode::NOT_FOUND, "文件不存在");
            }
            warn!("[files] 打开文件失败: {file_path:?}: {e}");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "打开文件失败");
        }
    };

    // 规范化路径并校验前缀，防止路径遍历
    let canonical = match file_path.canonicalize() {
        Ok(p) => p,
        Err(_) => return error_response(StatusCode::NOT_FOUND, "文件不存在"),
    };
    let base = match base_dir.canonicalize() {
        Ok(p) => p,
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "服务器错误"),
    };
    if !canonical.starts_with(&base) {
        drop(file);
        return error_response(StatusCode::NOT_FOUND, "文件不存在");
    }

    // ETag 计算
    let etag = match crate::cdn::rules::compute_etag(&metadata) {
        Ok(e) => e,
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "ETag 计算失败"),
    };

    // Last-Modified
    let last_modified = match metadata.modified() {
        Ok(time) => httpdate::fmt_http_date(time),
        Err(_) => String::new(),
    };

    // 304 协商缓存：If-None-Match 优先，其次 If-Modified-Since
    // 如果请求头中的 ETag（带引号）与当前文件匹配，返回 304。
    // trim_matches('"') 去掉请求头的引号后再比较 etag（hex 字符串无引号）。
    // 第二个条件兼容客户端未带引号的不规范实现。
    if let Some(if_none_match) = req_headers.get(header::IF_NONE_MATCH) {
        if let Ok(val) = if_none_match.to_str() {
            if val.trim_matches('"') == etag || val == &etag {
                return StatusCode::NOT_MODIFIED.into_response();
            }
        }
    }

    if !last_modified.is_empty() {
        if let Some(if_modified_since) = req_headers.get(header::IF_MODIFIED_SINCE) {
            if let Ok(val) = if_modified_since.to_str() {
                if let (Ok(client_time), Ok(server_time)) = (
                    httpdate::parse_http_date(val),
                    metadata.modified(),
                ) {
                    if client_time >= server_time {
                        return StatusCode::NOT_MODIFIED.into_response();
                    }
                }
            }
        }
    }

    // 流式读取文件，避免大文件 OOM
    let stream = tokio_util::io::ReaderStream::new(file);
    let body = axum::body::Body::from_stream(stream);
    let mut resp = Response::new(body);

    if let Some(content_type) = guess_mime_type(req_path) {
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_str(content_type).unwrap(),
        );
    }

    resp.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{}\"", etag)).unwrap(),
    );

    if !last_modified.is_empty() {
        resp.headers_mut().insert(
            header::LAST_MODIFIED,
            HeaderValue::from_str(&last_modified).unwrap(),
        );
    }

    // Cache-Control: Direct 模式用 no-cache，CDN 模式用 public
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_str(&if max_age == 0 {
            "no-cache".to_string()
        } else {
            format!("public, max-age={max_age}")
        })
        .unwrap(),
    );

    resp
}

// ---------------------------------------------------------------------------
// CDN 302 重定向
// ---------------------------------------------------------------------------

/// 返回 302 跳转到 CDN URL。
fn cdn_redirect(cdn_url: Option<&str>, path: &str, max_age: u64) -> Response {
    let Some(base) = cdn_url else {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "CDN URL 未配置");
    };

    // 去掉前导 /files/ 以拼接
    let relative = path
        .strip_prefix("/files/")
        .unwrap_or(path.strip_prefix('/').unwrap_or(path));

    let location = format!("{}/{}", base.trim_end_matches('/'), relative.trim_start_matches('/'));

    let mut resp = Response::new(axum::body::Body::empty());
    *resp.status_mut() = StatusCode::FOUND;

    resp.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&location).unwrap(),
    );

    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_str(&format!("public, max-age={}", max_age)).unwrap(),
    );

    resp
}

// ---------------------------------------------------------------------------
// 工具函数
// ---------------------------------------------------------------------------

/// 根据文件扩展名猜测 MIME 类型。
///
/// rsplit('.').next() 取最后一个 '.' 后的内容作为扩展名，
/// 因此 /a.tar.gz 只匹配 gz，/README（无扩展名）返回 None。
fn guess_mime_type(path: &str) -> Option<&'static str> {
    let ext = path.rsplit('.').next()?.to_lowercase();
    match ext.as_str() {
        "html" | "htm" => Some("text/html"),
        "css" => Some("text/css"),
        "js" => Some("application/javascript"),
        "json" => Some("application/json"),
        "png" => Some("image/png"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        "gif" => Some("image/gif"),
        "svg" => Some("image/svg+xml"),
        "ico" => Some("image/x-icon"),
        "mp4" => Some("video/mp4"),
        "webm" => Some("video/webm"),
        "mp3" => Some("audio/mpeg"),
        "pdf" => Some("application/pdf"),
        "zip" => Some("application/zip"),
        "gz" => Some("application/gzip"),
        "txt" => Some("text/plain"),
        "xml" => Some("application/xml"),
        "wasm" => Some("application/wasm"),
        _ => None,
    }
}
