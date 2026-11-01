//! Obrada HTTP zahtjeva (jedini HTTP parser API-ja u B1): dopuštene rute iz API_INVENTORY.md §2, ograničenja
//! veličine, a C++ servis dobiva samo strukturiranu poruku ({route, method, token, client_ip, …}).

use crate::backend::Backend;
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Body;
use hyper::header::{HeaderName, HeaderValue, AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, HOST, TRANSFER_ENCODING};
use hyper::{Method, Request, Response, StatusCode};
use serde_json::{json, Value};
use std::io;
use std::net::{IpAddr, SocketAddr};

pub const MAX_BODY: usize = 16 * 1024;

/// Ono što gateway treba od servisa (stvarni kanal ili lažni u testovima).
pub trait Upstream: Send + Sync + 'static {
    fn call(&self, msg: Value) -> impl std::future::Future<Output = io::Result<Value>> + Send;
}

impl Upstream for Backend {
    async fn call(&self, msg: Value) -> io::Result<Value> {
        Backend::call(self, msg).await
    }
}

/// Put → (ruta, slika). Samo točni putovi; sve ostalo 404 u gatewayu.
pub fn route(path: &str) -> Option<(&'static str, Option<&'static str>)> {
    Some(match path {
        "/api/v1/ping" => ("ping", None),
        "/api/v1/login" => ("login", None),
        "/api/v1/logout" => ("logout", None),
        "/api/v1/me" => ("me", None),
        "/api/v1/password" => ("password", None),
        "/api/v1/info" => ("info", None),
        "/api/v1/dashboard" => ("dashboard", None),
        "/api/v1/report" => ("report", None),
        "/api/v1/images/hero" => ("image", Some("hero")),
        "/api/v1/images/drawing" => ("image", Some("drawing")),
        "/api/v1/images/logo" => ("image", Some("logo")),
        _ => return None,
    })
}

fn bearer_token(req_auth: Option<&HeaderValue>) -> Option<String> {
    let v = req_auth?.to_str().ok()?;
    let token = v.strip_prefix("Bearer ")?.trim();
    let ok = !token.is_empty() && token.len() <= 512 && token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    ok.then(|| token.to_string())
}

fn query_int(query: Option<&str>, key: &str) -> i64 {
    query
        .unwrap_or("")
        .split('&')
        .filter_map(|p| p.split_once('='))
        .find(|(k, _)| *k == key)
        .and_then(|(_, v)| if v.len() <= 4 && !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) { v.parse().ok() } else { None })
        .unwrap_or(0) // 0 → servis odgovara 400 bad_month
}

fn client_ip(peer: IpAddr) -> IpAddr {
    match peer {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

pub fn error(status: StatusCode, code: &str, message: &str) -> Response<Full<Bytes>> {
    let body = json!({"error": code, "message": message}).to_string();
    let mut r = Response::new(Full::new(Bytes::from(body)));
    *r.status_mut() = status;
    let h = r.headers_mut();
    h.insert(CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
    secure_headers(h);
    r
}

fn secure_headers(h: &mut hyper::HeaderMap) {
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.entry(CACHE_CONTROL).or_insert(HeaderValue::from_static("no-store"));
}

/// Poruka za servis iz HTTP zahtjeva (bez tijela) ili gotov odgovor s greškom.
#[allow(clippy::result_large_err)]
pub fn to_ipc<B>(req: &Request<B>, peer: IpAddr) -> Result<Value, Response<Full<Bytes>>> {
    let Some((route, image)) = route(req.uri().path()) else {
        return Err(error(StatusCode::NOT_FOUND, "not_found", "Nije pronađeno."));
    };
    let method = match *req.method() {
        Method::GET => "GET",
        Method::HEAD => "HEAD",
        Method::POST => "POST",
        _ => return Err(error(StatusCode::METHOD_NOT_ALLOWED, "method", "Metoda nije dopuštena.")),
    };
    let h = req.headers();
    if h.contains_key(TRANSFER_ENCODING) {
        return Err(error(StatusCode::LENGTH_REQUIRED, "length_required", "Potrebna je duljina tijela (Content-Length)."));
    }
    if h.get_all(CONTENT_LENGTH).iter().count() > 1 || h.get_all(HOST).iter().count() > 1 {
        return Err(error(StatusCode::BAD_REQUEST, "bad_request", "Neispravan zahtjev."));
    }
    if let Some(len) = h.get(CONTENT_LENGTH) {
        match len.to_str().ok().and_then(|v| v.parse::<usize>().ok()) {
            Some(n) if n > MAX_BODY => return Err(error(StatusCode::PAYLOAD_TOO_LARGE, "too_large", "Zahtjev je prevelik.")),
            Some(_) => {}
            None => return Err(error(StatusCode::BAD_REQUEST, "bad_request", "Neispravan zahtjev.")),
        }
    }
    let ip = client_ip(peer);
    let mut msg = json!({"type": "request", "route": route, "method": method, "client_ip": ip.to_string()});
    if let Some(image) = image {
        msg["image"] = json!(image);
    }
    if route == "report" {
        msg["year"] = json!(query_int(req.uri().query(), "year"));
        msg["month"] = json!(query_int(req.uri().query(), "month"));
    }
    if let Some(token) = bearer_token(h.get(AUTHORIZATION)) {
        msg["token"] = json!(token);
    }
    // CF-Connecting-IP samo s loopbacka (cloudflared); servis ga ionako uzima samo za 127.0.0.1 (SMA-15)
    if ip.is_loopback() {
        if let Some(cf) = h.get("cf-connecting-ip").and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<IpAddr>().ok()) {
            msg["cf_ip"] = json!(cf.to_string());
        }
    }
    Ok(msg)
}

/// Odgovor servisa → HTTP odgovor (samo dopuštena zaglavlja).
pub fn from_ipc(resp: &Value) -> Response<Full<Bytes>> {
    if resp["ok"].as_bool() != Some(true) {
        return error(StatusCode::BAD_REQUEST, "bad_request", "Neispravan zahtjev.");
    }
    let status = resp["status"].as_u64().and_then(|s| u16::try_from(s).ok()).and_then(|s| StatusCode::from_u16(s).ok());
    let body = resp["body_b64"].as_str().and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok());
    let (Some(status), Some(body)) = (status, body) else {
        return error(StatusCode::BAD_GATEWAY, "bad_gateway", "Neispravan odgovor servisa.");
    };
    let mut r = Response::new(Full::new(Bytes::from(body)));
    *r.status_mut() = status;
    let h = r.headers_mut();
    if let Some(ct) = resp["content_type"].as_str().and_then(|c| HeaderValue::from_str(c).ok()) {
        h.insert(CONTENT_TYPE, ct);
    }
    if let Some(list) = resp["headers"].as_array() {
        for pair in list {
            let (Some(name), Some(value)) = (pair[0].as_str(), pair[1].as_str()) else { continue };
            let lower = name.to_ascii_lowercase();
            if !matches!(lower.as_str(), "www-authenticate" | "allow" | "cache-control" | "retry-after") {
                continue;
            }
            if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(lower.as_bytes()), HeaderValue::from_str(value)) {
                h.insert(n, v);
            }
        }
    }
    secure_headers(h);
    r
}

pub async fn handle<B, U>(req: Request<B>, peer: SocketAddr, upstream: &U) -> Response<Full<Bytes>>
where
    B: Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    U: Upstream,
{
    let mut msg = match to_ipc(&req, peer.ip()) {
        Ok(m) => m,
        Err(r) => return r,
    };
    if req.method() == Method::POST {
        let body = match Limited::new(req.into_body(), MAX_BODY).collect().await {
            Ok(c) => c.to_bytes(),
            Err(_) => return error(StatusCode::PAYLOAD_TOO_LARGE, "too_large", "Zahtjev je prevelik."),
        };
        match std::str::from_utf8(&body) {
            Ok(text) if !text.is_empty() => msg["body"] = json!(text),
            Ok(_) => {}
            Err(_) => return error(StatusCode::BAD_REQUEST, "bad_request", "Neispravan zahtjev."),
        }
    }
    match upstream.call(msg).await {
        Ok(resp) => from_ipc(&resp),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", "Servis Solarnog poslužitelja nije dostupan."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Fake(Mutex<Vec<Value>>);
    impl Upstream for Fake {
        async fn call(&self, msg: Value) -> io::Result<Value> {
            self.0.lock().unwrap().push(msg.clone());
            let body = base64::engine::general_purpose::STANDARD.encode(br#"{"ok":1}"#);
            Ok(json!({"ok": true, "status": 200, "content_type": "application/json; charset=utf-8", "body_b64": body,
                      "headers": [["WWW-Authenticate", "Bearer"], ["Set-Cookie", "x=1"]]}))
        }
    }

    fn req(method: &str, uri: &str) -> hyper::http::request::Builder {
        Request::builder().method(method).uri(uri)
    }

    fn peer(ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), 50000)
    }

    #[tokio::test]
    async fn routes_and_mapping() {
        let up = Fake(Mutex::new(Vec::new()));
        let r = req("GET", "/api/v1/report?year=2026&month=10")
            .header("authorization", "Bearer abc_DEF-1")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = handle(r, peer("192.168.1.5"), &up).await;
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers()["www-authenticate"], "Bearer");
        assert!(resp.headers().get("set-cookie").is_none());
        assert_eq!(resp.headers()["x-content-type-options"], "nosniff");
        let sent = up.0.lock().unwrap().pop().unwrap();
        assert_eq!(sent["route"], "report");
        assert_eq!(sent["year"], 2026);
        assert_eq!(sent["month"], 10);
        assert_eq!(sent["token"], "abc_DEF-1");
        assert_eq!(sent["client_ip"], "192.168.1.5");
        assert!(sent.get("cf_ip").is_none());
    }

    #[tokio::test]
    async fn unknown_paths_and_methods_never_reach_service() {
        let up = Fake(Mutex::new(Vec::new()));
        for (m, u, code) in [
            ("GET", "/api/v1/users", 404),
            ("GET", "/api/v1/ping/", 404),
            ("GET", "/web/index.html", 404),
            ("GET", "/api/dashboard", 404),
            ("GET", "/api/v1/images/../users.db", 404),
            ("GET", "/api/v1/images/%2e%2e", 404),
            ("DELETE", "/api/v1/me", 405),
            ("PUT", "/api/v1/login", 405),
        ] {
            let resp = handle(req(m, u).body(Full::new(Bytes::new())).unwrap(), peer("10.0.0.1"), &up).await;
            assert_eq!(resp.status().as_u16(), code, "{m} {u}");
        }
        assert!(up.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn smuggling_and_size_limits() {
        let up = Fake(Mutex::new(Vec::new()));
        let te = req("POST", "/api/v1/login").header("transfer-encoding", "chunked").body(Full::new(Bytes::new())).unwrap();
        assert_eq!(handle(te, peer("10.0.0.1"), &up).await.status(), 411);
        let dup = req("POST", "/api/v1/login")
            .header("content-length", "2")
            .header("content-length", "2")
            .body(Full::new(Bytes::from("{}")))
            .unwrap();
        assert_eq!(handle(dup, peer("10.0.0.1"), &up).await.status(), 400);
        let big = req("POST", "/api/v1/login").header("content-length", "16385").body(Full::new(Bytes::new())).unwrap();
        assert_eq!(handle(big, peer("10.0.0.1"), &up).await.status(), 413);
        // tijelo veće od 16 KB bez Content-Length
        let big2 = req("POST", "/api/v1/login").body(Full::new(Bytes::from(vec![b'a'; MAX_BODY + 1]))).unwrap();
        assert_eq!(handle(big2, peer("10.0.0.1"), &up).await.status(), 413);
        let bad_utf8 = req("POST", "/api/v1/login").body(Full::new(Bytes::from(vec![0xC3, 0x28]))).unwrap();
        assert_eq!(handle(bad_utf8, peer("10.0.0.1"), &up).await.status(), 400);
        assert!(up.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn token_cf_ip_and_body() {
        let up = Fake(Mutex::new(Vec::new()));
        let r = req("POST", "/api/v1/login")
            .header("authorization", "Bearer ima razmak")
            .header("cf-connecting-ip", "203.0.113.9")
            .body(Full::new(Bytes::from(r#"{"email":"a@b.hr"}"#)))
            .unwrap();
        handle(r, peer("127.0.0.1"), &up).await;
        let sent = up.0.lock().unwrap().pop().unwrap();
        assert!(sent.get("token").is_none());
        assert_eq!(sent["cf_ip"], "203.0.113.9");
        assert_eq!(sent["body"], r#"{"email":"a@b.hr"}"#);
        // iz mreže se CF-Connecting-IP ne prosljeđuje
        let r = req("GET", "/api/v1/ping").header("cf-connecting-ip", "203.0.113.9").body(Full::new(Bytes::new())).unwrap();
        handle(r, peer("::ffff:192.168.1.7"), &up).await;
        let sent = up.0.lock().unwrap().pop().unwrap();
        assert!(sent.get("cf_ip").is_none());
        assert_eq!(sent["client_ip"], "192.168.1.7");
        // izvještaj bez ispravnih parametara → 0 (servis vraća 400)
        let r = req("GET", "/api/v1/report?year=abc&month=99999").body(Full::new(Bytes::new())).unwrap();
        handle(r, peer("10.0.0.1"), &up).await;
        let sent = up.0.lock().unwrap().pop().unwrap();
        assert_eq!(sent["year"], 0);
        assert_eq!(sent["month"], 0);
    }

    #[test]
    fn bad_service_response_is_502() {
        assert_eq!(from_ipc(&json!({"ok": true, "status": 200, "body_b64": "%%%"})).status(), 502);
        assert_eq!(from_ipc(&json!({"ok": false})).status(), 400);
    }
}
