//! Shared fixtures: a recording mock of the node's loopback HTTP services, an
//! in-process nox-kps, and a raw KPS-HTTP/1 client over the `kps` crate.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use nox_kps::config::{RawConfig, RouteConfig};
use nox_kps::RunningServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

/// Generous bound for dials and exchanges on loopback.
pub const T: Duration = Duration::from_secs(20);

/// One request the mock upstream received.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    pub path_and_query: String,
    pub headers: HeaderMap,
    pub body: Bytes,
}

/// A mock of the node's ingress/topology HTTP services.
///
/// Behaviour by path:
/// - `POST /api/v1/packets`: `202` with a packet id (like the node)
/// - `POST /api/v1/responses/claim`: `204` for an empty id list, else `200` JSON
/// - `GET /topology`: `200` JSON
/// - `GET /health`: `200 ok`
/// - anything else: `200`, after `x-mock-delay-ms`, with `x-mock-response-bytes`
///   bytes of body (when the proxy forwards those headers)
///
/// Every response also carries `set-cookie` and `x-internal`, which the proxy
/// must not relay, and `x-nox-version`, which it must.
pub struct MockUpstream {
    pub addr: SocketAddr,
    pub requests: Arc<Mutex<Vec<Recorded>>>,
    task: tokio::task::JoinHandle<()>,
}

impl MockUpstream {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let recorded = Arc::clone(&recorded);
                        async move { Ok::<_, Infallible>(mock_handle(req, recorded).await) }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(tcp), svc)
                        .await;
                });
            }
        });
        Self {
            addr,
            requests,
            task,
        }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn recorded(&self) -> Vec<Recorded> {
        self.requests.lock().unwrap().clone()
    }

    pub fn last(&self) -> Recorded {
        self.recorded()
            .last()
            .cloned()
            .expect("upstream saw a request")
    }

    pub fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn mock_handle(
    req: Request<Incoming>,
    recorded: Arc<Mutex<Vec<Recorded>>>,
) -> Response<Full<Bytes>> {
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    let path = parts.uri.path().to_string();
    recorded.lock().unwrap().push(Recorded {
        method: parts.method.to_string(),
        path_and_query: parts
            .uri
            .path_and_query()
            .map_or_else(String::new, ToString::to_string),
        headers: parts.headers.clone(),
        body: body.clone(),
    });
    let header_num = |name: &str| -> u64 {
        parts
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    };
    let delay = header_num("x-mock-delay-ms");
    if delay > 0 {
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
    let (status, ctype, out): (StatusCode, &str, Bytes) =
        match (parts.method.as_str(), path.as_str()) {
            ("POST", "/api/v1/packets") => (
                StatusCode::ACCEPTED,
                "text/plain; charset=utf-8",
                Bytes::from(format!("http-{:016x}", body.len())),
            ),
            ("POST", "/api/v1/responses/claim") => {
                let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                let ids = json["surb_ids"].as_array().cloned().unwrap_or_default();
                if ids.is_empty() {
                    (StatusCode::NO_CONTENT, "application/json", Bytes::new())
                } else {
                    let size = header_num("x-mock-response-bytes") as usize;
                    let items: Vec<serde_json::Value> = ids
                        .iter()
                        .map(|id| serde_json::json!({"id": id, "data": vec![7u8; size.max(3)]}))
                        .collect();
                    (
                        StatusCode::OK,
                        "application/json",
                        Bytes::from(serde_json::to_vec(&items).unwrap()),
                    )
                }
            }
            ("GET", "/topology") => (
                StatusCode::OK,
                "application/json",
                Bytes::from_static(br#"{"nodes":[],"fingerprint":"0x00"}"#),
            ),
            ("GET", "/health") => (
                StatusCode::OK,
                "text/plain; charset=utf-8",
                Bytes::from_static(b"ok"),
            ),
            _ => {
                let size = header_num("x-mock-response-bytes") as usize;
                (
                    StatusCode::OK,
                    "application/octet-stream",
                    Bytes::from(vec![b'x'; size]),
                )
            }
        };
    let mut res = Response::new(Full::new(out));
    *res.status_mut() = status;
    let h = res.headers_mut();
    h.insert("content-type", ctype.parse().unwrap());
    h.insert("x-nox-version", "test-upstream".parse().unwrap());
    h.insert("set-cookie", "leak=1".parse().unwrap());
    h.insert("x-internal", "secret".parse().unwrap());
    res
}

/// A route config for tests.
pub fn route(name: &str, method: &str, path: &str, upstream: &str, max_body: usize) -> RouteConfig {
    RouteConfig {
        name: name.to_string(),
        method: method.to_string(),
        path: path.to_string(),
        upstream: upstream.to_string(),
        max_body_bytes: max_body,
    }
}

/// An in-process nox-kps pointed at a mock upstream.
pub struct TestServer {
    pub server: RunningServer,
    pub upstream: MockUpstream,
    pub dir: tempfile::TempDir,
    pub key_file: PathBuf,
}

impl TestServer {
    /// Test defaults: loopback UDP and metrics on ephemeral ports, a key in a
    /// temp dir, both upstreams on the mock. `mutate` adjusts the rest.
    pub async fn start(mutate: impl FnOnce(&mut RawConfig)) -> Self {
        let upstream = MockUpstream::start().await;
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("identity").join("kps.key");
        let mut raw = base_config(&upstream, &key_file);
        mutate(&mut raw);
        let settings = raw.validate().expect("test config validates");
        let server = nox_kps::start(settings).await.expect("server starts");
        Self {
            server,
            upstream,
            dir,
            key_file,
        }
    }

    pub fn addr(&self) -> String {
        self.server.local_address()
    }

    pub fn certhash(&self) -> String {
        self.server.certhash().to_string()
    }

    pub async fn stop(self) {
        self.server.shutdown();
        timeout(T, self.server.wait()).await.expect("server stops");
    }

    pub async fn metrics_text(&self) -> String {
        let addr = self.server.metrics_addr().expect("metrics enabled");
        let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        tcp.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut out = Vec::new();
        timeout(T, tcp.read_to_end(&mut out))
            .await
            .unwrap()
            .unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }
}

pub fn base_config(upstream: &MockUpstream, key_file: &std::path::Path) -> RawConfig {
    let mut raw = RawConfig::default();
    raw.kps.listen = "127.0.0.1:0".to_string();
    raw.kps.public_ips = vec!["127.0.0.1".to_string()];
    raw.kps.identity_key_file = key_file.to_path_buf();
    raw.upstreams.ingress = upstream.url();
    raw.upstreams.topology = upstream.url();
    raw.metrics.listen = "127.0.0.1:0".to_string();
    raw.log.filter = "error".to_string();
    raw.shutdown.grace_period_ms = 5_000;
    raw
}

/// KPS transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Quic,
    WebRtc,
}

impl Transport {
    pub fn name(self) -> &'static str {
        match self {
            Self::Quic => "quic",
            Self::WebRtc => "webrtc",
        }
    }
}

pub async fn dial(addr: &str, transport: Transport) -> Box<dyn kps::Conn> {
    let fut = async {
        match transport {
            Transport::Quic => kps::dial(addr).await,
            Transport::WebRtc => kps::dial_webrtc(addr).await,
        }
    };
    timeout(T, fut)
        .await
        .unwrap_or_else(|_| panic!("{} dial timed out", transport.name()))
        .unwrap_or_else(|e| panic!("{} dial failed: {e}", transport.name()))
}

/// A parsed KPS-HTTP/1 response.
#[derive(Debug)]
pub struct RawResponse {
    /// Minor HTTP version (1 for HTTP/1.1).
    pub version: u8,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl RawResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// Serialises a request. Nothing is added: tests choose Host and
/// Content-Length explicitly.
pub fn raw_request(method: &str, target: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("{method} {target} HTTP/1.1\r\n").into_bytes();
    for (n, v) in headers {
        out.extend_from_slice(format!("{n}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

/// A well-formed request: Host = certhash, Content-Length when there is a body.
pub fn request(
    method: &str,
    target: &str,
    certhash: &str,
    extra: &[(&str, &str)],
    body: &[u8],
) -> Vec<u8> {
    let len = body.len().to_string();
    let mut headers: Vec<(&str, &str)> = vec![("Host", certhash)];
    if !body.is_empty() {
        headers.push(("Content-Length", &len));
    }
    headers.extend_from_slice(extra);
    raw_request(method, target, &headers, body)
}

/// One exchange on a fresh stream: write the request, FIN, read to EOF.
/// `Err` when the stream is reset or the deadline passes.
pub async fn try_exchange(
    conn: &dyn kps::Conn,
    req: &[u8],
    deadline: Duration,
) -> Result<RawResponse, String> {
    let fut = async {
        let stream = conn
            .open_stream()
            .await
            .map_err(|e| format!("open_stream: {e}"))?;
        let (mut rd, mut wr) = tokio::io::split(stream);
        let (written, read) = tokio::join!(
            async {
                wr.write_all(req).await?;
                wr.shutdown().await
            },
            async {
                let mut out = Vec::new();
                rd.read_to_end(&mut out).await.map(|_| out)
            }
        );
        let bytes = read.map_err(|e| format!("read: {e}"))?;
        // A server may answer and close before reading the whole request.
        if bytes.is_empty() {
            written.map_err(|e| format!("write: {e}"))?;
            return Err("empty response (stream closed without a response)".to_string());
        }
        parse_response(&bytes, req.starts_with(b"HEAD "))
    };
    timeout(deadline, fut)
        .await
        .map_err(|_| format!("no response within {deadline:?}"))?
}

/// One exchange that must produce an HTTP/1.1 response.
pub async fn exchange(conn: &dyn kps::Conn, req: &[u8]) -> RawResponse {
    let res = try_exchange(conn, req, T).await.unwrap();
    assert_eq!(res.version, 1, "responses are HTTP/1.1");
    res
}

/// Strict parse: status line, headers, exact Content-Length when present
/// (a HEAD response states the length but carries no body), no
/// Transfer-Encoding.
pub fn parse_response(bytes: &[u8], head_request: bool) -> Result<RawResponse, String> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut res = httparse::Response::new(&mut headers);
    let head_len = match res.parse(bytes).map_err(|e| format!("parse: {e}"))? {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => return Err("partial response head".to_string()),
    };
    let version = res.version.ok_or("no version")?;
    let status = res.code.ok_or("no status")?;
    let headers: Vec<(String, String)> = res
        .headers
        .iter()
        .map(|h| {
            (
                h.name.to_ascii_lowercase(),
                String::from_utf8_lossy(h.value).into_owned(),
            )
        })
        .collect();
    if headers.iter().any(|(n, _)| n == "transfer-encoding") {
        return Err("response carries Transfer-Encoding".to_string());
    }
    let body = bytes[head_len..].to_vec();
    if let Some((_, cl)) = headers.iter().find(|(n, _)| n == "content-length") {
        let cl: usize = cl.parse().map_err(|_| "bad content-length")?;
        if head_request && !body.is_empty() {
            return Err("HEAD response carries a body".to_string());
        }
        if !head_request && cl != body.len() {
            return Err(format!("content-length {cl} but body {} bytes", body.len()));
        }
    }
    Ok(RawResponse {
        version,
        status,
        headers,
        body,
    })
}

/// Polls `cond` until it holds or `deadline` passes.
pub async fn eventually(deadline: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < deadline {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    cond()
}
