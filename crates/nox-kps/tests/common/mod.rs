//! Shared fixtures: a recording mock of the node's loopback HTTP services, an
//! in-process nox-kps, and a raw KPS-HTTP/1 client over the `kps` crate.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

use std::collections::HashMap;
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
use nox_kps::config::{RawConfig, MAX_REPLY_PAYLOAD_BYTES};
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

/// Per-path overrides for the mock's answers.
#[derive(Debug, Default)]
pub struct Behaviour {
    pub delay_ms: HashMap<String, u64>,
    pub body_bytes: HashMap<String, usize>,
    pub status: HashMap<String, u16>,
    /// Record request heads only (long soaks).
    pub skip_bodies: bool,
    /// Answer claims like a node holding a full-size reply for every ID
    /// (`MAX_REPLY_PAYLOAD_BYTES` of 255s, the longest JSON encoding).
    pub full_size_claims: bool,
    /// Answer claims like a v2 node holding nothing: a retaining claim with
    /// `wait_ms` waits that long, then `204`.
    pub claims_wait_then_empty: bool,
}

/// `x-nox-claim-wait-max-ms` the mock advertises on claim answers.
pub const MOCK_NODE_CLAIM_WAIT_MAX_MS: u64 = 30_000;

/// A mock of the node's ingress/topology HTTP services.
///
/// Default behaviour by path:
/// - `POST /api/v1/packets`: `202` with a packet id (like the node)
/// - `POST /api/v1/responses/claim`: `204` for an empty id list, else `200` JSON
/// - `GET /topology`: `200` JSON
/// - `GET /health`: `200 ok`
///
/// [`MockUpstream::set_delay`], [`MockUpstream::set_body_bytes`] and
/// [`MockUpstream::set_status`] change the answer for one path. Every
/// response also carries `set-cookie`, `x-internal` and `x-nox-version`,
/// which the proxy must not relay.
pub struct MockUpstream {
    pub addr: SocketAddr,
    pub requests: Arc<Mutex<Vec<Recorded>>>,
    pub behaviour: Arc<Mutex<Behaviour>>,
    task: tokio::task::JoinHandle<()>,
}

impl MockUpstream {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let behaviour = Arc::new(Mutex::new(Behaviour::default()));
        let recorded = Arc::clone(&requests);
        let shared = Arc::clone(&behaviour);
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let recorded = Arc::clone(&recorded);
                let shared = Arc::clone(&shared);
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let recorded = Arc::clone(&recorded);
                        let shared = Arc::clone(&shared);
                        async move { Ok::<_, Infallible>(mock_handle(req, recorded, shared).await) }
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
            behaviour,
            task,
        }
    }

    /// `host:port`, as `upstream_ingress` takes it.
    pub fn authority(&self) -> String {
        self.addr.to_string()
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

    pub fn count_path(&self, path: &str) -> usize {
        self.recorded()
            .iter()
            .filter(|r| r.path_and_query == path)
            .count()
    }

    pub fn set_delay(&self, path: &str, ms: u64) {
        self.behaviour
            .lock()
            .unwrap()
            .delay_ms
            .insert(path.to_string(), ms);
    }

    pub fn set_body_bytes(&self, path: &str, bytes: usize) {
        self.behaviour
            .lock()
            .unwrap()
            .body_bytes
            .insert(path.to_string(), bytes);
    }

    pub fn set_status(&self, path: &str, status: u16) {
        self.behaviour
            .lock()
            .unwrap()
            .status
            .insert(path.to_string(), status);
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
    behaviour: Arc<Mutex<Behaviour>>,
) -> Response<Full<Bytes>> {
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    let path = parts.uri.path().to_string();
    let (skip_bodies, full_size_claims, claims_wait) = {
        let b = behaviour.lock().unwrap();
        (b.skip_bodies, b.full_size_claims, b.claims_wait_then_empty)
    };
    recorded.lock().unwrap().push(Recorded {
        method: parts.method.to_string(),
        path_and_query: parts
            .uri
            .path_and_query()
            .map_or_else(String::new, ToString::to_string),
        headers: parts.headers.clone(),
        body: if skip_bodies {
            Bytes::new()
        } else {
            body.clone()
        },
    });
    let (delay, size, forced) = {
        let b = behaviour.lock().unwrap();
        (
            b.delay_ms.get(&path).copied().unwrap_or(0),
            b.body_bytes.get(&path).copied(),
            b.status.get(&path).copied(),
        )
    };
    if delay > 0 {
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
    let (status, ctype, out): (StatusCode, &str, Bytes) = match (
        parts.method.as_str(),
        path.as_str(),
    ) {
        ("POST", "/api/v1/packets") => (
            StatusCode::ACCEPTED,
            "text/plain; charset=utf-8",
            Bytes::from(format!("http-{:016x}", body.len())),
        ),
        ("POST", "/api/v1/responses/claim") => {
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            let ids = json["surb_ids"].as_array().cloned().unwrap_or_default();
            if claims_wait {
                if json["retain"] == true {
                    let wait = json["wait_ms"].as_u64().unwrap_or(0);
                    tokio::time::sleep(Duration::from_millis(wait)).await;
                }
                (StatusCode::NO_CONTENT, "application/json", Bytes::new())
            } else if ids.is_empty() {
                (StatusCode::NO_CONTENT, "application/json", Bytes::new())
            } else {
                let items: Vec<serde_json::Value> = ids
                        .iter()
                        .map(|id| {
                            if full_size_claims {
                                let id = format!("reply-0-{}", id.as_str().unwrap_or_default());
                                serde_json::json!({"id": id, "data": vec![255u8; MAX_REPLY_PAYLOAD_BYTES]})
                            } else {
                                serde_json::json!({"id": id, "data": [7, 7, 7]})
                            }
                        })
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
        _ => (
            StatusCode::NOT_FOUND,
            "text/plain",
            Bytes::from_static(b"mock: no such route"),
        ),
    };
    let out = size.map_or(out, |n| Bytes::from(vec![b'x'; n]));
    let status = forced
        .and_then(|s| StatusCode::from_u16(s).ok())
        .unwrap_or(status);
    let mut res = Response::new(Full::new(out));
    *res.status_mut() = status;
    let h = res.headers_mut();
    h.insert("content-type", ctype.parse().unwrap());
    h.insert("x-nox-version", "test-upstream".parse().unwrap());
    h.insert("set-cookie", "leak=1".parse().unwrap());
    h.insert("x-internal", "secret".parse().unwrap());
    if path == "/api/v1/responses/claim" {
        h.insert("x-nox-claim-version", "2".parse().unwrap());
        h.insert(
            "x-nox-claim-features",
            "max-replies, ack-ahead".parse().unwrap(),
        );
        h.insert(
            "x-nox-claim-wait-max-ms",
            MOCK_NODE_CLAIM_WAIT_MAX_MS.to_string().parse().unwrap(),
        );
    }
    res
}

/// An in-process nox-kps pointed at a mock upstream.
pub struct TestServer {
    pub server: RunningServer,
    pub upstream: MockUpstream,
    pub dir: tempfile::TempDir,
    pub key_file: PathBuf,
}

impl TestServer {
    /// Test defaults: loopback UDP and admin on ephemeral ports, an identity
    /// created in a temp dir, both upstreams on the mock, caches off, the
    /// bundle resolver off. `mutate` adjusts the rest.
    pub async fn start(mutate: impl FnOnce(&mut RawConfig)) -> Self {
        let upstream = MockUpstream::start().await;
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("identity").join("kps.key");
        nox_kps::identity::init(&key_file).unwrap();
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
        admin_get(self.server.admin_addr(), "/metrics").await
    }
}

/// One plain HTTP GET against the admin port; returns the raw response.
pub async fn admin_get(addr: SocketAddr, path: &str) -> String {
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tcp.write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut out = Vec::new();
    timeout(T, tcp.read_to_end(&mut out))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8_lossy(&out).into_owned()
}

/// Test config for an in-process server. `expected_certhash` is taken from
/// the key file when it exists.
pub fn base_config(upstream: &MockUpstream, key_file: &std::path::Path) -> RawConfig {
    let expected_certhash = nox_kps::identity::read_existing(key_file)
        .ok()
        .flatten()
        .map(|id| id.certhash)
        .unwrap_or_default();
    let mut raw = RawConfig {
        expected_certhash,
        listen: "127.0.0.1:0".to_string(),
        advertise: vec!["127.0.0.1".to_string()],
        allow_private_advertise: true,
        key_file: key_file.to_path_buf(),
        upstream_ingress: upstream.authority(),
        upstream_topology: upstream.authority(),
        keccak_dir: String::new(),
        admin_listen: "127.0.0.1:0".to_string(),
        log_level: "error".to_string(),
        summary_interval_secs: 0,
        ..RawConfig::default()
    };
    raw.limits.topology_cache_ms = 0;
    raw.limits.health_cache_ms = 0;
    raw.shutdown.grace_period_ms = 5_000;
    raw
}

/// A fixed-size Sphinx-sized packet.
pub fn packet(fill: u8) -> Vec<u8> {
    vec![fill; 32_768]
}

/// `POST /api/v1/packets` as the SDK sends it.
pub fn packet_request(certhash: &str, body: &[u8]) -> Vec<u8> {
    request(
        "POST",
        "/api/v1/packets",
        certhash,
        &[("Content-Type", "application/octet-stream")],
        body,
    )
}

/// `POST /api/v1/responses/claim` as the SDK sends it.
pub fn claim_request(certhash: &str, ids: &[&str]) -> Vec<u8> {
    let body = serde_json::json!({ "surb_ids": ids }).to_string();
    request(
        "POST",
        "/api/v1/responses/claim",
        certhash,
        &[("Content-Type", "application/json")],
        body.as_bytes(),
    )
}

/// A valid SURB ID.
pub const SURB_ID: &str = "00112233445566778899aabbccddeeff";

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
