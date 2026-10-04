//! One HTTP/1.1 exchange per KPS stream, under the `nox-kps-http/1` profile
//! (PROTOCOL.md; the tor-js KPS-HTTP/1 profile with one tightening: request
//! bodies are delimited by `Content-Length`).
//!
//! hyper's HTTP/1 server drives each stream (`kps::Stream` is `AsyncRead +
//! AsyncWrite`). On top of hyper, where hyper is lenient or the profile is
//! stricter, this module enforces:
//! - HTTP/1.1 only (`505`);
//! - the header block cap (`431`; hyper's `max_buf_size` is a soft cap);
//! - no `Transfer-Encoding`, no repeated `Content-Length`, no `Upgrade`, no
//!   `Expect` (`400`, before any body byte is read);
//! - `Host` present, origin-form target (`400`);
//! - the fixed route allowlist: unknown path `404`, known path with another
//!   method `405` + `Allow`, unknown method `501`;
//! - per-route request rules: exact packet size, media types, claim body
//!   shape, no body on GET (`400`/`411`/`413`/`415`);
//! - per-IP rate limits (`429` + `Retry-After`);
//! - responses always carry an exact `Content-Length`, never chunked;
//! - keep-alive off: one exchange, then the stream is finished.

use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderValue};
use http::{Method, Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Body as _;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use kps::ErrorCode;
use tokio::sync::OwnedSemaphorePermit;
use tracing::{debug, warn};

use crate::app::App;
use crate::bundles::{self, accepts_gzip, parse_bundle_path};
use crate::config::{SPHINX_PACKET_BYTES, SURB_ID_HEX_LEN};
use crate::error::ProxyError;
use crate::limits::RateLimited;
use crate::metrics::{ResultLabels, RouteLabels, StreamLabels, UpstreamErrorLabels};
use crate::proxy::{into_client_response, UpstreamCall, UpstreamResponse};
use crate::routes::{lookup, Lookup, Route, BUNDLE_PATH_PREFIX, KNOWN_METHODS};

/// Route label for requests that matched nothing.
const UNMATCHED: &str = "unmatched";

/// The exchange is abandoned: the stream is reset without a response (the
/// profile's answer to a body that does not match its `Content-Length`).
#[derive(Debug, thiserror::Error)]
#[error("exchange abandoned: {0}")]
pub struct Abandon(&'static str);

/// A permit held until the stream is finished (bundle responses).
type HeldPermit = Arc<Mutex<Option<OwnedSemaphorePermit>>>;

/// How a stream ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamOutcome {
    /// A response was written and the stream finished cleanly.
    Completed,
    /// No complete request head within `limits.header_read_timeout_ms`.
    HeaderTimeout,
    /// The exchange exceeded `limits.stream_timeout_ms`.
    StreamTimeout,
    /// Malformed or forbidden HTTP that hyper refused before routing.
    ProtocolError,
    /// nox-kps reset the exchange without a response (body length mismatch).
    Abandoned,
    /// The peer reset or the transport failed mid-exchange.
    Io,
}

impl StreamOutcome {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::HeaderTimeout => "header_timeout",
            Self::StreamTimeout => "stream_timeout",
            Self::ProtocolError => "protocol_error",
            Self::Abandoned => "abandoned",
            Self::Io => "io",
        }
    }
}

/// Serves one exchange on `stream` and finishes or resets the stream.
pub async fn serve_stream(
    mut stream: Box<dyn kps::Stream>,
    app: Arc<App>,
    client_ip: IpAddr,
) -> StreamOutcome {
    let limits = &app.settings.limits;
    let svc_app = Arc::clone(&app);
    let held: HeldPermit = Arc::new(Mutex::new(None));
    let svc_held = Arc::clone(&held);
    let service = service_fn(move |req: Request<Incoming>| {
        let app = Arc::clone(&svc_app);
        let held = Arc::clone(&svc_held);
        async move { handle_request(req, &app, client_ip, &held).await }
    });
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .keep_alive(false)
        .half_close(true)
        .auto_date_header(false)
        .max_buf_size(limits.header_max_bytes)
        .max_headers(limits.max_headers)
        .header_read_timeout(limits.header_read_timeout);
    let deadline = tokio::time::Instant::now() + limits.stream_timeout;
    let served = tokio::time::timeout_at(
        deadline,
        builder.serve_connection(TokioIo::new(&mut stream), service),
    )
    .await;
    let mut outcome = match served {
        Ok(Ok(())) => StreamOutcome::Completed,
        Ok(Err(e)) if e.is_timeout() => StreamOutcome::HeaderTimeout,
        Ok(Err(e)) if e.is_user() => StreamOutcome::Abandoned,
        Ok(Err(e)) if e.is_parse() || e.is_parse_too_large() || e.is_parse_status() => {
            StreamOutcome::ProtocolError
        }
        Ok(Err(e)) => {
            debug!(error = %e, "stream ended before the exchange completed");
            StreamOutcome::Io
        }
        Err(_) => StreamOutcome::StreamTimeout,
    };
    // hyper has handed the whole response to the stream; `close` queues the
    // FIN behind it, which waits while a slow client drains the response, so
    // it keeps the rest of the stream deadline (at least `close_timeout_ms`).
    // A transport that does not move data within that is treated as a stream
    // timeout. Every other end is an abortive close, never a lenient recovery,
    // bounded by `close_timeout_ms` so a stalled transport cannot hold the task.
    if outcome == StreamOutcome::Completed {
        let finish_by = deadline.max(tokio::time::Instant::now() + limits.close_timeout);
        if tokio::time::timeout_at(finish_by, stream.close())
            .await
            .is_err()
        {
            outcome = StreamOutcome::StreamTimeout;
        }
    }
    let code = match outcome {
        StreamOutcome::Completed => None,
        StreamOutcome::HeaderTimeout | StreamOutcome::StreamTimeout => Some(ErrorCode::Timeout),
        StreamOutcome::ProtocolError | StreamOutcome::Abandoned => Some(ErrorCode::ProtocolError),
        StreamOutcome::Io => Some(ErrorCode::Cancelled),
    };
    if let Some(code) = code {
        let _ = tokio::time::timeout(limits.close_timeout, stream.close_with_error(code)).await;
    }
    // A bundle-stream slot is released only once the response is written.
    drop(held.lock().unwrap_or_else(PoisonError::into_inner).take());
    outcome
}

/// Profile checks, routing and dispatch for one request.
async fn handle_request(
    req: Request<Incoming>,
    app: &App,
    client_ip: IpAddr,
    held: &HeldPermit,
) -> Result<Response<Full<Bytes>>, Abandon> {
    let started = Instant::now();
    let (label, response) = match dispatch(req, app, client_ip, held).await {
        Ok(answer) => answer,
        Err(abandon) => {
            debug!(reason = abandon.0, "exchange abandoned");
            return Err(abandon);
        }
    };
    let status = response.status();
    app.metrics
        .streams
        .get_or_create(&StreamLabels {
            route: label,
            status: status.as_u16(),
        })
        .inc();
    app.metrics
        .request_duration
        .get_or_create(&RouteLabels { route: label })
        .observe(started.elapsed().as_secs_f64());
    app.metrics.add_bytes(
        label,
        "out",
        response.body().size_hint().exact().unwrap_or(0) as usize,
    );
    debug!(
        route = label,
        status = status.as_u16(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "exchange"
    );
    Ok(response)
}

/// A refusal under the profile: counted by kind, answered with a short text.
fn violation(
    app: &App,
    kind: &'static str,
    status: StatusCode,
    msg: &str,
) -> Response<Full<Bytes>> {
    app.metrics.violation(kind);
    text(status, msg)
}

async fn dispatch(
    req: Request<Incoming>,
    app: &App,
    client_ip: IpAddr,
    held: &HeldPermit,
) -> Result<(&'static str, Response<Full<Bytes>>), Abandon> {
    let refuse = |kind, status, msg: &str| Ok((UNMATCHED, violation(app, kind, status, msg)));
    if req.version() != Version::HTTP_11 {
        return refuse(
            "http_version",
            StatusCode::HTTP_VERSION_NOT_SUPPORTED,
            "only HTTP/1.1 is supported",
        );
    }
    let cap = app.settings.limits.header_max_bytes;
    if header_block_size(&req) > cap {
        return refuse(
            "header_too_large",
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            &format!("header block exceeds {cap} bytes"),
        );
    }
    let headers = req.headers();
    if headers.contains_key(header::TRANSFER_ENCODING) {
        return refuse(
            "transfer_encoding",
            StatusCode::BAD_REQUEST,
            "Transfer-Encoding is not permitted",
        );
    }
    if headers.get_all(header::CONTENT_LENGTH).iter().count() > 1 {
        return refuse(
            "content_length",
            StatusCode::BAD_REQUEST,
            "multiple Content-Length fields",
        );
    }
    if headers.contains_key(header::UPGRADE) {
        return refuse(
            "upgrade",
            StatusCode::BAD_REQUEST,
            "protocol upgrades are not permitted",
        );
    }
    if headers.contains_key(header::EXPECT) {
        return refuse("expect", StatusCode::BAD_REQUEST, "Expect is not permitted");
    }
    if req.method() == Method::CONNECT || !KNOWN_METHODS.contains(req.method()) {
        return refuse("method", StatusCode::NOT_IMPLEMENTED, "unknown method");
    }
    if !headers.contains_key(header::HOST) {
        return refuse("host", StatusCode::BAD_REQUEST, "missing Host header");
    }
    if req.uri().scheme().is_some() || req.uri().authority().is_some() {
        return refuse(
            "target",
            StatusCode::BAD_REQUEST,
            "request target must be an absolute path",
        );
    }
    let Ok(declared) = content_length(req.headers()) else {
        return refuse(
            "content_length",
            StatusCode::BAD_REQUEST,
            "invalid Content-Length",
        );
    };

    let bundles_enabled = app.bundles.is_some();
    let route = match lookup(req.method(), req.uri().path(), bundles_enabled) {
        Lookup::Found(route) => route,
        Lookup::MethodNotAllowed(allow) => return Ok((UNMATCHED, method_not_allowed(allow))),
        Lookup::NotFound => return Ok((UNMATCHED, text(StatusCode::NOT_FOUND, "not found"))),
    };
    let label = route.label();
    if route.method() == Method::GET && declared.unwrap_or(0) > 0 {
        return Ok((
            label,
            violation(
                app,
                "body_on_get",
                StatusCode::BAD_REQUEST,
                "GET and HEAD requests take no body",
            ),
        ));
    }
    if let Some(limiter) = app.rate.for_route(route) {
        if let Err(why) = limiter.check(client_ip) {
            app.metrics
                .rate_limited
                .get_or_create(&RouteLabels { route: label })
                .inc();
            let msg = match why {
                RateLimited::Exhausted => "rate limit exceeded; retry shortly",
                RateLimited::TableFull => "server busy; retry shortly",
            };
            return Ok((label, retry_later(StatusCode::TOO_MANY_REQUESTS, msg)));
        }
    }
    let response = match route {
        Route::Packets => packets(req, app, client_ip, declared).await?,
        Route::Claim => claim(req, app, client_ip, declared).await?,
        Route::Topology => topology(app).await,
        Route::Health => health(app).await,
        Route::Metadata => with_type(
            StatusCode::OK,
            "application/json",
            app.metadata_json.clone(),
        ),
        Route::Bundle => bundle(&req, app, held),
    };
    Ok((label, response))
}

/// `Content-Type` essence (`type/subtype`, lowercase, parameters dropped).
fn media_type(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::CONTENT_TYPE)?.to_str().ok()?;
    let essence = value.split(';').next().unwrap_or("").trim();
    Some(essence.to_ascii_lowercase())
}

/// Reads a request body of exactly `len` bytes (already checked against the
/// route's cap). A body that ends early is abandoned, never answered.
async fn read_body(
    incoming: Incoming,
    len: usize,
    app: &App,
    label: &'static str,
) -> Result<Bytes, Abandon> {
    let short = |app: &App| {
        app.metrics.violation("body_length");
        Abandon("request body ended before Content-Length bytes arrived")
    };
    match Limited::new(incoming, len).collect().await {
        Ok(collected) => {
            let body = collected.to_bytes();
            app.metrics.add_bytes(label, "in", body.len());
            if body.len() == len {
                Ok(body)
            } else {
                Err(short(app))
            }
        }
        Err(_) => Err(short(app)),
    }
}

async fn packets(
    req: Request<Incoming>,
    app: &App,
    client_ip: IpAddr,
    declared: Option<u64>,
) -> Result<Response<Full<Bytes>>, Abandon> {
    let label = Route::Packets.label();
    if media_type(req.headers()).as_deref() != Some("application/octet-stream") {
        return Ok(violation(
            app,
            "content_type",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "packets must be sent as application/octet-stream",
        ));
    }
    let Some(len) = declared else {
        return Ok(violation(
            app,
            "length_required",
            StatusCode::LENGTH_REQUIRED,
            "Content-Length is required",
        ));
    };
    if len != SPHINX_PACKET_BYTES as u64 {
        let status = if len > SPHINX_PACKET_BYTES as u64 {
            StatusCode::PAYLOAD_TOO_LARGE
        } else {
            StatusCode::BAD_REQUEST
        };
        return Ok(violation(
            app,
            "packet_size",
            status,
            &format!("a packet is exactly {SPHINX_PACKET_BYTES} bytes"),
        ));
    }
    let body = read_body(req.into_body(), SPHINX_PACKET_BYTES, app, label).await?;
    let l = &app.settings.limits;
    let forwarded = forward(
        app,
        UpstreamCall {
            route: label,
            upstream: &app.settings.upstream_ingress,
            method: Method::POST,
            path: "/api/v1/packets",
            content_type: Some(HeaderValue::from_static("application/octet-stream")),
            body,
            client_ip: Some(client_ip),
            timeout: l.upstream_packet_timeout,
            max_response_bytes: l.small_response_max_bytes,
        },
    )
    .await;
    Ok(match forwarded {
        Ok(res) | Err(res) => into_client_response(res),
    })
}

async fn claim(
    req: Request<Incoming>,
    app: &App,
    client_ip: IpAddr,
    declared: Option<u64>,
) -> Result<Response<Full<Bytes>>, Abandon> {
    let label = Route::Claim.label();
    let l = &app.settings.limits;
    if media_type(req.headers()).as_deref() != Some("application/json") {
        return Ok(violation(
            app,
            "content_type",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "claims must be sent as application/json",
        ));
    }
    let Some(len) = declared else {
        return Ok(violation(
            app,
            "length_required",
            StatusCode::LENGTH_REQUIRED,
            "Content-Length is required",
        ));
    };
    if len > l.claim_request_max_bytes as u64 {
        return Ok(violation(
            app,
            "claim_size",
            StatusCode::PAYLOAD_TOO_LARGE,
            &format!(
                "a claim body is at most {} bytes",
                l.claim_request_max_bytes
            ),
        ));
    }
    let body = read_body(req.into_body(), len as usize, app, label).await?;
    if let Err(msg) = check_claim_body(&body, l.claim_max_surb_ids) {
        return Ok(violation(app, "claim_body", StatusCode::BAD_REQUEST, &msg));
    }
    let forwarded = forward(
        app,
        UpstreamCall {
            route: label,
            upstream: &app.settings.upstream_ingress,
            method: Method::POST,
            path: "/api/v1/responses/claim",
            content_type: Some(HeaderValue::from_static("application/json")),
            body,
            client_ip: Some(client_ip),
            timeout: l.upstream_claim_timeout,
            max_response_bytes: l.claim_response_max_bytes,
        },
    )
    .await;
    Ok(match forwarded {
        Ok(res) | Err(res) => into_client_response(res),
    })
}

/// `{"surb_ids": [<32 hex>, ...]}` with at most `max_ids` entries. The node
/// re-checks every ID; this keeps malformed input off the loopback.
pub fn check_claim_body(body: &[u8], max_ids: usize) -> Result<(), String> {
    #[derive(serde::Deserialize)]
    struct Claim {
        surb_ids: Vec<String>,
    }
    let claim: Claim = serde_json::from_slice(body)
        .map_err(|e| format!("claim body must be {{\"surb_ids\":[...]}}: {e}"))?;
    if claim.surb_ids.len() > max_ids {
        return Err(format!(
            "a claim names at most {max_ids} SURB IDs (got {})",
            claim.surb_ids.len()
        ));
    }
    if let Some(i) = claim
        .surb_ids
        .iter()
        .position(|id| id.len() != SURB_ID_HEX_LEN || !id.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(format!(
            "surb_ids[{i}] must be exactly {SURB_ID_HEX_LEN} hex characters"
        ));
    }
    Ok(())
}

async fn topology(app: &App) -> Response<Full<Bytes>> {
    let label = Route::Topology.label();
    let l = &app.settings.limits;
    let (res, _) = app
        .topology
        .get_or_fetch(async {
            match forward(
                app,
                UpstreamCall {
                    route: label,
                    upstream: &app.settings.upstream_topology,
                    method: Method::GET,
                    path: "/topology",
                    content_type: None,
                    body: Bytes::new(),
                    client_ip: None,
                    timeout: l.upstream_topology_timeout,
                    max_response_bytes: l.topology_response_max_bytes,
                },
            )
            .await
            {
                Ok(res) | Err(res) => res,
            }
        })
        .await;
    into_client_response(res)
}

async fn health(app: &App) -> Response<Full<Bytes>> {
    let label = Route::Health.label();
    let l = &app.settings.limits;
    let (res, _) = app
        .health
        .get_or_fetch(async {
            let probe = forward(
                app,
                UpstreamCall {
                    route: label,
                    upstream: &app.settings.upstream_ingress,
                    method: Method::GET,
                    path: "/health",
                    content_type: None,
                    body: Bytes::new(),
                    client_ip: None,
                    timeout: l.upstream_health_timeout,
                    max_response_bytes: l.small_response_max_bytes,
                },
            )
            .await;
            let (status, body): (StatusCode, &'static [u8]) = match probe {
                Ok(res) if res.status == StatusCode::OK => (StatusCode::OK, br#"{"status":"ok"}"#),
                _ => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    br#"{"status":"degraded","upstream":"ingress-unreachable"}"#,
                ),
            };
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            UpstreamResponse {
                status,
                headers,
                body: Bytes::from_static(body),
            }
        })
        .await;
    into_client_response(res)
}

/// Runs one upstream exchange under the in-flight cap, recording errors.
/// `Err` carries the response to send instead (`502`, `503`, `504`).
async fn forward(app: &App, call: UpstreamCall<'_>) -> Result<UpstreamResponse, UpstreamResponse> {
    let Ok(_permit) = app.inflight.clone().try_acquire_owned() else {
        return Err(retry_later_parts(
            StatusCode::SERVICE_UNAVAILABLE,
            "too many requests in flight; retry shortly",
        ));
    };
    let route = call.route;
    app.metrics.upstream_inflight.inc();
    let result = app.upstream.forward(call).await;
    app.metrics.upstream_inflight.dec();
    result.map_err(|e| {
        app.metrics
            .upstream_errors
            .get_or_create(&UpstreamErrorLabels {
                route,
                kind: e.kind(),
            })
            .inc();
        warn!(error = %e, "upstream exchange failed");
        let (status, msg) = match e {
            ProxyError::Timeout { .. } => (StatusCode::GATEWAY_TIMEOUT, "upstream timed out"),
            ProxyError::ResponseTooLarge { .. } => (
                StatusCode::BAD_GATEWAY,
                "upstream response exceeds the relay limit",
            ),
            _ => (StatusCode::BAD_GATEWAY, "upstream unavailable"),
        };
        text_parts(status, msg)
    })
}

fn bundle(req: &Request<Incoming>, app: &App, held: &HeldPermit) -> Response<Full<Bytes>> {
    let miss = |app: &App| {
        app.metrics
            .bundle_requests
            .get_or_create(&ResultLabels { result: "miss" })
            .inc();
        text(StatusCode::NOT_FOUND, "not found")
    };
    let Some(store) = app.bundles.as_ref() else {
        return miss(app);
    };
    let rest = req
        .uri()
        .path()
        .strip_prefix(BUNDLE_PATH_PREFIX)
        .unwrap_or("");
    let Some(hash) = parse_bundle_path(rest) else {
        return miss(app);
    };
    let Some(found) = store.get(&hash) else {
        return miss(app);
    };
    let Ok(permit) = Arc::clone(&app.bundle_streams).try_acquire_owned() else {
        app.metrics
            .bundle_requests
            .get_or_create(&ResultLabels { result: "busy" })
            .inc();
        return retry_later(
            StatusCode::SERVICE_UNAVAILABLE,
            "too many bundle downloads in progress; retry shortly",
        );
    };
    *held.lock().unwrap_or_else(PoisonError::into_inner) = Some(permit);
    app.metrics
        .bundle_requests
        .get_or_create(&ResultLabels { result: "hit" })
        .inc();
    let gzip = found.gzip.as_ref().filter(|_| accepts_gzip(req.headers()));
    let body = gzip.map_or_else(|| found.identity.clone(), Clone::clone);
    let mut res = with_type(StatusCode::OK, bundles::BUNDLE_CONTENT_TYPE, body);
    let h = res.headers_mut();
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(bundles::IMMUTABLE_CACHE_CONTROL),
    );
    if found.gzip.is_some() {
        h.insert(header::VARY, HeaderValue::from_static("accept-encoding"));
    }
    if gzip.is_some() {
        h.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    }
    res
}

/// The declared `Content-Length`, if any. `Err` when it is not a number.
fn content_length(headers: &HeaderMap) -> Result<Option<u64>, ()> {
    match headers.get(header::CONTENT_LENGTH) {
        None => Ok(None),
        Some(v) => v
            .to_str()
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(Some)
            .ok_or(()),
    }
}

/// Reconstructed size of the request head (request line + header fields).
/// hyper's `max_buf_size` is a soft cap (a head arriving in one read can
/// exceed it), so the cap is also enforced here, where `431` can still be sent.
/// Omits the final blank line: it may read two bytes low, never high.
fn header_block_size<B>(req: &Request<B>) -> usize {
    let request_line =
        req.method().as_str().len() + req.uri().to_string().len() + " HTTP/1.1\r\n".len() + 1;
    req.headers().iter().fold(request_line, |n, (name, value)| {
        n + name.as_str().len() + value.len() + 4
    })
}

fn method_not_allowed(allow: &'static str) -> Response<Full<Bytes>> {
    let mut res = text(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
    res.headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static(allow));
    res
}

fn retry_later_parts(status: StatusCode, msg: &str) -> UpstreamResponse {
    let mut parts = text_parts(status, msg);
    parts
        .headers
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    parts
}

fn retry_later(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    into_client_response(retry_later_parts(status, msg))
}

fn with_type(status: StatusCode, content_type: &'static str, body: Bytes) -> Response<Full<Bytes>> {
    let mut res = Response::new(Full::new(body));
    *res.status_mut() = status;
    res.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    res
}

/// Short diagnostic body (KPS-HTTP/1 §3.5: never parsed for control flow).
fn text_parts(status: StatusCode, msg: &str) -> UpstreamResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    UpstreamResponse {
        status,
        headers,
        body: Bytes::from(format!("{msg}\n")),
    }
}

fn text(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    into_client_response(text_parts(status, msg))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]

    use super::*;

    fn req(method: &str, uri: &str, headers: &[(&str, &str)]) -> Request<()> {
        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap()
    }

    #[test]
    fn header_block_size_reconstructs_the_wire_bytes() {
        assert_eq!(header_block_size(&req("GET", "/", &[])), 16);
        assert_eq!(
            header_block_size(&req("GET", "/", &[("host", "x")])),
            16 + "host: x\r\n".len()
        );
        assert_eq!(
            header_block_size(&req("GET", "/topology?a=1", &[])),
            16 + "/topology?a=1".len() - 1
        );
    }

    #[test]
    fn header_block_size_never_overcounts() {
        let head = "GET /x HTTP/1.1\r\nhost: example.com\r\naccept: */*\r\n\r\n";
        let counted = header_block_size(&req(
            "GET",
            "/x",
            &[("host", "example.com"), ("accept", "*/*")],
        ));
        assert_eq!(counted, head.len() - 2);
    }

    #[test]
    fn header_block_size_accumulates_across_fields() {
        let headers: Vec<(String, String)> = (0..600)
            .map(|i| (format!("x-pad-{i:03}"), "v".repeat(24)))
            .collect();
        let borrowed: Vec<(&str, &str)> = headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        assert!(header_block_size(&req("GET", "/", &borrowed)) > 16 * 1024);
    }

    #[test]
    fn content_length_parsing() {
        let mut h = HeaderMap::new();
        assert_eq!(content_length(&h), Ok(None));
        h.insert(header::CONTENT_LENGTH, HeaderValue::from_static("32768"));
        assert_eq!(content_length(&h), Ok(Some(32768)));
        h.insert(header::CONTENT_LENGTH, HeaderValue::from_static("-1"));
        assert_eq!(content_length(&h), Err(()));
        h.insert(header::CONTENT_LENGTH, HeaderValue::from_static("ten"));
        assert_eq!(content_length(&h), Err(()));
    }

    #[test]
    fn claim_bodies_are_checked_for_shape() {
        let id = "00112233445566778899aabbccddeeff";
        assert!(check_claim_body(br#"{"surb_ids":[]}"#, 4).is_ok());
        assert!(check_claim_body(
            format!(r#"{{"surb_ids":["{id}","{}"]}}"#, id.to_uppercase()).as_bytes(),
            4
        )
        .is_ok());
        for (body, needle) in [
            (r#"{"surb_ids":["0011"]}"#.to_string(), "surb_ids[0]"),
            (
                format!(r#"{{"surb_ids":["{id}","zz112233445566778899aabbccddeeff"]}}"#),
                "surb_ids[1]",
            ),
            (r#"{"surb_ids":"x"}"#.to_string(), "claim body must be"),
            (r#"[1,2]"#.to_string(), "claim body must be"),
            ("not json".to_string(), "claim body must be"),
            (
                format!(r#"{{"surb_ids":["{id}","{id}","{id}"]}}"#),
                "at most 2",
            ),
        ] {
            let err = check_claim_body(body.as_bytes(), 2).unwrap_err();
            assert!(err.contains(needle), "{body}: {err}");
        }
    }

    #[test]
    fn media_types_ignore_parameters_and_case() {
        let mut h = HeaderMap::new();
        assert_eq!(media_type(&h), None);
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("Application/JSON; charset=utf-8"),
        );
        assert_eq!(media_type(&h).as_deref(), Some("application/json"));
    }

    #[test]
    fn error_bodies_are_short_plain_text() {
        let res = text(StatusCode::NOT_FOUND, "not found");
        assert_eq!(
            res.headers()[header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
        let res = method_not_allowed("GET, HEAD");
        assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(res.headers()[header::ALLOW], "GET, HEAD");
    }
}
