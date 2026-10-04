//! One HTTP/1.1 exchange per KPS stream, under the strict KPS-HTTP/1 profile
//! (tor-js-gateway PROTOCOL.md §3; anon-rpc SPEC §4.2 for bundle fetches).
//!
//! hyper's HTTP/1 server drives each stream (`kps::Stream` is `AsyncRead +
//! AsyncWrite`). On top of hyper, where hyper is lenient or the profile is
//! stricter, this module enforces:
//! - HTTP/1.1 only (`505` otherwise);
//! - the header block cap (`431`; hyper's `max_buf_size` is a soft cap);
//! - no `Transfer-Encoding`, no repeated `Content-Length`, no `Upgrade` (`400`);
//! - `Host` present, origin-form target (`400`);
//! - unknown path `404`, known path with another method `405` + `Allow`,
//!   unknown method `501`;
//! - request bodies only on routes that take one, with `Content-Length`
//!   (`411` without it, `413` over the route cap);
//! - responses always carry an exact `Content-Length`, never chunked;
//! - keep-alive off: one exchange, then the stream is finished.
//!
//! hyper reads request bodies by `Content-Length`, so a client sending a body
//! must state its length; the length is checked against the bytes received.

use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderValue};
use http::{Method, Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use kps::ErrorCode;
use tracing::debug;

use crate::app::{App, Lookup};
use crate::bundles::{self, accepts_gzip, parse_bundle_path};
use crate::config::{Route, BUNDLE_PATH_PREFIX, METADATA_PATH};
use crate::metrics::{EncodingLabels, Metrics, RequestLabels, RouteLabels};
use crate::proxy::into_client_response;

/// Route label for requests that matched nothing.
const UNMATCHED: &str = "unmatched";
const METADATA: &str = "metadata";
const BUNDLE: &str = "bundle";

/// Methods recognised at all; anything else is `501`.
const KNOWN_METHODS: &[Method] = &[
    Method::GET,
    Method::HEAD,
    Method::POST,
    Method::PUT,
    Method::DELETE,
    Method::OPTIONS,
    Method::PATCH,
    Method::TRACE,
];

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
    let service = service_fn(move |req: Request<Incoming>| {
        let app = Arc::clone(&svc_app);
        async move { Ok::<_, Infallible>(handle_request(req, &app, client_ip).await) }
    });
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .keep_alive(false)
        .half_close(true)
        .auto_date_header(false)
        .max_buf_size(limits.max_header_bytes)
        .max_headers(limits.max_headers)
        .header_read_timeout(limits.header_read_timeout);
    let served = tokio::time::timeout(
        limits.stream_timeout,
        builder.serve_connection(TokioIo::new(&mut stream), service),
    )
    .await;
    let outcome = match served {
        Ok(Ok(())) => StreamOutcome::Completed,
        Ok(Err(e)) if e.is_timeout() => StreamOutcome::HeaderTimeout,
        Ok(Err(e)) if e.is_parse() || e.is_parse_too_large() || e.is_parse_status() => {
            StreamOutcome::ProtocolError
        }
        Ok(Err(e)) => {
            debug!(error = %e, "stream ended before the exchange completed");
            StreamOutcome::Io
        }
        Err(_) => StreamOutcome::StreamTimeout,
    };
    // hyper already sent FIN after a complete response; `close` also stops the
    // read half. Anything else is an abortive close, never a lenient recovery.
    let _ = match outcome {
        StreamOutcome::Completed => stream.close().await,
        StreamOutcome::HeaderTimeout | StreamOutcome::StreamTimeout => {
            stream.close_with_error(ErrorCode::Timeout).await
        }
        StreamOutcome::ProtocolError => stream.close_with_error(ErrorCode::ProtocolError).await,
        StreamOutcome::Io => stream.close_with_error(ErrorCode::Cancelled).await,
    };
    outcome
}

/// Profile checks, routing and dispatch for one request.
async fn handle_request(
    req: Request<Incoming>,
    app: &App,
    client_ip: IpAddr,
) -> Response<Full<Bytes>> {
    let started = Instant::now();
    let (label, response) = dispatch(req, app, client_ip).await;
    record(&app.metrics, &label, response.status(), started);
    debug!(
        route = %label,
        status = response.status().as_u16(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "exchange"
    );
    response
}

fn record(metrics: &Metrics, route: &str, status: StatusCode, started: Instant) {
    metrics
        .requests
        .get_or_create(&RequestLabels {
            route: route.to_string(),
            status: status.as_u16().to_string(),
        })
        .inc();
    metrics
        .request_duration
        .get_or_create(&RouteLabels {
            route: route.to_string(),
        })
        .observe(started.elapsed().as_secs_f64());
}

async fn dispatch(
    req: Request<Incoming>,
    app: &App,
    client_ip: IpAddr,
) -> (String, Response<Full<Bytes>>) {
    let unmatched = |res| (UNMATCHED.to_string(), res);
    if req.version() != Version::HTTP_11 {
        return unmatched(text(
            StatusCode::HTTP_VERSION_NOT_SUPPORTED,
            "only HTTP/1.1 is supported",
        ));
    }
    let cap = app.settings.limits.max_header_bytes;
    if header_block_size(&req) > cap {
        return unmatched(text(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            &format!("header block exceeds {cap} bytes"),
        ));
    }
    let headers = req.headers();
    if headers.contains_key(header::TRANSFER_ENCODING) {
        return unmatched(text(
            StatusCode::BAD_REQUEST,
            "Transfer-Encoding is not permitted",
        ));
    }
    if headers.get_all(header::CONTENT_LENGTH).iter().count() > 1 {
        return unmatched(text(
            StatusCode::BAD_REQUEST,
            "multiple Content-Length fields",
        ));
    }
    if headers.contains_key(header::UPGRADE) {
        return unmatched(text(
            StatusCode::BAD_REQUEST,
            "protocol upgrades are not permitted",
        ));
    }
    if req.method() == Method::CONNECT {
        return unmatched(text(
            StatusCode::NOT_IMPLEMENTED,
            "CONNECT is not supported",
        ));
    }
    if !KNOWN_METHODS.contains(req.method()) {
        return unmatched(text(StatusCode::NOT_IMPLEMENTED, "unknown method"));
    }
    if !headers.contains_key(header::HOST) {
        return unmatched(text(StatusCode::BAD_REQUEST, "missing Host header"));
    }
    if req.uri().scheme().is_some() || req.uri().authority().is_some() {
        return unmatched(text(
            StatusCode::BAD_REQUEST,
            "request target must be an absolute path",
        ));
    }
    let Ok(declared) = content_length(req.headers()) else {
        return unmatched(text(StatusCode::BAD_REQUEST, "invalid Content-Length"));
    };

    let path = req.uri().path().to_string();
    if path == METADATA_PATH {
        return (METADATA.to_string(), metadata(&req, app, declared));
    }
    if let (Some(rest), Some(_)) = (path.strip_prefix(BUNDLE_PATH_PREFIX), app.bundles.as_ref()) {
        return (BUNDLE.to_string(), bundle(&req, app, rest, declared));
    }
    match app.router.lookup(req.method(), &path) {
        Lookup::Found(route) => {
            let route = route.clone();
            let response = proxy(&route, req, app, client_ip, declared).await;
            (route.name, response)
        }
        Lookup::MethodNotAllowed(allow) => unmatched(method_not_allowed(&allow)),
        Lookup::NotFound => unmatched(text(StatusCode::NOT_FOUND, "not found")),
    }
}

fn metadata(req: &Request<Incoming>, app: &App, declared: Option<u64>) -> Response<Full<Bytes>> {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return method_not_allowed("GET, HEAD");
    }
    if declared.unwrap_or(0) > 0 {
        return text(
            StatusCode::BAD_REQUEST,
            "GET and HEAD requests take no body",
        );
    }
    with_type(
        StatusCode::OK,
        "application/json",
        app.metadata_json.clone(),
    )
}

fn bundle(
    req: &Request<Incoming>,
    app: &App,
    rest: &str,
    declared: Option<u64>,
) -> Response<Full<Bytes>> {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return method_not_allowed("GET, HEAD");
    }
    if declared.unwrap_or(0) > 0 {
        return text(
            StatusCode::BAD_REQUEST,
            "GET and HEAD requests take no body",
        );
    }
    let Some(store) = app.bundles.as_ref() else {
        return text(StatusCode::NOT_FOUND, "not found");
    };
    let Some(hash) = parse_bundle_path(rest) else {
        return text(StatusCode::NOT_FOUND, "not found");
    };
    let Some(found) = store.get(&hash) else {
        return text(StatusCode::NOT_FOUND, "not found");
    };
    let gzip = found.gzip.as_ref().filter(|_| accepts_gzip(req.headers()));
    let (body, encoding) = match gzip {
        Some(gz) => (gz.clone(), "gzip"),
        None => (found.identity.clone(), "identity"),
    };
    app.metrics
        .bundle_responses
        .get_or_create(&EncodingLabels {
            encoding: encoding.to_string(),
        })
        .inc();
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

async fn proxy(
    route: &Route,
    req: Request<Incoming>,
    app: &App,
    client_ip: IpAddr,
    declared: Option<u64>,
) -> Response<Full<Bytes>> {
    let (parts, incoming) = req.into_parts();
    let body = if route.max_body_bytes == 0 {
        if declared.unwrap_or(0) > 0 {
            return text(StatusCode::BAD_REQUEST, "this route takes no request body");
        }
        Bytes::new()
    } else {
        let Some(len) = declared else {
            return text(
                StatusCode::LENGTH_REQUIRED,
                "Content-Length is required for a request body",
            );
        };
        if len > route.max_body_bytes as u64 {
            return text(
                StatusCode::PAYLOAD_TOO_LARGE,
                &format!("request body exceeds {} bytes", route.max_body_bytes),
            );
        }
        match Limited::new(incoming, route.max_body_bytes).collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e)
                if e.downcast_ref::<http_body_util::LengthLimitError>()
                    .is_some() =>
            {
                return text(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    &format!("request body exceeds {} bytes", route.max_body_bytes),
                );
            }
            Err(_) => {
                return text(
                    StatusCode::BAD_REQUEST,
                    "request body ended before Content-Length bytes arrived",
                );
            }
        }
    };

    // Taken after the body is read, so slow clients cannot hold upstream slots.
    let Ok(_permit) = app.inflight.clone().try_acquire_owned() else {
        let mut res = text(
            StatusCode::SERVICE_UNAVAILABLE,
            "too many requests in flight; retry shortly",
        );
        res.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return res;
    };
    app.metrics.upstream_inflight.inc();
    let result = app.upstream.forward(route, &parts, body, client_ip).await;
    app.metrics.upstream_inflight.dec();
    match result {
        Ok(upstream) => into_client_response(upstream),
        Err(e) => {
            app.metrics
                .upstream_errors
                .get_or_create(&crate::metrics::UpstreamErrorLabels {
                    upstream: route.upstream.name.clone(),
                    kind: e.kind().to_string(),
                })
                .inc();
            tracing::warn!(route = %route.name, error = %e, "upstream exchange failed");
            let status = match e {
                crate::error::ProxyError::Timeout { .. } => StatusCode::GATEWAY_TIMEOUT,
                _ => StatusCode::BAD_GATEWAY,
            };
            let msg = match e {
                crate::error::ProxyError::Timeout { .. } => "upstream timed out",
                crate::error::ProxyError::ResponseTooLarge { .. } => {
                    "upstream response exceeds the relay limit"
                }
                _ => "upstream unavailable",
            };
            text(status, msg)
        }
    }
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

fn method_not_allowed(allow: &str) -> Response<Full<Bytes>> {
    let mut res = text(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
    if let Ok(v) = HeaderValue::from_str(allow) {
        res.headers_mut().insert(header::ALLOW, v);
    }
    res
}

fn with_type(status: StatusCode, content_type: &'static str, body: Bytes) -> Response<Full<Bytes>> {
    let mut res = Response::new(Full::new(body));
    *res.status_mut() = status;
    res.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    res
}

/// Short diagnostic body (KPS-HTTP/1 §3.5: never parsed for control flow).
fn text(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    with_type(
        status,
        "text/plain; charset=utf-8",
        Bytes::from(format!("{msg}\n")),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

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
