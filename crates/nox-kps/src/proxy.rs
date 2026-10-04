//! Forwarding allowlisted exchanges to the node's loopback HTTP services.
//!
//! The upstream request is built from scratch: the route's fixed method and
//! path, the client's (already validated) body, `Host`, `Content-Type`,
//! `Content-Length`, and the client-IP header set from the KPS connection's
//! observed source address. Nothing else the client sent (forwarding headers,
//! hop-by-hop headers, query strings, cookies) reaches the node. The response
//! is buffered up to the route's cap and copied back with `Content-Type`,
//! `Cache-Control` and `Retry-After` only; nox-kps sets the framing itself.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode, Uri, Version};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use tokio::sync::Mutex;

use crate::config::Upstream;
use crate::error::ProxyError;

/// Response headers relayed from the node.
const RELAYED_RESPONSE_HEADERS: [HeaderName; 3] = [
    header::CONTENT_TYPE,
    header::CACHE_CONTROL,
    header::RETRY_AFTER,
];

/// Idle pooled connections to the loopback upstreams are dropped after this.
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Idle pooled connections kept per upstream.
const POOL_MAX_IDLE: usize = 32;

/// A pooled HTTP/1.1 client for the loopback upstreams.
#[derive(Debug, Clone)]
pub struct UpstreamClient {
    client: Client<HttpConnector, Full<Bytes>>,
    client_ip_header: HeaderName,
}

/// One upstream exchange to perform.
#[derive(Debug)]
pub struct UpstreamCall<'a> {
    /// Route label, for errors and logs.
    pub route: &'static str,
    pub upstream: &'a Upstream,
    pub method: Method,
    pub path: &'static str,
    pub content_type: Option<HeaderValue>,
    pub body: Bytes,
    /// `None` for nox-kps's own probes (no client to attribute).
    pub client_ip: Option<IpAddr>,
    pub timeout: Duration,
    pub max_response_bytes: usize,
}

/// The parts of an upstream response relayed to the client.
#[derive(Debug, Clone)]
pub struct UpstreamResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl UpstreamClient {
    #[must_use]
    pub fn new(connect_timeout: Duration, client_ip_header: HeaderName) -> Self {
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(connect_timeout));
        connector.set_nodelay(true);
        connector.enforce_http(true);
        let client = Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(POOL_IDLE_TIMEOUT)
            .pool_max_idle_per_host(POOL_MAX_IDLE)
            .build(connector);
        Self {
            client,
            client_ip_header,
        }
    }

    /// Sends one exchange, bounded by `call.timeout` (connect, request and the
    /// whole response body).
    pub async fn forward(&self, call: UpstreamCall<'_>) -> Result<UpstreamResponse, ProxyError> {
        let route = call.route;
        let upstream = call.upstream.name;
        let timeout = call.timeout;
        let limit = call.max_response_bytes;
        let req = build_upstream_request(&call, &self.client_ip_header)?;
        let started = Instant::now();
        let exchange = async {
            let res = self.client.request(req).await.map_err(|e| {
                if e.is_connect() {
                    ProxyError::Connect {
                        route,
                        upstream,
                        authority: call.upstream.authority.to_string(),
                        elapsed_ms: started.elapsed().as_millis(),
                        reason: error_chain(&e),
                    }
                } else {
                    ProxyError::Upstream {
                        route,
                        upstream,
                        elapsed_ms: started.elapsed().as_millis(),
                        reason: error_chain(&e),
                    }
                }
            })?;
            let (parts, incoming) = res.into_parts();
            let body = Limited::new(incoming, limit)
                .collect()
                .await
                .map_err(|e| {
                    if e.downcast_ref::<http_body_util::LengthLimitError>()
                        .is_some()
                    {
                        ProxyError::ResponseTooLarge {
                            route,
                            upstream,
                            limit,
                        }
                    } else {
                        ProxyError::Upstream {
                            route,
                            upstream,
                            elapsed_ms: started.elapsed().as_millis(),
                            reason: e.to_string(),
                        }
                    }
                })?
                .to_bytes();
            Ok(UpstreamResponse {
                status: parts.status,
                headers: filter_response_headers(&parts.headers),
                body,
            })
        };
        tokio::time::timeout(timeout, exchange)
            .await
            .map_err(|_| ProxyError::Timeout {
                route,
                upstream,
                timeout_ms: timeout.as_millis(),
            })?
    }
}

/// The request sent upstream.
pub fn build_upstream_request(
    call: &UpstreamCall<'_>,
    client_ip_header: &HeaderName,
) -> Result<Request<Full<Bytes>>, ProxyError> {
    let build_err = |reason: String| ProxyError::BuildRequest {
        route: call.route,
        upstream: call.upstream.name,
        reason,
    };
    let uri = Uri::builder()
        .scheme(http::uri::Scheme::HTTP)
        .authority(call.upstream.authority.clone())
        .path_and_query(call.path)
        .build()
        .map_err(|e| build_err(e.to_string()))?;
    let has_body = !call.body.is_empty();
    let mut req = Request::new(Full::new(call.body.clone()));
    *req.method_mut() = call.method.clone();
    *req.uri_mut() = uri;
    *req.version_mut() = Version::HTTP_11;
    let headers = req.headers_mut();
    headers.insert(header::HOST, call.upstream.host_header.clone());
    if let Some(ct) = &call.content_type {
        headers.insert(header::CONTENT_TYPE, ct.clone());
    }
    if has_body || call.method == Method::POST {
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(call.body.len()));
    }
    if let Some(ip) = call.client_ip {
        let value = HeaderValue::from_str(&ip.to_canonical().to_string())
            .map_err(|e| build_err(e.to_string()))?;
        headers.insert(client_ip_header.clone(), value);
    }
    Ok(req)
}

/// Upstream headers relayed to the client.
#[must_use]
pub fn filter_response_headers(upstream: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for name in &RELAYED_RESPONSE_HEADERS {
        if let Some(value) = upstream.get(name) {
            out.insert(name.clone(), value.clone());
        }
    }
    out
}

/// Builds the client-facing response from an upstream answer.
#[must_use]
pub fn into_client_response(upstream: UpstreamResponse) -> Response<Full<Bytes>> {
    let mut res = Response::new(Full::new(upstream.body));
    *res.status_mut() = upstream.status;
    *res.headers_mut() = upstream.headers;
    res
}

/// A short-lived shared response (topology, health): one upstream exchange
/// answers every client for `ttl`, and concurrent misses wait for that one
/// exchange instead of each reaching the node.
#[derive(Debug)]
pub struct SharedResponse {
    ttl: Duration,
    slot: Mutex<Option<(Instant, UpstreamResponse)>>,
}

impl SharedResponse {
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            slot: Mutex::new(None),
        }
    }

    /// The cached response while fresh; otherwise runs `fetch` (once, for all
    /// concurrent callers) and caches its result. Returns whether it was a
    /// cache hit.
    pub async fn get_or_fetch<F>(&self, fetch: F) -> (UpstreamResponse, bool)
    where
        F: std::future::Future<Output = UpstreamResponse>,
    {
        if self.ttl.is_zero() {
            return (fetch.await, false);
        }
        let mut slot = self.slot.lock().await;
        if let Some((at, res)) = slot.as_ref() {
            if at.elapsed() < self.ttl {
                return (res.clone(), true);
            }
        }
        let res = fetch.await;
        *slot = Some((Instant::now(), res.clone()));
        (res, false)
    }
}

fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut msg = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        msg.push_str(": ");
        msg.push_str(&s.to_string());
        source = s.source();
    }
    msg
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]

    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::config::RawConfig;

    fn ingress() -> Upstream {
        let raw = RawConfig {
            advertise: vec!["203.0.113.5".into()],
            ..RawConfig::default()
        };
        raw.validate().unwrap().upstream_ingress
    }

    fn call<'a>(upstream: &'a Upstream, ip: &str) -> UpstreamCall<'a> {
        UpstreamCall {
            route: "packets",
            upstream,
            method: Method::POST,
            path: "/api/v1/packets",
            content_type: Some(HeaderValue::from_static("application/octet-stream")),
            body: Bytes::from_static(b"body"),
            client_ip: Some(ip.parse().unwrap()),
            timeout: Duration::from_secs(1),
            max_response_bytes: 1024,
        }
    }

    #[test]
    fn builds_the_request_from_scratch() {
        let upstream = ingress();
        let req = build_upstream_request(
            &call(&upstream, "203.0.113.9"),
            &HeaderName::from_static("x-real-ip"),
        )
        .unwrap();
        assert_eq!(req.method(), Method::POST);
        assert_eq!(
            req.uri().to_string(),
            "http://127.0.0.1:15002/api/v1/packets"
        );
        let h = req.headers();
        let names: Vec<&str> = h.keys().map(HeaderName::as_str).collect();
        assert_eq!(
            names,
            ["host", "content-type", "content-length", "x-real-ip"]
        );
        assert_eq!(h["host"], "127.0.0.1:15002");
        assert_eq!(h["content-length"], "4");
        assert_eq!(h["x-real-ip"], "203.0.113.9");
    }

    #[test]
    fn client_ip_is_canonical_and_ipv6_is_unbracketed() {
        let upstream = ingress();
        let header = HeaderName::from_static("x-real-ip");
        let req = build_upstream_request(&call(&upstream, "::ffff:198.51.100.4"), &header).unwrap();
        assert_eq!(req.headers()["x-real-ip"], "198.51.100.4");
        let req = build_upstream_request(&call(&upstream, "2001:db8::9"), &header).unwrap();
        assert_eq!(req.headers()["x-real-ip"], "2001:db8::9");
        let mut probe = call(&upstream, "1.1.1.1");
        probe.client_ip = None;
        probe.method = Method::GET;
        probe.body = Bytes::new();
        probe.content_type = None;
        let req = build_upstream_request(&probe, &header).unwrap();
        assert!(req.headers().get("x-real-ip").is_none());
        assert!(req.headers().get("content-length").is_none());
    }

    #[test]
    fn response_headers_are_allowlisted() {
        let mut upstream = HeaderMap::new();
        upstream.insert("content-type", HeaderValue::from_static("application/json"));
        upstream.insert("x-nox-version", HeaderValue::from_static("0.4.0-rc.4"));
        upstream.insert("retry-after", HeaderValue::from_static("1"));
        upstream.insert("set-cookie", HeaderValue::from_static("s=1"));
        upstream.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        upstream.insert("content-length", HeaderValue::from_static("99"));
        upstream.insert("access-control-allow-origin", HeaderValue::from_static("*"));
        let out = filter_response_headers(&upstream);
        let mut names: Vec<&str> = out.keys().map(HeaderName::as_str).collect();
        names.sort_unstable();
        assert_eq!(names, ["content-type", "retry-after"]);
    }

    #[tokio::test]
    async fn shared_responses_fetch_once_per_ttl() {
        let cache = std::sync::Arc::new(SharedResponse::new(Duration::from_millis(200)));
        let fetches = std::sync::Arc::new(AtomicUsize::new(0));
        let fetch = |fetches: std::sync::Arc<AtomicUsize>| async move {
            fetches.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(20)).await;
            UpstreamResponse {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body: Bytes::from_static(b"topology"),
            }
        };
        let mut tasks = Vec::new();
        for _ in 0..10 {
            let cache = std::sync::Arc::clone(&cache);
            let fetches = std::sync::Arc::clone(&fetches);
            tasks.push(tokio::spawn(async move {
                cache.get_or_fetch(fetch(fetches)).await.0.body
            }));
        }
        for t in tasks {
            assert_eq!(t.await.unwrap(), "topology");
        }
        assert_eq!(
            fetches.load(Ordering::SeqCst),
            1,
            "concurrent misses share one fetch"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
        let (_, hit) = cache
            .get_or_fetch(fetch(std::sync::Arc::clone(&fetches)))
            .await;
        assert!(!hit);
        assert_eq!(fetches.load(Ordering::SeqCst), 2, "refetched after the ttl");
        let uncached = SharedResponse::new(Duration::ZERO);
        uncached
            .get_or_fetch(fetch(std::sync::Arc::clone(&fetches)))
            .await;
        uncached
            .get_or_fetch(fetch(std::sync::Arc::clone(&fetches)))
            .await;
        assert_eq!(fetches.load(Ordering::SeqCst), 4, "a zero ttl never caches");
    }
}
