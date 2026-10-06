//! Per-client rate limiting and CORS policy for the public HTTP ports.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tracing::{debug, warn};

use super::claim::{CLAIM_VERSION_HEADER, CLAIM_WAIT_MAX_HEADER};
use crate::config::IngressConfig;
use crate::telemetry::metrics::MetricsService;

/// Number of checks between sweeps that drop idle client entries.
const SWEEP_INTERVAL_CHECKS: u64 = 4096;

/// IPv6 clients are limited per /64, the smallest prefix normally routed to one site.
const IPV6_CLIENT_PREFIX_SEGMENTS: usize = 4;

/// Token bucket per client IP for the HTTP ingress.
pub struct IngressRateLimiter {
    limiter: DefaultKeyedRateLimiter<IpAddr>,
    client_ip_header: Option<HeaderName>,
    checks: AtomicU64,
    metrics: MetricsService,
}

impl IngressRateLimiter {
    /// Returns `None` when the limit is disabled (`rate_limit_per_sec = 0`).
    #[must_use]
    pub fn from_config(config: &IngressConfig, metrics: MetricsService) -> Option<Arc<Self>> {
        let rate = NonZeroU32::new(config.rate_limit_per_sec)?;
        let burst = NonZeroU32::new(config.rate_limit_burst).unwrap_or(rate);
        let client_ip_header = if config.client_ip_header.is_empty() {
            None
        } else {
            match HeaderName::from_bytes(config.client_ip_header.as_bytes()) {
                Ok(name) => Some(name),
                Err(error) => {
                    warn!(
                        header = %config.client_ip_header,
                        error = %error,
                        "Ignoring invalid ingress.client_ip_header; loopback clients will not be limited"
                    );
                    None
                }
            }
        };
        Some(Arc::new(Self {
            limiter: RateLimiter::keyed(Quota::per_second(rate).allow_burst(burst)),
            client_ip_header,
            checks: AtomicU64::new(0),
            metrics,
        }))
    }

    /// The key a request is limited under, or `None` when it is not limited here.
    ///
    /// Direct connections are keyed by peer address. Connections from loopback come
    /// from a local reverse proxy: they are keyed by the configured client IP header,
    /// and are not limited when no header is configured or the header is missing.
    fn client_key(&self, peer: Option<SocketAddr>, headers: &HeaderMap) -> Option<IpAddr> {
        let peer_ip = canonical_ip(peer?.ip());
        if !peer_ip.is_loopback() {
            return Some(client_bucket(peer_ip));
        }
        let header = self.client_ip_header.as_ref()?;
        let forwarded = headers.get_all(header).iter().next_back()?.to_str().ok()?;
        let client = forwarded
            .rsplit(',')
            .next()?
            .trim()
            .parse::<IpAddr>()
            .ok()?;
        Some(client_bucket(canonical_ip(client)))
    }

    /// `true` when the request may proceed.
    fn admit(&self, key: IpAddr) -> bool {
        if self.checks.fetch_add(1, Ordering::Relaxed) % SWEEP_INTERVAL_CHECKS
            == SWEEP_INTERVAL_CHECKS - 1
        {
            self.limiter.retain_recent();
            self.limiter.shrink_to_fit();
        }
        self.limiter.check_key(&key).is_ok()
    }
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

fn client_bucket(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let mut segments = v6.segments();
            for segment in segments.iter_mut().skip(IPV6_CLIENT_PREFIX_SEGMENTS) {
                *segment = 0;
            }
            IpAddr::V6(Ipv6Addr::from(segments))
        }
    }
}

/// Middleware: answers 429 once a client IP exceeds its token bucket.
pub async fn rate_limit(
    State(limiter): State<Arc<IngressRateLimiter>>,
    request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);
    if let Some(key) = limiter.client_key(peer, request.headers()) {
        if !limiter.admit(key) {
            debug!(path = %request.uri().path(), "HTTP ingress: client rate limited");
            limiter
                .metrics
                .ingress_http_requests_total
                .get_or_create(&vec![
                    ("endpoint".to_string(), "any".to_string()),
                    ("status".to_string(), "rate_limited".to_string()),
                ])
                .inc();
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", "1")],
                "Too many requests from this address",
            )
                .into_response();
        }
    }
    next.run(request).await
}

/// Response headers a browser client may read cross-origin: the claim
/// protocol headers a v2 client uses to find the entry's long-poll cap.
fn exposed_headers() -> [HeaderName; 2] {
    [
        HeaderName::from_static(CLAIM_VERSION_HEADER),
        HeaderName::from_static(CLAIM_WAIT_MAX_HEADER),
    ]
}

/// CORS for the public ports. An empty origin list allows any origin, which keeps
/// browser clients served from any site working; a non-empty list allows only those.
pub fn cors_layer(allowed_origins: &[String]) -> CorsLayer {
    if allowed_origins.is_empty() {
        return CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
            .expose_headers(exposed_headers());
    }
    let origins: Vec<HeaderValue> = allowed_origins
        .iter()
        .filter_map(|origin| match HeaderValue::from_str(origin) {
            Ok(value) => Some(value),
            Err(error) => {
                warn!(origin = %origin, error = %error, "Ignoring invalid CORS origin");
                None
            }
        })
        .collect();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any)
        .expose_headers(exposed_headers())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use axum::Router;
    use std::net::Ipv4Addr;
    use tower::ServiceExt;

    fn config(rate: u32, burst: u32, header: &str) -> IngressConfig {
        IngressConfig {
            rate_limit_per_sec: rate,
            rate_limit_burst: burst,
            client_ip_header: header.to_string(),
            cors_allowed_origins: Vec::new(),
            ..IngressConfig::default()
        }
    }

    fn limiter(rate: u32, burst: u32, header: &str) -> Arc<IngressRateLimiter> {
        IngressRateLimiter::from_config(&config(rate, burst, header), MetricsService::new())
            .expect("limit enabled")
    }

    fn router(limiter: Arc<IngressRateLimiter>) -> Router {
        Router::new()
            .route("/health", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(limiter, rate_limit))
    }

    async fn status_from(app: &Router, peer: SocketAddr, forwarded: Option<&str>) -> StatusCode {
        let mut request = Request::builder().uri("/health");
        if let Some(value) = forwarded {
            request = request.header("x-forwarded-for", value);
        }
        let mut request = request.body(Body::empty()).expect("request");
        request.extensions_mut().insert(ConnectInfo(peer));
        app.clone()
            .oneshot(request)
            .await
            .expect("response")
            .status()
    }

    fn peer(ip: [u8; 4]) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::from(ip), 40_000))
    }

    #[test]
    fn disabled_when_rate_is_zero() {
        assert!(
            IngressRateLimiter::from_config(&config(0, 10, ""), MetricsService::new()).is_none()
        );
    }

    #[tokio::test]
    async fn limits_each_client_ip_separately() {
        let app = router(limiter(1, 2, ""));
        let first = peer([203, 0, 113, 7]);
        let second = peer([203, 0, 113, 8]);

        assert_eq!(status_from(&app, first, None).await, StatusCode::OK);
        assert_eq!(status_from(&app, first, None).await, StatusCode::OK);
        assert_eq!(
            status_from(&app, first, None).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(status_from(&app, second, None).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn direct_clients_cannot_choose_their_key_with_forwarding_headers() {
        let app = router(limiter(1, 1, "x-forwarded-for"));
        let client = peer([203, 0, 113, 9]);

        assert_eq!(
            status_from(&app, client, Some("198.51.100.1")).await,
            StatusCode::OK
        );
        assert_eq!(
            status_from(&app, client, Some("198.51.100.2")).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn loopback_proxy_is_keyed_by_the_rightmost_forwarded_address() {
        let app = router(limiter(1, 1, "x-forwarded-for"));
        let proxy = peer([127, 0, 0, 1]);

        assert_eq!(
            status_from(&app, proxy, Some("10.9.9.9, 198.51.100.1")).await,
            StatusCode::OK
        );
        assert_eq!(
            status_from(&app, proxy, Some("10.8.8.8, 198.51.100.1")).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            status_from(&app, proxy, Some("198.51.100.2")).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn loopback_without_a_configured_header_is_not_limited() {
        let app = router(limiter(1, 1, ""));
        let proxy = peer([127, 0, 0, 1]);
        for _ in 0..5 {
            assert_eq!(
                status_from(&app, proxy, Some("198.51.100.1")).await,
                StatusCode::OK
            );
        }
    }

    #[tokio::test]
    async fn requests_without_peer_information_are_not_limited() {
        let app = router(limiter(1, 1, ""));
        for _ in 0..3 {
            let request = Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("request");
            let status = app
                .clone()
                .oneshot(request)
                .await
                .expect("response")
                .status();
            assert_eq!(status, StatusCode::OK);
        }
    }

    #[test]
    fn ipv6_clients_share_a_bucket_per_64() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().expect("ipv6");
        let b: IpAddr = "2001:db8:1:2:bbbb::2".parse().expect("ipv6");
        let c: IpAddr = "2001:db8:1:3::1".parse().expect("ipv6");
        assert_eq!(client_bucket(a), client_bucket(b));
        assert_ne!(client_bucket(a), client_bucket(c));

        let mapped: IpAddr = "::ffff:203.0.113.7".parse().expect("mapped");
        assert_eq!(
            canonical_ip(mapped),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
        );
    }

    async fn preflight(app: Router, origin: &str) -> Option<HeaderValue> {
        let request = Request::builder()
            .method(Method::OPTIONS)
            .uri("/health")
            .header("origin", origin)
            .header("access-control-request-method", "POST")
            .body(Body::empty())
            .expect("request");
        app.oneshot(request)
            .await
            .expect("response")
            .headers()
            .get("access-control-allow-origin")
            .cloned()
    }

    #[tokio::test]
    async fn cors_allows_any_origin_when_no_list_is_configured() {
        let app = Router::new()
            .route("/health", get(|| async { "ok" }))
            .layer(cors_layer(&[]));
        assert_eq!(
            preflight(app, "https://anything.example").await,
            Some(HeaderValue::from_static("*"))
        );
    }

    #[tokio::test]
    async fn cors_allows_only_listed_origins() {
        let allowed = vec!["https://demo.example".to_string()];
        let app = Router::new()
            .route("/health", get(|| async { "ok" }))
            .layer(cors_layer(&allowed));
        assert_eq!(
            preflight(app.clone(), "https://demo.example").await,
            Some(HeaderValue::from_static("https://demo.example"))
        );
        assert_eq!(preflight(app, "https://other.example").await, None);
    }

    #[tokio::test]
    async fn cors_exposes_the_claim_headers() {
        for allowed in [Vec::new(), vec!["https://demo.example".to_string()]] {
            let app = Router::new()
                .route("/health", get(|| async { "ok" }))
                .layer(cors_layer(&allowed));
            let response = app
                .oneshot(
                    Request::builder()
                        .uri("/health")
                        .header("origin", "https://demo.example")
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            let exposed = response
                .headers()
                .get("access-control-expose-headers")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_ascii_lowercase();
            assert!(exposed.contains(CLAIM_VERSION_HEADER), "{exposed}");
            assert!(exposed.contains(CLAIM_WAIT_MAX_HEADER), "{exposed}");
        }
    }
}
