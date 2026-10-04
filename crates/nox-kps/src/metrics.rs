//! Prometheus metrics and the `/health` endpoint, served over plain HTTP on a
//! loopback TCP port, plus the client used by `nox-kps healthcheck`.
//!
//! Labels carry route names, status codes and reasons only: never client
//! addresses, paths outside the allowlist, or request contents.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{header, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::Registry;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, warn};

use crate::error::HealthcheckError;

/// Header read timeout and total lifetime of one metrics/health connection.
const METRICS_CONN_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const METRICS_CONN_LIFETIME: Duration = Duration::from_secs(30);
/// Back-off after a failed TCP accept (for example EMFILE) before retrying.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ReasonLabels {
    pub reason: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RequestLabels {
    pub route: String,
    pub status: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RouteLabels {
    pub route: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct UpstreamErrorLabels {
    pub upstream: String,
    pub kind: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct EncodingLabels {
    pub encoding: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct BuildLabels {
    pub version: String,
}

fn duration_histogram() -> Histogram {
    // 1 ms .. ~33 s
    Histogram::new(exponential_buckets(0.001, 2.0, 16))
}

/// All metrics, registered under the `nox_kps` prefix.
#[derive(Debug)]
pub struct Metrics {
    registry: Registry,
    pub connections_active: Gauge,
    pub connections_accepted: Counter,
    pub connections_rejected: Family<ReasonLabels, Counter>,
    pub connections_closed: Family<ReasonLabels, Counter>,
    pub streams_active: Gauge,
    pub streams_accepted: Counter,
    pub streams_rejected: Family<ReasonLabels, Counter>,
    pub stream_failures: Family<ReasonLabels, Counter>,
    pub requests: Family<RequestLabels, Counter>,
    pub request_duration: Family<RouteLabels, Histogram>,
    pub upstream_errors: Family<UpstreamErrorLabels, Counter>,
    pub upstream_inflight: Gauge,
    pub bundles_loaded: Gauge,
    pub bundle_responses: Family<EncodingLabels, Counter>,
    pub build_info: Family<BuildLabels, Gauge>,
}

impl Metrics {
    #[must_use]
    pub fn new() -> Arc<Self> {
        let mut registry = Registry::with_prefix("nox_kps");
        let m = Self {
            connections_active: Gauge::default(),
            connections_accepted: Counter::default(),
            connections_rejected: Family::default(),
            connections_closed: Family::default(),
            streams_active: Gauge::default(),
            streams_accepted: Counter::default(),
            streams_rejected: Family::default(),
            stream_failures: Family::default(),
            requests: Family::default(),
            request_duration: Family::new_with_constructor(duration_histogram),
            upstream_errors: Family::default(),
            upstream_inflight: Gauge::default(),
            bundles_loaded: Gauge::default(),
            bundle_responses: Family::default(),
            build_info: Family::default(),
            registry: Registry::default(),
        };
        registry.register(
            "connections_active",
            "KPS connections currently open",
            m.connections_active.clone(),
        );
        registry.register(
            "connections_accepted",
            "KPS connections admitted",
            m.connections_accepted.clone(),
        );
        registry.register(
            "connections_rejected",
            "KPS connections refused by a connection limit",
            m.connections_rejected.clone(),
        );
        registry.register(
            "connections_closed",
            "KPS connections closed, by reason (peer, idle, shutdown)",
            m.connections_closed.clone(),
        );
        registry.register(
            "streams_active",
            "KPS streams (exchanges) in progress",
            m.streams_active.clone(),
        );
        registry.register(
            "streams_accepted",
            "KPS streams served",
            m.streams_accepted.clone(),
        );
        registry.register(
            "streams_rejected",
            "KPS streams reset by the per-connection stream limit",
            m.streams_rejected.clone(),
        );
        registry.register(
            "stream_failures",
            "Exchanges that ended without a complete response (timeouts, protocol errors, I/O)",
            m.stream_failures.clone(),
        );
        registry.register(
            "requests",
            "HTTP exchanges answered, by route and status",
            m.requests.clone(),
        );
        registry.register(
            "request_duration_seconds",
            "Time from request head to response, by route",
            m.request_duration.clone(),
        );
        registry.register(
            "upstream_errors",
            "Upstream exchanges that failed, by upstream and kind",
            m.upstream_errors.clone(),
        );
        registry.register(
            "upstream_inflight",
            "Upstream requests in flight",
            m.upstream_inflight.clone(),
        );
        registry.register(
            "bundles_loaded",
            "Worker bundles verified and held in memory",
            m.bundles_loaded.clone(),
        );
        registry.register(
            "bundle_responses",
            "Worker bundle responses, by content coding",
            m.bundle_responses.clone(),
        );
        registry.register(
            "build_info",
            "Build version (value is always 1)",
            m.build_info.clone(),
        );
        m.build_info
            .get_or_create(&BuildLabels {
                version: env!("CARGO_PKG_VERSION").to_string(),
            })
            .set(1);
        Arc::new(Self { registry, ..m })
    }

    /// Prometheus text exposition.
    pub fn encode(&self) -> Result<String, std::fmt::Error> {
        let mut out = String::new();
        prometheus_client::encoding::text::encode(&mut out, &self.registry)?;
        Ok(out)
    }

    pub(crate) fn reason(family: &Family<ReasonLabels, Counter>, reason: &str) {
        family
            .get_or_create(&ReasonLabels {
                reason: reason.to_string(),
            })
            .inc();
    }
}

/// What `/health` reports.
#[derive(Debug)]
pub struct HealthInfo {
    pub certhash: String,
    pub addresses: Vec<String>,
    pub shutting_down: AtomicBool,
}

/// Serves `/metrics` and `/health` until `shutdown` fires.
pub async fn serve(
    listener: TcpListener,
    metrics: Arc<Metrics>,
    health: Arc<HealthInfo>,
    shutdown: CancellationToken,
) {
    let tracker = TaskTracker::new();
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((tcp, _)) => {
                    let metrics = Arc::clone(&metrics);
                    let health = Arc::clone(&health);
                    tracker.spawn(serve_conn(tcp, metrics, health));
                }
                Err(e) => {
                    warn!(error = %e, "metrics endpoint: accept failed; retrying");
                    tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                }
            }
        }
    }
    tracker.close();
    tracker.wait().await;
}

async fn serve_conn(tcp: TcpStream, metrics: Arc<Metrics>, health: Arc<HealthInfo>) {
    let service = service_fn(move |req: Request<Incoming>| {
        let metrics = Arc::clone(&metrics);
        let health = Arc::clone(&health);
        async move { Ok::<_, Infallible>(route(&req, &metrics, &health)) }
    });
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .keep_alive(false)
        .header_read_timeout(METRICS_CONN_HEADER_TIMEOUT);
    let conn = builder.serve_connection(TokioIo::new(tcp), service);
    match tokio::time::timeout(METRICS_CONN_LIFETIME, conn).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => debug!(error = %e, "metrics endpoint: connection error"),
        Err(_) => debug!("metrics endpoint: connection exceeded its lifetime"),
    }
}

fn route(req: &Request<Incoming>, metrics: &Metrics, health: &HealthInfo) -> Response<Full<Bytes>> {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return plain(StatusCode::METHOD_NOT_ALLOWED, "only GET is supported\n");
    }
    match req.uri().path() {
        "/metrics" => match metrics.encode() {
            Ok(text) => response(
                StatusCode::OK,
                "application/openmetrics-text; version=1.0.0; charset=utf-8",
                Bytes::from(text),
            ),
            Err(e) => plain(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("cannot encode metrics: {e}\n"),
            ),
        },
        "/health" => {
            let shutting_down = health.shutting_down.load(Ordering::Relaxed);
            let body = serde_json::json!({
                "status": if shutting_down { "shutting_down" } else { "ok" },
                "certhash": health.certhash,
                "addresses": health.addresses,
                "version": env!("CARGO_PKG_VERSION"),
            });
            let status = if shutting_down {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::OK
            };
            response(status, "application/json", Bytes::from(body.to_string()))
        }
        _ => plain(StatusCode::NOT_FOUND, "not found\n"),
    }
}

fn response(status: StatusCode, content_type: &'static str, body: Bytes) -> Response<Full<Bytes>> {
    let mut res = Response::new(Full::new(body));
    *res.status_mut() = status;
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        http::HeaderValue::from_static(content_type),
    );
    res
}

fn plain(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    response(
        status,
        "text/plain; charset=utf-8",
        Bytes::copy_from_slice(msg.as_bytes()),
    )
}

/// `GET /health` against a running instance; `Ok` only on `200`.
pub async fn probe_health(addr: SocketAddr, timeout: Duration) -> Result<(), HealthcheckError> {
    let probe = async {
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|source| HealthcheckError::Connect { addr, source })?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
            .await
            .map_err(|e| HealthcheckError::Request {
                addr,
                reason: e.to_string(),
            })?;
        let conn_task = tokio::spawn(conn);
        let req = Request::builder()
            .method(Method::GET)
            .uri("/health")
            .header(header::HOST, addr.to_string())
            .body(Empty::<Bytes>::new())
            .map_err(|e| HealthcheckError::Request {
                addr,
                reason: e.to_string(),
            })?;
        let res = sender
            .send_request(req)
            .await
            .map_err(|e| HealthcheckError::Request {
                addr,
                reason: e.to_string(),
            })?;
        let status = res.status();
        // Drain so the connection closes cleanly.
        let _ = res.into_body().collect().await;
        conn_task.abort();
        if status == StatusCode::OK {
            Ok(())
        } else {
            Err(HealthcheckError::Unhealthy {
                addr,
                status: status.as_u16(),
            })
        }
    };
    tokio::time::timeout(timeout, probe)
        .await
        .map_err(|_| HealthcheckError::Timeout {
            addr,
            timeout_ms: timeout.as_millis(),
        })?
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn registry_encodes_prefixed_metrics() {
        let m = Metrics::new();
        m.connections_accepted.inc();
        Metrics::reason(&m.connections_rejected, "per_ip_limit");
        m.requests
            .get_or_create(&RequestLabels {
                route: "nox-packets".into(),
                status: "202".into(),
            })
            .inc();
        m.request_duration
            .get_or_create(&RouteLabels {
                route: "nox-packets".into(),
            })
            .observe(0.004);
        let text = m.encode().unwrap();
        assert!(
            text.contains("nox_kps_connections_accepted_total 1"),
            "{text}"
        );
        assert!(text.contains("nox_kps_connections_rejected_total{reason=\"per_ip_limit\"} 1"));
        assert!(text.contains("nox_kps_requests_total{route=\"nox-packets\",status=\"202\"} 1"));
        assert!(text.contains("nox_kps_request_duration_seconds_bucket"));
        assert!(text.contains("nox_kps_build_info{version="));
    }

    #[tokio::test]
    async fn health_endpoint_reports_ok_then_shutting_down() {
        let metrics = Metrics::new();
        let health = Arc::new(HealthInfo {
            certhash: "uEiTest".into(),
            addresses: vec!["127.0.0.1:1:uEiTest".into()],
            shutting_down: AtomicBool::new(false),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(serve(
            listener,
            Arc::clone(&metrics),
            Arc::clone(&health),
            shutdown.clone(),
        ));
        probe_health(addr, Duration::from_secs(5)).await.unwrap();
        health.shutting_down.store(true, Ordering::Relaxed);
        let err = probe_health(addr, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(
            matches!(err, HealthcheckError::Unhealthy { status: 503, .. }),
            "{err}"
        );
        shutdown.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn probe_reports_connection_failures() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let err = probe_health(addr, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(err, HealthcheckError::Connect { .. }), "{err}");
    }
}
