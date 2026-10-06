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

/// Timeouts of the admin endpoint (`limits.admin_*`).
#[derive(Debug, Clone, Copy)]
pub struct AdminTimeouts {
    /// Time a client gets to send its request head.
    pub header_read: Duration,
    /// Total lifetime of one connection.
    pub conn_lifetime: Duration,
    /// Pause after a failed TCP accept (for example `EMFILE`) before retrying.
    pub accept_retry: Duration,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ReasonLabels {
    pub reason: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct StreamLabels {
    pub route: &'static str,
    pub status: u16,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RouteLabels {
    pub route: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct KindLabels {
    pub kind: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct UpstreamErrorLabels {
    pub route: &'static str,
    pub kind: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct BytesLabels {
    pub route: &'static str,
    /// `in` (client to nox-kps) or `out` (nox-kps to client).
    pub direction: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ResultLabels {
    pub result: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct BuildLabels {
    pub version: &'static str,
    pub kps_version: &'static str,
}

fn duration_histogram() -> Histogram {
    // 1 ms .. ~33 s
    Histogram::new(exponential_buckets(0.001, 2.0, 16))
}

/// All metrics, registered under the `nox_kps` prefix (README.md, Observability).
#[derive(Debug)]
pub struct Metrics {
    registry: Registry,
    pub connections_accepted: Counter,
    pub connections_active: Gauge,
    pub connections_rejected: Family<ReasonLabels, Counter>,
    pub connections_closed: Family<ReasonLabels, Counter>,
    pub streams: Family<StreamLabels, Counter>,
    pub streams_active: Gauge,
    pub streams_rejected: Family<ReasonLabels, Counter>,
    pub stream_failures: Family<ReasonLabels, Counter>,
    pub profile_violations: Family<KindLabels, Counter>,
    pub request_duration: Family<RouteLabels, Histogram>,
    pub upstream_errors: Family<UpstreamErrorLabels, Counter>,
    pub upstream_inflight: Gauge,
    pub bytes: Family<BytesLabels, Counter>,
    pub rate_limited: Family<RouteLabels, Counter>,
    pub bundle_requests: Family<ResultLabels, Counter>,
    /// Long-poll claims, by result (`granted`, `busy`, `off`).
    pub claim_waits: Family<ResultLabels, Counter>,
    pub bundles_loaded: Gauge,
    pub build_info: Family<BuildLabels, Gauge>,
}

impl Metrics {
    #[must_use]
    pub fn new() -> Arc<Self> {
        let mut registry = Registry::with_prefix("nox_kps");
        let m = Self {
            registry: Registry::default(),
            connections_accepted: Counter::default(),
            connections_active: Gauge::default(),
            connections_rejected: Family::default(),
            connections_closed: Family::default(),
            streams: Family::default(),
            streams_active: Gauge::default(),
            streams_rejected: Family::default(),
            stream_failures: Family::default(),
            profile_violations: Family::default(),
            request_duration: Family::new_with_constructor(duration_histogram),
            upstream_errors: Family::default(),
            upstream_inflight: Gauge::default(),
            bytes: Family::default(),
            rate_limited: Family::default(),
            bundle_requests: Family::default(),
            claim_waits: Family::default(),
            bundles_loaded: Gauge::default(),
            build_info: Family::default(),
        };
        registry.register(
            "connections_accepted",
            "KPS connections admitted",
            m.connections_accepted.clone(),
        );
        registry.register(
            "connections_active",
            "KPS connections currently open",
            m.connections_active.clone(),
        );
        registry.register(
            "connections_rejected",
            "KPS connections refused by a connection limit, by reason",
            m.connections_rejected.clone(),
        );
        registry.register(
            "connections_closed",
            "KPS connections closed, by reason (peer, idle, lifetime, shutdown)",
            m.connections_closed.clone(),
        );
        registry.register(
            "streams",
            "HTTP exchanges answered, by route and status",
            m.streams.clone(),
        );
        registry.register(
            "streams_active",
            "KPS streams (exchanges) in progress",
            m.streams_active.clone(),
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
            "profile_violations",
            "Requests refused by the KPS-HTTP/1 profile or a route's request rules, by kind",
            m.profile_violations.clone(),
        );
        registry.register(
            "request_duration_seconds",
            "Time from request head to response, by route",
            m.request_duration.clone(),
        );
        registry.register(
            "upstream_errors",
            "Upstream exchanges that failed, by route and kind",
            m.upstream_errors.clone(),
        );
        registry.register(
            "upstream_inflight",
            "Upstream requests in flight",
            m.upstream_inflight.clone(),
        );
        registry.register(
            "bytes",
            "HTTP body bytes, by route and direction (in: from clients, out: to clients)",
            m.bytes.clone(),
        );
        registry.register(
            "rate_limited",
            "Requests answered 429 by a per-IP rate limit, by route",
            m.rate_limited.clone(),
        );
        registry.register(
            "bundle_requests",
            "Worker bundle requests, by result (hit, miss)",
            m.bundle_requests.clone(),
        );
        registry.register(
            "claim_waits",
            "Claims that asked to long-poll, by result (granted, busy: no slot free, off: long-polling disabled)",
            m.claim_waits.clone(),
        );
        registry.register(
            "bundles_loaded",
            "Worker bundles verified and held in memory",
            m.bundles_loaded.clone(),
        );
        registry.register(
            "build_info",
            "Build and kps library version (value is always 1)",
            m.build_info.clone(),
        );
        m.build_info
            .get_or_create(&BuildLabels {
                version: env!("CARGO_PKG_VERSION"),
                kps_version: crate::KPS_VERSION,
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

    pub(crate) fn reason(family: &Family<ReasonLabels, Counter>, reason: &'static str) {
        family.get_or_create(&ReasonLabels { reason }).inc();
    }

    pub(crate) fn violation(&self, kind: &'static str) {
        self.profile_violations
            .get_or_create(&KindLabels { kind })
            .inc();
    }

    pub(crate) fn add_bytes(&self, route: &'static str, direction: &'static str, n: usize) {
        if n > 0 {
            self.bytes
                .get_or_create(&BytesLabels { route, direction })
                .inc_by(n as u64);
        }
    }

    /// Sum of a reason family, for the periodic log summary.
    #[must_use]
    pub fn total(family: &Family<ReasonLabels, Counter>, reasons: &[&'static str]) -> u64 {
        reasons
            .iter()
            .map(|reason| family.get_or_create(&ReasonLabels { reason }).get())
            .sum()
    }
}

/// What `/healthz` reports.
#[derive(Debug)]
pub struct HealthInfo {
    pub certhash: String,
    pub addresses: Vec<String>,
    pub shutting_down: AtomicBool,
    /// Cleared when the KPS accept loop stops.
    pub listener_alive: AtomicBool,
}

/// Admin path for the liveness document.
pub const HEALTHZ_PATH: &str = "/healthz";

/// Serves `/metrics` and `/healthz` until `shutdown` fires.
pub async fn serve(
    listener: TcpListener,
    metrics: Arc<Metrics>,
    health: Arc<HealthInfo>,
    timeouts: AdminTimeouts,
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
                    tracker.spawn(serve_conn(tcp, metrics, health, timeouts));
                }
                Err(e) => {
                    warn!(error = %e, "metrics endpoint: accept failed; retrying");
                    tokio::time::sleep(timeouts.accept_retry).await;
                }
            }
        }
    }
    tracker.close();
    tracker.wait().await;
}

async fn serve_conn(
    tcp: TcpStream,
    metrics: Arc<Metrics>,
    health: Arc<HealthInfo>,
    timeouts: AdminTimeouts,
) {
    let service = service_fn(move |req: Request<Incoming>| {
        let metrics = Arc::clone(&metrics);
        let health = Arc::clone(&health);
        async move { Ok::<_, Infallible>(route(&req, &metrics, &health)) }
    });
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .keep_alive(false)
        .header_read_timeout(timeouts.header_read);
    let conn = builder.serve_connection(TokioIo::new(tcp), service);
    match tokio::time::timeout(timeouts.conn_lifetime, conn).await {
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
        HEALTHZ_PATH => {
            let state = if health.shutting_down.load(Ordering::Relaxed) {
                "shutting_down"
            } else if !health.listener_alive.load(Ordering::Relaxed) {
                "listener_stopped"
            } else {
                "ok"
            };
            let body = serde_json::json!({
                "status": state,
                "certhash": health.certhash,
                "addresses": health.addresses,
                "version": env!("CARGO_PKG_VERSION"),
            });
            let status = if state == "ok" {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
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

/// `GET /healthz` against a running instance's admin port; `Ok` only on `200`.
pub async fn probe_health(addr: SocketAddr, timeout: Duration) -> Result<(), HealthcheckError> {
    let target = format!("http://{addr}{HEALTHZ_PATH}");
    let probe = async {
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|source| HealthcheckError::Connect { addr, source })?;
        let request_err = |e: &dyn std::fmt::Display| HealthcheckError::Request {
            target: target.clone(),
            reason: e.to_string(),
        };
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
            .await
            .map_err(|e| request_err(&e))?;
        let conn_task = tokio::spawn(conn);
        let req = Request::builder()
            .method(Method::GET)
            .uri(HEALTHZ_PATH)
            .header(header::HOST, addr.to_string())
            .body(Empty::<Bytes>::new())
            .map_err(|e| request_err(&e))?;
        let res = sender
            .send_request(req)
            .await
            .map_err(|e| request_err(&e))?;
        let status = res.status();
        // Drain so the connection closes cleanly.
        let _ = res.into_body().collect().await;
        conn_task.abort();
        if status == StatusCode::OK {
            Ok(())
        } else {
            Err(HealthcheckError::Unhealthy {
                target: target.clone(),
                status: status.as_u16(),
            })
        }
    };
    tokio::time::timeout(timeout, probe)
        .await
        .map_err(|_| HealthcheckError::Timeout {
            target: format!("http://{addr}{HEALTHZ_PATH}"),
            timeout_ms: timeout.as_millis(),
        })?
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]

    use super::*;

    #[test]
    fn registry_encodes_prefixed_metrics() {
        let m = Metrics::new();
        m.connections_accepted.inc();
        Metrics::reason(&m.connections_rejected, "per_ip_limit");
        m.streams
            .get_or_create(&StreamLabels {
                route: "packets",
                status: 202,
            })
            .inc();
        m.request_duration
            .get_or_create(&RouteLabels { route: "packets" })
            .observe(0.004);
        m.add_bytes("packets", "in", 32_768);
        m.violation("transfer_encoding");
        let text = m.encode().unwrap();
        assert!(
            text.contains("nox_kps_connections_accepted_total 1"),
            "{text}"
        );
        assert!(text.contains("nox_kps_connections_rejected_total{reason=\"per_ip_limit\"} 1"));
        assert!(text.contains("nox_kps_streams_total{route=\"packets\",status=\"202\"} 1"));
        assert!(text.contains("nox_kps_request_duration_seconds_bucket"));
        assert!(text.contains("nox_kps_bytes_total{route=\"packets\",direction=\"in\"} 32768"));
        assert!(text.contains("nox_kps_profile_violations_total{kind=\"transfer_encoding\"} 1"));
        assert!(text.contains("kps_version=\"0.2.2\""), "{text}");
    }

    #[tokio::test]
    async fn health_endpoint_reports_ok_then_shutting_down() {
        let metrics = Metrics::new();
        let health = Arc::new(HealthInfo {
            certhash: "uEiTest".into(),
            addresses: vec!["127.0.0.1:1:uEiTest".into()],
            shutting_down: AtomicBool::new(false),
            listener_alive: AtomicBool::new(true),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(serve(
            listener,
            Arc::clone(&metrics),
            Arc::clone(&health),
            AdminTimeouts {
                header_read: Duration::from_secs(5),
                conn_lifetime: Duration::from_secs(30),
                accept_retry: Duration::from_millis(100),
            },
            shutdown.clone(),
        ));
        probe_health(addr, Duration::from_secs(5)).await.unwrap();
        health.listener_alive.store(false, Ordering::Relaxed);
        assert!(probe_health(addr, Duration::from_secs(5)).await.is_err());
        health.listener_alive.store(true, Ordering::Relaxed);
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
