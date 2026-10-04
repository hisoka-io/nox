//! Shared per-process state: settings, the route allowlist, the upstream
//! client, the bundle store, the capability document and the metrics.

use std::sync::Arc;

use bytes::Bytes;
use http::Method;
use tokio::sync::Semaphore;

use crate::bundles::BundleStore;
use crate::config::{Route, Settings};
use crate::limits::ConnLimiter;
use crate::metrics::Metrics;
use crate::proxy::UpstreamClient;

/// Everything a stream handler needs.
#[derive(Debug)]
pub struct App {
    pub settings: Arc<Settings>,
    pub router: Router,
    pub upstream: UpstreamClient,
    pub bundles: Option<Arc<BundleStore>>,
    /// `GET /metadata.json` body, built once at startup.
    pub metadata_json: Bytes,
    pub metrics: Arc<Metrics>,
    /// Upstream requests in flight across all clients.
    pub inflight: Arc<Semaphore>,
    pub conn_limiter: Arc<ConnLimiter>,
}

/// Exact-match allowlist of proxied routes.
#[derive(Debug, Clone)]
pub struct Router {
    routes: Vec<Route>,
}

/// Result of a route lookup.
#[derive(Debug, PartialEq, Eq)]
pub enum Lookup<'a> {
    Found(&'a Route),
    /// The path exists with other methods; carries the `Allow` value.
    MethodNotAllowed(String),
    NotFound,
}

impl Router {
    #[must_use]
    pub fn new(routes: Vec<Route>) -> Self {
        Self { routes }
    }

    #[must_use]
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    /// Exact path match; the method must match too.
    #[must_use]
    pub fn lookup(&self, method: &Method, path: &str) -> Lookup<'_> {
        let mut allowed: Vec<&str> = Vec::new();
        for route in self.routes.iter().filter(|r| r.path == path) {
            if route.method == *method {
                return Lookup::Found(route);
            }
            allowed.push(route.method.as_str());
        }
        if allowed.is_empty() {
            Lookup::NotFound
        } else {
            allowed.sort_unstable();
            allowed.dedup();
            Lookup::MethodNotAllowed(allowed.join(", "))
        }
    }
}

/// The capability document served at `/metadata.json` (the KPS-HTTP/1
/// convention from tor-js-gateway PROTOCOL.md §5): protocol, software,
/// version, capabilities (`metadata`, the route names, `worker-bundles` when
/// enabled) and the published addresses.
#[must_use]
pub fn metadata_document(routes: &[Route], bundles_enabled: bool, addresses: &[String]) -> Bytes {
    let mut capabilities = vec!["metadata".to_string()];
    capabilities.extend(routes.iter().map(|r| r.name.clone()));
    if bundles_enabled {
        capabilities.push("worker-bundles".to_string());
    }
    let doc = serde_json::json!({
        "protocol": "kps-http/1",
        "software": "nox-kps",
        "version": env!("CARGO_PKG_VERSION"),
        "capabilities": capabilities,
        "addresses": addresses,
    });
    Bytes::from(doc.to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::config::RawConfig;

    fn router() -> Router {
        Router::new(RawConfig::default().validate().unwrap().routes)
    }

    #[test]
    fn exact_matches_only() {
        let r = router();
        assert!(
            matches!(r.lookup(&Method::POST, "/api/v1/packets"), Lookup::Found(route) if route.name == "nox-packets")
        );
        assert!(matches!(
            r.lookup(&Method::GET, "/topology"),
            Lookup::Found(_)
        ));
        assert_eq!(
            r.lookup(&Method::POST, "/api/v1/packets/"),
            Lookup::NotFound
        );
        assert_eq!(r.lookup(&Method::POST, "/api/v1/packet"), Lookup::NotFound);
        assert_eq!(r.lookup(&Method::GET, "/api/v1/ws"), Lookup::NotFound);
        assert_eq!(
            r.lookup(&Method::GET, "/api/v1/responses/stream"),
            Lookup::NotFound
        );
        assert_eq!(r.lookup(&Method::GET, "/metrics"), Lookup::NotFound);
        assert_eq!(r.lookup(&Method::GET, "/API/V1/PACKETS"), Lookup::NotFound);
    }

    #[test]
    fn wrong_method_lists_the_allowed_ones() {
        let r = router();
        assert_eq!(
            r.lookup(&Method::GET, "/api/v1/packets"),
            Lookup::MethodNotAllowed("POST".to_string())
        );
        assert_eq!(
            r.lookup(&Method::HEAD, "/topology"),
            Lookup::MethodNotAllowed("GET".to_string())
        );
    }

    #[test]
    fn metadata_lists_capabilities_and_addresses() {
        let routes = RawConfig::default().validate().unwrap().routes;
        let doc = metadata_document(&routes, true, &["203.0.113.5:15005:uEiX".to_string()]);
        let v: serde_json::Value = serde_json::from_slice(&doc).unwrap();
        assert_eq!(v["protocol"], "kps-http/1");
        assert_eq!(v["software"], "nox-kps");
        let caps: Vec<&str> = v["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap())
            .collect();
        assert_eq!(
            caps,
            [
                "metadata",
                "nox-packets",
                "nox-responses-claim",
                "nox-topology",
                "nox-health",
                "worker-bundles"
            ]
        );
        assert_eq!(v["addresses"][0], "203.0.113.5:15005:uEiX");
        let doc = metadata_document(&routes, false, &[]);
        assert!(!String::from_utf8_lossy(&doc).contains("worker-bundles"));
    }
}
