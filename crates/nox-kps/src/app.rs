//! Shared per-process state: settings, the upstream client, response caches,
//! rate limiters, the bundle store, the capability document and the metrics.

use std::sync::Arc;

use bytes::Bytes;
use serde::Serialize;
use tokio::sync::Semaphore;

use crate::bundles::BundleStore;
use crate::config::{Settings, SPHINX_PACKET_BYTES};
use crate::limits::{ConnLimiter, RateLimiter};
use crate::metrics::Metrics;
use crate::proxy::{SharedResponse, UpstreamClient};
use crate::routes::Route;

/// Everything a stream handler needs.
#[derive(Debug)]
pub struct App {
    pub settings: Arc<Settings>,
    pub upstream: UpstreamClient,
    pub bundles: Option<Arc<BundleStore>>,
    /// `GET /metadata.json` body, built once at startup.
    pub metadata_json: Bytes,
    pub metrics: Arc<Metrics>,
    /// Upstream requests in flight across all clients.
    pub inflight: Arc<Semaphore>,
    /// Bundle responses being written across all clients.
    pub bundle_streams: Arc<Semaphore>,
    pub conn_limiter: Arc<ConnLimiter>,
    pub rate: RateLimiters,
    pub topology: SharedResponse,
    pub health: SharedResponse,
}

/// Per-IP token buckets, one per rate-limited route class.
#[derive(Debug)]
pub struct RateLimiters {
    pub packets: RateLimiter,
    pub claim: RateLimiter,
    pub topology: RateLimiter,
    pub bundle: RateLimiter,
}

impl RateLimiters {
    #[must_use]
    pub fn new(settings: &Settings) -> Self {
        let l = &settings.limits;
        let make = |rate| RateLimiter::new(rate, l.ipv6_prefix_len, l.rate_limit_max_clients);
        Self {
            packets: make(l.packet_rate),
            claim: make(l.claim_rate),
            topology: make(l.topology_rate),
            bundle: make(l.bundle_rate),
        }
    }

    /// The limiter for `route`; `None` for routes without a per-IP rate.
    #[must_use]
    pub fn for_route(&self, route: Route) -> Option<&RateLimiter> {
        match route {
            Route::Packets => Some(&self.packets),
            Route::Claim => Some(&self.claim),
            Route::Topology => Some(&self.topology),
            Route::Bundle => Some(&self.bundle),
            Route::Health | Route::Metadata => None,
        }
    }

    /// Drops idle client buckets (run periodically).
    pub fn sweep(&self) {
        for limiter in [&self.packets, &self.claim, &self.topology, &self.bundle] {
            limiter.sweep();
        }
    }
}

/// `/metadata.json` (ARCHITECTURE §2.9), in this key order.
#[derive(Debug, Serialize)]
struct MetadataDocument<'a> {
    protocol: &'static str,
    software: &'static str,
    version: &'static str,
    node: Option<&'a str>,
    addresses: &'a [String],
    capabilities: Vec<&'static str>,
    limits: MetadataLimits,
    demo: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_field_names)] // the JSON keys are part of the published format
struct MetadataLimits {
    packet_bytes: usize,
    claim_request_max_bytes: usize,
    claim_max_surb_ids: usize,
    claim_response_max_bytes: usize,
}

/// The capability document served at `/metadata.json`.
pub fn metadata_document(
    settings: &Settings,
    addresses: &[String],
    bundles_enabled: bool,
) -> Result<Bytes, serde_json::Error> {
    let capabilities = Route::ALL
        .iter()
        .filter(|r| bundles_enabled || **r != Route::Bundle)
        .map(|r| r.label())
        .collect();
    let doc = MetadataDocument {
        protocol: crate::PROTOCOL,
        software: "nox-kps",
        version: env!("CARGO_PKG_VERSION"),
        node: settings.node_address.as_deref(),
        addresses,
        capabilities,
        limits: MetadataLimits {
            packet_bytes: SPHINX_PACKET_BYTES,
            claim_request_max_bytes: settings.limits.claim_request_max_bytes,
            claim_max_surb_ids: settings.limits.claim_max_surb_ids,
            claim_response_max_bytes: settings.limits.claim_response_max_bytes,
        },
        demo: false,
    };
    serde_json::to_vec(&doc).map(Bytes::from)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]

    use super::*;
    use crate::config::RawConfig;

    fn settings(node: &str) -> Settings {
        RawConfig {
            advertise: vec!["3.239.73.249".into()],
            node_address: node.into(),
            ..RawConfig::default()
        }
        .validate()
        .unwrap()
    }

    #[test]
    fn metadata_matches_the_architecture_shape() {
        let s = settings("0x862D6B1105bdE9d64dC5182fe3CD9d09F6F37463");
        let addrs = vec!["3.239.73.249:15005:uEiX".to_string()];
        let doc = metadata_document(&s, &addrs, true).unwrap();
        let text = std::str::from_utf8(&doc).unwrap();
        assert_eq!(
            text,
            concat!(
                r#"{"protocol":"nox-kps-http/1","software":"nox-kps","version":""#,
                env!("CARGO_PKG_VERSION"),
                r#"","node":"0x862d6b1105bde9d64dc5182fe3cd9d09f6f37463","addresses":["3.239.73.249:15005:uEiX"],"#,
                r#""capabilities":["metadata","health","packets","claim","topology","worker-bundles"],"#,
                r#""limits":{"packetBytes":32768,"claimRequestMaxBytes":65536,"claimMaxSurbIds":128,"claimResponseMaxBytes":16777216},"demo":false}"#
            )
        );
        let doc = metadata_document(&settings(""), &addrs, false).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&doc).unwrap();
        assert!(v["node"].is_null());
        assert!(!v["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "worker-bundles"));
    }
}
