//! Configuration: a TOML file plus `NOX_KPS__SECTION__FIELD` environment
//! overrides, validated into [`Settings`] before anything binds a socket.
//!
//! [`RawConfig`] mirrors the file format (strings, plain integers) so the TOML
//! and the environment stay easy to write; [`RawConfig::validate`] turns it
//! into typed [`Settings`] and reports every invalid field at once.

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use http::header::HeaderName;
use http::uri::{Authority, Scheme};
use http::{HeaderValue, Method, Uri};
use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

/// Default config file location inside the container image.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/nox-kps/config.toml";
/// Environment variable prefix for overrides (`NOX_KPS__LIMITS__MAX_CONNECTIONS=512`).
pub const ENV_PREFIX: &str = "NOX_KPS";
/// Separator between the prefix, sections and fields in override variables.
pub const ENV_SEPARATOR: &str = "__";

/// Lowest header-block cap hyper accepts (its read buffer cannot be smaller).
pub const MIN_HEADER_BYTES: usize = 8 * 1024;
/// Upper bound for the header-block cap; KPS-HTTP/1 recommends 16 KiB.
pub const MAX_HEADER_BYTES: usize = 1024 * 1024;
/// Upper bound for a proxied request body (a Sphinx packet is 32 KiB).
pub const MAX_ROUTE_BODY_BYTES: usize = 16 * 1024 * 1024;
/// Upper bound for concurrent streams per connection (KPS peers grant 100 by
/// default, so larger values only matter for tuned clients).
pub const MAX_STREAMS_PER_CONNECTION: usize = 10_000;
/// Upper bound for concurrent upstream requests.
pub const MAX_INFLIGHT_UPSTREAM: usize = 1_000_000;
/// Path prefix of the worker-bundle resolver routes (anon-rpc SPEC §4.2).
pub const BUNDLE_PATH_PREFIX: &str = "/keccak/";
/// Path of the capability document.
pub const METADATA_PATH: &str = "/metadata.json";

/// Upstream names a route can reference.
pub const UPSTREAM_INGRESS: &str = "ingress";
pub const UPSTREAM_TOPOLOGY: &str = "topology";

/// Headers a route must never forward or copy back: hop-by-hop headers, framing
/// headers the proxy sets itself, and forwarding headers a client could spoof.
const RESERVED_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
    "expect",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
];

/// The file/environment shape of the configuration. Every section and field
/// has a default, so an empty file (or no file) is a valid production setup
/// once `kps.public_ips` is set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct RawConfig {
    pub kps: KpsConfig,
    pub upstreams: UpstreamsConfig,
    /// The allowlist. When the file lists `[[routes]]`, they replace the
    /// defaults entirely.
    pub routes: Vec<RouteConfig>,
    pub proxy: ProxyConfig,
    pub limits: LimitsConfig,
    pub bundles: BundlesConfig,
    pub metrics: MetricsConfig,
    pub log: LogConfig,
    pub shutdown: ShutdownConfig,
}

impl Default for RawConfig {
    fn default() -> Self {
        Self {
            kps: KpsConfig::default(),
            upstreams: UpstreamsConfig::default(),
            routes: default_routes(),
            proxy: ProxyConfig::default(),
            limits: LimitsConfig::default(),
            bundles: BundlesConfig::default(),
            metrics: MetricsConfig::default(),
            log: LogConfig::default(),
            shutdown: ShutdownConfig::default(),
        }
    }
}

/// The KPS listener and its identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct KpsConfig {
    /// UDP bind address. Both transports (WebRTC and QUIC) share this port.
    /// `[::]` serves IPv4 and IPv6 on a dual-stack host; use `0.0.0.0` on a
    /// host without IPv6 support.
    pub listen: String,
    /// Persistent identity (combined PRIVATE KEY + CERTIFICATE PEM, mode 0600).
    /// The certhash in the published address is derived from it, so keep it
    /// on a persistent volume and back it up with the node's other secrets.
    pub identity_key_file: PathBuf,
    /// Public IPs to advertise. Empty: detect the outbound source address,
    /// which behind NAT (including EC2) is a private address, so production
    /// nodes set this explicitly.
    pub public_ips: Vec<String>,
}

impl Default for KpsConfig {
    fn default() -> Self {
        Self {
            listen: "[::]:15005".to_string(),
            identity_key_file: PathBuf::from("/var/lib/nox-kps/kps.key"),
            public_ips: Vec::new(),
        }
    }
}

/// Loopback HTTP services on the node that routes forward to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamsConfig {
    /// The node's HTTP ingress (`ingress_port`): packets, response claims, health.
    pub ingress: String,
    /// The node's topology API (`topology_api_port`).
    pub topology: String,
}

impl Default for UpstreamsConfig {
    fn default() -> Self {
        Self {
            ingress: "http://127.0.0.1:15002".to_string(),
            topology: "http://127.0.0.1:15003".to_string(),
        }
    }
}

/// One allowlisted route: an exact method and path forwarded to an upstream.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// Label used in metrics and in `/metadata.json` capabilities.
    pub name: String,
    pub method: String,
    /// Exact path; no wildcards, no query.
    pub path: String,
    /// `ingress` or `topology`.
    pub upstream: String,
    /// Largest accepted request body. 0 means the route takes no body.
    #[serde(default)]
    pub max_body_bytes: usize,
}

/// The routes the Nox SDK uses (`nox-client` transport + topology fetch).
#[must_use]
pub fn default_routes() -> Vec<RouteConfig> {
    vec![
        RouteConfig {
            name: "nox-packets".to_string(),
            method: "POST".to_string(),
            path: "/api/v1/packets".to_string(),
            upstream: UPSTREAM_INGRESS.to_string(),
            // One Sphinx packet, exactly 32 768 bytes; the node checks the size.
            max_body_bytes: 32 * 1024,
        },
        RouteConfig {
            name: "nox-responses-claim".to_string(),
            method: "POST".to_string(),
            path: "/api/v1/responses/claim".to_string(),
            upstream: UPSTREAM_INGRESS.to_string(),
            // A JSON list of 32-hex SURB IDs; matches the 64k nginx body cap.
            max_body_bytes: 64 * 1024,
        },
        RouteConfig {
            name: "nox-topology".to_string(),
            method: "GET".to_string(),
            path: "/topology".to_string(),
            upstream: UPSTREAM_TOPOLOGY.to_string(),
            max_body_bytes: 0,
        },
        RouteConfig {
            name: "nox-health".to_string(),
            method: "GET".to_string(),
            path: "/health".to_string(),
            upstream: UPSTREAM_INGRESS.to_string(),
            max_body_bytes: 0,
        },
    ]
}

/// How requests and responses cross the proxy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyConfig {
    /// Header carrying the client's KPS source IP to the node. Must match the
    /// node's `ingress.client_ip_header` so per-IP rate limits apply to KPS
    /// clients. Any client-supplied value is discarded.
    pub client_ip_header: String,
    /// Request headers copied from the client to the upstream.
    pub forward_request_headers: Vec<String>,
    /// Response headers copied from the upstream back to the client.
    pub forward_response_headers: Vec<String>,
    pub upstream_connect_timeout_ms: u64,
    /// Upper bound for one upstream exchange (connect, request, full response).
    pub upstream_timeout_ms: u64,
    /// Largest upstream response body relayed to a client.
    pub max_response_body_bytes: usize,
    /// Upstream requests in flight at once across all clients; beyond it
    /// clients get `503` with `Retry-After`.
    pub max_inflight_upstream: usize,
    pub upstream_pool_idle_timeout_ms: u64,
    pub upstream_pool_max_idle: usize,
    /// Upstreams must be loopback addresses unless this is set: the node only
    /// trusts the client IP header on loopback connections.
    pub allow_non_loopback_upstreams: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            client_ip_header: "x-forwarded-for".to_string(),
            forward_request_headers: vec!["content-type".to_string(), "accept".to_string()],
            forward_response_headers: vec![
                "content-type".to_string(),
                "retry-after".to_string(),
                "cache-control".to_string(),
                "x-nox-version".to_string(),
            ],
            upstream_connect_timeout_ms: 2_000,
            upstream_timeout_ms: 15_000,
            max_response_body_bytes: 32 * 1024 * 1024,
            max_inflight_upstream: 256,
            upstream_pool_idle_timeout_ms: 30_000,
            upstream_pool_max_idle: 32,
            allow_non_loopback_upstreams: false,
        }
    }
}

/// Resource limits for KPS connections and streams.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    /// Concurrent KPS connections across all clients.
    pub max_connections: usize,
    /// Concurrent KPS connections per client IP (IPv6: per prefix below).
    pub max_connections_per_ip: usize,
    /// IPv6 clients are counted per prefix of this length (the node uses /64).
    pub ipv6_prefix_len: u8,
    /// Concurrent streams (exchanges) per connection; extra streams are reset
    /// with the KPS `queue-full` code.
    pub max_streams_per_connection: usize,
    /// Request header block cap, request line included (KPS-HTTP/1: 16 KiB).
    pub max_header_bytes: usize,
    /// Maximum number of request header fields.
    pub max_headers: usize,
    /// Stream open to complete request header block (KPS-HTTP/1: 30 s).
    pub header_read_timeout_ms: u64,
    /// Stream open to response fully written; the stream is reset after it.
    pub stream_timeout_ms: u64,
    /// A connection with no stream activity for this long is closed.
    pub connection_idle_timeout_ms: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: 256,
            max_connections_per_ip: 16,
            ipv6_prefix_len: 64,
            max_streams_per_connection: 64,
            max_header_bytes: 16 * 1024,
            max_headers: 64,
            header_read_timeout_ms: 30_000,
            stream_timeout_ms: 60_000,
            connection_idle_timeout_ms: 120_000,
        }
    }
}

/// Worker bundles served under `/keccak/<hh>/<62 hex>` (anon-rpc SPEC §4.2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct BundlesConfig {
    /// Directory of keccak-named bundle files, either `<hh>/<62 hex>` (the
    /// GitHub `keccak` branch layout) or flat `<64 hex>`. Empty disables the
    /// resolver.
    pub dir: String,
    /// Files larger than this are not served (the reference harness caps
    /// bundles at 64 MiB).
    pub max_bundle_bytes: usize,
    /// Most bundles held in memory.
    pub max_bundles: usize,
    /// Seconds between directory rescans; 0 scans only at startup.
    pub rescan_interval_secs: u64,
    /// Serve a gzip copy to clients that advertise `gzip`.
    pub gzip: bool,
}

impl Default for BundlesConfig {
    fn default() -> Self {
        Self {
            dir: String::new(),
            max_bundle_bytes: 64 * 1024 * 1024,
            max_bundles: 64,
            rescan_interval_secs: 60,
            gzip: true,
        }
    }
}

/// Prometheus metrics and `/health` on a TCP port.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsConfig {
    /// TCP bind address. Empty disables the endpoint.
    pub listen: String,
    /// The endpoint is loopback-only unless this is set.
    pub allow_non_loopback: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:15006".to_string(),
            allow_non_loopback: false,
        }
    }
}

/// Log output format.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

/// Logging. `RUST_LOG`, when set, replaces `filter`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    pub format: LogFormat,
    /// `tracing` filter directives. The default keeps third-party transport
    /// crates at `error`, because their debug output includes peer addresses.
    pub filter: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::Text,
            filter: "error,nox_kps=info".to_string(),
        }
    }
}

/// Graceful shutdown.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ShutdownConfig {
    /// Time in-flight exchanges get to finish after SIGTERM/SIGINT.
    pub grace_period_ms: u64,
    /// After its exchanges finish, a connection stays open this long (or until
    /// the client closes it) so the last responses reach the client: closing
    /// a KPS connection is immediate and drops unacknowledged data.
    pub close_linger_ms: u64,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            grace_period_ms: 10_000,
            close_linger_ms: 2_000,
        }
    }
}

/// Where the config file comes from.
#[derive(Debug, Clone)]
pub enum ConfigSource {
    /// Given on the command line or in `NOX_KPS_CONFIG`: must exist.
    Explicit(PathBuf),
    /// The default location: used when present, otherwise defaults + env.
    Default(PathBuf),
}

impl ConfigSource {
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            Self::Explicit(p) | Self::Default(p) => p,
        }
    }
}

impl RawConfig {
    /// Loads the file (when present) and applies `NOX_KPS__*` overrides from
    /// the process environment.
    pub fn load(source: &ConfigSource) -> Result<Self, ConfigError> {
        Self::load_with_env(source, None)
    }

    /// Like [`RawConfig::load`], with an explicit environment map instead of
    /// the process environment (tests).
    pub fn load_with_env(
        source: &ConfigSource,
        env: Option<std::collections::HashMap<String, String>>,
    ) -> Result<Self, ConfigError> {
        let path = source.path();
        let required = matches!(source, ConfigSource::Explicit(_));
        if required && !path.exists() {
            return Err(ConfigError::Missing {
                path: path.to_path_buf(),
            });
        }
        let mut env_source = config::Environment::with_prefix(ENV_PREFIX)
            .prefix_separator(ENV_SEPARATOR)
            .separator(ENV_SEPARATOR)
            .try_parsing(true)
            .list_separator(",")
            .with_list_parse_key("kps.public_ips")
            .with_list_parse_key("proxy.forward_request_headers")
            .with_list_parse_key("proxy.forward_response_headers");
        if let Some(map) = env {
            env_source = env_source.source(Some(map.into_iter().collect()));
        }
        config::Config::builder()
            .add_source(
                config::File::from(path)
                    .format(config::FileFormat::Toml)
                    .required(required),
            )
            .add_source(env_source)
            .build()
            .and_then(config::Config::try_deserialize::<RawConfig>)
            .map_err(|source| ConfigError::Load {
                path: path.to_path_buf(),
                source: Box::new(source),
            })
    }

    /// Parses a TOML document directly (tests and tooling).
    pub fn from_toml_str(toml: &str) -> Result<Self, ConfigError> {
        config::Config::builder()
            .add_source(config::File::from_str(toml, config::FileFormat::Toml))
            .build()
            .and_then(config::Config::try_deserialize::<RawConfig>)
            .map_err(|source| ConfigError::Load {
                path: PathBuf::from("<inline>"),
                source: Box::new(source),
            })
    }

    /// Checks every field and returns typed settings, or one message per
    /// problem.
    pub fn validate(&self) -> Result<Settings, ConfigError> {
        let mut errors = Vec::new();

        let listen = parse_or_report::<SocketAddr>(&self.kps.listen, "kps.listen", &mut errors);
        if self.kps.identity_key_file.as_os_str().is_empty() {
            errors.push("kps.identity_key_file must not be empty".to_string());
        }
        let mut public_ips = Vec::new();
        for (i, ip) in self.kps.public_ips.iter().enumerate() {
            let field = format!("kps.public_ips[{i}]");
            if let Some(ip) = parse_or_report::<IpAddr>(ip.trim(), &field, &mut errors) {
                if ip.is_unspecified() || ip.is_multicast() {
                    errors.push(format!("{field} must be a unicast address (got: \"{ip}\")"));
                } else if !public_ips.contains(&ip) {
                    public_ips.push(ip);
                }
            }
        }

        let allow_remote = self.proxy.allow_non_loopback_upstreams;
        let ingress = parse_upstream(
            UPSTREAM_INGRESS,
            &self.upstreams.ingress,
            allow_remote,
            &mut errors,
        );
        let topology = parse_upstream(
            UPSTREAM_TOPOLOGY,
            &self.upstreams.topology,
            allow_remote,
            &mut errors,
        );
        let routes = validate_routes(
            &self.routes,
            ingress.as_ref(),
            topology.as_ref(),
            &mut errors,
        );

        let client_ip_header = parse_header_name(
            &self.proxy.client_ip_header,
            "proxy.client_ip_header",
            &[
                "connection",
                "keep-alive",
                "proxy-connection",
                "te",
                "trailer",
                "transfer-encoding",
                "upgrade",
                "host",
                "content-length",
                "content-type",
                "expect",
            ],
            &mut errors,
        );
        let forward_request_headers = parse_header_list(
            &self.proxy.forward_request_headers,
            "proxy.forward_request_headers",
            &mut errors,
        );
        if let (Some(ip_header), Some(list)) = (&client_ip_header, &forward_request_headers) {
            if list.contains(ip_header) {
                errors.push(format!(
                    "proxy.forward_request_headers must not include the client IP header \"{ip_header}\""
                ));
            }
        }
        let forward_response_headers = parse_header_list(
            &self.proxy.forward_response_headers,
            "proxy.forward_response_headers",
            &mut errors,
        );
        positive_u64(
            self.proxy.upstream_connect_timeout_ms,
            "proxy.upstream_connect_timeout_ms",
            &mut errors,
        );
        positive_u64(
            self.proxy.upstream_timeout_ms,
            "proxy.upstream_timeout_ms",
            &mut errors,
        );
        positive_usize(
            self.proxy.max_response_body_bytes,
            "proxy.max_response_body_bytes",
            &mut errors,
        );
        if !(1..=MAX_INFLIGHT_UPSTREAM).contains(&self.proxy.max_inflight_upstream) {
            errors.push(format!(
                "proxy.max_inflight_upstream must be between 1 and {MAX_INFLIGHT_UPSTREAM} (got: {})",
                self.proxy.max_inflight_upstream
            ));
        }
        positive_u64(
            self.proxy.upstream_pool_idle_timeout_ms,
            "proxy.upstream_pool_idle_timeout_ms",
            &mut errors,
        );

        let l = &self.limits;
        positive_usize(l.max_connections, "limits.max_connections", &mut errors);
        positive_usize(
            l.max_connections_per_ip,
            "limits.max_connections_per_ip",
            &mut errors,
        );
        if l.max_connections_per_ip > l.max_connections {
            errors.push(format!(
                "limits.max_connections_per_ip ({}) must not exceed limits.max_connections ({})",
                l.max_connections_per_ip, l.max_connections
            ));
        }
        if !(1..=128).contains(&l.ipv6_prefix_len) {
            errors.push(format!(
                "limits.ipv6_prefix_len must be between 1 and 128 (got: {})",
                l.ipv6_prefix_len
            ));
        }
        if !(1..=MAX_STREAMS_PER_CONNECTION).contains(&l.max_streams_per_connection) {
            errors.push(format!(
                "limits.max_streams_per_connection must be between 1 and {MAX_STREAMS_PER_CONNECTION} (got: {})",
                l.max_streams_per_connection
            ));
        }
        if !(MIN_HEADER_BYTES..=MAX_HEADER_BYTES).contains(&l.max_header_bytes) {
            errors.push(format!(
                "limits.max_header_bytes must be between {MIN_HEADER_BYTES} and {MAX_HEADER_BYTES} (got: {})",
                l.max_header_bytes
            ));
        }
        if !(8..=1024).contains(&l.max_headers) {
            errors.push(format!(
                "limits.max_headers must be between 8 and 1024 (got: {})",
                l.max_headers
            ));
        }
        positive_u64(
            l.header_read_timeout_ms,
            "limits.header_read_timeout_ms",
            &mut errors,
        );
        positive_u64(l.stream_timeout_ms, "limits.stream_timeout_ms", &mut errors);
        positive_u64(
            l.connection_idle_timeout_ms,
            "limits.connection_idle_timeout_ms",
            &mut errors,
        );
        if l.stream_timeout_ms <= self.proxy.upstream_timeout_ms {
            errors.push(format!(
                "limits.stream_timeout_ms ({}) must exceed proxy.upstream_timeout_ms ({}) so a slow upstream is answered with 504 before the stream is reset",
                l.stream_timeout_ms, self.proxy.upstream_timeout_ms
            ));
        }
        if l.stream_timeout_ms < l.header_read_timeout_ms {
            errors.push(format!(
                "limits.stream_timeout_ms ({}) must be at least limits.header_read_timeout_ms ({})",
                l.stream_timeout_ms, l.header_read_timeout_ms
            ));
        }

        if self.shutdown.close_linger_ms > self.shutdown.grace_period_ms {
            errors.push(format!(
                "shutdown.close_linger_ms ({}) must not exceed shutdown.grace_period_ms ({})",
                self.shutdown.close_linger_ms, self.shutdown.grace_period_ms
            ));
        }

        let bundles = if self.bundles.dir.trim().is_empty() {
            None
        } else {
            positive_usize(
                self.bundles.max_bundle_bytes,
                "bundles.max_bundle_bytes",
                &mut errors,
            );
            positive_usize(self.bundles.max_bundles, "bundles.max_bundles", &mut errors);
            Some(BundleSettings {
                dir: PathBuf::from(self.bundles.dir.trim()),
                max_bundle_bytes: self.bundles.max_bundle_bytes,
                max_bundles: self.bundles.max_bundles,
                rescan_interval: (self.bundles.rescan_interval_secs > 0)
                    .then(|| Duration::from_secs(self.bundles.rescan_interval_secs)),
                gzip: self.bundles.gzip,
            })
        };

        let metrics_listen = if self.metrics.listen.trim().is_empty() {
            None
        } else {
            let addr = parse_or_report::<SocketAddr>(
                self.metrics.listen.trim(),
                "metrics.listen",
                &mut errors,
            );
            if let Some(addr) = addr {
                if !addr.ip().is_loopback() && !self.metrics.allow_non_loopback {
                    errors.push(format!(
                        "metrics.listen must be a loopback address (got: \"{addr}\"); set metrics.allow_non_loopback = true to expose it"
                    ));
                }
            }
            addr
        };

        if let Err(e) = tracing_subscriber::EnvFilter::try_new(&self.log.filter) {
            errors.push(format!(
                "log.filter is not a valid filter (\"{}\"): {e}",
                self.log.filter
            ));
        }

        if !errors.is_empty() {
            return Err(ConfigError::Invalid(errors));
        }

        // Every Option below is Some once `errors` is empty; the fallbacks are
        // unreachable and only keep this free of unwraps.
        let (
            Some(listen),
            Some(client_ip_header),
            Some(forward_request_headers),
            Some(forward_response_headers),
        ) = (
            listen,
            client_ip_header,
            forward_request_headers,
            forward_response_headers,
        )
        else {
            return Err(ConfigError::Invalid(vec![
                "internal: validated configuration is incomplete".to_string(),
            ]));
        };

        Ok(Settings {
            listen,
            identity_key_file: self.kps.identity_key_file.clone(),
            public_ips,
            routes,
            proxy: ProxySettings {
                client_ip_header,
                forward_request_headers,
                forward_response_headers,
                connect_timeout: Duration::from_millis(self.proxy.upstream_connect_timeout_ms),
                timeout: Duration::from_millis(self.proxy.upstream_timeout_ms),
                max_response_body_bytes: self.proxy.max_response_body_bytes,
                max_inflight: self.proxy.max_inflight_upstream,
                pool_idle_timeout: Duration::from_millis(self.proxy.upstream_pool_idle_timeout_ms),
                pool_max_idle: self.proxy.upstream_pool_max_idle,
            },
            limits: Limits {
                max_connections: l.max_connections,
                max_connections_per_ip: l.max_connections_per_ip,
                ipv6_prefix_len: l.ipv6_prefix_len,
                max_streams_per_connection: l.max_streams_per_connection,
                max_header_bytes: l.max_header_bytes,
                max_headers: l.max_headers,
                header_read_timeout: Duration::from_millis(l.header_read_timeout_ms),
                stream_timeout: Duration::from_millis(l.stream_timeout_ms),
                connection_idle_timeout: Duration::from_millis(l.connection_idle_timeout_ms),
            },
            bundles,
            metrics_listen,
            log: self.log.clone(),
            shutdown_grace: Duration::from_millis(self.shutdown.grace_period_ms),
            shutdown_linger: Duration::from_millis(self.shutdown.close_linger_ms),
        })
    }
}

/// Validated, typed settings the server runs on.
#[derive(Debug, Clone)]
pub struct Settings {
    pub listen: SocketAddr,
    pub identity_key_file: PathBuf,
    pub public_ips: Vec<IpAddr>,
    pub routes: Vec<Route>,
    pub proxy: ProxySettings,
    pub limits: Limits,
    pub bundles: Option<BundleSettings>,
    pub metrics_listen: Option<SocketAddr>,
    pub log: LogConfig,
    pub shutdown_grace: Duration,
    pub shutdown_linger: Duration,
}

/// A validated upstream: scheme + authority of a loopback HTTP service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub name: String,
    pub scheme: Scheme,
    pub authority: Authority,
    /// `Host` header value sent upstream.
    pub host_header: HeaderValue,
}

/// A validated allowlist entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub name: String,
    pub method: Method,
    pub path: String,
    pub upstream: Upstream,
    pub max_body_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct ProxySettings {
    pub client_ip_header: HeaderName,
    pub forward_request_headers: Vec<HeaderName>,
    pub forward_response_headers: Vec<HeaderName>,
    pub connect_timeout: Duration,
    pub timeout: Duration,
    pub max_response_body_bytes: usize,
    pub max_inflight: usize,
    pub pool_idle_timeout: Duration,
    pub pool_max_idle: usize,
}

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    pub ipv6_prefix_len: u8,
    pub max_streams_per_connection: usize,
    pub max_header_bytes: usize,
    pub max_headers: usize,
    pub header_read_timeout: Duration,
    pub stream_timeout: Duration,
    pub connection_idle_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct BundleSettings {
    pub dir: PathBuf,
    pub max_bundle_bytes: usize,
    pub max_bundles: usize,
    pub rescan_interval: Option<Duration>,
    pub gzip: bool,
}

fn parse_or_report<T: std::str::FromStr>(
    value: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<T>
where
    T::Err: std::fmt::Display,
{
    match value.parse::<T>() {
        Ok(v) => Some(v),
        Err(e) => {
            errors.push(format!("{field} is invalid (got: \"{value}\"): {e}"));
            None
        }
    }
}

fn positive_u64(value: u64, field: &str, errors: &mut Vec<String>) {
    if value == 0 {
        errors.push(format!("{field} must be greater than 0"));
    }
}

fn positive_usize(value: usize, field: &str, errors: &mut Vec<String>) {
    if value == 0 {
        errors.push(format!("{field} must be greater than 0"));
    }
}

fn parse_upstream(
    name: &str,
    value: &str,
    allow_remote: bool,
    errors: &mut Vec<String>,
) -> Option<Upstream> {
    let field = format!("upstreams.{name}");
    let uri: Uri = match value.parse() {
        Ok(uri) => uri,
        Err(e) => {
            errors.push(format!(
                "{field} is not a valid URL (got: \"{value}\"): {e}"
            ));
            return None;
        }
    };
    if uri.scheme() != Some(&Scheme::HTTP) {
        errors.push(format!(
            "{field} must be a plain http:// URL to a loopback service (got: \"{value}\")"
        ));
        return None;
    }
    let Some(authority) = uri.authority().cloned() else {
        errors.push(format!("{field} has no host (got: \"{value}\")"));
        return None;
    };
    if authority.port_u16().is_none() {
        errors.push(format!("{field} must name a port (got: \"{value}\")"));
        return None;
    }
    let has_path = !(uri.path().is_empty() || uri.path() == "/");
    if has_path || uri.query().is_some() {
        errors.push(format!(
            "{field} must not have a path or query; routes supply the path (got: \"{value}\")"
        ));
        return None;
    }
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let loopback = host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
    if !loopback && !allow_remote {
        errors.push(format!(
            "{field} must be a loopback address such as http://127.0.0.1:15002 (got: \"{value}\"); the node only reads the client IP header on loopback connections"
        ));
        return None;
    }
    let host_header = match HeaderValue::from_str(authority.as_str()) {
        Ok(v) => v,
        Err(e) => {
            errors.push(format!("{field} authority is not a valid Host value: {e}"));
            return None;
        }
    };
    Some(Upstream {
        name: name.to_string(),
        scheme: Scheme::HTTP,
        authority,
        host_header,
    })
}

fn validate_routes(
    routes: &[RouteConfig],
    ingress: Option<&Upstream>,
    topology: Option<&Upstream>,
    errors: &mut Vec<String>,
) -> Vec<Route> {
    if routes.is_empty() {
        errors.push("routes must list at least one route".to_string());
    }
    let mut names = HashSet::new();
    let mut keys = HashSet::new();
    let mut out = Vec::new();
    for (i, r) in routes.iter().enumerate() {
        let field = format!("routes[{i}]");
        let before = errors.len();
        if r.name.trim().is_empty()
            || !r
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            errors.push(format!(
                "{field}.name must be non-empty ASCII letters, digits, '-' or '_' (got: \"{}\")",
                r.name
            ));
        } else if !names.insert(r.name.clone()) {
            errors.push(format!(
                "{field}.name \"{}\" is used by another route",
                r.name
            ));
        }
        let method = match r.method.to_ascii_uppercase().as_str() {
            "GET" => Some(Method::GET),
            "HEAD" => Some(Method::HEAD),
            "POST" => Some(Method::POST),
            "PUT" => Some(Method::PUT),
            "PATCH" => Some(Method::PATCH),
            "DELETE" => Some(Method::DELETE),
            other => {
                errors.push(format!(
                    "{field}.method must be one of GET, HEAD, POST, PUT, PATCH, DELETE (got: \"{other}\")"
                ));
                None
            }
        };
        let path_ok = r.path.starts_with('/')
            && !r.path.contains(['?', '#', '%', '\\', ' '])
            && !r.path.split('/').any(|seg| seg == ".." || seg == ".")
            && r.path.parse::<http::uri::PathAndQuery>().is_ok();
        if !path_ok {
            errors.push(format!(
                "{field}.path must be an absolute path without query, fragment, escapes or dot segments (got: \"{}\")",
                r.path
            ));
        } else if r.path == METADATA_PATH || r.path.starts_with(BUNDLE_PATH_PREFIX) {
            errors.push(format!(
                "{field}.path \"{}\" is served by nox-kps itself and cannot be proxied",
                r.path
            ));
        }
        if let Some(m) = &method {
            if !keys.insert((m.clone(), r.path.clone())) {
                errors.push(format!("{field} duplicates {} {}", m, r.path));
            }
            if (*m == Method::GET || *m == Method::HEAD) && r.max_body_bytes > 0 {
                errors.push(format!("{field}.max_body_bytes must be 0 for {m} routes"));
            }
        }
        if r.max_body_bytes > MAX_ROUTE_BODY_BYTES {
            errors.push(format!(
                "{field}.max_body_bytes must be at most {MAX_ROUTE_BODY_BYTES} (got: {})",
                r.max_body_bytes
            ));
        }
        let upstream = match r.upstream.as_str() {
            UPSTREAM_INGRESS => ingress.cloned(),
            UPSTREAM_TOPOLOGY => topology.cloned(),
            other => {
                errors.push(format!(
                    "{field}.upstream must be \"{UPSTREAM_INGRESS}\" or \"{UPSTREAM_TOPOLOGY}\" (got: \"{other}\")"
                ));
                None
            }
        };
        if errors.len() == before {
            if let (Some(method), Some(upstream)) = (method, upstream) {
                out.push(Route {
                    name: r.name.clone(),
                    method,
                    path: r.path.clone(),
                    upstream,
                    max_body_bytes: r.max_body_bytes,
                });
            }
        }
    }
    out
}

fn parse_header_name(
    value: &str,
    field: &str,
    forbidden: &[&str],
    errors: &mut Vec<String>,
) -> Option<HeaderName> {
    let name = match HeaderName::from_bytes(value.trim().as_bytes()) {
        Ok(name) => name,
        Err(e) => {
            errors.push(format!(
                "{field} is not a valid header name (got: \"{value}\"): {e}"
            ));
            return None;
        }
    };
    if forbidden.contains(&name.as_str()) {
        errors.push(format!("{field} must not be \"{name}\""));
        return None;
    }
    Some(name)
}

fn parse_header_list(
    values: &[String],
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<HeaderName>> {
    let before = errors.len();
    let mut out: Vec<HeaderName> = Vec::new();
    for (i, v) in values.iter().enumerate() {
        if let Some(name) = parse_header_name(v, &format!("{field}[{i}]"), RESERVED_HEADERS, errors)
        {
            if !out.contains(&name) {
                out.push(name);
            }
        }
    }
    (errors.len() == before).then_some(out)
}

/// Settings as a redacted, human-readable summary for `check-config` and the
/// startup log. Holds no secrets: the identity key is referenced by path only.
#[must_use]
pub fn summary(settings: &Settings) -> BTreeMap<&'static str, String> {
    let mut m = BTreeMap::new();
    m.insert("kps.listen (udp)", settings.listen.to_string());
    m.insert(
        "kps.identity_key_file",
        settings.identity_key_file.display().to_string(),
    );
    m.insert(
        "kps.public_ips",
        if settings.public_ips.is_empty() {
            "(auto-detect)".to_string()
        } else {
            settings
                .public_ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        },
    );
    m.insert(
        "routes",
        settings
            .routes
            .iter()
            .map(|r| format!("{} {} -> {}", r.method, r.path, r.upstream.authority))
            .collect::<Vec<_>>()
            .join("; "),
    );
    m.insert(
        "proxy.client_ip_header",
        settings.proxy.client_ip_header.to_string(),
    );
    m.insert(
        "limits",
        format!(
            "connections {} (per ip {}), streams/conn {}, header {} B, idle {:?}, stream {:?}",
            settings.limits.max_connections,
            settings.limits.max_connections_per_ip,
            settings.limits.max_streams_per_connection,
            settings.limits.max_header_bytes,
            settings.limits.connection_idle_timeout,
            settings.limits.stream_timeout,
        ),
    );
    m.insert(
        "bundles.dir",
        settings
            .bundles
            .as_ref()
            .map_or_else(|| "(disabled)".to_string(), |b| b.dir.display().to_string()),
    );
    m.insert(
        "metrics.listen (tcp)",
        settings
            .metrics_listen
            .map_or_else(|| "(disabled)".to_string(), |a| a.to_string()),
    );
    m
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::collections::HashMap;

    use super::*;

    fn errors_of(raw: &RawConfig) -> Vec<String> {
        match raw.validate() {
            Ok(_) => Vec::new(),
            Err(ConfigError::Invalid(errors)) => errors,
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn defaults_are_valid_and_match_the_node_ports() {
        let settings = RawConfig::default().validate().expect("defaults validate");
        assert_eq!(settings.listen.port(), 15005);
        assert_eq!(settings.routes.len(), 4);
        let by_name: HashMap<_, _> = settings
            .routes
            .iter()
            .map(|r| (r.name.as_str(), r))
            .collect();
        let packets = by_name["nox-packets"];
        assert_eq!(packets.method, Method::POST);
        assert_eq!(packets.path, "/api/v1/packets");
        assert_eq!(packets.upstream.authority.as_str(), "127.0.0.1:15002");
        assert_eq!(packets.max_body_bytes, 32_768);
        assert_eq!(
            by_name["nox-topology"].upstream.authority.as_str(),
            "127.0.0.1:15003"
        );
        assert_eq!(settings.proxy.client_ip_header, "x-forwarded-for");
        assert_eq!(settings.metrics_listen.unwrap().port(), 15006);
        assert!(settings.bundles.is_none());
    }

    #[test]
    fn empty_toml_is_the_default_config() {
        let raw = RawConfig::from_toml_str("").unwrap();
        assert_eq!(raw, RawConfig::default());
        assert_eq!(raw.routes, default_routes());
    }

    #[test]
    fn partial_sections_keep_the_other_defaults() {
        let raw = RawConfig::from_toml_str(
            "[kps]\npublic_ips = [\"203.0.113.5\"]\n[limits]\nmax_connections = 512\n",
        )
        .unwrap();
        assert_eq!(raw.kps.listen, "[::]:15005");
        assert_eq!(raw.kps.public_ips, vec!["203.0.113.5".to_string()]);
        assert_eq!(raw.limits.max_connections, 512);
        assert_eq!(raw.limits.max_connections_per_ip, 16);
        assert_eq!(raw.routes, default_routes());
    }

    #[test]
    fn configured_routes_replace_the_defaults() {
        let raw = RawConfig::from_toml_str(
            "[[routes]]\nname = \"only\"\nmethod = \"GET\"\npath = \"/health\"\nupstream = \"ingress\"\n",
        )
        .unwrap();
        assert_eq!(raw.routes.len(), 1);
        assert_eq!(raw.routes[0].name, "only");
        raw.validate().unwrap();
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let err = RawConfig::from_toml_str("[limits]\nmax_conections = 5\n").unwrap_err();
        assert!(err.to_string().contains("max_conections"), "{err}");
    }

    #[test]
    fn environment_overrides_scalars_lists_and_nested_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[limits]\nmax_connections = 300\n").unwrap();
        let env: HashMap<String, String> = [
            ("NOX_KPS__KPS__PUBLIC_IPS", "203.0.113.5,2001:db8::7"),
            ("NOX_KPS__LIMITS__MAX_CONNECTIONS_PER_IP", "4"),
            ("NOX_KPS__PROXY__CLIENT_IP_HEADER", "x-real-ip"),
            ("NOX_KPS__UPSTREAMS__TOPOLOGY", "http://127.0.0.1:15001"),
            ("NOX_KPS__BUNDLES__GZIP", "false"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let raw = RawConfig::load_with_env(&ConfigSource::Explicit(path), Some(env)).unwrap();
        assert_eq!(raw.limits.max_connections, 300);
        assert_eq!(raw.limits.max_connections_per_ip, 4);
        assert_eq!(raw.kps.public_ips, vec!["203.0.113.5", "2001:db8::7"]);
        assert_eq!(raw.proxy.client_ip_header, "x-real-ip");
        assert_eq!(raw.upstreams.topology, "http://127.0.0.1:15001");
        assert_eq!(
            raw.upstreams.ingress, "http://127.0.0.1:15002",
            "other upstream keeps its default"
        );
        assert!(!raw.bundles.gzip);
        let settings = raw.validate().unwrap();
        assert_eq!(settings.public_ips.len(), 2);
    }

    #[test]
    fn explicit_config_path_must_exist_but_default_path_may_be_absent() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.toml");
        let err = RawConfig::load_with_env(
            &ConfigSource::Explicit(missing.clone()),
            Some(HashMap::new()),
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::Missing { .. }), "{err}");
        let raw = RawConfig::load_with_env(&ConfigSource::Default(missing), Some(HashMap::new()))
            .unwrap();
        assert_eq!(raw, RawConfig::default());
    }

    #[test]
    fn rejects_non_loopback_upstreams_by_default() {
        let mut raw = RawConfig::default();
        raw.upstreams.ingress = "http://10.0.0.5:15002".to_string();
        let errors = errors_of(&raw);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("upstreams.ingress must be a loopback")),
            "{errors:?}"
        );
        raw.proxy.allow_non_loopback_upstreams = true;
        assert!(errors_of(&raw).is_empty());
    }

    #[test]
    fn rejects_bad_upstream_urls() {
        for bad in [
            "https://127.0.0.1:15002",
            "127.0.0.1:15002",
            "http://127.0.0.1",
            "http://127.0.0.1:15002/api",
            "not a url",
        ] {
            let mut raw = RawConfig::default();
            raw.upstreams.ingress = bad.to_string();
            assert!(!errors_of(&raw).is_empty(), "{bad} should be rejected");
        }
        let mut raw = RawConfig::default();
        raw.upstreams.ingress = "http://[::1]:15002".to_string();
        assert!(errors_of(&raw).is_empty());
        raw.upstreams.ingress = "http://localhost:15002".to_string();
        assert!(errors_of(&raw).is_empty());
    }

    #[test]
    fn rejects_unsafe_routes() {
        let route = |method: &str, path: &str, upstream: &str, body: usize| RouteConfig {
            name: format!("r{}", path.len()),
            method: method.to_string(),
            path: path.to_string(),
            upstream: upstream.to_string(),
            max_body_bytes: body,
        };
        for (r, needle) in [
            (route("GET", "no-slash", "ingress", 0), "path must be"),
            (route("GET", "/a/../b", "ingress", 0), "path must be"),
            (route("GET", "/a?x=1", "ingress", 0), "path must be"),
            (route("GET", "/a%2e", "ingress", 0), "path must be"),
            (
                route("GET", "/keccak/ab/cd", "ingress", 0),
                "served by nox-kps",
            ),
            (
                route("GET", "/metadata.json", "ingress", 0),
                "served by nox-kps",
            ),
            (route("CONNECT", "/x", "ingress", 0), "method must be"),
            (route("GET", "/x", "elsewhere", 0), "upstream must be"),
            (route("GET", "/x", "ingress", 10), "must be 0 for GET"),
            (
                route("POST", "/x", "ingress", MAX_ROUTE_BODY_BYTES + 1),
                "at most",
            ),
        ] {
            let raw = RawConfig {
                routes: vec![r],
                ..RawConfig::default()
            };
            let errors = errors_of(&raw);
            assert!(
                errors.iter().any(|e| e.contains(needle)),
                "expected {needle:?} in {errors:?}"
            );
        }
        let dup = RawConfig {
            routes: vec![
                route("GET", "/x", "ingress", 0),
                RouteConfig {
                    name: "other".into(),
                    ..route("GET", "/x", "ingress", 0)
                },
            ],
            ..RawConfig::default()
        };
        assert!(errors_of(&dup).iter().any(|e| e.contains("duplicates")));
        let empty = RawConfig {
            routes: vec![],
            ..RawConfig::default()
        };
        assert!(errors_of(&empty)
            .iter()
            .any(|e| e.contains("at least one route")));
    }

    #[test]
    fn rejects_reserved_or_invalid_headers() {
        let mut raw = RawConfig::default();
        raw.proxy.client_ip_header = "host".to_string();
        assert!(errors_of(&raw)
            .iter()
            .any(|e| e.contains("client_ip_header")));
        raw.proxy.client_ip_header = "bad header".to_string();
        assert!(errors_of(&raw)
            .iter()
            .any(|e| e.contains("client_ip_header")));

        let mut raw = RawConfig::default();
        raw.proxy
            .forward_request_headers
            .push("x-forwarded-for".to_string());
        assert!(
            !errors_of(&raw).is_empty(),
            "forwarding headers are reserved"
        );
        let mut raw = RawConfig::default();
        raw.proxy.client_ip_header = "x-client".to_string();
        raw.proxy
            .forward_request_headers
            .push("x-client".to_string());
        assert!(errors_of(&raw)
            .iter()
            .any(|e| e.contains("client IP header")));
        let mut raw = RawConfig::default();
        raw.proxy
            .forward_response_headers
            .push("transfer-encoding".to_string());
        assert!(!errors_of(&raw).is_empty());
    }

    #[test]
    fn rejects_out_of_range_limits() {
        type Mutation = Box<dyn Fn(&mut RawConfig)>;
        let cases: Vec<(Mutation, &str)> = vec![
            (
                Box::new(|r| r.limits.max_connections = 0),
                "limits.max_connections must",
            ),
            (
                Box::new(|r| r.limits.max_connections_per_ip = 1000),
                "must not exceed",
            ),
            (
                Box::new(|r| r.limits.ipv6_prefix_len = 0),
                "ipv6_prefix_len",
            ),
            (
                Box::new(|r| r.limits.max_header_bytes = 4096),
                "max_header_bytes",
            ),
            (Box::new(|r| r.limits.max_headers = 2), "max_headers"),
            (
                Box::new(|r| r.limits.stream_timeout_ms = 1000),
                "must exceed proxy.upstream_timeout_ms",
            ),
            (
                Box::new(|r| r.proxy.max_inflight_upstream = 0),
                "max_inflight_upstream",
            ),
            (Box::new(|r| r.kps.listen = "15005".into()), "kps.listen"),
            (
                Box::new(|r| r.kps.public_ips = vec!["0.0.0.0".into()]),
                "unicast",
            ),
            (
                Box::new(|r| r.kps.public_ips = vec!["nope".into()]),
                "kps.public_ips[0]",
            ),
            (
                Box::new(|r| r.metrics.listen = "0.0.0.0:15006".into()),
                "loopback",
            ),
            (Box::new(|r| r.log.filter = "=[".into()), "log.filter"),
        ];
        for (mutate, needle) in cases {
            let mut raw = RawConfig::default();
            mutate(&mut raw);
            let errors = errors_of(&raw);
            assert!(
                errors.iter().any(|e| e.contains(needle)),
                "expected {needle:?} in {errors:?}"
            );
        }
    }

    #[test]
    fn reports_every_problem_at_once() {
        let mut raw = RawConfig::default();
        raw.limits.max_connections = 0;
        raw.kps.listen = "x".into();
        raw.proxy.client_ip_header = "host".into();
        assert!(errors_of(&raw).len() >= 3);
    }

    #[test]
    fn bundles_and_metrics_can_be_disabled_or_enabled() {
        let mut raw = RawConfig::default();
        raw.metrics.listen = String::new();
        raw.bundles.dir = "/srv/bundles".into();
        raw.bundles.rescan_interval_secs = 0;
        let s = raw.validate().unwrap();
        assert!(s.metrics_listen.is_none());
        let b = s.bundles.unwrap();
        assert_eq!(b.dir, PathBuf::from("/srv/bundles"));
        assert!(b.rescan_interval.is_none());
    }

    #[test]
    fn summary_names_no_secrets() {
        let s = RawConfig::default().validate().unwrap();
        let text = format!("{:?}", summary(&s));
        assert!(text.contains("kps.key"));
        assert!(!text.contains("PRIVATE"));
    }
}
