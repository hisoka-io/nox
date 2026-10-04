//! Configuration: a TOML file plus `NOX_KPS__<KEY>` environment overrides
//! (`NOX_KPS__LIMITS__MAX_CONNECTIONS=256`), validated into [`Settings`]
//! before anything binds a socket.
//!
//! [`RawConfig`] mirrors the file format (strings and plain integers, so the
//! TOML and the environment stay easy to write); [`RawConfig::validate`]
//! turns it into typed [`Settings`] and reports every invalid field at once,
//! naming the field, the value and what was expected.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use http::header::HeaderName;
use http::HeaderValue;
use serde::{Deserialize, Serialize};

use crate::error::ConfigError;
use crate::identity::is_non_public;

/// Default config file location inside the container image.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/nox-kps/config.toml";
/// Environment variable prefix for overrides.
pub const ENV_PREFIX: &str = "NOX_KPS";
/// Separator between the prefix, sections and fields in override variables.
pub const ENV_SEPARATOR: &str = "__";

/// Size of one Sphinx packet (`nox-crypto` `PACKET_SIZE`). The packet route
/// accepts bodies of exactly this length.
pub const SPHINX_PACKET_BYTES: usize = 32_768;
/// Hex length of one SURB ID (`nox-node` `SURB_ID_HEX_LEN`).
pub const SURB_ID_HEX_LEN: usize = 32;

/// Lowest header-block cap hyper accepts (its read buffer cannot be smaller).
pub const MIN_HEADER_BYTES: usize = 8 * 1024;
/// Upper bound for the header-block cap; KPS-HTTP/1 recommends 16 KiB.
pub const MAX_HEADER_BYTES: usize = 1024 * 1024;
/// Upper bound for any relayed body or bundle (the anon-rpc harness caps
/// bundles at 64 MiB; claim responses stay far below it).
pub const MAX_BODY_BYTES: usize = 256 * 1024 * 1024;
/// Upper bound for concurrent streams per connection.
pub const MAX_STREAMS_PER_CONNECTION: usize = 10_000;
/// Upper bound for any timeout, in milliseconds (one day).
pub const MAX_TIMEOUT_MS: u64 = 86_400_000;

/// Header names a client-IP header may not take: framing, hop-by-hop and
/// routing headers the proxy sets or strips itself.
const RESERVED_CLIENT_IP_HEADERS: &[&str] = &[
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
];

/// The file/environment shape of the configuration (ARCHITECTURE §2.10).
/// Every key has a default except `advertise`, which a node must set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct RawConfig {
    /// UDP bind address. WebRTC and QUIC share this one port. `[::]` serves
    /// IPv4 and IPv6 on a dual-stack host.
    pub listen: String,
    /// Public IPs clients dial. EC2 hosts sit behind 1:1 NAT, so the public
    /// address cannot be detected locally and must be listed here.
    pub advertise: Vec<String>,
    /// Permits private, shared or loopback addresses in `advertise` (local
    /// test beds only).
    pub allow_private_advertise: bool,
    /// Persistent identity (combined PRIVATE KEY + CERTIFICATE PEM, mode
    /// 0600). Created once by `nox-kps init`; `run` never creates it.
    pub key_file: PathBuf,
    /// The certhash `init` printed for `key_file`. `run` refuses to start
    /// without it or when the loaded key has another certhash, so a swapped or
    /// wrongly restored volume never serves under the published address.
    pub expected_certhash: String,
    /// The node's registry address, shown in `/metadata.json` (informational).
    pub node_address: String,
    /// The node's HTTP ingress on loopback (packets, claims, health).
    pub upstream_ingress: String,
    /// The node's topology API on loopback.
    pub upstream_topology: String,
    /// Header that carries the client's KPS source IP to the node. Must match
    /// the node's `[ingress] client_ip_header`.
    pub client_ip_header: String,
    /// Directory of keccak-named worker bundles (`<hh>/<62 hex>`). Empty
    /// disables the `kps:` bundle resolver.
    pub keccak_dir: String,
    /// Loopback TCP address for `/metrics` and `/healthz`.
    pub admin_listen: String,
    /// `trace`, `debug`, `info`, `warn` or `error` for nox-kps itself (other
    /// crates log errors only, because transport debug output names peers),
    /// or a full `tracing` filter such as `warn,nox_kps=debug`. `RUST_LOG`
    /// replaces it.
    pub log_level: String,
    pub log_format: LogFormat,
    /// Seconds between the counter summaries logged at `info`; 0 disables.
    pub summary_interval_secs: u64,
    pub limits: LimitsConfig,
    pub shutdown: ShutdownConfig,
}

impl Default for RawConfig {
    fn default() -> Self {
        Self {
            listen: "[::]:15005".to_string(),
            advertise: Vec::new(),
            allow_private_advertise: false,
            key_file: PathBuf::from("/var/lib/nox-kps/kps.key"),
            expected_certhash: String::new(),
            node_address: String::new(),
            upstream_ingress: "127.0.0.1:15002".to_string(),
            upstream_topology: "127.0.0.1:15003".to_string(),
            client_ip_header: "x-real-ip".to_string(),
            keccak_dir: "/var/lib/nox-kps/keccak".to_string(),
            admin_listen: "127.0.0.1:15006".to_string(),
            log_level: "info".to_string(),
            log_format: LogFormat::Json,
            summary_interval_secs: 60,
            limits: LimitsConfig::default(),
            shutdown: ShutdownConfig::default(),
        }
    }
}

/// Every resource limit (ARCHITECTURE §2.6). Defaults are sized for a 2 GiB
/// host running the node next to nox-kps.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    /// Concurrent KPS connections across all clients.
    pub max_connections: usize,
    /// Concurrent KPS connections per client IP (IPv6: per prefix).
    pub max_connections_per_ip: usize,
    /// IPv6 clients are counted per prefix of this length (the node uses /64).
    pub ipv6_prefix_len: u8,
    /// Concurrent streams per connection; extra streams are reset with the
    /// KPS `queue-full` code.
    pub max_streams_per_connection: usize,
    /// A connection with no stream activity for this long is closed.
    pub conn_idle_timeout_secs: u64,
    /// A connection is closed after this long regardless of activity.
    pub conn_max_lifetime_secs: u64,
    /// Request header block cap, request line included (KPS-HTTP/1: 16 KiB).
    pub header_max_bytes: usize,
    /// Maximum number of request header fields.
    pub max_headers: usize,
    /// Stream open to complete request header block (KPS-HTTP/1: 30 s).
    pub header_read_timeout_ms: u64,
    /// Stream open to response written; the stream is reset after it.
    pub stream_timeout_ms: u64,
    /// This many streams in a row hitting `stream_timeout_ms` close the
    /// connection: its transport is treated as stalled, which frees its
    /// buffers and lets the client redial.
    pub max_stream_timeouts_per_connection: usize,
    /// Upper bound for resetting a stream or closing a connection, so a
    /// stalled transport cannot hold a task.
    pub close_timeout_ms: u64,
    /// Per-IP token buckets (requests per second and burst) per route class.
    pub packet_rate_per_ip: u32,
    pub packet_burst: u32,
    pub claim_rate_per_ip: u32,
    pub claim_burst: u32,
    pub topology_rate_per_ip: u32,
    pub topology_burst: u32,
    pub bundle_rate_per_ip: u32,
    pub bundle_burst: u32,
    /// Client buckets tracked per route class before idle ones are swept;
    /// when every tracked bucket is active, new clients get `429`.
    pub rate_limit_max_clients: usize,
    /// Largest `POST /api/v1/responses/claim` body (nginx uses 64 KiB).
    pub claim_request_max_bytes: usize,
    /// Most SURB IDs in one claim.
    pub claim_max_surb_ids: usize,
    /// Largest claim response relayed (JSON is ~3.6x the binary size).
    pub claim_response_max_bytes: usize,
    /// Largest topology response relayed.
    pub topology_response_max_bytes: usize,
    /// Largest packet-submit or health response relayed.
    pub small_response_max_bytes: usize,
    pub upstream_connect_timeout_ms: u64,
    pub upstream_packet_timeout_ms: u64,
    pub upstream_claim_timeout_ms: u64,
    pub upstream_topology_timeout_ms: u64,
    pub upstream_health_timeout_ms: u64,
    /// Upstream requests in flight at once across all clients; beyond it
    /// clients get `503` with `Retry-After`.
    pub max_inflight_upstream: usize,
    /// One topology response is shared by every client for this long.
    pub topology_cache_ms: u64,
    /// One upstream health probe answers every `GET /health` for this long.
    pub health_cache_ms: u64,
    /// Bundle files larger than this are not served (harness cap: 64 MiB).
    pub max_bundle_bytes: usize,
    /// Most bundles held in memory.
    pub max_bundles: usize,
    /// Bundle responses being written at once (each is ~0.7 MB, and WebRTC
    /// costs ~4x QUIC CPU); beyond it clients get `503` with `Retry-After`.
    pub max_concurrent_bundle_streams: usize,
    /// Seconds between bundle directory rescans; 0 scans only at startup.
    pub bundle_rescan_secs: u64,
    /// Serve a gzip copy to clients that list `gzip` in `Accept-Encoding`.
    /// Off in v1: identity is always acceptable (anon-rpc SPEC §4.2).
    pub bundle_gzip: bool,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: 256,
            max_connections_per_ip: 16,
            ipv6_prefix_len: 64,
            max_streams_per_connection: 32,
            conn_idle_timeout_secs: 120,
            conn_max_lifetime_secs: 3_600,
            header_max_bytes: 16 * 1024,
            max_headers: 64,
            header_read_timeout_ms: 10_000,
            stream_timeout_ms: 30_000,
            max_stream_timeouts_per_connection: 2,
            close_timeout_ms: 1_000,
            packet_rate_per_ip: 20,
            packet_burst: 100,
            claim_rate_per_ip: 30,
            claim_burst: 200,
            topology_rate_per_ip: 2,
            topology_burst: 10,
            bundle_rate_per_ip: 1,
            bundle_burst: 5,
            rate_limit_max_clients: 100_000,
            claim_request_max_bytes: 64 * 1024,
            claim_max_surb_ids: 1024,
            claim_response_max_bytes: 16 * 1024 * 1024,
            topology_response_max_bytes: 1024 * 1024,
            small_response_max_bytes: 1024,
            upstream_connect_timeout_ms: 1_000,
            upstream_packet_timeout_ms: 5_000,
            upstream_claim_timeout_ms: 10_000,
            upstream_topology_timeout_ms: 5_000,
            upstream_health_timeout_ms: 1_000,
            max_inflight_upstream: 128,
            topology_cache_ms: 1_000,
            health_cache_ms: 1_000,
            max_bundle_bytes: 64 * 1024 * 1024,
            max_bundles: 16,
            max_concurrent_bundle_streams: 8,
            bundle_rescan_secs: 60,
            bundle_gzip: false,
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

/// Log output format.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Text,
    #[default]
    Json,
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
            .with_list_parse_key("advertise");
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
        let mut v = Validator::default();

        let listen = v.parse::<SocketAddr>(&self.listen, "listen", "an ip:port such as [::]:15005");
        let advertise = self.validate_advertise(&mut v);
        if self.key_file.as_os_str().is_empty() {
            v.err("key_file must not be empty (expected a path such as /var/lib/nox-kps/kps.key)");
        }
        let node_address = self.validate_node_address(&mut v);
        let expected_certhash = self.expected_certhash.trim();
        if !expected_certhash.is_empty() && !is_certhash(expected_certhash) {
            v.err(format!(
                "expected_certhash must be the certhash `nox-kps init` printed (\"uEi\" + 44 base64url characters) or empty (got: \"{expected_certhash}\")"
            ));
        }
        let ingress = parse_upstream("upstream_ingress", &self.upstream_ingress, &mut v);
        let topology = parse_upstream("upstream_topology", &self.upstream_topology, &mut v);
        let client_ip_header = parse_client_ip_header(&self.client_ip_header, &mut v);
        let admin_listen = v
            .parse::<SocketAddr>(
                self.admin_listen.trim(),
                "admin_listen",
                "a loopback ip:port such as 127.0.0.1:15006",
            )
            .filter(|addr| {
                let ok = addr.ip().is_loopback();
                if !ok {
                    v.err(format!(
                        "admin_listen must be a loopback address (got: \"{addr}\"); metrics and health stay on the host"
                    ));
                }
                ok
            });
        let log_filter = log_filter(&self.log_level);
        if let Err(e) = tracing_subscriber::EnvFilter::try_new(&log_filter) {
            v.err(format!(
                "log_level must be a level (trace, debug, info, warn, error) or a tracing filter (got: \"{}\"): {e}",
                self.log_level
            ));
        }
        let limits = self.limits.validate(&mut v);
        if self.shutdown.close_linger_ms > self.shutdown.grace_period_ms {
            v.err(format!(
                "shutdown.close_linger_ms ({}) must not exceed shutdown.grace_period_ms ({})",
                self.shutdown.close_linger_ms, self.shutdown.grace_period_ms
            ));
        }
        v.timeout(self.shutdown.grace_period_ms, "shutdown.grace_period_ms");

        if !v.errors.is_empty() {
            return Err(ConfigError::Invalid(v.errors));
        }
        let (
            Some(listen),
            Some(ingress),
            Some(topology),
            Some(client_ip_header),
            Some(admin_listen),
            Some(limits),
        ) = (
            listen,
            ingress,
            topology,
            client_ip_header,
            admin_listen,
            limits,
        )
        else {
            return Err(ConfigError::Invalid(vec![
                "internal: a field failed to parse without reporting an error".to_string(),
            ]));
        };
        let keccak_dir = self.keccak_dir.trim();
        Ok(Settings {
            listen,
            advertise,
            key_file: self.key_file.clone(),
            expected_certhash: (!expected_certhash.is_empty())
                .then(|| expected_certhash.to_string()),
            node_address,
            upstream_ingress: ingress,
            upstream_topology: topology,
            client_ip_header,
            keccak_dir: (!keccak_dir.is_empty()).then(|| PathBuf::from(keccak_dir)),
            admin_listen,
            log_filter,
            log_format: self.log_format,
            summary_interval: (self.summary_interval_secs > 0)
                .then(|| Duration::from_secs(self.summary_interval_secs)),
            limits,
            shutdown_grace: Duration::from_millis(self.shutdown.grace_period_ms),
            shutdown_linger: Duration::from_millis(self.shutdown.close_linger_ms),
        })
    }

    fn validate_advertise(&self, v: &mut Validator) -> Vec<IpAddr> {
        if self.advertise.is_empty() {
            v.err(
                "advertise must list the node's public IP(s) (got: []); EC2 hosts are behind 1:1 NAT, so the public address cannot be detected locally",
            );
        }
        let mut out = Vec::new();
        for (i, raw) in self.advertise.iter().enumerate() {
            let field = format!("advertise[{i}]");
            let trimmed = raw.trim().trim_start_matches('[').trim_end_matches(']');
            let Some(ip) = v.parse::<IpAddr>(trimmed, &field, "an IPv4 or IPv6 address") else {
                continue;
            };
            let ip = ip.to_canonical();
            if ip.is_unspecified() || ip.is_multicast() {
                v.err(format!(
                    "{field} must be a unicast address (got: \"{raw}\")"
                ));
            } else if is_non_public(ip) && !self.allow_private_advertise {
                v.err(format!(
                    "{field} is not publicly routable (got: \"{raw}\"); remote clients cannot dial it. Set allow_private_advertise = true for a local test bed"
                ));
            } else if !out.contains(&ip) {
                out.push(ip);
            }
        }
        out
    }

    fn validate_node_address(&self, v: &mut Validator) -> Option<String> {
        let addr = self.node_address.trim();
        if addr.is_empty() {
            return None;
        }
        let hex = addr.strip_prefix("0x").unwrap_or("");
        if hex.len() == 40 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            Some(format!("0x{}", hex.to_ascii_lowercase()))
        } else {
            v.err(format!(
                "node_address must be a 0x-prefixed 20-byte hex address or empty (got: \"{addr}\")"
            ));
            None
        }
    }
}

impl LimitsConfig {
    fn validate(&self, v: &mut Validator) -> Option<Limits> {
        let before = v.errors.len();
        v.range(self.max_connections, 1, 1_000_000, "limits.max_connections");
        v.range(
            self.max_connections_per_ip,
            1,
            self.max_connections.max(1),
            "limits.max_connections_per_ip",
        );
        v.range(
            usize::from(self.ipv6_prefix_len),
            1,
            128,
            "limits.ipv6_prefix_len",
        );
        v.range(
            self.max_streams_per_connection,
            1,
            MAX_STREAMS_PER_CONNECTION,
            "limits.max_streams_per_connection",
        );
        v.range(
            self.header_max_bytes,
            MIN_HEADER_BYTES,
            MAX_HEADER_BYTES,
            "limits.header_max_bytes",
        );
        v.range(self.max_headers, 8, 1024, "limits.max_headers");
        v.range(
            self.max_stream_timeouts_per_connection,
            1,
            1_000,
            "limits.max_stream_timeouts_per_connection",
        );
        v.range(
            self.rate_limit_max_clients,
            16,
            100_000_000,
            "limits.rate_limit_max_clients",
        );
        v.range(
            self.claim_request_max_bytes,
            64,
            MAX_BODY_BYTES,
            "limits.claim_request_max_bytes",
        );
        v.range(
            self.claim_max_surb_ids,
            1,
            1_000_000,
            "limits.claim_max_surb_ids",
        );
        v.range(
            self.claim_response_max_bytes,
            1,
            MAX_BODY_BYTES,
            "limits.claim_response_max_bytes",
        );
        v.range(
            self.topology_response_max_bytes,
            1,
            MAX_BODY_BYTES,
            "limits.topology_response_max_bytes",
        );
        v.range(
            self.small_response_max_bytes,
            64,
            MAX_BODY_BYTES,
            "limits.small_response_max_bytes",
        );
        v.range(
            self.max_inflight_upstream,
            1,
            1_000_000,
            "limits.max_inflight_upstream",
        );
        v.range(
            self.max_bundle_bytes,
            1,
            MAX_BODY_BYTES,
            "limits.max_bundle_bytes",
        );
        v.range(self.max_bundles, 1, 100_000, "limits.max_bundles");
        v.range(
            self.max_concurrent_bundle_streams,
            1,
            100_000,
            "limits.max_concurrent_bundle_streams",
        );
        for (value, field) in [
            (self.packet_rate_per_ip, "limits.packet_rate_per_ip"),
            (self.packet_burst, "limits.packet_burst"),
            (self.claim_rate_per_ip, "limits.claim_rate_per_ip"),
            (self.claim_burst, "limits.claim_burst"),
            (self.topology_rate_per_ip, "limits.topology_rate_per_ip"),
            (self.topology_burst, "limits.topology_burst"),
            (self.bundle_rate_per_ip, "limits.bundle_rate_per_ip"),
            (self.bundle_burst, "limits.bundle_burst"),
        ] {
            v.range(value as usize, 1, 1_000_000, field);
        }
        for (value, field) in [
            (self.header_read_timeout_ms, "limits.header_read_timeout_ms"),
            (self.stream_timeout_ms, "limits.stream_timeout_ms"),
            (
                self.upstream_connect_timeout_ms,
                "limits.upstream_connect_timeout_ms",
            ),
            (
                self.upstream_packet_timeout_ms,
                "limits.upstream_packet_timeout_ms",
            ),
            (
                self.upstream_claim_timeout_ms,
                "limits.upstream_claim_timeout_ms",
            ),
            (
                self.upstream_topology_timeout_ms,
                "limits.upstream_topology_timeout_ms",
            ),
            (
                self.upstream_health_timeout_ms,
                "limits.upstream_health_timeout_ms",
            ),
            (self.close_timeout_ms, "limits.close_timeout_ms"),
        ] {
            v.timeout(value, field);
        }
        for (value, field) in [
            (self.conn_idle_timeout_secs, "limits.conn_idle_timeout_secs"),
            (self.conn_max_lifetime_secs, "limits.conn_max_lifetime_secs"),
        ] {
            v.range(
                usize::try_from(value).unwrap_or(usize::MAX),
                1,
                31_536_000,
                field,
            );
        }
        if self.topology_cache_ms > MAX_TIMEOUT_MS {
            v.err(format!(
                "limits.topology_cache_ms must be at most {MAX_TIMEOUT_MS} (got: {})",
                self.topology_cache_ms
            ));
        }
        if self.health_cache_ms > MAX_TIMEOUT_MS {
            v.err(format!(
                "limits.health_cache_ms must be at most {MAX_TIMEOUT_MS} (got: {})",
                self.health_cache_ms
            ));
        }
        if self.bundle_rescan_secs > 86_400 {
            v.err(format!(
                "limits.bundle_rescan_secs must be at most 86400 (got: {})",
                self.bundle_rescan_secs
            ));
        }
        let slowest_upstream = [
            self.upstream_packet_timeout_ms,
            self.upstream_claim_timeout_ms,
            self.upstream_topology_timeout_ms,
            self.upstream_health_timeout_ms,
        ]
        .into_iter()
        .max()
        .unwrap_or(0);
        if self.stream_timeout_ms <= slowest_upstream {
            v.err(format!(
                "limits.stream_timeout_ms ({}) must exceed every upstream_*_timeout_ms (largest: {slowest_upstream}) so a slow upstream is answered with 504 before the stream is reset",
                self.stream_timeout_ms
            ));
        }
        if self.stream_timeout_ms < self.header_read_timeout_ms {
            v.err(format!(
                "limits.stream_timeout_ms ({}) must be at least limits.header_read_timeout_ms ({})",
                self.stream_timeout_ms, self.header_read_timeout_ms
            ));
        }
        if self.conn_max_lifetime_secs < self.conn_idle_timeout_secs {
            v.err(format!(
                "limits.conn_max_lifetime_secs ({}) must be at least limits.conn_idle_timeout_secs ({})",
                self.conn_max_lifetime_secs, self.conn_idle_timeout_secs
            ));
        }
        if v.errors.len() != before {
            return None;
        }
        let ms = Duration::from_millis;
        Some(Limits {
            max_connections: self.max_connections,
            max_connections_per_ip: self.max_connections_per_ip,
            ipv6_prefix_len: self.ipv6_prefix_len,
            max_streams_per_connection: self.max_streams_per_connection,
            conn_idle_timeout: Duration::from_secs(self.conn_idle_timeout_secs),
            conn_max_lifetime: Duration::from_secs(self.conn_max_lifetime_secs),
            header_max_bytes: self.header_max_bytes,
            max_headers: self.max_headers,
            header_read_timeout: ms(self.header_read_timeout_ms),
            stream_timeout: ms(self.stream_timeout_ms),
            max_stream_timeouts_per_connection: self.max_stream_timeouts_per_connection,
            close_timeout: ms(self.close_timeout_ms),
            packet_rate: Rate::new(self.packet_rate_per_ip, self.packet_burst),
            claim_rate: Rate::new(self.claim_rate_per_ip, self.claim_burst),
            topology_rate: Rate::new(self.topology_rate_per_ip, self.topology_burst),
            bundle_rate: Rate::new(self.bundle_rate_per_ip, self.bundle_burst),
            rate_limit_max_clients: self.rate_limit_max_clients,
            claim_request_max_bytes: self.claim_request_max_bytes,
            claim_max_surb_ids: self.claim_max_surb_ids,
            claim_response_max_bytes: self.claim_response_max_bytes,
            topology_response_max_bytes: self.topology_response_max_bytes,
            small_response_max_bytes: self.small_response_max_bytes,
            upstream_connect_timeout: ms(self.upstream_connect_timeout_ms),
            upstream_packet_timeout: ms(self.upstream_packet_timeout_ms),
            upstream_claim_timeout: ms(self.upstream_claim_timeout_ms),
            upstream_topology_timeout: ms(self.upstream_topology_timeout_ms),
            upstream_health_timeout: ms(self.upstream_health_timeout_ms),
            max_inflight_upstream: self.max_inflight_upstream,
            topology_cache: ms(self.topology_cache_ms),
            health_cache: ms(self.health_cache_ms),
            max_bundle_bytes: self.max_bundle_bytes,
            max_bundles: self.max_bundles,
            max_concurrent_bundle_streams: self.max_concurrent_bundle_streams,
            bundle_rescan: (self.bundle_rescan_secs > 0)
                .then(|| Duration::from_secs(self.bundle_rescan_secs)),
            bundle_gzip: self.bundle_gzip,
        })
    }
}

/// Collects validation errors.
#[derive(Default)]
struct Validator {
    errors: Vec<String>,
}

impl Validator {
    fn err(&mut self, msg: impl Into<String>) {
        self.errors.push(msg.into());
    }

    fn parse<T: std::str::FromStr>(&mut self, value: &str, field: &str, expected: &str) -> Option<T>
    where
        T::Err: std::fmt::Display,
    {
        match value.parse::<T>() {
            Ok(v) => Some(v),
            Err(e) => {
                self.err(format!(
                    "{field} must be {expected} (got: \"{value}\"): {e}"
                ));
                None
            }
        }
    }

    fn range(&mut self, value: usize, min: usize, max: usize, field: &str) {
        if !(min..=max).contains(&value) {
            self.err(format!(
                "{field} must be between {min} and {max} (got: {value})"
            ));
        }
    }

    fn timeout(&mut self, value: u64, field: &str) {
        if !(1..=MAX_TIMEOUT_MS).contains(&value) {
            self.err(format!(
                "{field} must be between 1 and {MAX_TIMEOUT_MS} ms (got: {value})"
            ));
        }
    }
}

/// A KPS certhash: multibase `u` + base64url (no padding) of the 34-byte
/// sha2-256 multihash, i.e. `uEi` followed by 44 more characters.
#[must_use]
pub fn is_certhash(s: &str) -> bool {
    s.len() == 47
        && s.starts_with("uEi")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// `log_level` as a `tracing` filter: a bare level applies to nox-kps only.
#[must_use]
pub fn log_filter(level: &str) -> String {
    let level = level.trim();
    match level.to_ascii_lowercase().as_str() {
        l @ ("trace" | "debug" | "info" | "warn" | "error") => format!("error,nox_kps={l}"),
        "off" => "off".to_string(),
        _ => level.to_string(),
    }
}

/// Validated, typed settings the server runs on.
#[derive(Debug, Clone)]
pub struct Settings {
    pub listen: SocketAddr,
    pub advertise: Vec<IpAddr>,
    pub key_file: PathBuf,
    /// Required by `run`; `None` only for `init`, `address` and `check-config`.
    pub expected_certhash: Option<String>,
    /// Lowercase `0x…` registry address, when configured.
    pub node_address: Option<String>,
    pub upstream_ingress: Upstream,
    pub upstream_topology: Upstream,
    pub client_ip_header: HeaderName,
    pub keccak_dir: Option<PathBuf>,
    pub admin_listen: SocketAddr,
    pub log_filter: String,
    pub log_format: LogFormat,
    pub summary_interval: Option<Duration>,
    pub limits: Limits,
    pub shutdown_grace: Duration,
    pub shutdown_linger: Duration,
}

/// A validated loopback upstream (`host:port`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    /// Config key, for errors and metrics (`upstream_ingress`).
    pub name: &'static str,
    /// `host:port` as configured.
    pub authority: http::uri::Authority,
    /// `Host` header value sent upstream.
    pub host_header: HeaderValue,
}

/// A token-bucket rate: sustained requests per second and burst size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    pub per_second: u32,
    pub burst: u32,
}

impl Rate {
    #[must_use]
    pub fn new(per_second: u32, burst: u32) -> Self {
        Self { per_second, burst }
    }
}

/// Validated limits; see [`LimitsConfig`] for each field.
#[derive(Debug, Clone)]
pub struct Limits {
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    pub ipv6_prefix_len: u8,
    pub max_streams_per_connection: usize,
    pub conn_idle_timeout: Duration,
    pub conn_max_lifetime: Duration,
    pub header_max_bytes: usize,
    pub max_headers: usize,
    pub header_read_timeout: Duration,
    pub stream_timeout: Duration,
    pub max_stream_timeouts_per_connection: usize,
    pub close_timeout: Duration,
    pub packet_rate: Rate,
    pub claim_rate: Rate,
    pub topology_rate: Rate,
    pub bundle_rate: Rate,
    pub rate_limit_max_clients: usize,
    pub claim_request_max_bytes: usize,
    pub claim_max_surb_ids: usize,
    pub claim_response_max_bytes: usize,
    pub topology_response_max_bytes: usize,
    pub small_response_max_bytes: usize,
    pub upstream_connect_timeout: Duration,
    pub upstream_packet_timeout: Duration,
    pub upstream_claim_timeout: Duration,
    pub upstream_topology_timeout: Duration,
    pub upstream_health_timeout: Duration,
    pub max_inflight_upstream: usize,
    pub topology_cache: Duration,
    pub health_cache: Duration,
    pub max_bundle_bytes: usize,
    pub max_bundles: usize,
    pub max_concurrent_bundle_streams: usize,
    pub bundle_rescan: Option<Duration>,
    pub bundle_gzip: bool,
}

fn parse_upstream(field: &'static str, value: &str, v: &mut Validator) -> Option<Upstream> {
    let value = value.trim();
    if value.contains("://") {
        v.err(format!(
            "{field} must be a bare host:port such as 127.0.0.1:15002, without a scheme (got: \"{value}\")"
        ));
        return None;
    }
    let loopback = match value.parse::<SocketAddr>() {
        Ok(addr) => addr.ip().is_loopback() && addr.port() != 0,
        Err(_) => value
            .strip_prefix("localhost:")
            .and_then(|p| p.parse::<u16>().ok())
            .is_some_and(|p| p != 0),
    };
    if !loopback {
        v.err(format!(
            "{field} must be a loopback host:port such as 127.0.0.1:15002 (got: \"{value}\"); the node trusts the client IP header only on loopback connections, and client traffic never leaves the host"
        ));
        return None;
    }
    let authority = match value.parse::<http::uri::Authority>() {
        Ok(a) => a,
        Err(e) => {
            v.err(format!(
                "{field} is not a valid host:port (got: \"{value}\"): {e}"
            ));
            return None;
        }
    };
    let host_header = match HeaderValue::from_str(authority.as_str()) {
        Ok(h) => h,
        Err(e) => {
            v.err(format!(
                "{field} is not a valid Host value (got: \"{value}\"): {e}"
            ));
            return None;
        }
    };
    Some(Upstream {
        name: field,
        authority,
        host_header,
    })
}

fn parse_client_ip_header(value: &str, v: &mut Validator) -> Option<HeaderName> {
    let name = match HeaderName::from_bytes(value.trim().as_bytes()) {
        Ok(name) => name,
        Err(e) => {
            v.err(format!(
                "client_ip_header must be a valid header name such as x-real-ip (got: \"{value}\"): {e}"
            ));
            return None;
        }
    };
    if RESERVED_CLIENT_IP_HEADERS.contains(&name.as_str()) {
        v.err(format!(
            "client_ip_header must not be the framing or routing header \"{name}\"; use x-real-ip, as the node's [ingress] client_ip_header"
        ));
        return None;
    }
    Some(name)
}

/// Settings as a redacted, human-readable summary for `check-config` and the
/// startup log. Holds no secrets: the identity key is referenced by path only.
#[must_use]
pub fn summary(settings: &Settings) -> BTreeMap<&'static str, String> {
    let l = &settings.limits;
    let mut m = BTreeMap::new();
    m.insert("listen (udp)", settings.listen.to_string());
    m.insert(
        "advertise",
        settings
            .advertise
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", "),
    );
    m.insert("key_file", settings.key_file.display().to_string());
    m.insert(
        "routes",
        format!(
            "POST /api/v1/packets, POST /api/v1/responses/claim, GET /health -> {}; GET /topology -> {}; GET /metadata.json, GET /keccak/<hh>/<62 hex> served locally",
            settings.upstream_ingress.authority, settings.upstream_topology.authority
        ),
    );
    m.insert("client_ip_header", settings.client_ip_header.to_string());
    m.insert(
        "keccak_dir",
        settings.keccak_dir.as_ref().map_or_else(
            || "(bundle resolver disabled)".to_string(),
            |d| d.display().to_string(),
        ),
    );
    m.insert("admin_listen (tcp)", settings.admin_listen.to_string());
    m.insert(
        "limits",
        format!(
            "connections {} (per ip {}), streams/conn {}, idle {}s, lifetime {}s, header {} B, stream {} ms, packets {}/s burst {}, claims {}/s burst {}",
            l.max_connections,
            l.max_connections_per_ip,
            l.max_streams_per_connection,
            l.conn_idle_timeout.as_secs(),
            l.conn_max_lifetime.as_secs(),
            l.header_max_bytes,
            l.stream_timeout.as_millis(),
            l.packet_rate.per_second,
            l.packet_rate.burst,
            l.claim_rate.per_second,
            l.claim_rate.burst,
        ),
    );
    m
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::pedantic
    )]

    use std::collections::HashMap;

    use super::*;

    fn valid() -> RawConfig {
        RawConfig {
            advertise: vec!["203.0.113.5".to_string()],
            ..RawConfig::default()
        }
    }

    fn errors_of(raw: &RawConfig) -> Vec<String> {
        match raw.validate() {
            Ok(_) => Vec::new(),
            Err(ConfigError::Invalid(errors)) => errors,
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    fn assert_error(raw: &RawConfig, needle: &str) {
        let errors = errors_of(raw);
        assert!(
            errors.iter().any(|e| e.contains(needle)),
            "expected {needle:?} in {errors:?}"
        );
    }

    #[test]
    fn defaults_match_the_architecture() {
        let s = valid().validate().expect("defaults validate");
        assert_eq!(s.listen.to_string(), "[::]:15005");
        assert_eq!(s.upstream_ingress.authority.as_str(), "127.0.0.1:15002");
        assert_eq!(s.upstream_topology.authority.as_str(), "127.0.0.1:15003");
        assert_eq!(s.client_ip_header, "x-real-ip");
        assert_eq!(s.admin_listen.to_string(), "127.0.0.1:15006");
        assert_eq!(s.key_file, PathBuf::from("/var/lib/nox-kps/kps.key"));
        assert_eq!(s.keccak_dir, Some(PathBuf::from("/var/lib/nox-kps/keccak")));
        assert_eq!(s.log_format, LogFormat::Json);
        let l = &s.limits;
        assert_eq!(
            (
                l.max_connections,
                l.max_connections_per_ip,
                l.max_streams_per_connection
            ),
            (256, 16, 32)
        );
        assert_eq!(l.conn_idle_timeout, Duration::from_mins(2));
        assert_eq!(l.conn_max_lifetime, Duration::from_hours(1));
        assert_eq!(l.header_read_timeout, Duration::from_secs(10));
        assert_eq!(l.max_inflight_upstream, 128);
        assert_eq!(l.max_concurrent_bundle_streams, 8);
        assert!(s.expected_certhash.is_none());
        assert_eq!(l.header_max_bytes, 16_384);
        assert_eq!(l.packet_rate, Rate::new(20, 100));
        assert_eq!(l.claim_rate, Rate::new(30, 200));
        assert_eq!(l.topology_rate, Rate::new(2, 10));
        assert_eq!(l.bundle_rate, Rate::new(1, 5));
        assert_eq!(l.claim_request_max_bytes, 65_536);
        assert_eq!(l.claim_response_max_bytes, 16_777_216);
        assert_eq!(l.topology_response_max_bytes, 1_048_576);
        assert_eq!(l.max_bundle_bytes, 67_108_864);
        assert!(!l.bundle_gzip, "v1 serves identity bytes only");
    }

    #[test]
    fn the_architecture_example_parses() {
        let raw = RawConfig::from_toml_str(
            r#"
listen = "[::]:15005"
advertise = ["3.239.73.249"]
key_file = "/var/lib/nox-kps/kps.key"
node_address = "0x862D6B1105bdE9d64dC5182fe3CD9d09F6F37463"
upstream_ingress = "127.0.0.1:15002"
upstream_topology = "127.0.0.1:15003"
client_ip_header = "x-real-ip"
keccak_dir = "/var/lib/nox-kps/keccak"
admin_listen = "127.0.0.1:15006"
log_level = "info"
log_format = "json"

[limits]
max_connections = 512
"#,
        )
        .unwrap();
        let s = raw.validate().unwrap();
        assert_eq!(
            s.node_address.as_deref(),
            Some("0x862d6b1105bde9d64dc5182fe3cd9d09f6f37463")
        );
        assert_eq!(s.advertise, vec!["3.239.73.249".parse::<IpAddr>().unwrap()]);
        assert_eq!(s.log_filter, "error,nox_kps=info");
    }

    #[test]
    fn the_shipped_example_config_is_valid_and_states_the_defaults() {
        let raw =
            RawConfig::from_toml_str(include_str!("../../../deploy/nox-kps.example.toml")).unwrap();
        raw.validate().unwrap();
        assert_eq!(raw.limits, LimitsConfig::default());
        assert_eq!(raw.shutdown, ShutdownConfig::default());
        assert_eq!(
            RawConfig {
                advertise: Vec::new(),
                ..raw
            },
            RawConfig::default(),
            "every top-level value in the example is the default"
        );
    }

    #[test]
    fn empty_toml_is_the_default_config() {
        assert_eq!(RawConfig::from_toml_str("").unwrap(), RawConfig::default());
    }

    #[test]
    fn advertise_is_required_and_must_be_public() {
        assert_error(&RawConfig::default(), "advertise must list");
        let mut raw = valid();
        raw.advertise = vec!["172.31.66.207".into()];
        assert_error(&raw, "not publicly routable");
        raw.allow_private_advertise = true;
        assert!(errors_of(&raw).is_empty());
        raw.advertise = vec!["0.0.0.0".into()];
        assert_error(&raw, "unicast");
        raw.advertise = vec!["nope".into()];
        assert_error(&raw, "advertise[0] must be an IPv4 or IPv6 address");
        let mut raw = valid();
        raw.advertise = vec![
            "[2600:1f18::1]".into(),
            "203.0.113.5".into(),
            "203.0.113.5".into(),
        ];
        assert_eq!(
            raw.validate().unwrap().advertise.len(),
            2,
            "bracketed v6, duplicates dropped"
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let err = RawConfig::from_toml_str("[limits]\nmax_conections = 5\n").unwrap_err();
        assert!(err.to_string().contains("max_conections"), "{err}");
        let err = RawConfig::from_toml_str("upstream = \"x\"\n").unwrap_err();
        assert!(err.to_string().contains("upstream"), "{err}");
    }

    #[test]
    fn environment_overrides_scalars_lists_and_nested_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[limits]\nmax_connections = 300\n").unwrap();
        let env: HashMap<String, String> = [
            ("NOX_KPS__ADVERTISE", "203.0.113.5,2001:db8::7"),
            ("NOX_KPS__ALLOW_PRIVATE_ADVERTISE", "true"),
            ("NOX_KPS__LIMITS__MAX_CONNECTIONS_PER_IP", "4"),
            ("NOX_KPS__CLIENT_IP_HEADER", "x-forwarded-for"),
            ("NOX_KPS__UPSTREAM_TOPOLOGY", "127.0.0.1:16003"),
            ("NOX_KPS__LIMITS__BUNDLE_GZIP", "true"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let raw = RawConfig::load_with_env(&ConfigSource::Explicit(path), Some(env)).unwrap();
        assert_eq!(raw.limits.max_connections, 300);
        assert_eq!(raw.limits.max_connections_per_ip, 4);
        assert_eq!(raw.advertise, vec!["203.0.113.5", "2001:db8::7"]);
        assert_eq!(raw.client_ip_header, "x-forwarded-for");
        assert_eq!(raw.upstream_topology, "127.0.0.1:16003");
        assert_eq!(
            raw.upstream_ingress, "127.0.0.1:15002",
            "other upstream keeps its default"
        );
        assert!(raw.limits.bundle_gzip);
        assert_eq!(raw.validate().unwrap().advertise.len(), 2);
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
    fn upstreams_must_be_bare_loopback_addresses() {
        for bad in [
            "10.0.0.5:15002",
            "0.0.0.0:15002",
            "http://127.0.0.1:15002",
            "127.0.0.1",
            "127.0.0.1:0",
            "example.com:15002",
            "not an address",
        ] {
            let mut raw = valid();
            raw.upstream_ingress = bad.to_string();
            assert_error(&raw, "upstream_ingress must");
        }
        for good in [
            "127.0.0.1:15002",
            "[::1]:15002",
            "localhost:15002",
            "127.0.0.2:15002",
        ] {
            let mut raw = valid();
            raw.upstream_topology = good.to_string();
            assert!(errors_of(&raw).is_empty(), "{good}");
        }
    }

    #[test]
    fn admin_listen_must_be_loopback() {
        let mut raw = valid();
        raw.admin_listen = "0.0.0.0:15006".into();
        assert_error(&raw, "admin_listen must be a loopback address");
        raw.admin_listen = "15006".into();
        assert_error(&raw, "admin_listen must be a loopback ip:port");
    }

    #[test]
    fn client_ip_header_must_be_a_plain_header_name() {
        let mut raw = valid();
        raw.client_ip_header = "host".into();
        assert_error(&raw, "client_ip_header must not be");
        raw.client_ip_header = "bad header".into();
        assert_error(&raw, "client_ip_header must be a valid header name");
    }

    #[test]
    fn expected_certhash_has_the_certhash_shape() {
        let mut raw = valid();
        raw.expected_certhash = "uEiAm9Bz8s3aYgpiYn3xD94v1TXQyWi0gOw4Vmv7gD2DWpw".into();
        assert!(raw.validate().unwrap().expected_certhash.is_some());
        raw.expected_certhash = "uEi".into();
        assert_error(&raw, "expected_certhash must be");
        raw.expected_certhash = "sha256:abcd".into();
        assert_error(&raw, "expected_certhash must be");
    }

    #[test]
    fn node_address_is_optional_hex() {
        let mut raw = valid();
        raw.node_address = "0x1234".into();
        assert_error(&raw, "node_address must be");
        raw.node_address = String::new();
        assert!(raw.validate().unwrap().node_address.is_none());
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
                "limits.max_connections_per_ip must",
            ),
            (
                Box::new(|r| r.limits.ipv6_prefix_len = 0),
                "ipv6_prefix_len",
            ),
            (
                Box::new(|r| r.limits.header_max_bytes = 4096),
                "header_max_bytes",
            ),
            (Box::new(|r| r.limits.max_headers = 2), "max_headers"),
            (
                Box::new(|r| r.limits.packet_rate_per_ip = 0),
                "packet_rate_per_ip",
            ),
            (Box::new(|r| r.limits.claim_burst = 0), "claim_burst"),
            (
                Box::new(|r| r.limits.stream_timeout_ms = 9_000),
                "must exceed every upstream",
            ),
            (
                Box::new(|r| r.limits.upstream_claim_timeout_ms = 0),
                "upstream_claim_timeout_ms",
            ),
            (
                Box::new(|r| r.limits.conn_idle_timeout_secs = 0),
                "conn_idle_timeout_secs",
            ),
            (
                Box::new(|r| r.limits.conn_max_lifetime_secs = 10),
                "conn_max_lifetime_secs (10) must be at least",
            ),
            (
                Box::new(|r| r.limits.max_inflight_upstream = 0),
                "max_inflight_upstream",
            ),
            (Box::new(|r| r.limits.max_bundles = 0), "max_bundles"),
            (
                Box::new(|r| r.limits.close_timeout_ms = 0),
                "close_timeout_ms",
            ),
            (
                Box::new(|r| r.limits.max_stream_timeouts_per_connection = 0),
                "max_stream_timeouts_per_connection",
            ),
            (Box::new(|r| r.listen = "15005".into()), "listen must be"),
            (Box::new(|r| r.log_level = "=[".into()), "log_level"),
            (
                Box::new(|r| r.shutdown.close_linger_ms = 20_000),
                "close_linger_ms",
            ),
        ];
        for (mutate, needle) in cases {
            let mut raw = valid();
            mutate(&mut raw);
            assert_error(&raw, needle);
        }
    }

    #[test]
    fn reports_every_problem_at_once() {
        let mut raw = RawConfig::default();
        raw.limits.max_connections = 0;
        raw.listen = "x".into();
        raw.client_ip_header = "host".into();
        raw.upstream_ingress = "10.0.0.1:1".into();
        assert!(errors_of(&raw).len() >= 5, "{:?}", errors_of(&raw));
    }

    #[test]
    fn log_levels_scope_to_nox_kps() {
        assert_eq!(log_filter("debug"), "error,nox_kps=debug");
        assert_eq!(log_filter("WARN"), "error,nox_kps=warn");
        assert_eq!(log_filter("warn,nox_kps=trace"), "warn,nox_kps=trace");
    }

    #[test]
    fn keccak_dir_can_be_disabled() {
        let mut raw = valid();
        raw.keccak_dir = " ".into();
        assert!(raw.validate().unwrap().keccak_dir.is_none());
    }

    #[test]
    fn summary_names_no_secrets() {
        let s = valid().validate().unwrap();
        let text = format!("{:?}", summary(&s));
        assert!(text.contains("kps.key"));
        assert!(text.contains("127.0.0.1:15002"));
        assert!(!text.contains("PRIVATE"));
    }
}
