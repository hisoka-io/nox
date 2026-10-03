use config::{Config, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use tracing::info;
use zeroize::Zeroize;

use nox_core::models::handshake::Capabilities;
use x25519_dalek::StaticSecret as X25519SecretKey;

pub const DEFAULT_ORACLE_CACHE_TTL_SECS: u64 = 10;
pub const DEFAULT_ORACLE_MAX_OBSERVATION_AGE_SECS: u64 = 300;
pub const DEFAULT_ORACLE_MAX_FUTURE_SKEW_SECS: u64 = 30;
pub const MAX_ORACLE_OBSERVATION_AGE_SECS: u64 = 3_600;
pub const MAX_ORACLE_FUTURE_SKEW_SECS: u64 = 300;
pub const DEFAULT_GAS_LIMIT_BUFFER_BPS: u32 = 2_000;
pub const DEFAULT_INITIAL_FEE_BUFFER_BPS: u32 = 2_000;
pub const DEFAULT_REPLACEMENT_STEP_BPS: u32 = 2_000;
pub const MAX_BUFFER_BPS: u32 = 10_000;
pub const MAX_MARGIN_PERCENT: u64 = 1_000;
pub const MAX_NATIVE_ASSET_DECIMALS: u8 = 36;
pub const BASIS_POINTS: u128 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainDataFeeMode {
    RpcGasEstimateIncludesDataFee,
}

/// Maps a token contract address to its symbol, decimals, and oracle price ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenConfig {
    pub address: String,
    pub symbol: String,
    pub decimals: u8,
    /// Must match a key returned by the price oracle at /prices
    pub price_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentAdapterConfig {
    pub address: String,
    pub fee_assets: Vec<String>,
    pub maximum_payment_gas: u64,
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeRole {
    Relay,
    Exit,
    #[default]
    Full,
}

impl NodeRole {
    #[must_use]
    pub fn is_exit_capable(&self) -> bool {
        matches!(self, NodeRole::Exit | NodeRole::Full)
    }

    /// Capabilities bitmask: RELAY=1, EXIT=2, FULL=3 (RELAY|EXIT).
    #[must_use]
    pub fn to_on_chain_role(&self) -> u8 {
        match self {
            NodeRole::Relay => 1,
            NodeRole::Exit => 2,
            NodeRole::Full => 3,
        }
    }

    #[must_use]
    pub fn from_on_chain_role(role: u8) -> Self {
        match role {
            1 => NodeRole::Relay,
            2 => NodeRole::Exit,
            _ => NodeRole::Full,
        }
    }

    #[must_use]
    pub fn to_capabilities(&self) -> Capabilities {
        match self {
            NodeRole::Relay => Capabilities::RELAY,
            NodeRole::Exit | NodeRole::Full => Capabilities::RELAY | Capabilities::EXIT_NODE,
        }
    }
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct RateLimitConfig {
    pub burst_unknown: u32,
    pub rate_unknown: u32,
    pub burst_trusted: u32,
    pub rate_trusted: u32,
    pub burst_penalized: u32,
    pub rate_penalized: u32,
    pub violations_before_disconnect: u32,
    pub violation_window_secs: u64,
    pub trust_promotion_time_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            burst_unknown: 50,
            rate_unknown: 100,
            burst_trusted: 100,
            rate_trusted: 200,
            burst_penalized: 10,
            rate_penalized: 25,
            violations_before_disconnect: 5,
            violation_window_secs: 60,
            trust_promotion_time_secs: 3600,
        }
    }
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct ConnectionFilterConfig {
    pub max_per_subnet: u32,
    pub subnet_prefix_len: u8,
    /// /48 = standard allocation for a single site.
    pub ipv6_subnet_prefix_len: u8,
}

impl Default for ConnectionFilterConfig {
    fn default() -> Self {
        Self {
            max_per_subnet: 50,
            subnet_prefix_len: 24,
            ipv6_subnet_prefix_len: 48,
        }
    }
}

/// How the P2P layer treats peers whose libp2p identity is not in the registry.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerAdmissionMode {
    /// No registry check; IP bans and subnet caps are only logged.
    Off,
    /// Count and log what `enforce` would refuse, refuse nothing.
    Monitor,
    /// Refuse connections and packets from peers outside the registry once the
    /// node set has been verified against the chain and the startup grace
    /// period has passed. Existing links to a peer that left the registry are
    /// closed after the grace period.
    #[default]
    Enforce,
}

const fn default_peer_admission_grace_secs() -> u64 {
    120
}

const fn default_topology_liveness_window_secs() -> u64 {
    60
}

const fn default_cover_loop_timeout_secs() -> u64 {
    60
}

const fn default_topology_reconcile_interval_secs() -> u64 {
    300
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct NetworkConfig {
    pub max_connections: u32,
    pub max_connections_per_peer: u32,
    pub ping_interval_secs: u64,
    pub ping_timeout_secs: u64,
    pub gossip_heartbeat_secs: u64,
    pub idle_connection_timeout_secs: u64,
    pub session_ttl_secs: u64,
    /// Raise to ~5,000+ for burst SURB-response traffic in benchmarks.
    pub max_concurrent_streams: usize,
    pub rate_limit: RateLimitConfig,
    pub connection_filter: ConnectionFilterConfig,
    #[serde(default)]
    pub peer_admission: PeerAdmissionMode,
    /// Delay after startup before enforcement starts, and how long a link to a
    /// peer that left the registry is kept before it is closed.
    #[serde(default = "default_peer_admission_grace_secs")]
    pub peer_admission_grace_secs: u64,
    /// A member counts as online in `/topology` liveness if it answered on P2P
    /// (connection or ping) within this many seconds.
    #[serde(default = "default_topology_liveness_window_secs")]
    pub topology_liveness_window_secs: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            max_connections: 1000,
            max_connections_per_peer: 2,
            ping_interval_secs: 15,
            ping_timeout_secs: 10,
            gossip_heartbeat_secs: 1,
            idle_connection_timeout_secs: 3600,
            session_ttl_secs: 86400,
            max_concurrent_streams: 100,
            rate_limit: RateLimitConfig::default(),
            connection_filter: ConnectionFilterConfig::default(),
            peer_admission: PeerAdmissionMode::default(),
            peer_admission_grace_secs: default_peer_admission_grace_secs(),
            topology_liveness_window_secs: default_topology_liveness_window_secs(),
        }
    }
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct RelayerConfig {
    pub queue_size: usize,
    pub worker_count: usize,
    pub replay_window: u64,
    /// Right-size based on expected packets per `replay_window`.
    pub bloom_capacity: usize,
    /// How often (seconds) the replay filter is written to disk while it changes.
    /// It is also written on rotation and on graceful shutdown. 0 = only those.
    #[serde(default = "default_bloom_persist_interval_secs")]
    pub bloom_persist_interval_secs: u64,
    /// 0.0 = disable mixing (instant forwarding via `NoMixStrategy`).
    pub mix_delay_ms: f64,
    pub cover_traffic_rate: f64,
    pub drop_traffic_rate: f64,
    /// A loop cover packet not back within this many seconds counts as lost.
    #[serde(default = "default_cover_loop_timeout_secs")]
    pub cover_loop_timeout_secs: u64,
    pub fragmentation: FragmentationConfig,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct FragmentationConfig {
    pub max_pending_bytes: usize,
    pub max_concurrent_messages: usize,
    pub timeout_seconds: u64,
    pub prune_interval_seconds: u64,
}

impl Default for FragmentationConfig {
    fn default() -> Self {
        Self {
            max_pending_bytes: nox_core::protocol::fragmentation::DEFAULT_MAX_BUFFER_BYTES,
            max_concurrent_messages:
                nox_core::protocol::fragmentation::DEFAULT_MAX_CONCURRENT_MESSAGES,
            timeout_seconds: 300,
            prune_interval_seconds: 60,
        }
    }
}

fn default_bloom_persist_interval_secs() -> u64 {
    60
}

impl Default for RelayerConfig {
    fn default() -> Self {
        Self {
            queue_size: 10_000,
            worker_count: num_cpus::get(),
            replay_window: 3600,
            bloom_capacity: 100_000,
            bloom_persist_interval_secs: default_bloom_persist_interval_secs(),
            mix_delay_ms: 500.0,
            cover_traffic_rate: 0.05,
            drop_traffic_rate: 0.05,
            cover_loop_timeout_secs: default_cover_loop_timeout_secs(),
            fragmentation: FragmentationConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct HttpConfig {
    /// None = open web (SSRF still enforced), Some([]) = block all.
    pub allowed_domains: Option<Vec<String>>,
    pub allow_private_ips: bool,
    pub request_timeout_secs: u64,
    pub max_response_bytes: usize,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            allowed_domains: None,
            allow_private_ips: false,
            request_timeout_secs: 10,
            max_response_bytes: 1024 * 1024,
        }
    }
}

/// Default sustained requests per second one client IP may send to the HTTP ingress.
pub const DEFAULT_INGRESS_RATE_LIMIT_PER_SEC: u32 = 100;
/// Default number of requests one client IP may send in a burst above the sustained rate.
pub const DEFAULT_INGRESS_RATE_LIMIT_BURST: u32 = 400;

/// Abuse controls for the public HTTP ingress (`ingress_port`) and API (`metrics_port`).
#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(default)]
pub struct IngressConfig {
    /// Sustained requests per second allowed per client IP. 0 disables the limit.
    pub rate_limit_per_sec: u32,
    /// Requests per client IP allowed in a burst above the sustained rate.
    pub rate_limit_burst: u32,
    /// Header that carries the client IP when the ingress sits behind a local reverse
    /// proxy (for example `x-forwarded-for` or `x-real-ip`). Only read for connections
    /// from a loopback address; the rightmost value is used. Empty means loopback
    /// connections are not limited here and the proxy is expected to limit them.
    pub client_ip_header: String,
    /// Browser origins allowed by CORS on the ingress and API ports, for example
    /// `https://demo.nox.hisoka.io`. Empty allows any origin.
    pub cors_allowed_origins: Vec<String>,
}

impl Default for IngressConfig {
    fn default() -> Self {
        Self {
            rate_limit_per_sec: DEFAULT_INGRESS_RATE_LIMIT_PER_SEC,
            rate_limit_burst: DEFAULT_INGRESS_RATE_LIMIT_BURST,
            client_ip_header: String::new(),
            cors_allowed_origins: Vec::new(),
        }
    }
}

impl IngressConfig {
    /// Configuration errors, one message per invalid field.
    #[must_use]
    pub fn validation_errors(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.rate_limit_per_sec > 0 && self.rate_limit_burst == 0 {
            errors.push(
                "ingress.rate_limit_burst must be at least 1 when ingress.rate_limit_per_sec is set"
                    .to_string(),
            );
        }
        if !self.client_ip_header.is_empty()
            && axum::http::HeaderName::from_bytes(self.client_ip_header.as_bytes()).is_err()
        {
            errors.push(format!(
                "ingress.client_ip_header is not a valid header name (got: \"{}\")",
                self.client_ip_header
            ));
        }
        for origin in &self.cors_allowed_origins {
            let is_http_origin = (origin.starts_with("https://") || origin.starts_with("http://"))
                && !origin.ends_with('/')
                && axum::http::HeaderValue::from_str(origin).is_ok();
            if !is_http_origin {
                errors.push(format!(
                    "ingress.cors_allowed_origins entry must be an origin such as \
                     https://app.example.org without a trailing slash (got: \"{origin}\")"
                ));
            }
        }
        errors
    }
}

/// Exit dispatch lanes. Each lane has its own queue and concurrency limit, so slow proxy
/// calls cannot hold up paid quotes and submissions, and a burst on one lane cannot starve
/// another.
#[derive(Debug, Deserialize, Clone, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct ExitWorkerConfig {
    /// Paid transaction submissions handled at once.
    pub paid_concurrency: usize,
    /// Paid quote requests handled at once.
    pub quote_concurrency: usize,
    /// HTTP, RPC and broadcast proxy requests handled at once.
    pub proxy_concurrency: usize,
    /// Echo, cover and other cheap payloads handled at once.
    pub control_concurrency: usize,
    /// Payloads that may wait per lane; further payloads are dropped and counted.
    pub queue_capacity: usize,
}

impl Default for ExitWorkerConfig {
    fn default() -> Self {
        Self {
            paid_concurrency: 4,
            quote_concurrency: 8,
            proxy_concurrency: 32,
            control_concurrency: 16,
            queue_capacity: 256,
        }
    }
}

#[derive(Deserialize, Clone, Serialize)]
pub struct NoxConfig {
    pub eth_rpc_url: String,
    pub oracle_url: String,
    pub registry_contract_address: String,
    pub p2p_port: u16,
    pub p2p_listen_addr: String,
    pub db_path: String,
    #[serde(skip_serializing, default)]
    pub routing_private_key: String,
    #[serde(skip_serializing, default)]
    pub p2p_private_key: String,
    pub p2p_identity_path: String,
    pub min_pow_difficulty: u32,
    pub metrics_port: u16,

    #[serde(skip_serializing, default)]
    pub eth_wallet_private_key: String,

    pub min_gas_balance: String,
    pub min_profit_margin_percent: u64,
    pub oracle_cache_ttl_secs: u64,
    pub oracle_max_observation_age_secs: u64,
    pub oracle_max_future_skew_secs: u64,
    pub native_asset_price_id: String,
    pub native_asset_decimals: u8,
    pub gas_limit_buffer_bps: u32,
    pub initial_fee_buffer_bps: u32,
    pub replacement_step_bps: u32,
    pub chain_data_fee_mode: ChainDataFeeMode,

    pub chain_id: u64,

    pub network: NetworkConfig,
    pub relayer: RelayerConfig,
    pub benchmark_mode: bool,

    pub node_role: NodeRole,
    pub http: HttpConfig,
    #[serde(default)]
    pub exit_workers: ExitWorkerConfig,
    pub block_poll_interval_secs: u64,
    /// Block where `NoxRegistry` was deployed; scanned inclusively on first boot.
    /// 0 = start from latest.
    #[serde(default)]
    pub chain_start_block: u64,
    /// How often the node set is re-read from the registry and checked against
    /// `topologyFingerprint()` and `relayerCount()`. 0 = disabled.
    #[serde(default = "default_topology_reconcile_interval_secs")]
    pub topology_reconcile_interval_secs: u64,
    /// Falls back to `ChainObserver` replay if all seed URLs fail.
    #[serde(default)]
    pub bootstrap_topology_urls: Vec<String>,
    /// 0 = disabled. Binds to 0.0.0.0 when enabled.
    pub topology_api_port: u16,
    pub max_broadcast_tx_size: usize,
    /// 0 = disabled.
    pub ingress_port: u16,
    /// Rate limit and CORS policy for the ingress and API ports.
    #[serde(default)]
    pub ingress: IngressConfig,
    pub response_prune_interval_secs: u64,
    pub nox_reward_pool_address: String,
    pub nox_entry_point_address: String,
    pub quote_ttl_secs: u64,
    pub quote_network_fee_bps: u32,
    pub quote_maximum_transaction_gas: u64,
    pub quote_max_outstanding: u32,
    pub quote_max_pending_sponsored_gas: u64,
    pub quote_rolling_loss_limit_native: String,
    pub quote_rolling_loss_window_secs: u64,
    #[serde(default)]
    pub payment_adapters: Vec<PaymentAdapterConfig>,
    /// Non-empty replaces hardcoded mainnet defaults.
    #[serde(default)]
    pub tokens: Vec<TokenConfig>,
}

impl Drop for NoxConfig {
    fn drop(&mut self) {
        self.routing_private_key.zeroize();
        self.p2p_private_key.zeroize();
        self.eth_wallet_private_key.zeroize();
    }
}

impl std::fmt::Debug for NoxConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoxConfig")
            .field("eth_rpc_url", &self.eth_rpc_url)
            .field("oracle_url", &self.oracle_url)
            .field("registry_contract_address", &self.registry_contract_address)
            .field("p2p_port", &self.p2p_port)
            .field("p2p_listen_addr", &self.p2p_listen_addr)
            .field("db_path", &self.db_path)
            .field("routing_private_key", &"[REDACTED]")
            .field("p2p_private_key", &"[REDACTED]")
            .field("p2p_identity_path", &self.p2p_identity_path)
            .field("min_pow_difficulty", &self.min_pow_difficulty)
            .field("metrics_port", &self.metrics_port)
            .field("eth_wallet_private_key", &"[REDACTED]")
            .field("min_gas_balance", &self.min_gas_balance)
            .field("min_profit_margin_percent", &self.min_profit_margin_percent)
            .field("oracle_cache_ttl_secs", &self.oracle_cache_ttl_secs)
            .field(
                "oracle_max_observation_age_secs",
                &self.oracle_max_observation_age_secs,
            )
            .field(
                "oracle_max_future_skew_secs",
                &self.oracle_max_future_skew_secs,
            )
            .field("native_asset_price_id", &self.native_asset_price_id)
            .field("native_asset_decimals", &self.native_asset_decimals)
            .field("gas_limit_buffer_bps", &self.gas_limit_buffer_bps)
            .field("initial_fee_buffer_bps", &self.initial_fee_buffer_bps)
            .field("replacement_step_bps", &self.replacement_step_bps)
            .field("chain_data_fee_mode", &self.chain_data_fee_mode)
            .field("chain_id", &self.chain_id)
            .field("network", &self.network)
            .field("relayer", &self.relayer)
            .field("benchmark_mode", &self.benchmark_mode)
            .field("node_role", &self.node_role)
            .field("http", &self.http)
            .field("exit_workers", &self.exit_workers)
            .field("block_poll_interval_secs", &self.block_poll_interval_secs)
            .field("chain_start_block", &self.chain_start_block)
            .field(
                "topology_reconcile_interval_secs",
                &self.topology_reconcile_interval_secs,
            )
            .field("bootstrap_topology_urls", &self.bootstrap_topology_urls)
            .field("topology_api_port", &self.topology_api_port)
            .field("max_broadcast_tx_size", &self.max_broadcast_tx_size)
            .field("ingress_port", &self.ingress_port)
            .field("ingress", &self.ingress)
            .field(
                "response_prune_interval_secs",
                &self.response_prune_interval_secs,
            )
            .field("nox_reward_pool_address", &self.nox_reward_pool_address)
            .field("nox_entry_point_address", &self.nox_entry_point_address)
            .field("quote_ttl_secs", &self.quote_ttl_secs)
            .field("quote_network_fee_bps", &self.quote_network_fee_bps)
            .field(
                "quote_maximum_transaction_gas",
                &self.quote_maximum_transaction_gas,
            )
            .field("quote_max_outstanding", &self.quote_max_outstanding)
            .field(
                "quote_max_pending_sponsored_gas",
                &self.quote_max_pending_sponsored_gas,
            )
            .field(
                "quote_rolling_loss_limit_native",
                &self.quote_rolling_loss_limit_native,
            )
            .field(
                "quote_rolling_loss_window_secs",
                &self.quote_rolling_loss_window_secs,
            )
            .field(
                "payment_adapters",
                &format!("{} configured", self.payment_adapters.len()),
            )
            .field("tokens", &format!("{} registered", self.tokens.len()))
            .finish()
    }
}

impl Default for NoxConfig {
    fn default() -> Self {
        Self {
            eth_rpc_url: "http://127.0.0.1:8545".to_string(),
            oracle_url: "http://127.0.0.1:3000".to_string(),
            registry_contract_address: "0x0000000000000000000000000000000000000000".to_string(),
            p2p_port: 9000,
            p2p_listen_addr: "0.0.0.0".to_string(),
            db_path: "./data/nox_db".to_string(),
            routing_private_key: String::new(),
            p2p_private_key: String::new(),
            p2p_identity_path: "./data/p2p_id.key".to_string(),
            min_pow_difficulty: 3,
            metrics_port: 9090,

            eth_wallet_private_key: String::new(),
            min_gas_balance: "10000000000000000".to_string(),
            min_profit_margin_percent: 10,
            oracle_cache_ttl_secs: DEFAULT_ORACLE_CACHE_TTL_SECS,
            oracle_max_observation_age_secs: DEFAULT_ORACLE_MAX_OBSERVATION_AGE_SECS,
            oracle_max_future_skew_secs: DEFAULT_ORACLE_MAX_FUTURE_SKEW_SECS,
            native_asset_price_id: String::new(),
            native_asset_decimals: 18,
            gas_limit_buffer_bps: DEFAULT_GAS_LIMIT_BUFFER_BPS,
            initial_fee_buffer_bps: DEFAULT_INITIAL_FEE_BUFFER_BPS,
            replacement_step_bps: DEFAULT_REPLACEMENT_STEP_BPS,
            chain_data_fee_mode: ChainDataFeeMode::RpcGasEstimateIncludesDataFee,
            chain_id: 0,

            network: NetworkConfig::default(),
            relayer: RelayerConfig::default(),
            benchmark_mode: false,
            node_role: NodeRole::default(),
            http: HttpConfig::default(),
            exit_workers: ExitWorkerConfig::default(),

            block_poll_interval_secs: 12,
            chain_start_block: 0,
            topology_reconcile_interval_secs: default_topology_reconcile_interval_secs(),

            bootstrap_topology_urls: Vec::new(),
            topology_api_port: 0,

            max_broadcast_tx_size: 128 * 1024,

            ingress_port: 0,
            ingress: IngressConfig::default(),
            response_prune_interval_secs: 60,

            nox_reward_pool_address: "0x0000000000000000000000000000000000000000".to_string(),
            nox_entry_point_address: "0x0000000000000000000000000000000000000000".to_string(),
            quote_ttl_secs: 0,
            quote_network_fee_bps: 0,
            quote_maximum_transaction_gas: 0,
            quote_max_outstanding: 0,
            quote_max_pending_sponsored_gas: 0,
            quote_rolling_loss_limit_native: "0".to_string(),
            quote_rolling_loss_window_secs: 0,
            payment_adapters: Vec::new(),

            tokens: Vec::new(),
        }
    }
}

impl NoxConfig {
    pub fn load(config_path: &str) -> Result<Self, ConfigError> {
        info!("Loading configuration from: {}", config_path);

        let builder = Config::builder()
            .add_source(Config::try_from(&NoxConfig::default())?)
            .add_source(File::from(Path::new(config_path)).required(false))
            .add_source(Environment::with_prefix("NOX").separator("__"));

        builder.build()?.try_deserialize()
    }

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if !self.benchmark_mode {
            if self.routing_private_key.is_empty() {
                errors.push("routing_private_key is empty (required in production)".into());
            }
            if self.node_role.is_exit_capable() && self.eth_wallet_private_key.is_empty() {
                errors.push("eth_wallet_private_key is empty (required for exit/full role)".into());
            }
        }

        let zero_addr = "0x0000000000000000000000000000000000000000";
        for (name, addr) in [
            ("registry_contract_address", &self.registry_contract_address),
            ("nox_reward_pool_address", &self.nox_reward_pool_address),
            ("nox_entry_point_address", &self.nox_entry_point_address),
        ] {
            if !addr.starts_with("0x") || addr.len() != 42 || hex::decode(&addr[2..]).is_err() {
                errors.push(format!(
                    "{name} is not a valid Ethereum address (got: \"{}\")",
                    &addr[..addr.len().min(20)]
                ));
            }
        }
        if !self.benchmark_mode {
            if self.registry_contract_address == zero_addr {
                errors.push("registry_contract_address is zero address".into());
            }
            if self.node_role.is_exit_capable() && self.nox_reward_pool_address == zero_addr {
                errors.push(
                    "nox_reward_pool_address is zero address (required for exit/full role)".into(),
                );
            }
            if self.node_role.is_exit_capable() && self.nox_entry_point_address == zero_addr {
                errors.push(
                    "nox_entry_point_address is zero address (required for exit/full role)".into(),
                );
            }
        }

        if self.p2p_port == 0 {
            errors.push("p2p_port is 0".into());
        }

        errors.extend(self.ingress.validation_errors());

        if self.chain_id == 0 && !self.benchmark_mode {
            errors.push("chain_id is 0 (must be set for production)".into());
        }

        if self.eth_rpc_url.is_empty() {
            errors.push("eth_rpc_url is empty".into());
        }

        if self.oracle_url.is_empty() && self.node_role.is_exit_capable() && !self.benchmark_mode {
            errors.push("oracle_url is empty (required for exit/full role)".into());
        }

        if self.node_role.is_exit_capable() && !self.benchmark_mode {
            if self.oracle_max_observation_age_secs == 0
                || self.oracle_max_observation_age_secs > MAX_ORACLE_OBSERVATION_AGE_SECS
            {
                errors.push(format!(
                    "oracle_max_observation_age_secs must be in 1..={MAX_ORACLE_OBSERVATION_AGE_SECS}"
                ));
            }
            if self.oracle_cache_ttl_secs == 0
                || self.oracle_cache_ttl_secs > self.oracle_max_observation_age_secs
            {
                errors.push(
                    "oracle_cache_ttl_secs must be in 1..=oracle_max_observation_age_secs".into(),
                );
            }
            if self.oracle_max_future_skew_secs > MAX_ORACLE_FUTURE_SKEW_SECS {
                errors.push(format!(
                    "oracle_max_future_skew_secs must be in 0..={MAX_ORACLE_FUTURE_SKEW_SECS}"
                ));
            }
            if self.native_asset_price_id.trim().is_empty() {
                errors.push("native_asset_price_id is empty (required for exit/full role)".into());
            }
            if self.native_asset_decimals == 0
                || self.native_asset_decimals > MAX_NATIVE_ASSET_DECIMALS
            {
                errors.push(format!(
                    "native_asset_decimals must be in 1..={MAX_NATIVE_ASSET_DECIMALS}"
                ));
            }
            if self.gas_limit_buffer_bps > MAX_BUFFER_BPS {
                errors.push(format!("gas_limit_buffer_bps must be <= {MAX_BUFFER_BPS}"));
            }
            if self.initial_fee_buffer_bps > MAX_BUFFER_BPS {
                errors.push(format!(
                    "initial_fee_buffer_bps must be <= {MAX_BUFFER_BPS}"
                ));
            }
            if self.replacement_step_bps == 0 || self.replacement_step_bps > MAX_BUFFER_BPS {
                errors.push(format!(
                    "replacement_step_bps must be in 1..={MAX_BUFFER_BPS}"
                ));
            }
            if self.min_profit_margin_percent > MAX_MARGIN_PERCENT {
                errors.push(format!(
                    "min_profit_margin_percent must be <= {MAX_MARGIN_PERCENT}"
                ));
            }
            if self.quote_ttl_secs == 0 || self.quote_ttl_secs > 300 {
                errors.push("quote_ttl_secs must be in 1..=300".to_string());
            }
            if self.quote_network_fee_bps > MAX_BUFFER_BPS {
                errors.push(format!("quote_network_fee_bps must be <= {MAX_BUFFER_BPS}"));
            }
            if self.quote_maximum_transaction_gas == 0 {
                errors.push("quote_maximum_transaction_gas must be positive".to_string());
            }
            if self.quote_max_outstanding == 0 {
                errors.push("quote_max_outstanding must be positive".to_string());
            }
            if self.quote_max_pending_sponsored_gas == 0 {
                errors.push("quote_max_pending_sponsored_gas must be positive".to_string());
            }
            if self
                .quote_rolling_loss_limit_native
                .parse::<ethers::types::U256>()
                .map_or(true, |limit| limit.is_zero())
            {
                errors
                    .push("quote_rolling_loss_limit_native must be a positive integer".to_string());
            }
            if self.quote_rolling_loss_window_secs == 0 {
                errors.push("quote_rolling_loss_window_secs must be positive".to_string());
            }
            if self.payment_adapters.is_empty() {
                errors.push("payment_adapters must contain at least one exit adapter".to_string());
            }
            if self.tokens.is_empty() {
                errors.push("tokens must contain explicit exit fee-asset metadata".to_string());
            }
            let mut token_addresses = HashSet::new();
            for token in &self.tokens {
                match token.address.parse::<ethers::types::Address>() {
                    Ok(address) if !address.is_zero() => {
                        if !token_addresses.insert(address) {
                            errors.push("token addresses must be unique".to_string());
                        }
                    }
                    Ok(_) | Err(_) => errors.push("token address is invalid".to_string()),
                }
                if token.symbol.trim().is_empty() {
                    errors.push("token symbol must not be empty".to_string());
                }
                if token.price_id.trim().is_empty() {
                    errors.push("token price_id must not be empty".to_string());
                }
                if token.decimals > MAX_NATIVE_ASSET_DECIMALS {
                    errors.push(format!(
                        "token decimals must be <= {MAX_NATIVE_ASSET_DECIMALS}"
                    ));
                }
            }
            let mut adapter_addresses = HashSet::new();
            for adapter in &self.payment_adapters {
                if adapter.maximum_payment_gas == 0 {
                    errors.push("payment adapter maximum_payment_gas must be positive".to_string());
                }
                if adapter.fee_assets.is_empty() {
                    errors.push("payment adapter must allow at least one fee asset".to_string());
                }
                if let Ok(address) = adapter.address.parse::<ethers::types::Address>() {
                    if !adapter_addresses.insert(address) {
                        errors.push("payment adapter addresses must be unique".to_string());
                    }
                }
                let mut fee_assets = HashSet::new();
                for asset in &adapter.fee_assets {
                    if let Ok(address) = asset.parse::<ethers::types::Address>() {
                        if !fee_assets.insert(address) {
                            errors.push("payment adapter fee assets must be unique".to_string());
                        }
                        if !token_addresses.contains(&address) {
                            errors.push(format!(
                                "payment adapter fee asset {address:?} is missing token metadata"
                            ));
                        }
                    }
                }
                for (field, address) in std::iter::once(("payment adapter", &adapter.address))
                    .chain(
                        adapter
                            .fee_assets
                            .iter()
                            .map(|asset| ("payment adapter fee asset", asset)),
                    )
                {
                    if !address.starts_with("0x")
                        || address.len() != 42
                        || hex::decode(&address[2..]).is_err()
                        || address == zero_addr
                    {
                        errors.push(format!("{field} address is invalid"));
                    }
                }
            }
        }

        if self.network.max_connections == 0 {
            errors.push("network.max_connections is 0".into());
        }
        if self.relayer.queue_size == 0 {
            errors.push("relayer.queue_size is 0".into());
        }
        if self.relayer.worker_count == 0 {
            errors.push("relayer.worker_count is 0 (relay pipeline would stall)".into());
        }
        for (name, value) in [
            (
                "exit_workers.paid_concurrency",
                self.exit_workers.paid_concurrency,
            ),
            (
                "exit_workers.quote_concurrency",
                self.exit_workers.quote_concurrency,
            ),
            (
                "exit_workers.proxy_concurrency",
                self.exit_workers.proxy_concurrency,
            ),
            (
                "exit_workers.control_concurrency",
                self.exit_workers.control_concurrency,
            ),
            (
                "exit_workers.queue_capacity",
                self.exit_workers.queue_capacity,
            ),
        ] {
            if value == 0 {
                errors.push(format!("{name} is 0 (exit lane would stall)"));
            }
        }

        if self.block_poll_interval_secs == 0 && !self.benchmark_mode {
            errors.push("block_poll_interval_secs is 0 (would cause 100% CPU spin)".into());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn min_profit_margin_bps(&self) -> Result<u128, String> {
        u128::from(self.min_profit_margin_percent)
            .checked_mul(100)
            .ok_or_else(|| "min_profit_margin_percent conversion overflow".to_string())
    }

    /// Ephemeral keys only available with `dev-node` feature + `benchmark_mode`.
    pub fn get_routing_key(&self) -> Result<X25519SecretKey, anyhow::Error> {
        if self.routing_private_key.is_empty() {
            #[cfg(feature = "dev-node")]
            if self.benchmark_mode {
                tracing::warn!(
                    "Using ephemeral routing key (benchmark mode). \
                     Identity will be lost on restart."
                );
                return Ok(X25519SecretKey::random_from_rng(rand::rngs::OsRng));
            }

            anyhow::bail!(
                "routing_private_key is empty. \
                 Set it in config.toml or via NOX__ROUTING_PRIVATE_KEY env var."
            );
        }

        let bytes = hex::decode(&self.routing_private_key)
            .map_err(|e| anyhow::anyhow!("Hex decode failed: {e}"))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid key length (expected 32 bytes)"))?;
        Ok(X25519SecretKey::from(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configure_quote_policy(config: &mut NoxConfig) {
        config.quote_ttl_secs = 30;
        config.quote_network_fee_bps = 500;
        config.quote_maximum_transaction_gas = 10_000_000;
        config.quote_max_outstanding = 256;
        config.quote_max_pending_sponsored_gas = 500_000_000;
        config.quote_rolling_loss_limit_native = "100000000000000000".to_string();
        config.quote_rolling_loss_window_secs = 3_600;
        config.payment_adapters = vec![PaymentAdapterConfig {
            address: "0x2222222222222222222222222222222222222222".to_string(),
            fee_assets: vec!["0x3333333333333333333333333333333333333333".to_string()],
            maximum_payment_gas: 4_000_000,
        }];
        config.tokens = vec![TokenConfig {
            address: "0x3333333333333333333333333333333333333333".to_string(),
            symbol: "TEST".to_string(),
            decimals: 18,
            price_id: "test-token".to_string(),
        }];
    }

    #[test]
    fn test_fragmentation_config_matches_core_defaults() {
        let config = FragmentationConfig::default();
        assert_eq!(
            config.max_pending_bytes,
            nox_core::protocol::fragmentation::DEFAULT_MAX_BUFFER_BYTES,
        );
        assert_eq!(
            config.max_concurrent_messages,
            nox_core::protocol::fragmentation::DEFAULT_MAX_CONCURRENT_MESSAGES,
        );
    }

    #[test]
    fn test_response_prune_interval_default() {
        let config = NoxConfig::default();
        assert_eq!(config.response_prune_interval_secs, 60);
    }

    #[test]
    fn test_config_validate_rejects_invalid_address() {
        let mut config = NoxConfig::default();
        config.benchmark_mode = true;
        config.registry_contract_address = "not-an-address".to_string();

        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.contains("registry_contract_address")
                && e.contains("not a valid Ethereum address")));
    }

    #[test]
    fn ingress_policy_defaults_are_valid_and_keep_any_origin() {
        let ingress = IngressConfig::default();
        assert!(ingress.validation_errors().is_empty());
        assert!(ingress.cors_allowed_origins.is_empty());
        assert_eq!(
            ingress.rate_limit_per_sec,
            DEFAULT_INGRESS_RATE_LIMIT_PER_SEC
        );
    }

    #[test]
    fn ingress_policy_rejects_malformed_values() {
        let ingress = IngressConfig {
            rate_limit_per_sec: 10,
            rate_limit_burst: 0,
            client_ip_header: "bad header".to_string(),
            cors_allowed_origins: vec![
                "https://demo.example".to_string(),
                "https://demo.example/".to_string(),
                "demo.example".to_string(),
            ],
        };
        let errors = ingress.validation_errors();
        assert_eq!(errors.len(), 4, "{errors:?}");
        assert!(errors.iter().any(|e| e.contains("rate_limit_burst")));
        assert!(errors.iter().any(|e| e.contains("client_ip_header")));
        assert!(errors
            .iter()
            .any(|e| e.contains("\"https://demo.example/\"")));
        assert!(errors.iter().any(|e| e.contains("\"demo.example\"")));
    }

    #[test]
    fn ingress_policy_is_optional_in_config_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nox.toml");
        std::fs::write(&path, "benchmark_mode = true\n").expect("write config");
        let config = NoxConfig::load(path.to_str().expect("utf-8 path")).expect("load");
        assert_eq!(
            config.ingress.rate_limit_burst,
            DEFAULT_INGRESS_RATE_LIMIT_BURST
        );

        std::fs::write(
            &path,
            "benchmark_mode = true\n[ingress]\ncors_allowed_origins = [\"https://demo.example\"]\n",
        )
        .expect("write config");
        let config = NoxConfig::load(path.to_str().expect("utf-8 path")).expect("load");
        assert_eq!(
            config.ingress.cors_allowed_origins,
            vec!["https://demo.example".to_string()]
        );
        assert_eq!(
            config.ingress.rate_limit_per_sec,
            DEFAULT_INGRESS_RATE_LIMIT_PER_SEC
        );
    }

    #[test]
    fn test_config_validate_accepts_valid_addresses() {
        let mut config = NoxConfig::default();
        config.benchmark_mode = true;
        let result = config.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_validate_production_rejects_defaults() {
        let config = NoxConfig::default();
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("routing_private_key")),
            "Should reject empty routing_private_key in production"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("registry_contract_address") && e.contains("zero")),
            "Should reject zero registry address in production"
        );
        assert!(
            errors.iter().any(|e| e.contains("chain_id")),
            "Should reject zero chain_id in production"
        );
    }

    #[test]
    fn test_config_validate_production_accepts_valid_config() {
        let mut config = NoxConfig::default();
        config.routing_private_key = "aa".repeat(32);
        config.eth_wallet_private_key = "bb".repeat(32);
        config.registry_contract_address = "0x1234567890abcdef1234567890abcdef12345678".to_string();
        config.nox_reward_pool_address = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string();
        config.nox_entry_point_address = "0x1111111111111111111111111111111111111111".to_string();
        config.native_asset_price_id = "avalanche-2".to_string();
        config.chain_id = 1;
        configure_quote_policy(&mut config);
        let result = config.validate();
        assert!(
            result.is_ok(),
            "Valid production config should pass: {:?}",
            result
        );
    }

    #[test]
    fn test_config_validate_rejects_zero_worker_count() {
        let mut config = NoxConfig::default();
        config.benchmark_mode = true;
        config.relayer.worker_count = 0;
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("worker_count")));
    }

    #[test]
    fn test_config_validate_rejects_zero_block_poll_interval() {
        let mut config = NoxConfig::default();
        config.benchmark_mode = false;
        config.block_poll_interval_secs = 0;
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.contains("block_poll_interval_secs")));
    }

    #[test]
    fn test_config_validate_relay_role_skips_wallet_check() {
        let mut config = NoxConfig::default();
        config.routing_private_key = "aa".repeat(32);
        config.registry_contract_address = "0x1234567890abcdef1234567890abcdef12345678".to_string();
        config.chain_id = 1;
        config.node_role = NodeRole::Relay;
        let result = config.validate();
        assert!(
            result.is_ok(),
            "Relay role should not require exit-only fields: {:?}",
            result
        );
    }

    #[test]
    fn oracle_freshness_and_economics_boundaries_are_enforced() {
        let mut config = NoxConfig::default();
        config.benchmark_mode = false;
        config.node_role = NodeRole::Exit;
        config.routing_private_key = "aa".repeat(32);
        config.eth_wallet_private_key = "bb".repeat(32);
        config.registry_contract_address = "0x1234567890abcdef1234567890abcdef12345678".to_string();
        config.nox_reward_pool_address = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string();
        config.nox_entry_point_address = "0x1111111111111111111111111111111111111111".to_string();
        config.chain_id = 1;
        config.native_asset_price_id = "avalanche-2".to_string();
        configure_quote_policy(&mut config);
        assert!(config.validate().is_ok());

        config.oracle_cache_ttl_secs = config.oracle_max_observation_age_secs + 1;
        assert!(config
            .validate()
            .unwrap_err()
            .iter()
            .any(|error| error.contains("oracle_cache_ttl_secs")));
        config.oracle_cache_ttl_secs = DEFAULT_ORACLE_CACHE_TTL_SECS;
        config.oracle_max_future_skew_secs = MAX_ORACLE_FUTURE_SKEW_SECS + 1;
        assert!(config
            .validate()
            .unwrap_err()
            .iter()
            .any(|error| error.contains("oracle_max_future_skew_secs")));
        config.oracle_max_future_skew_secs = DEFAULT_ORACLE_MAX_FUTURE_SKEW_SECS;
        config.gas_limit_buffer_bps = MAX_BUFFER_BPS + 1;
        assert!(config
            .validate()
            .unwrap_err()
            .iter()
            .any(|error| error.contains("gas_limit_buffer_bps")));
    }

    #[test]
    fn percent_to_basis_points_is_exact() {
        let mut config = NoxConfig::default();
        config.min_profit_margin_percent = 10;
        assert_eq!(config.min_profit_margin_bps().unwrap(), 1_000);
    }

    #[test]
    fn rpc_total_gas_cost_mode_is_the_only_accepted_spelling() {
        assert_eq!(
            serde_json::from_str::<ChainDataFeeMode>(r#""rpc_gas_estimate_includes_data_fee""#,)
                .unwrap(),
            ChainDataFeeMode::RpcGasEstimateIncludesDataFee,
        );
        assert!(serde_json::from_str::<ChainDataFeeMode>(r#""zero""#).is_err());
    }

    #[test]
    fn exit_requires_a_nonzero_entry_point() {
        let mut config = NoxConfig::default();
        config.node_role = NodeRole::Exit;
        config.nox_entry_point_address = "0x0000000000000000000000000000000000000000".to_string();
        assert!(config
            .validate()
            .unwrap_err()
            .iter()
            .any(|error| error.contains("nox_entry_point_address")));
    }

    #[test]
    fn quote_policy_rejects_duplicate_adapters_and_fee_assets() {
        let mut config = NoxConfig::default();
        config.node_role = NodeRole::Exit;
        configure_quote_policy(&mut config);
        let duplicate_asset = config.payment_adapters[0].fee_assets[0].clone();
        config.payment_adapters[0].fee_assets.push(duplicate_asset);
        let duplicate_adapter = config.payment_adapters[0].clone();
        config.payment_adapters.push(duplicate_adapter);
        let errors = config.validate().unwrap_err();
        assert!(errors
            .iter()
            .any(|error| error.contains("addresses must be unique")));
        assert!(errors
            .iter()
            .any(|error| error.contains("fee assets must be unique")));
    }

    #[test]
    fn exit_quote_assets_require_explicit_unambiguous_token_metadata() {
        let mut config = NoxConfig::default();
        config.node_role = NodeRole::Exit;
        configure_quote_policy(&mut config);

        config.tokens.clear();
        let errors = config.validate().unwrap_err();
        assert!(errors
            .iter()
            .any(|error| error.contains("tokens must contain")));

        configure_quote_policy(&mut config);
        config.tokens.push(config.tokens[0].clone());
        let errors = config.validate().unwrap_err();
        assert!(errors
            .iter()
            .any(|error| error.contains("token addresses must be unique")));

        configure_quote_policy(&mut config);
        config.tokens[0].price_id.clear();
        config.tokens[0].symbol.clear();
        config.tokens[0].decimals = MAX_NATIVE_ASSET_DECIMALS + 1;
        let errors = config.validate().unwrap_err();
        assert!(errors.iter().any(|error| error.contains("token symbol")));
        assert!(errors.iter().any(|error| error.contains("token price_id")));
        assert!(errors.iter().any(|error| error.contains("token decimals")));

        configure_quote_policy(&mut config);
        config.payment_adapters[0].fee_assets[0] =
            "0x4444444444444444444444444444444444444444".to_string();
        let errors = config.validate().unwrap_err();
        assert!(errors
            .iter()
            .any(|error| error.contains("missing token metadata")));
    }
}
