use config::{Config, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::info;
use zeroize::Zeroize;

use nox_core::models::handshake::Capabilities;
use x25519_dalek::StaticSecret as X25519SecretKey;

/// Maps a token contract address to its symbol, decimals, and oracle price ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenConfig {
    pub address: String,
    pub symbol: String,
    pub decimals: u8,
    /// Must match a key returned by the price oracle at /prices
    pub price_id: String,
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
    /// 0.0 = disable mixing (instant forwarding via `NoMixStrategy`).
    pub mix_delay_ms: f64,
    pub cover_traffic_rate: f64,
    pub drop_traffic_rate: f64,
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

impl Default for RelayerConfig {
    fn default() -> Self {
        Self {
            queue_size: 10_000,
            worker_count: num_cpus::get(),
            replay_window: 3600,
            bloom_capacity: 100_000,
            mix_delay_ms: 500.0,
            cover_traffic_rate: 0.05,
            drop_traffic_rate: 0.05,
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

    pub chain_id: u64,

    pub network: NetworkConfig,
    pub relayer: RelayerConfig,
    pub benchmark_mode: bool,

    pub node_role: NodeRole,
    pub http: HttpConfig,
    pub block_poll_interval_secs: u64,
    /// Block where `NoxRegistry` was deployed. 0 = start from latest.
    #[serde(default)]
    pub chain_start_block: u64,
    /// Falls back to `ChainObserver` replay if all seed URLs fail.
    #[serde(default)]
    pub bootstrap_topology_urls: Vec<String>,
    /// 0 = disabled. Binds to 0.0.0.0 when enabled.
    pub topology_api_port: u16,
    pub max_broadcast_tx_size: usize,
    /// 0 = disabled.
    pub ingress_port: u16,
    pub response_prune_interval_secs: u64,
    pub relayer_multicall_address: String,
    pub nox_reward_pool_address: String,
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
            .field("chain_id", &self.chain_id)
            .field("network", &self.network)
            .field("relayer", &self.relayer)
            .field("benchmark_mode", &self.benchmark_mode)
            .field("node_role", &self.node_role)
            .field("http", &self.http)
            .field("block_poll_interval_secs", &self.block_poll_interval_secs)
            .field("chain_start_block", &self.chain_start_block)
            .field("bootstrap_topology_urls", &self.bootstrap_topology_urls)
            .field("topology_api_port", &self.topology_api_port)
            .field("max_broadcast_tx_size", &self.max_broadcast_tx_size)
            .field("ingress_port", &self.ingress_port)
            .field(
                "response_prune_interval_secs",
                &self.response_prune_interval_secs,
            )
            .field("relayer_multicall_address", &self.relayer_multicall_address)
            .field("nox_reward_pool_address", &self.nox_reward_pool_address)
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
            chain_id: 0,

            network: NetworkConfig::default(),
            relayer: RelayerConfig::default(),
            benchmark_mode: false,
            node_role: NodeRole::default(),
            http: HttpConfig::default(),

            block_poll_interval_secs: 12,
            chain_start_block: 0,

            bootstrap_topology_urls: Vec::new(),
            topology_api_port: 0,

            max_broadcast_tx_size: 128 * 1024,

            ingress_port: 0,
            response_prune_interval_secs: 60,

            relayer_multicall_address: "0x0000000000000000000000000000000000000000".to_string(),
            nox_reward_pool_address: "0x0000000000000000000000000000000000000000".to_string(),

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
            ("relayer_multicall_address", &self.relayer_multicall_address),
            ("nox_reward_pool_address", &self.nox_reward_pool_address),
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
            if self.node_role.is_exit_capable() && self.relayer_multicall_address == zero_addr {
                errors.push(
                    "relayer_multicall_address is zero address (required for exit/full role)"
                        .into(),
                );
            }
            if self.node_role.is_exit_capable() && self.nox_reward_pool_address == zero_addr {
                errors.push(
                    "nox_reward_pool_address is zero address (required for exit/full role)".into(),
                );
            }
        }

        if self.p2p_port == 0 {
            errors.push("p2p_port is 0".into());
        }

        if self.chain_id == 0 && !self.benchmark_mode {
            errors.push("chain_id is 0 (must be set for production)".into());
        }

        if self.eth_rpc_url.is_empty() {
            errors.push("eth_rpc_url is empty".into());
        }

        if self.oracle_url.is_empty() && self.node_role.is_exit_capable() && !self.benchmark_mode {
            errors.push("oracle_url is empty (required for exit/full role)".into());
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

        if self.block_poll_interval_secs == 0 && !self.benchmark_mode {
            errors.push("block_poll_interval_secs is 0 (would cause 100% CPU spin)".into());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
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
        config.relayer_multicall_address = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string();
        config.nox_reward_pool_address = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string();
        config.chain_id = 1;
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
}
