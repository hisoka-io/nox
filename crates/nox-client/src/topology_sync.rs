//! Fetches topology from seed nodes, verifies XOR fingerprint against on-chain
//! `NoxRegistry.topologyFingerprint()`, and hot-swaps the client's topology.

use ethers::prelude::*;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

use crate::topology_node::TopologyNode;
use nox_core::compute_topology_fingerprint;
use nox_core::models::topology::TopologySnapshot;

/// Default seed URLs tried when `seed_urls` is empty.
pub const DEFAULT_SEED_URLS: &[&str] = &["https://api.hisoka.io/seed/topology"];

#[derive(Debug, Clone)]
pub struct TopologySyncConfig {
    /// Seed node URLs serving `GET /topology`. Tried in order; first verified wins.
    /// If empty, `DEFAULT_SEED_URLS` are used automatically.
    pub seed_urls: Vec<String>,
    pub eth_rpc_url: String,
    pub registry_address: Address,
    pub refresh_interval: Duration,
    pub request_timeout: Duration,
    /// Skip on-chain verification (benchmarks/simulations only).
    /// Self-consistency check (computed == claimed fingerprint) always runs.
    pub skip_chain_verification: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum TopologySyncError {
    #[error("No seed URLs configured")]
    NoSeedNodes,

    #[error("All seed nodes failed: {0}")]
    AllSeedsFailed(String),

    #[error("Fingerprint mismatch: computed={computed}, on_chain={on_chain}")]
    FingerprintMismatch { computed: String, on_chain: String },

    #[error("Chain verification error: {0}")]
    ChainError(String),

    #[error("HTTP fetch error: {0}")]
    FetchError(String),

    #[error("Node conversion error: {0}")]
    ConversionError(String),
}

pub struct TopologySyncClient {
    config: TopologySyncConfig,
    topology: Arc<RwLock<Vec<TopologyNode>>>,
    /// Network-advertised `PoW` difficulty, updated on each successful sync.
    pow_difficulty: Arc<AtomicU32>,
    http_client: reqwest::Client,
}

impl std::fmt::Debug for TopologySyncClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TopologySyncClient")
            .field("config", &self.config)
            .field("topology_len", &self.topology.read().len())
            .finish_non_exhaustive()
    }
}

impl TopologySyncClient {
    pub fn new(
        config: TopologySyncConfig,
        topology: Arc<RwLock<Vec<TopologyNode>>>,
    ) -> Result<Self, TopologySyncError> {
        Self::with_pow_difficulty(config, topology, Arc::new(AtomicU32::new(0)))
    }

    pub fn with_pow_difficulty(
        mut config: TopologySyncConfig,
        topology: Arc<RwLock<Vec<TopologyNode>>>,
        pow_difficulty: Arc<AtomicU32>,
    ) -> Result<Self, TopologySyncError> {
        if config.seed_urls.is_empty() {
            config.seed_urls = DEFAULT_SEED_URLS.iter().map(|s| (*s).to_string()).collect();
            info!(
                "No seed URLs configured, using defaults: {:?}",
                config.seed_urls
            );
        }

        let http_client = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .build()
            .map_err(|e| TopologySyncError::FetchError(format!("HTTP client init: {e}")))?;

        Ok(Self {
            config,
            topology,
            pow_difficulty,
            http_client,
        })
    }

    /// Fetch from seed, verify, hot-swap. Returns node count on success.
    pub async fn sync_once(&self) -> Result<usize, TopologySyncError> {
        let mut last_error = String::new();

        for url in &self.config.seed_urls {
            match self.fetch_and_verify(url).await {
                Ok((nodes, pow_diff)) => {
                    let count = nodes.len();
                    *self.topology.write() = nodes;
                    self.pow_difficulty.store(pow_diff, Ordering::Relaxed);
                    info!(
                        "Topology synced: {} nodes from {url} (pow_difficulty={pow_diff})",
                        count
                    );
                    return Ok(count);
                }
                Err(e) => {
                    last_error = format!("{url}: {e}");
                    warn!("Seed {url} failed: {e}");
                }
            }
        }

        Err(TopologySyncError::AllSeedsFailed(last_error))
    }

    async fn fetch_and_verify(
        &self,
        url: &str,
    ) -> Result<(Vec<TopologyNode>, u32), TopologySyncError> {
        let resp = self
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| TopologySyncError::FetchError(format!("{e}")))?;

        if !resp.status().is_success() {
            return Err(TopologySyncError::FetchError(format!(
                "HTTP {}",
                resp.status()
            )));
        }

        let snapshot: TopologySnapshot = resp
            .json()
            .await
            .map_err(|e| TopologySyncError::FetchError(format!("JSON parse: {e}")))?;

        if snapshot.nodes.is_empty() {
            return Err(TopologySyncError::FetchError(
                "Empty topology snapshot".into(),
            ));
        }

        let addresses: Vec<_> = snapshot.nodes.iter().map(|n| n.address.clone()).collect();
        let computed = compute_topology_fingerprint(&addresses);
        let computed_hex = hex::encode(computed);

        if computed_hex != snapshot.fingerprint {
            return Err(TopologySyncError::FingerprintMismatch {
                computed: computed_hex,
                on_chain: snapshot.fingerprint,
            });
        }

        if self.config.skip_chain_verification {
            debug!("Skipping on-chain fingerprint verification (benchmark mode)");
        } else {
            self.verify_on_chain_fingerprint(&computed).await?;
        }

        let pow_diff = snapshot.pow_difficulty;
        let mut topology_nodes = Vec::with_capacity(snapshot.nodes.len());
        for node in &snapshot.nodes {
            let topo_node = TopologyNode::from_relayer_node(node)
                .map_err(TopologySyncError::ConversionError)?;
            topology_nodes.push(topo_node);
        }

        debug!(
            "Verified {} nodes from {url} (fingerprint={}, pow_difficulty={})",
            topology_nodes.len(),
            computed_hex,
            pow_diff
        );

        Ok((topology_nodes, pow_diff))
    }

    /// Raw `eth_call` with function selector (no abigen needed).
    async fn verify_on_chain_fingerprint(
        &self,
        computed: &[u8; 32],
    ) -> Result<(), TopologySyncError> {
        let provider = Provider::<Http>::try_from(&self.config.eth_rpc_url)
            .map_err(|e| TopologySyncError::ChainError(format!("Provider init: {e}")))?;

        let mut selector = [0u8; 4];
        let mut hasher = tiny_keccak::Keccak::v256();
        tiny_keccak::Hasher::update(&mut hasher, b"topologyFingerprint()");
        let mut full_hash = [0u8; 32];
        tiny_keccak::Hasher::finalize(hasher, &mut full_hash);
        selector.copy_from_slice(&full_hash[..4]);

        let tx = TransactionRequest::new()
            .to(self.config.registry_address)
            .data(selector.to_vec());

        let result = tokio::time::timeout(Duration::from_secs(10), provider.call(&tx.into(), None))
            .await
            .map_err(|_| TopologySyncError::ChainError("eth_call timed out (10s)".into()))?
            .map_err(|e| TopologySyncError::ChainError(format!("eth_call: {e}")))?;

        if result.len() < 32 {
            return Err(TopologySyncError::ChainError(format!(
                "Unexpected return length: {} (expected >= 32)",
                result.len()
            )));
        }

        let on_chain: [u8; 32] = result[..32]
            .try_into()
            .map_err(|_| TopologySyncError::ChainError("Failed to parse bytes32".into()))?;

        if computed != &on_chain {
            return Err(TopologySyncError::FingerprintMismatch {
                computed: hex::encode(computed),
                on_chain: hex::encode(on_chain),
            });
        }

        debug!("On-chain fingerprint verified: {}", hex::encode(on_chain));
        Ok(())
    }

    /// Returns the shared `AtomicU32` backing the network-advertised `PoW` difficulty.
    /// Callers (e.g. `MixnetClient`) can read this to stay in sync with the network.
    #[must_use]
    pub fn pow_difficulty_handle(&self) -> Arc<AtomicU32> {
        Arc::clone(&self.pow_difficulty)
    }

    /// Run the sync loop. Errors are logged; stale topology used until refresh succeeds.
    pub async fn run(&self) {
        info!(
            "TopologySyncClient starting (refresh interval: {:?}, {} seed URLs)",
            self.config.refresh_interval,
            self.config.seed_urls.len()
        );

        match self.sync_once().await {
            Ok(count) => info!("Initial topology sync: {} nodes", count),
            Err(e) => error!("Initial topology sync failed: {e}"),
        }

        let mut interval = tokio::time::interval(self.config.refresh_interval);
        interval.tick().await; // consume immediate first tick (just synced)

        loop {
            interval.tick().await;
            match self.sync_once().await {
                Ok(count) => debug!("Topology refresh: {} nodes", count),
                Err(e) => warn!("Topology refresh failed (using stale data): {e}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_empty_seed_urls_uses_defaults() {
        let config = TopologySyncConfig {
            seed_urls: vec![],
            eth_rpc_url: "http://localhost:8545".into(),
            registry_address: Address::zero(),
            refresh_interval: Duration::from_secs(60),
            request_timeout: Duration::from_secs(10),
            skip_chain_verification: false,
        };
        let topology = Arc::new(RwLock::new(Vec::new()));
        let result = TopologySyncClient::new(config, topology);
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_with_seed_urls_accepted() {
        let config = TopologySyncConfig {
            seed_urls: vec!["http://seed1:8080/topology".into()],
            eth_rpc_url: "http://localhost:8545".into(),
            registry_address: Address::zero(),
            refresh_interval: Duration::from_secs(60),
            request_timeout: Duration::from_secs(10),
            skip_chain_verification: false,
        };
        let topology = Arc::new(RwLock::new(Vec::new()));
        let result = TopologySyncClient::new(config, topology);
        assert!(result.is_ok());
    }

    #[test]
    fn test_fingerprint_computation_matches_nox_core() {
        let addresses = vec![
            "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string(),
        ];

        let fp1 = compute_topology_fingerprint(&addresses);

        // Reverse order should produce the same result (XOR is commutative)
        let reversed = vec![addresses[1].clone(), addresses[0].clone()];
        let fp2 = compute_topology_fingerprint(&reversed);

        assert_eq!(fp1, fp2);

        // Single address XOR'd twice should cancel out (XOR self-inverse)
        let double = vec![addresses[0].clone(), addresses[0].clone()];
        let fp_double = compute_topology_fingerprint(&double);
        assert_eq!(fp_double, [0u8; 32]);
    }
}
