//! Fetches topology from seed nodes, verifies XOR fingerprint against on-chain
//! `NoxRegistry.topologyFingerprint()`, and hot-swaps the client's topology.

use ethers::prelude::*;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

use crate::topology_node::TopologyNode;
use nox_core::compute_topology_fingerprint;
use nox_core::models::topology::{
    layers_for_role, RelayerNode, TopologyLivenessStatus, TopologySnapshot,
};

const VERIFIED_TOPOLOGY_SCHEMA_VERSION: u8 = 2;
pub const DEFAULT_LIVENESS_MAX_AGE: Duration = Duration::from_mins(3);

abigen!(
    NoxRegistryTopology,
    r#"[
        function relayers(address) view returns (bytes32 sphinxKey, string url, string ingressUrl, string metadataUrl, uint256 stakedAmount, uint256 unlockTime, bool isRegistered, uint8 status, bool frozen)
        function getNodeRole(address) view returns (uint8)
        function relayerCount() view returns (uint256)
        function topologyFingerprint() view returns (bytes32)
    ]"#
);

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
    /// Maximum local age for an online availability observation.
    pub liveness_max_age: Duration,
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

    #[error("Duplicate topology address: {0}")]
    DuplicateAddress(String),

    #[error("Registry profile mismatch for {address}: {field}")]
    ProfileMismatch { address: String, field: String },

    #[error("Unsupported topology schema version {0}")]
    UnsupportedSchema(u8),

    #[error("Invalid topology liveness: {0}")]
    InvalidLiveness(String),

    #[error("Invalid topology configuration: {0}")]
    InvalidConfig(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedTopologySnapshot {
    pub block_number: u64,
    pub verified_at_unix: u64,
    pub expires_at_unix: u64,
}

#[derive(Debug)]
struct RegistryProfile {
    sphinx_key: [u8; 32],
    url: String,
    ingress_url: String,
    metadata_url: String,
    staked_amount: U256,
    is_registered: bool,
    status: u8,
    frozen: bool,
    role: u8,
}

fn profile_mismatch(node: &RelayerNode, field: &str) -> TopologySyncError {
    TopologySyncError::ProfileMismatch {
        address: node.address.clone(),
        field: field.to_string(),
    }
}

fn validate_snapshot_nodes(nodes: &[RelayerNode]) -> Result<(), TopologySyncError> {
    let mut addresses = HashSet::with_capacity(nodes.len());
    let mut previous_address: Option<String> = None;
    for node in nodes {
        let address = node.address.parse::<Address>().map_err(|e| {
            TopologySyncError::ConversionError(format!("Invalid eth address {}: {e}", node.address))
        })?;
        if !addresses.insert(address) {
            return Err(TopologySyncError::DuplicateAddress(node.address.clone()));
        }
        let normalized = format!("{address:?}");
        if node.address != normalized {
            return Err(profile_mismatch(node, "address is not normalized"));
        }
        if previous_address
            .as_ref()
            .is_some_and(|previous| previous >= &normalized)
        {
            return Err(profile_mismatch(
                node,
                "addresses are not in canonical order",
            ));
        }
        previous_address = Some(normalized);
        if !matches!(node.role, 1..=3) {
            return Err(profile_mismatch(node, "unsupported role"));
        }
        if !layers_for_role(node.role).contains(&node.layer) {
            return Err(profile_mismatch(node, "layer is not permitted by role"));
        }
    }
    Ok(())
}

fn validate_snapshot_schema(
    snapshot: &TopologySnapshot,
    require_verified_schema: bool,
) -> Result<(), TopologySyncError> {
    if snapshot.schema_version != VERIFIED_TOPOLOGY_SCHEMA_VERSION {
        if !require_verified_schema && snapshot.schema_version == 1 {
            return Ok(());
        }
        return Err(TopologySyncError::UnsupportedSchema(
            snapshot.schema_version,
        ));
    }
    if snapshot.block_number == 0 {
        return Err(TopologySyncError::ChainError(
            "verified topology snapshot block number is zero".to_string(),
        ));
    }
    for node in &snapshot.nodes {
        if node.layer != nox_core::primary_layer_for_role(&node.address, node.role) {
            return Err(profile_mismatch(
                node,
                "layer is not canonical for address and role",
            ));
        }
    }
    if snapshot.liveness.len() != snapshot.nodes.len() {
        return Err(TopologySyncError::InvalidLiveness(format!(
            "record count {} does not match member count {}",
            snapshot.liveness.len(),
            snapshot.nodes.len()
        )));
    }
    let mut addresses = HashSet::with_capacity(snapshot.liveness.len());
    for (member, liveness) in snapshot.nodes.iter().zip(&snapshot.liveness) {
        let address = liveness.address.parse::<Address>().map_err(|error| {
            TopologySyncError::InvalidLiveness(format!(
                "invalid address {}: {error}",
                liveness.address
            ))
        })?;
        let normalized = format!("{address:?}");
        if liveness.address != normalized {
            return Err(TopologySyncError::InvalidLiveness(format!(
                "address {} is not normalized",
                liveness.address
            )));
        }
        if !addresses.insert(address) {
            return Err(TopologySyncError::InvalidLiveness(format!(
                "duplicate address {}",
                liveness.address
            )));
        }
        if liveness.address != member.address {
            return Err(TopologySyncError::InvalidLiveness(format!(
                "address {} does not match member {}",
                liveness.address, member.address
            )));
        }
    }
    Ok(())
}

fn is_loopback_url(value: &str) -> bool {
    reqwest::Url::parse(value)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        })
}

fn liveness_max_age_secs(max_age: Duration) -> u64 {
    u64::try_from(max_age.as_millis().div_ceil(1_000)).unwrap_or(u64::MAX)
}

fn eligible_nodes<'a>(
    snapshot: &'a TopologySnapshot,
    local_now_unix: u64,
    liveness_max_age: Duration,
    chain_active_addresses: Option<&HashSet<Address>>,
) -> (Vec<&'a RelayerNode>, Option<u64>) {
    if snapshot.schema_version != VERIFIED_TOPOLOGY_SCHEMA_VERSION {
        return (snapshot.nodes.iter().collect(), None);
    }
    let max_age_secs = liveness_max_age_secs(liveness_max_age);
    let mut earliest_expiry = None;
    let nodes = snapshot
        .nodes
        .iter()
        .zip(&snapshot.liveness)
        .filter_map(|(node, liveness)| {
            let Ok(address) = liveness.address.parse::<Address>() else {
                return None;
            };
            let chain_active =
                chain_active_addresses.is_none_or(|addresses| addresses.contains(&address));
            let observation_is_fresh = liveness.observed_at_unix <= local_now_unix
                && local_now_unix - liveness.observed_at_unix <= max_age_secs;
            let eligible = chain_active
                && liveness.status == TopologyLivenessStatus::Online
                && observation_is_fresh;
            if eligible {
                let expiry = liveness.observed_at_unix.saturating_add(max_age_secs);
                earliest_expiry =
                    Some(earliest_expiry.map_or(expiry, |current: u64| current.min(expiry)));
            }
            eligible.then_some(node)
        })
        .collect();
    (nodes, earliest_expiry)
}

fn validate_relayer_count(
    snapshot_count: usize,
    relayer_count: U256,
) -> Result<(), TopologySyncError> {
    if relayer_count != U256::from(snapshot_count) {
        return Err(TopologySyncError::ChainError(format!(
            "relayer count mismatch: snapshot={snapshot_count}, on_chain={relayer_count}"
        )));
    }
    Ok(())
}

fn select_verification_block(
    advertised_block: u64,
    current_block: u64,
) -> Result<u64, TopologySyncError> {
    let block = if advertised_block == 0 {
        current_block
    } else {
        advertised_block
    };
    if block == 0 {
        return Err(TopologySyncError::ChainError(
            "registry verification block is zero".to_string(),
        ));
    }
    Ok(block)
}

fn build_ethers_http1_provider(rpc_url: &str) -> Result<Provider<Http>, TopologySyncError> {
    let url = rpc_url.parse::<reqwest_legacy::Url>().map_err(|error| {
        TopologySyncError::ChainError(format!("invalid Ethers RPC URL: {error}"))
    })?;
    let client = reqwest_legacy::Client::builder()
        .http1_only()
        .build()
        .map_err(|error| {
            TopologySyncError::ChainError(format!(
                "Ethers HTTP/1 client initialization failed: {error}"
            ))
        })?;
    Ok(Provider::new(Http::new_with_client(url, client)))
}

fn validate_registry_profile(
    node: &RelayerNode,
    profile: &RegistryProfile,
) -> Result<bool, TopologySyncError> {
    let sphinx_key = hex::decode(&node.sphinx_key)
        .map_err(|_| profile_mismatch(node, "invalid sphinx key encoding"))?;
    if sphinx_key.as_slice() != profile.sphinx_key {
        return Err(profile_mismatch(node, "sphinx key"));
    }
    if node.url != profile.url {
        return Err(profile_mismatch(node, "p2p url"));
    }
    if node.ingress_url.as_deref().unwrap_or_default() != profile.ingress_url {
        return Err(profile_mismatch(node, "ingress url"));
    }
    if node.metadata_url.as_deref().unwrap_or_default() != profile.metadata_url {
        return Err(profile_mismatch(node, "metadata url"));
    }
    let stake =
        U256::from_dec_str(&node.stake).map_err(|_| profile_mismatch(node, "invalid stake"))?;
    if stake != profile.staked_amount {
        return Err(profile_mismatch(node, "stake"));
    }
    if node.is_privileged != profile.staked_amount.is_zero() {
        return Err(profile_mismatch(node, "privileged status"));
    }
    if !profile.is_registered {
        return Err(profile_mismatch(node, "registered membership"));
    }
    if !matches!(profile.status, 1 | 2) {
        return Err(profile_mismatch(node, "known registration status"));
    }
    if node.role != profile.role {
        return Err(profile_mismatch(node, "role"));
    }
    Ok(!profile.frozen)
}

pub struct TopologySyncClient {
    config: TopologySyncConfig,
    topology: Arc<RwLock<Vec<TopologyNode>>>,
    /// Network-advertised `PoW` difficulty, updated on each successful sync.
    pow_difficulty: Arc<AtomicU32>,
    last_verified_block: Arc<AtomicU64>,
    last_verified_at_unix: Arc<AtomicU64>,
    topology_expires_at_unix: Arc<AtomicU64>,
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
        if config.liveness_max_age.is_zero() {
            return Err(TopologySyncError::InvalidLiveness(
                "maximum age must be positive".to_string(),
            ));
        }
        if config.seed_urls.is_empty() {
            config.seed_urls = DEFAULT_SEED_URLS.iter().map(|s| (*s).to_string()).collect();
            info!(
                "No seed URLs configured, using defaults: {:?}",
                config.seed_urls
            );
        }
        if config.skip_chain_verification
            && !config.seed_urls.iter().all(|url| is_loopback_url(url))
        {
            return Err(TopologySyncError::InvalidConfig(
                "skip_chain_verification is restricted to loopback test meshes".to_string(),
            ));
        }
        if config.refresh_interval.is_zero() || config.refresh_interval > config.liveness_max_age {
            return Err(TopologySyncError::InvalidConfig(
                "refresh interval must be positive and not exceed liveness maximum age".to_string(),
            ));
        }

        let http_client = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .build()
            .map_err(|e| TopologySyncError::FetchError(format!("HTTP client init: {e}")))?;

        Ok(Self {
            config,
            topology,
            pow_difficulty,
            last_verified_block: Arc::new(AtomicU64::new(0)),
            last_verified_at_unix: Arc::new(AtomicU64::new(0)),
            topology_expires_at_unix: Arc::new(AtomicU64::new(0)),
            http_client,
        })
    }

    /// Fetch from seed, verify, hot-swap. Returns node count on success.
    pub async fn sync_once(&self) -> Result<usize, TopologySyncError> {
        let mut last_error = String::new();

        for url in &self.config.seed_urls {
            match self.fetch_and_verify(url).await {
                Ok((nodes, pow_diff, verification)) => {
                    let count = nodes.len();
                    *self.topology.write() = nodes;
                    self.pow_difficulty.store(pow_diff, Ordering::Relaxed);
                    if let Some(verification) = verification {
                        self.last_verified_block
                            .store(verification.block_number, Ordering::Release);
                        self.last_verified_at_unix
                            .store(verification.verified_at_unix, Ordering::Release);
                        self.topology_expires_at_unix
                            .store(verification.expires_at_unix, Ordering::Release);
                    }
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

        if !self.config.skip_chain_verification {
            let now_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(u64::MAX, |duration| duration.as_secs());
            self.clear_topology_if_expired(now_unix);
        }
        Err(TopologySyncError::AllSeedsFailed(last_error))
    }

    fn clear_topology_if_expired(&self, now_unix: u64) {
        let expires_at = self.topology_expires_at_unix.load(Ordering::Acquire);
        if expires_at == 0 || now_unix > expires_at {
            self.topology.write().clear();
            self.topology_expires_at_unix.store(0, Ordering::Release);
        }
    }

    async fn wait_for_topology_expiry(&self) {
        let expires_at = self.topology_expires_at_unix.load(Ordering::Acquire);
        if expires_at == 0 {
            std::future::pending::<()>().await;
            return;
        }
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(u64::MAX, |duration| duration.as_secs());
        let delay = expires_at.saturating_sub(now_unix).saturating_add(1);
        tokio::time::sleep(Duration::from_secs(delay)).await;
    }

    async fn fetch_and_verify(
        &self,
        url: &str,
    ) -> Result<(Vec<TopologyNode>, u32, Option<VerifiedTopologySnapshot>), TopologySyncError> {
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

        validate_snapshot_nodes(&snapshot.nodes)?;
        validate_snapshot_schema(&snapshot, !self.config.skip_chain_verification)?;
        let addresses: Vec<_> = snapshot.nodes.iter().map(|n| n.address.clone()).collect();
        let computed = compute_topology_fingerprint(&addresses);
        let computed_hex = hex::encode(computed);

        if computed_hex != snapshot.fingerprint {
            return Err(TopologySyncError::FingerprintMismatch {
                computed: computed_hex,
                on_chain: snapshot.fingerprint,
            });
        }

        let (verification_block, chain_active_addresses) = if self.config.skip_chain_verification {
            debug!("Skipping on-chain fingerprint verification (benchmark mode)");
            (None, None)
        } else {
            let (block_number, chain_active_addresses) = self
                .verify_on_chain_snapshot(&snapshot.nodes, &computed, snapshot.block_number)
                .await?;
            (Some(block_number), Some(chain_active_addresses))
        };

        let pow_diff = snapshot.pow_difficulty;
        let local_now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                TopologySyncError::InvalidLiveness("system clock is before Unix epoch".to_string())
            })?
            .as_secs();
        let (eligible_nodes, earliest_expiry) = eligible_nodes(
            &snapshot,
            local_now_unix,
            self.config.liveness_max_age,
            chain_active_addresses.as_ref(),
        );
        let mut topology_nodes = Vec::with_capacity(snapshot.nodes.len());
        for node in eligible_nodes {
            let topo_node = TopologyNode::from_relayer_node(node)
                .map_err(TopologySyncError::ConversionError)?;
            topology_nodes.push(topo_node);
        }
        let verification = verification_block.map(|block_number| VerifiedTopologySnapshot {
            block_number,
            verified_at_unix: local_now_unix,
            expires_at_unix: earliest_expiry.unwrap_or(local_now_unix),
        });

        debug!(
            "Verified {} nodes from {url} (fingerprint={}, pow_difficulty={})",
            topology_nodes.len(),
            computed_hex,
            pow_diff
        );

        Ok((topology_nodes, pow_diff, verification))
    }

    async fn verify_on_chain_snapshot(
        &self,
        nodes: &[RelayerNode],
        computed: &[u8; 32],
        block_number: u64,
    ) -> Result<(u64, HashSet<Address>), TopologySyncError> {
        let provider = build_ethers_http1_provider(&self.config.eth_rpc_url)?;
        let current_block = if block_number == 0 {
            tokio::time::timeout(Duration::from_secs(10), provider.get_block_number())
                .await
                .map_err(|_| {
                    TopologySyncError::ChainError(
                        "current block lookup timed out for legacy seed snapshot".to_string(),
                    )
                })?
                .map_err(|error| {
                    TopologySyncError::ChainError(format!(
                        "current block lookup failed for legacy seed snapshot: {error}"
                    ))
                })?
                .as_u64()
        } else {
            block_number
        };
        let block_number = select_verification_block(block_number, current_block)?;
        let registry = NoxRegistryTopology::new(self.config.registry_address, Arc::new(provider));
        let block = BlockId::Number(BlockNumber::Number(block_number.into()));
        let on_chain = tokio::time::timeout(
            Duration::from_secs(10),
            registry.topology_fingerprint().block(block).call(),
        )
        .await
        .map_err(|_| TopologySyncError::ChainError("topology fingerprint call timed out".into()))?
        .map_err(|e| TopologySyncError::ChainError(format!("topology fingerprint call: {e}")))?;

        if computed != &on_chain {
            return Err(TopologySyncError::FingerprintMismatch {
                computed: hex::encode(computed),
                on_chain: hex::encode(on_chain),
            });
        }

        let relayer_count = tokio::time::timeout(
            Duration::from_secs(10),
            registry.relayer_count().block(block).call(),
        )
        .await
        .map_err(|_| TopologySyncError::ChainError("relayer count call timed out".into()))?
        .map_err(|e| TopologySyncError::ChainError(format!("relayer count call: {e}")))?;
        validate_relayer_count(nodes.len(), relayer_count)?;

        let mut chain_active_addresses = HashSet::with_capacity(nodes.len());
        for node in nodes {
            let address = node.address.parse::<Address>().map_err(|e| {
                TopologySyncError::ConversionError(format!(
                    "Invalid eth address {}: {e}",
                    node.address
                ))
            })?;
            let profile = tokio::time::timeout(
                Duration::from_secs(10),
                registry.relayers(address).block(block).call(),
            )
            .await
            .map_err(|_| {
                TopologySyncError::ChainError(format!(
                    "relayer profile call timed out for {}",
                    node.address
                ))
            })?
            .map_err(|e| {
                TopologySyncError::ChainError(format!(
                    "relayer profile call for {}: {e}",
                    node.address
                ))
            })?;
            let role = tokio::time::timeout(
                Duration::from_secs(10),
                registry.get_node_role(address).block(block).call(),
            )
            .await
            .map_err(|_| {
                TopologySyncError::ChainError(format!(
                    "relayer role call timed out for {}",
                    node.address
                ))
            })?
            .map_err(|e| {
                TopologySyncError::ChainError(format!(
                    "relayer role call for {}: {e}",
                    node.address
                ))
            })?;

            let is_chain_active = validate_registry_profile(
                node,
                &RegistryProfile {
                    sphinx_key: profile.0,
                    url: profile.1,
                    ingress_url: profile.2,
                    metadata_url: profile.3,
                    staked_amount: profile.4,
                    is_registered: profile.6,
                    status: profile.7,
                    frozen: profile.8,
                    role,
                },
            )?;
            if is_chain_active {
                chain_active_addresses.insert(address);
            }
        }

        debug!(
            "On-chain topology and {} relayer profiles verified at block {}: {}",
            nodes.len(),
            block_number,
            hex::encode(on_chain)
        );
        Ok((block_number, chain_active_addresses))
    }

    /// Returns the shared `AtomicU32` backing the network-advertised `PoW` difficulty.
    /// Callers (e.g. `MixnetClient`) can read this to stay in sync with the network.
    #[must_use]
    pub fn pow_difficulty_handle(&self) -> Arc<AtomicU32> {
        Arc::clone(&self.pow_difficulty)
    }

    #[must_use]
    pub fn last_verified_snapshot(&self) -> Option<VerifiedTopologySnapshot> {
        let block_number = self.last_verified_block.load(Ordering::Acquire);
        let verified_at_unix = self.last_verified_at_unix.load(Ordering::Acquire);
        let expires_at_unix = self.topology_expires_at_unix.load(Ordering::Acquire);
        if block_number == 0 || verified_at_unix == 0 {
            None
        } else {
            Some(VerifiedTopologySnapshot {
                block_number,
                verified_at_unix,
                expires_at_unix,
            })
        }
    }

    /// Run refreshes and clear routes when their earliest accepted liveness expires.
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
            tokio::select! {
                _ = interval.tick() => {
                    match self.sync_once().await {
                        Ok(count) => debug!("Topology refresh: {} nodes", count),
                        Err(e) => warn!("Topology refresh failed: {e}"),
                    }
                }
                () = self.wait_for_topology_expiry() => {
                    let now_unix = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_or(u64::MAX, |duration| duration.as_secs());
                    self.clear_topology_if_expired(now_unix);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nox_core::TopologyLiveness;

    fn node(address: &str) -> RelayerNode {
        RelayerNode {
            address: address.to_string(),
            sphinx_key: "11".repeat(32),
            url: "/ip4/127.0.0.1/tcp/9000".to_string(),
            stake: "1000".to_string(),
            last_seen: 0,
            is_privileged: false,
            layer: 2,
            role: 2,
            ingress_url: Some("https://exit.example/submit".to_string()),
            metadata_url: Some("https://exit.example/metadata".to_string()),
        }
    }

    fn registry_profile() -> RegistryProfile {
        RegistryProfile {
            sphinx_key: [0x11; 32],
            url: "/ip4/127.0.0.1/tcp/9000".to_string(),
            ingress_url: "https://exit.example/submit".to_string(),
            metadata_url: "https://exit.example/metadata".to_string(),
            staked_amount: U256::from(1000),
            is_registered: true,
            status: 1,
            frozen: false,
            role: 2,
        }
    }

    fn verified_snapshot() -> TopologySnapshot {
        let mut first = node("0x1111111111111111111111111111111111111111");
        first.layer = nox_core::primary_layer_for_role(&first.address, first.role);
        let mut second = node("0x2222222222222222222222222222222222222222");
        second.layer = nox_core::primary_layer_for_role(&second.address, second.role);
        TopologySnapshot {
            nodes: vec![first, second],
            fingerprint: "00".repeat(32),
            timestamp: 1_800_000_000,
            block_number: 42,
            pow_difficulty: 0,
            schema_version: VERIFIED_TOPOLOGY_SCHEMA_VERSION,
            liveness: vec![
                TopologyLiveness {
                    address: "0x1111111111111111111111111111111111111111".to_string(),
                    status: TopologyLivenessStatus::Online,
                    observed_at_unix: 1_800_000_000,
                },
                TopologyLiveness {
                    address: "0x2222222222222222222222222222222222222222".to_string(),
                    status: TopologyLivenessStatus::Offline,
                    observed_at_unix: 1_800_000_000,
                },
            ],
        }
    }

    #[test]
    fn test_config_empty_seed_urls_uses_defaults() {
        let config = TopologySyncConfig {
            seed_urls: vec![],
            eth_rpc_url: "http://localhost:8545".into(),
            registry_address: Address::zero(),
            refresh_interval: Duration::from_mins(1),
            request_timeout: Duration::from_secs(10),
            liveness_max_age: DEFAULT_LIVENESS_MAX_AGE,
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
            refresh_interval: Duration::from_mins(1),
            request_timeout: Duration::from_secs(10),
            liveness_max_age: DEFAULT_LIVENESS_MAX_AGE,
            skip_chain_verification: false,
        };
        let topology = Arc::new(RwLock::new(Vec::new()));
        let result = TopologySyncClient::new(config, topology);
        assert!(result.is_ok());
    }

    #[test]
    fn zero_liveness_max_age_is_rejected() {
        let config = TopologySyncConfig {
            seed_urls: vec!["http://seed1:8080/topology".into()],
            eth_rpc_url: "http://localhost:8545".into(),
            registry_address: Address::zero(),
            refresh_interval: Duration::from_mins(1),
            request_timeout: Duration::from_secs(10),
            liveness_max_age: Duration::ZERO,
            skip_chain_verification: false,
        };
        let topology = Arc::new(RwLock::new(Vec::new()));
        assert!(matches!(
            TopologySyncClient::new(config, topology),
            Err(TopologySyncError::InvalidLiveness(_))
        ));
    }

    #[test]
    fn verification_skip_is_restricted_to_loopback_seed_urls() {
        let topology = Arc::new(RwLock::new(Vec::new()));
        let remote = TopologySyncConfig {
            seed_urls: vec!["https://seed.example/topology".into()],
            eth_rpc_url: String::new(),
            registry_address: Address::zero(),
            refresh_interval: Duration::from_mins(1),
            request_timeout: Duration::from_secs(10),
            liveness_max_age: DEFAULT_LIVENESS_MAX_AGE,
            skip_chain_verification: true,
        };
        assert!(matches!(
            TopologySyncClient::new(remote, topology.clone()),
            Err(TopologySyncError::InvalidConfig(_))
        ));

        let loopback = TopologySyncConfig {
            seed_urls: vec!["http://127.0.0.1:8080/topology".into()],
            eth_rpc_url: String::new(),
            registry_address: Address::zero(),
            refresh_interval: Duration::from_mins(1),
            request_timeout: Duration::from_secs(10),
            liveness_max_age: DEFAULT_LIVENESS_MAX_AGE,
            skip_chain_verification: true,
        };
        assert!(TopologySyncClient::new(loopback, topology).is_ok());
    }

    #[test]
    fn installed_topology_is_cleared_after_verification_age_expires() {
        let installed =
            TopologyNode::from_relayer_node(&node("0x1234567890abcdef1234567890abcdef12345678"))
                .unwrap();
        let topology = Arc::new(RwLock::new(vec![installed]));
        let config = TopologySyncConfig {
            seed_urls: vec!["http://127.0.0.1:8080/topology".into()],
            eth_rpc_url: "http://127.0.0.1:8545".into(),
            registry_address: Address::zero(),
            refresh_interval: Duration::from_mins(1),
            request_timeout: Duration::from_secs(10),
            liveness_max_age: DEFAULT_LIVENESS_MAX_AGE,
            skip_chain_verification: false,
        };
        let client = TopologySyncClient::new(config, topology.clone()).unwrap();
        client
            .topology_expires_at_unix
            .store(280, Ordering::Release);
        client.clear_topology_if_expired(280);
        assert_eq!(topology.read().len(), 1);
        client.clear_topology_if_expired(281);
        assert!(topology.read().is_empty());
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
    }

    #[test]
    fn duplicate_addresses_are_rejected_before_fingerprint_verification() {
        let first = node("0x1234567890abcdef1234567890abcdef12345678");
        let mut duplicate = first.clone();
        duplicate.address = "0x1234567890ABCDEF1234567890aBCDeF12345678".to_string();

        let error = validate_snapshot_nodes(&[first, duplicate]).unwrap_err();
        assert!(matches!(error, TopologySyncError::DuplicateAddress(_)));
    }

    #[test]
    fn registry_profile_binds_routing_fields_and_role() {
        let relayer = node("0x1234567890abcdef1234567890abcdef12345678");
        assert!(matches!(
            validate_registry_profile(&relayer, &registry_profile()),
            Ok(true)
        ));

        let mut forged = registry_profile();
        forged.sphinx_key = [0x22; 32];
        let error = validate_registry_profile(&relayer, &forged).unwrap_err();
        assert!(matches!(
            error,
            TopologySyncError::ProfileMismatch { field, .. } if field == "sphinx key"
        ));

        let mut forged = registry_profile();
        forged.url = "/dns4/attacker.example/tcp/9000".to_string();
        assert!(validate_registry_profile(&relayer, &forged).is_err());

        let mut forged = registry_profile();
        forged.role = 1;
        assert!(validate_registry_profile(&relayer, &forged).is_err());
    }

    #[test]
    fn frozen_member_is_retained_but_not_chain_active() {
        let relayer = node("0x1234567890abcdef1234567890abcdef12345678");
        let mut frozen = registry_profile();
        frozen.frozen = true;
        assert!(matches!(
            validate_registry_profile(&relayer, &frozen),
            Ok(false)
        ));

        let mut unregistered = registry_profile();
        unregistered.is_registered = false;
        assert!(validate_registry_profile(&relayer, &unregistered).is_err());

        let mut unknown_status = registry_profile();
        unknown_status.status = 3;
        assert!(validate_registry_profile(&relayer, &unknown_status).is_err());
    }

    #[test]
    fn snapshot_must_cover_every_registered_relayer() {
        assert!(validate_relayer_count(3, U256::from(3)).is_ok());
        assert!(validate_relayer_count(2, U256::from(3)).is_err());
    }

    #[test]
    fn legacy_snapshot_uses_one_nonzero_current_block() {
        assert_eq!(select_verification_block(0, 42).unwrap(), 42);
        assert_eq!(select_verification_block(41, 42).unwrap(), 41);
        assert!(select_verification_block(0, 0).is_err());
    }

    #[test]
    fn production_requires_complete_v2_liveness_at_a_pinned_block() {
        let mut snapshot = verified_snapshot();
        assert!(validate_snapshot_nodes(&snapshot.nodes).is_ok());
        assert!(validate_snapshot_schema(&snapshot, true).is_ok());

        snapshot.schema_version = 1;
        assert!(matches!(
            validate_snapshot_schema(&snapshot, true),
            Err(TopologySyncError::UnsupportedSchema(1))
        ));
        assert!(validate_snapshot_schema(&snapshot, false).is_ok());

        snapshot = verified_snapshot();
        snapshot.block_number = 0;
        assert!(validate_snapshot_schema(&snapshot, true).is_err());

        snapshot = verified_snapshot();
        snapshot.liveness.pop();
        assert!(validate_snapshot_schema(&snapshot, true).is_err());

        snapshot = verified_snapshot();
        snapshot.liveness[1].address = snapshot.liveness[0].address.clone();
        assert!(validate_snapshot_schema(&snapshot, true).is_err());
    }

    #[test]
    fn member_and_liveness_order_must_be_canonical_and_identical() {
        let mut snapshot = verified_snapshot();
        snapshot.nodes.swap(0, 1);
        assert!(validate_snapshot_nodes(&snapshot.nodes).is_err());

        snapshot = verified_snapshot();
        snapshot.liveness.swap(0, 1);
        assert!(validate_snapshot_schema(&snapshot, true).is_err());

        snapshot = verified_snapshot();
        snapshot.nodes[0].layer = (snapshot.nodes[0].layer + 1) % 3;
        assert!(matches!(
            validate_snapshot_schema(&snapshot, true),
            Err(TopologySyncError::ProfileMismatch { field, .. })
                if field == "layer is not canonical for address and role"
        ));
    }

    #[test]
    fn routing_uses_only_online_fresh_nonfuture_liveness() {
        let mut snapshot = verified_snapshot();
        snapshot.liveness[0].observed_at_unix = 1_000;
        snapshot.liveness[1].status = TopologyLivenessStatus::Online;
        snapshot.liveness[1].observed_at_unix = 1_001;
        assert_eq!(
            eligible_nodes(&snapshot, 1_000, DEFAULT_LIVENESS_MAX_AGE, None,)
                .0
                .len(),
            1
        );

        snapshot.liveness[0].observed_at_unix = 819;
        snapshot.liveness[1].observed_at_unix = 1_000;
        assert_eq!(
            eligible_nodes(&snapshot, 1_000, Duration::from_millis(180_001), None,)
                .0
                .len(),
            2
        );
        assert_eq!(
            eligible_nodes(&snapshot, 1_000, DEFAULT_LIVENESS_MAX_AGE, None,)
                .0
                .len(),
            1
        );

        let active = HashSet::from(["0x2222222222222222222222222222222222222222"
            .parse::<Address>()
            .unwrap()]);
        assert_eq!(
            eligible_nodes(
                &snapshot,
                1_000,
                Duration::from_millis(180_001),
                Some(&active),
            )
            .0
            .len(),
            1
        );

        snapshot.liveness[0].status = TopologyLivenessStatus::Online;
        snapshot.liveness[0].observed_at_unix = 821;
        snapshot.liveness[1].status = TopologyLivenessStatus::Offline;
        let (eligible, earliest_expiry) =
            eligible_nodes(&snapshot, 1_000, DEFAULT_LIVENESS_MAX_AGE, None);
        assert_eq!(eligible.len(), 1);
        assert_eq!(earliest_expiry, Some(1_001));
    }
}
