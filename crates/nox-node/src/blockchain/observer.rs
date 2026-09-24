use crate::blockchain::executor::build_ethers_http1_provider;
use crate::config::NoxConfig;
use crate::telemetry::metrics::MetricsService;
use ethers::prelude::*;
use nox_core::{
    events::NoxEvent,
    traits::{IEventPublisher, IStorageRepository, InfrastructureError},
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Storage key for persisting the last processed block number
pub(crate) const LAST_BLOCK_KEY: &[u8] = b"chain_observer:last_block";

/// Maximum blocks per `eth_getLogs` call. Public RPC providers commonly cap the
/// range (10k is the widely supported ceiling), and an unbounded catch-up after
/// downtime would otherwise be rejected outright.
const MAX_BLOCK_RANGE: u64 = 10_000;

/// Cursor (last block treated as already scanned) available without an RPC
/// call: the persisted one, else the block before `chain_start_block`. The
/// start block itself must be scanned because the registry deployment and its
/// first registrations can land in the same block. `None` = start from head.
fn resume_cursor(persisted: Option<u64>, chain_start_block: u64) -> Option<u64> {
    persisted.or_else(|| chain_start_block.checked_sub(1))
}

/// How far `/topology` reports behind the scanned block when no registry log is
/// newer. Clients verify a snapshot with `eth_call` at its `block_number`, and
/// providers trail each other by a few blocks: one that has not seen the block
/// rejects the call ("unsupported block number"). 16 blocks is ~4s on Arbitrum.
const TOPOLOGY_BLOCK_LAG: u64 = 16;

/// The observer's chain position, shared with the topology API so `/topology`
/// reports a `block_number` that matches the node set it serves, without an RPC
/// call per request.
#[derive(Debug, Default)]
pub struct ObservedChain {
    /// Every registry log up to and including this block has been published.
    scanned_through: AtomicU64,
    /// Newest block that carried a registry log, or the resume cursor (history
    /// before it is unknown). The node set matches the registry at every block
    /// from here through `scanned_through`.
    last_registry_log: AtomicU64,
}

impl ObservedChain {
    fn resume_at(&self, cursor: u64) {
        self.last_registry_log.fetch_max(cursor, Ordering::AcqRel);
        self.scanned_through.store(cursor, Ordering::Release);
    }

    /// Called before the log is published, so a node set that already contains
    /// it is never reported at an older block.
    fn record_registry_log(&self, block: u64) {
        self.last_registry_log.fetch_max(block, Ordering::AcqRel);
    }

    fn scanned(&self, block: u64) {
        self.scanned_through.store(block, Ordering::Release);
    }

    /// Block at which the served topology can be verified on-chain, or 0 while
    /// the observer has no position (clients then verify at their own head).
    pub fn topology_block(&self) -> u64 {
        let scanned = self.scanned_through.load(Ordering::Acquire);
        if scanned == 0 {
            return 0;
        }
        let last_log = self.last_registry_log.load(Ordering::Acquire);
        scanned.saturating_sub(TOPOLOGY_BLOCK_LAG).max(last_log)
    }
}

// Generate type-safe bindings for the specific events we care about
abigen!(
    NoxRegistryContract,
    r#"[
        event RelayerRegistered(address indexed relayer, bytes32 sphinxKey, string url, string ingressUrl, string metadataUrl, uint256 stake, uint8 nodeRole)
        event PrivilegedRelayerRegistered(address indexed relayer, bytes32 sphinxKey, string url, string ingressUrl, string metadataUrl, uint8 nodeRole)
        event RelayerRemoved(address indexed relayer, address indexed by)
        event Unstaked(address indexed relayer, uint256 amount)
        event KeyRotated(address indexed relayer, bytes32 newSphinxKey)
        event RoleUpdated(address indexed relayer, uint8 newRole)
        event RelayerUpdated(address indexed relayer, string newUrl)
        event IngressUrlUpdated(address indexed relayer, string newIngressUrl)
        event MetadataUrlUpdated(address indexed relayer, string newMetadataUrl)
        event Slashed(address indexed relayer, uint256 amount, address indexed slasher)
        event Paused(address account)
        event Unpaused(address account)
    ]"#
);

pub struct ChainObserver {
    provider: Provider<Http>,
    registry_address: Address,
    publisher: Arc<dyn IEventPublisher>,
    storage: Arc<dyn IStorageRepository>,
    poll_interval: Duration,
    metrics: MetricsService,
    cancel_token: CancellationToken,
    /// Block to start scanning from on first boot (0 = use latest).
    chain_start_block: u64,
    observed: Arc<ObservedChain>,
}

impl ChainObserver {
    pub fn new(
        config: &NoxConfig,
        registry_address_hex: &str,
        publisher: Arc<dyn IEventPublisher>,
        storage: Arc<dyn IStorageRepository>,
        metrics: MetricsService,
    ) -> Result<Self, InfrastructureError> {
        let provider = build_ethers_http1_provider(&config.eth_rpc_url)?;

        let address = registry_address_hex.parse::<Address>().map_err(|e| {
            InfrastructureError::Blockchain(format!("Invalid Registry Address: {e}"))
        })?;

        Ok(Self {
            provider,
            registry_address: address,
            publisher,
            storage,
            poll_interval: Duration::from_secs(config.block_poll_interval_secs),
            metrics,
            cancel_token: CancellationToken::new(),
            chain_start_block: config.chain_start_block,
            observed: Arc::default(),
        })
    }

    #[must_use]
    pub fn with_cancel_token(mut self, token: CancellationToken) -> Self {
        self.cancel_token = token;
        self
    }

    /// Publishes the observer's position to `observed` (read by `/topology`).
    #[must_use]
    pub fn with_observed_chain(mut self, observed: Arc<ObservedChain>) -> Self {
        self.observed = observed;
        self
    }

    /// Load the last processed block from persistent storage.
    /// Returns `None` if no block was previously persisted.
    async fn load_last_block(&self) -> Option<u64> {
        match self.storage.get(LAST_BLOCK_KEY).await {
            Ok(Some(bytes)) if bytes.len() == 8 => {
                let block = u64::from_be_bytes(bytes.as_slice().try_into().ok()?);
                info!("Resuming chain observer from persisted block {}", block);
                Some(block)
            }
            Ok(_) => None,
            Err(e) => {
                warn!("Failed to load last block from storage: {}", e);
                None
            }
        }
    }

    /// Persist the last processed block to storage.
    async fn save_last_block(&self, block: u64) {
        let bytes = block.to_be_bytes();
        if let Err(e) = self.storage.put(LAST_BLOCK_KEY, &bytes).await {
            warn!("Failed to persist last block {}: {}", block, e);
        }
    }

    pub async fn start(&self) {
        info!(
            "Chain Observer started. Watching Registry at {:?}",
            self.registry_address
        );

        // Resume from persisted block, or use chain_start_block, or start from latest
        let persisted = self.load_last_block().await;
        let mut last_block = if let Some(cursor) = resume_cursor(persisted, self.chain_start_block)
        {
            if persisted.is_none() {
                info!(
                    "No persisted block. Using chain_start_block={} from config (inclusive).",
                    self.chain_start_block
                );
            }
            cursor
        } else {
            let mut block_num = None;
            for attempt in 1..=5u64 {
                match self.provider.get_block_number().await {
                    Ok(n) => {
                        block_num = Some(n.as_u64());
                        break;
                    }
                    Err(e) => {
                        error!("Failed to get initial block (attempt {attempt}/5): {e}");
                        tokio::select! {
                            () = sleep(Duration::from_secs(2 * attempt)) => {}
                            () = self.cancel_token.cancelled() => {
                                info!("Chain Observer shutting down during init (cancellation token).");
                                return;
                            }
                        }
                    }
                }
            }
            if let Some(n) = block_num {
                n
            } else {
                error!(
                    "Cannot determine initial block after 5 attempts. \
                     Observer will NOT start to avoid scanning from block 0."
                );
                return;
            }
        };

        self.observed.resume_at(last_block);

        let contract =
            NoxRegistryContract::new(self.registry_address, Arc::new(self.provider.clone()));

        loop {
            let current_block = match self.provider.get_block_number().await {
                Ok(n) => n.as_u64(),
                Err(e) => {
                    error!("RPC Error: {}", e);
                    self.metrics
                        .chain_observer_errors_total
                        .get_or_create(&vec![("type".into(), "rpc_error".into())])
                        .inc();
                    tokio::select! {
                        () = sleep(self.poll_interval) => {}
                        () = self.cancel_token.cancelled() => {
                            info!("Chain Observer shutting down (cancellation token).");
                            return;
                        }
                    }
                    continue;
                }
            };

            if current_block <= last_block {
                tokio::select! {
                    () = sleep(self.poll_interval) => {}
                    () = self.cancel_token.cancelled() => {
                        info!("Chain Observer shutting down (cancellation token).");
                        return;
                    }
                }
                continue;
            }

            debug!("Processing blocks {} to {}", last_block + 1, current_block);

            // Scan in bounded chunks. A stale cursor (node downtime, or a storage
            // layer that could not persist progress) can leave a gap of millions
            // of blocks, and RPC providers reject unbounded `eth_getLogs` ranges.
            let mut cursor = last_block;
            while cursor < current_block {
                if self.cancel_token.is_cancelled() {
                    info!("Chain Observer shutting down (cancellation token).");
                    return;
                }

                let chunk_end = current_block.min(cursor + MAX_BLOCK_RANGE);
                let filter = Filter::new()
                    .address(self.registry_address)
                    .from_block(cursor + 1)
                    .to_block(chunk_end);

                match self.provider.get_logs(&filter).await {
                    Ok(logs) => {
                        for log in logs {
                            self.observed.record_registry_log(
                                log.block_number.map_or(chunk_end, |block| block.as_u64()),
                            );
                            self.process_log(&contract, log).await;
                        }
                        // Only advance past a range that was actually scanned, so a
                        // failure can never silently skip registry events.
                        cursor = chunk_end;
                        self.metrics.chain_observer_last_block.set(cursor as i64);
                        self.observed.scanned(cursor);
                        self.save_last_block(cursor).await;
                    }
                    Err(e) => {
                        error!(
                            "Failed to fetch logs for blocks {}..={}: {}. \
                             Cursor held at {}; range will be retried.",
                            cursor + 1,
                            chunk_end,
                            e,
                            cursor
                        );
                        self.metrics
                            .chain_observer_errors_total
                            .get_or_create(&vec![("type".into(), "rpc_error".into())])
                            .inc();
                        break;
                    }
                }
            }

            last_block = cursor;
            tokio::select! {
                () = sleep(self.poll_interval) => {}
                () = self.cancel_token.cancelled() => {
                    info!("Chain Observer shutting down (cancellation token).");
                    return;
                }
            }
        }
    }

    async fn process_log(&self, contract: &NoxRegistryContract<Provider<Http>>, log: Log) {
        // Try to decode as RelayerRegistered (Community)
        if let Ok(event) = contract.decode_event::<RelayerRegisteredFilter>(
            "RelayerRegistered",
            log.topics.clone(),
            log.data.clone(),
        ) {
            info!(
                "User Registered: {:?} (role={})",
                event.relayer, event.node_role
            );
            let ingress = Some(event.ingress_url);
            let metadata = if event.metadata_url.is_empty() {
                None
            } else {
                Some(event.metadata_url)
            };
            if let Err(e) = self.publisher.publish(NoxEvent::RelayerRegistered {
                address: format!("{:?}", event.relayer),
                sphinx_key: hex::encode(event.sphinx_key),
                url: event.url,
                stake: event.stake.to_string(),
                role: event.node_role,
                ingress_url: ingress,
                metadata_url: metadata,
            }) {
                warn!(
                    relayer = ?event.relayer,
                    error = %e,
                    "Could not broadcast registration event, topology updates on next scan"
                );
                self.metrics
                    .event_bus_publish_errors_total
                    .get_or_create(&vec![
                        ("event".into(), "RelayerRegistered".into()),
                        ("caller".into(), "chain_observer".into()),
                    ])
                    .inc();
            }
            self.metrics
                .chain_events_processed_total
                .get_or_create(&vec![("type".into(), "relayer_registered".into())])
                .inc();
            return;
        }

        // Try to decode as PrivilegedRelayerRegistered (Admin)
        if let Ok(event) = contract.decode_event::<PrivilegedRelayerRegisteredFilter>(
            "PrivilegedRelayerRegistered",
            log.topics.clone(),
            log.data.clone(),
        ) {
            info!(
                "Privileged Node Registered: {:?} (role={})",
                event.relayer, event.node_role
            );
            let ingress = Some(event.ingress_url);
            let metadata = if event.metadata_url.is_empty() {
                None
            } else {
                Some(event.metadata_url)
            };
            if let Err(e) = self.publisher.publish(NoxEvent::RelayerRegistered {
                address: format!("{:?}", event.relayer),
                sphinx_key: hex::encode(event.sphinx_key),
                url: event.url,
                stake: "0".to_string(), // Privileged = 0 stake
                role: event.node_role,
                ingress_url: ingress,
                metadata_url: metadata,
            }) {
                warn!(
                    relayer = ?event.relayer,
                    error = %e,
                    "Privileged registration event not delivered, next scan will reconcile"
                );
                self.metrics
                    .event_bus_publish_errors_total
                    .get_or_create(&vec![
                        ("event".into(), "RelayerRegistered".into()),
                        ("caller".into(), "chain_observer_privileged".into()),
                    ])
                    .inc();
            }
            self.metrics
                .chain_events_processed_total
                .get_or_create(&vec![("type".into(), "privileged_registered".into())])
                .inc();
            return;
        }

        // Try to decode as RelayerRemoved
        if let Ok(event) = contract.decode_event::<RelayerRemovedFilter>(
            "RelayerRemoved",
            log.topics.clone(),
            log.data.clone(),
        ) {
            info!("Relayer Removed: {:?}", event.relayer);
            if let Err(e) = self.publisher.publish(NoxEvent::RelayerRemoved {
                address: format!("{:?}", event.relayer),
            }) {
                error!(
                    relayer = ?event.relayer,
                    error = %e,
                    "Removal event dropped, topology may retain stale entry"
                );
                self.metrics
                    .event_bus_publish_errors_total
                    .get_or_create(&vec![
                        ("event".into(), "RelayerRemoved".into()),
                        ("caller".into(), "chain_observer".into()),
                    ])
                    .inc();
            }
            self.metrics
                .chain_events_processed_total
                .get_or_create(&vec![("type".into(), "relayer_removed".into())])
                .inc();
            return;
        }

        // Try to decode as Unstaked
        if let Ok(event) = contract.decode_event::<UnstakedFilter>(
            "Unstaked",
            log.topics.clone(),
            log.data.clone(),
        ) {
            info!("Relayer Unstaked: {:?}", event.relayer);
            if let Err(e) = self.publisher.publish(NoxEvent::RelayerRemoved {
                address: format!("{:?}", event.relayer),
            }) {
                error!(
                    relayer = ?event.relayer,
                    error = %e,
                    "Unstake event lost, relayer may linger in topology"
                );
                self.metrics
                    .event_bus_publish_errors_total
                    .get_or_create(&vec![
                        ("event".into(), "RelayerRemoved".into()),
                        ("caller".into(), "chain_observer_unstaked".into()),
                    ])
                    .inc();
            }
            self.metrics
                .chain_events_processed_total
                .get_or_create(&vec![("type".into(), "unstaked".into())])
                .inc();
            return;
        }

        // Try to decode as KeyRotated
        if let Ok(event) = contract.decode_event::<KeyRotatedFilter>(
            "KeyRotated",
            log.topics.clone(),
            log.data.clone(),
        ) {
            info!(
                "Key Rotated: {:?} -> {}",
                event.relayer,
                hex::encode(event.new_sphinx_key)
            );
            if let Err(e) = self.publisher.publish(NoxEvent::RelayerKeyRotated {
                address: format!("{:?}", event.relayer),
                new_sphinx_key: hex::encode(event.new_sphinx_key),
            }) {
                error!(
                    relayer = ?event.relayer,
                    error = %e,
                    "Key rotation event not propagated, sphinx keys may be outdated"
                );
                self.metrics
                    .event_bus_publish_errors_total
                    .get_or_create(&vec![
                        ("event".into(), "KeyRotated".into()),
                        ("caller".into(), "chain_observer".into()),
                    ])
                    .inc();
            }
            self.metrics
                .chain_events_processed_total
                .get_or_create(&vec![("type".into(), "key_rotated".into())])
                .inc();
            return;
        }

        // Try to decode as RoleUpdated
        if let Ok(event) = contract.decode_event::<RoleUpdatedFilter>(
            "RoleUpdated",
            log.topics.clone(),
            log.data.clone(),
        ) {
            info!(
                "Role Updated: {:?} -> role={}",
                event.relayer, event.new_role
            );
            if let Err(e) = self.publisher.publish(NoxEvent::RelayerRoleUpdated {
                address: format!("{:?}", event.relayer),
                new_role: event.new_role,
            }) {
                error!(
                    relayer = ?event.relayer,
                    error = %e,
                    "Role change not propagated, layer assignments may be stale"
                );
                self.metrics
                    .event_bus_publish_errors_total
                    .get_or_create(&vec![
                        ("event".into(), "RoleUpdated".into()),
                        ("caller".into(), "chain_observer".into()),
                    ])
                    .inc();
            }
            self.metrics
                .chain_events_processed_total
                .get_or_create(&vec![("type".into(), "role_updated".into())])
                .inc();
            return;
        }

        // Try to decode as RelayerUpdated (URL change)
        if let Ok(event) = contract.decode_event::<RelayerUpdatedFilter>(
            "RelayerUpdated",
            log.topics.clone(),
            log.data.clone(),
        ) {
            info!(
                "Relayer URL Updated: {:?} -> {}",
                event.relayer, event.new_url
            );
            if let Err(e) = self.publisher.publish(NoxEvent::RelayerUrlUpdated {
                address: format!("{:?}", event.relayer),
                new_url: event.new_url,
            }) {
                error!(
                    relayer = ?event.relayer,
                    error = %e,
                    "URL update event lost, topology may hold outdated endpoints"
                );
                self.metrics
                    .event_bus_publish_errors_total
                    .get_or_create(&vec![
                        ("event".into(), "RelayerUpdated".into()),
                        ("caller".into(), "chain_observer".into()),
                    ])
                    .inc();
            }
            self.metrics
                .chain_events_processed_total
                .get_or_create(&vec![("type".into(), "relayer_updated".into())])
                .inc();
            return;
        }

        // Try to decode as Slashed
        if let Ok(event) =
            contract.decode_event::<SlashedFilter>("Slashed", log.topics.clone(), log.data.clone())
        {
            warn!(
                "Relayer Slashed: {:?} amount={} by={:?}",
                event.relayer, event.amount, event.slasher
            );
            if let Err(e) = self.publisher.publish(NoxEvent::RelayerSlashed {
                address: format!("{:?}", event.relayer),
                amount: event.amount.to_string(),
                slasher: format!("{:?}", event.slasher),
            }) {
                error!(
                    relayer = ?event.relayer,
                    error = %e,
                    "Failed to publish Slashed event"
                );
                self.metrics
                    .event_bus_publish_errors_total
                    .get_or_create(&vec![
                        ("event".into(), "Slashed".into()),
                        ("caller".into(), "chain_observer".into()),
                    ])
                    .inc();
            }
            self.metrics
                .chain_events_processed_total
                .get_or_create(&vec![("type".into(), "slashed".into())])
                .inc();
            return;
        }

        // Try to decode as Paused
        if let Ok(event) =
            contract.decode_event::<PausedFilter>("Paused", log.topics.clone(), log.data.clone())
        {
            warn!("NoxRegistry PAUSED by {:?}", event.account);
            if let Err(e) = self.publisher.publish(NoxEvent::RegistryPaused {
                by: format!("{:?}", event.account),
            }) {
                error!(error = %e, "Failed to publish RegistryPaused event");
            }
            self.metrics
                .chain_events_processed_total
                .get_or_create(&vec![("type".into(), "paused".into())])
                .inc();
            return;
        }

        // Try to decode as Unpaused
        if let Ok(event) = contract.decode_event::<UnpausedFilter>(
            "Unpaused",
            log.topics.clone(),
            log.data.clone(),
        ) {
            info!("NoxRegistry UNPAUSED by {:?}", event.account);
            if let Err(e) = self.publisher.publish(NoxEvent::RegistryUnpaused {
                by: format!("{:?}", event.account),
            }) {
                error!(error = %e, "Failed to publish RegistryUnpaused event");
            }
            self.metrics
                .chain_events_processed_total
                .get_or_create(&vec![("type".into(), "unpaused".into())])
                .inc();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_cursor_wins_over_chain_start_block() {
        assert_eq!(resume_cursor(Some(500), 100), Some(500));
        assert_eq!(resume_cursor(Some(500), 0), Some(500));
    }

    #[test]
    fn chain_start_block_is_scanned_inclusively() {
        // The first range scanned starts at cursor + 1.
        let cursor = resume_cursor(None, 312_333_820).unwrap();
        assert_eq!(cursor + 1, 312_333_820);
        assert_eq!(resume_cursor(None, 1), Some(0));
    }

    #[test]
    fn zero_chain_start_block_starts_from_head() {
        assert_eq!(resume_cursor(None, 0), None);
    }

    #[test]
    fn topology_block_is_zero_until_the_observer_has_a_position() {
        assert_eq!(ObservedChain::default().topology_block(), 0);
    }

    #[test]
    fn topology_block_on_resume_is_the_cursor() {
        // Registry history before a resumed cursor is unknown, so nothing older
        // than the cursor is reported.
        let chain = ObservedChain::default();
        chain.resume_at(1_000);
        assert_eq!(chain.topology_block(), 1_000);
        chain.scanned(1_005);
        assert_eq!(chain.topology_block(), 1_000);
        chain.scanned(1_000 + TOPOLOGY_BLOCK_LAG + 50);
        assert_eq!(chain.topology_block(), 1_050);
    }

    #[test]
    fn topology_block_never_predates_the_last_registry_log() {
        let chain = ObservedChain::default();
        chain.resume_at(1_000);
        chain.scanned(2_000);
        assert_eq!(chain.topology_block(), 2_000 - TOPOLOGY_BLOCK_LAG);

        chain.record_registry_log(1_995);
        assert_eq!(chain.topology_block(), 1_995);
        // Mid-chunk: the log is ahead of the last completed chunk.
        chain.record_registry_log(2_100);
        assert_eq!(chain.topology_block(), 2_100);
        chain.scanned(2_200);
        assert_eq!(chain.topology_block(), 2_200 - TOPOLOGY_BLOCK_LAG);
        // Out-of-order logs never move it backwards.
        chain.record_registry_log(1_500);
        assert_eq!(chain.topology_block(), 2_200 - TOPOLOGY_BLOCK_LAG);
    }

    #[test]
    fn topology_block_saturates_near_genesis() {
        let chain = ObservedChain::default();
        chain.resume_at(0);
        chain.scanned(5);
        assert_eq!(chain.topology_block(), 0);
        chain.record_registry_log(3);
        assert_eq!(chain.topology_block(), 3);
    }
}
