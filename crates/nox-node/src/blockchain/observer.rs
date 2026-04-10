use crate::config::NoxConfig;
use crate::telemetry::metrics::MetricsService;
use ethers::prelude::*;
use nox_core::{
    events::NoxEvent,
    traits::{IEventPublisher, IStorageRepository, InfrastructureError},
};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Storage key for persisting the last processed block number
const LAST_BLOCK_KEY: &[u8] = b"chain_observer:last_block";

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
}

impl ChainObserver {
    pub fn new(
        config: &NoxConfig,
        registry_address_hex: &str,
        publisher: Arc<dyn IEventPublisher>,
        storage: Arc<dyn IStorageRepository>,
        metrics: MetricsService,
    ) -> Result<Self, InfrastructureError> {
        let provider = Provider::<Http>::try_from(&config.eth_rpc_url)
            .map_err(|e| InfrastructureError::Blockchain(format!("Invalid RPC URL: {e}")))?;

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
        })
    }

    #[must_use]
    pub fn with_cancel_token(mut self, token: CancellationToken) -> Self {
        self.cancel_token = token;
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
        let mut last_block = if let Some(block) = self.load_last_block().await {
            block
        } else if self.chain_start_block > 0 {
            info!(
                "No persisted block. Using chain_start_block={} from config.",
                self.chain_start_block
            );
            self.chain_start_block
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

            let filter = Filter::new()
                .address(self.registry_address)
                .from_block(last_block + 1)
                .to_block(current_block);

            match self.provider.get_logs(&filter).await {
                Ok(logs) => {
                    for log in logs {
                        self.process_log(&contract, log).await;
                    }
                }
                Err(e) => {
                    error!("Failed to fetch logs: {}", e);
                    self.metrics
                        .chain_observer_errors_total
                        .get_or_create(&vec![("type".into(), "rpc_error".into())])
                        .inc();
                }
            }

            last_block = current_block;
            self.metrics
                .chain_observer_last_block
                .set(current_block as i64);
            self.save_last_block(current_block).await;
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
            let ingress = if event.ingress_url.is_empty() {
                None
            } else {
                Some(event.ingress_url)
            };
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
            let ingress = if event.ingress_url.is_empty() {
                None
            } else {
                Some(event.ingress_url)
            };
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
