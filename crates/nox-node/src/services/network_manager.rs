use dashmap::DashMap;
use nox_core::utils::{compute_topology_fingerprint, xor_into_fingerprint};
use parking_lot::RwLock;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use nox_core::{
    events::NoxEvent,
    models::topology::RelayerNode,
    traits::{IEventSubscriber, IStorageRepository},
};

pub struct TopologyManager {
    storage: Arc<dyn IStorageRepository>,
    bus: Arc<dyn IEventSubscriber>,
    layers: Arc<DashMap<u8, Vec<RelayerNode>>>,
    /// O(1) lookup by lowercase Ethereum address, used for P2P handshake verification.
    address_index: Arc<DashMap<String, RelayerNode>>,
    /// XOR(keccak256(addr)) for each registered node. Matches on-chain `NoxRegistry.topologyFingerprint`.
    fingerprint: RwLock<[u8; 32]>,
    cancel_token: CancellationToken,
}

impl TopologyManager {
    /// `initial_fingerprint` defaults to `[0; 32]` (XOR identity / empty set).
    pub fn new(
        storage: Arc<dyn IStorageRepository>,
        bus: Arc<dyn IEventSubscriber>,
        initial_fingerprint: Option<[u8; 32]>,
    ) -> Self {
        Self::with_cancel_token(storage, bus, initial_fingerprint, CancellationToken::new())
    }

    pub fn with_cancel_token(
        storage: Arc<dyn IStorageRepository>,
        bus: Arc<dyn IEventSubscriber>,
        initial_fingerprint: Option<[u8; 32]>,
        cancel_token: CancellationToken,
    ) -> Self {
        // XOR identity: empty set = 0x0. Builds incrementally from chain events.
        let fingerprint = initial_fingerprint.unwrap_or([0u8; 32]);
        Self {
            storage,
            bus,
            layers: Arc::new(DashMap::new()),
            address_index: Arc::new(DashMap::new()),
            fingerprint: RwLock::new(fingerprint),
            cancel_token,
        }
    }

    #[must_use]
    pub fn compute_topology_fingerprint(addresses: &[String]) -> [u8; 32] {
        compute_topology_fingerprint(addresses)
    }

    /// Recomputes the fingerprint from the current node set.
    ///
    /// Toggling one XOR term per event drifts as soon as an event is applied
    /// twice (a chain replay over a bootstrapped or hydrated topology, or a
    /// removal of an unknown node). Deriving it from `address_index` keeps it
    /// equal to `XOR(keccak256(addr))` over exactly the nodes being served.
    /// The write lock is held while computing so a concurrent mutation's own
    /// recompute always lands last.
    fn recompute_fingerprint(&self) {
        let mut fp = self.fingerprint.write();
        *fp = self.address_index.iter().fold([0u8; 32], |acc, entry| {
            xor_into_fingerprint(&acc, entry.key())
        });
        debug!("Fingerprint recomputed: {}", hex::encode(*fp));
    }

    pub fn get_current_fingerprint(&self) -> [u8; 32] {
        *self.fingerprint.read()
    }

    pub fn set_fingerprint(&self, fingerprint: [u8; 32]) {
        *self.fingerprint.write() = fingerprint;
        info!(
            "Fingerprint synced from chain: {}",
            hex::encode(fingerprint)
        );
    }

    /// Called once on startup to hydrate from persisted `peer:*` keys before the event loop.
    pub async fn hydrate_from_storage(&self) {
        let peers = match self.storage.scan(b"peer:").await {
            Ok(peers) => peers,
            Err(e) => {
                warn!("Failed to scan peers from storage: {e}. Starting with empty topology.");
                return;
            }
        };
        let mut count = 0u32;
        for (_key, value) in &peers {
            match serde_json::from_slice::<RelayerNode>(value) {
                Ok(node) => {
                    let addr_lower = node.address.to_lowercase();
                    for &layer in nox_core::models::topology::layers_for_role(node.role) {
                        let mut layer_node = node.clone();
                        layer_node.layer = layer;
                        self.layers.entry(layer).or_default().push(layer_node);
                    }
                    self.address_index.insert(addr_lower, node);
                    count += 1;
                }
                Err(e) => {
                    warn!("Failed to deserialize persisted peer: {e}");
                }
            }
        }
        self.recompute_fingerprint();
        if count > 0 {
            let fp = hex::encode(self.get_current_fingerprint());
            info!("Hydrated topology from storage: {count} peers. Fingerprint: {fp}");
        }
    }

    pub async fn run(&self) {
        info!("Topology Manager started.");
        let mut rx = self.bus.subscribe();

        loop {
            tokio::select! {
                result = rx.recv() => {
                    match result {
                        Ok(event) => match event {
                            NoxEvent::RelayerRegistered {
                                address,
                                sphinx_key,
                                url,
                                stake,
                                role,
                                ingress_url,
                                metadata_url,
                            } => {
                                self.handle_registration(address, sphinx_key, url, stake, role, ingress_url, metadata_url)
                                    .await;
                            }
                            NoxEvent::RelayerRemoved { address } => {
                                self.handle_removal(address).await;
                            }
                            NoxEvent::RelayerKeyRotated {
                                address,
                                new_sphinx_key,
                            } => {
                                self.handle_key_rotation(address, new_sphinx_key).await;
                            }
                            NoxEvent::RelayerRoleUpdated { address, new_role } => {
                                self.handle_role_update(address, new_role).await;
                            }
                            NoxEvent::RelayerUrlUpdated { address, new_url } => {
                                self.handle_url_update(address, new_url).await;
                            }
                            NoxEvent::RelayerSlashed {
                                address,
                                amount,
                                slasher,
                            } => {
                                warn!(
                                    address = %address,
                                    amount = %amount,
                                    slasher = %slasher,
                                    "Relayer slashed -- updating topology stake"
                                );
                                // Update stake in address index (node remains in topology)
                                if let Some(mut entry) = self.address_index.get_mut(&address.to_lowercase()) {
                                    entry.stake = "0".to_string();
                                }
                            }
                            NoxEvent::RegistryPaused { by } => {
                                warn!(by = %by, "NoxRegistry PAUSED -- exit nodes should stop submitting transactions");
                            }
                            NoxEvent::RegistryUnpaused { by } => {
                                info!(by = %by, "NoxRegistry UNPAUSED -- normal operations resumed");
                            }
                            _ => {} // Ignore non-topology events
                        },
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            warn!("Topology bus lagged by {} events, continuing.", n);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            warn!("Event bus closed, Topology Manager shutting down.");
                            break;
                        }
                    }
                }
                () = self.cancel_token.cancelled() => {
                    info!("Topology Manager shutting down (cancellation token).");
                    break;
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_registration(
        &self,
        address: String,
        sphinx_key: String,
        url: String,
        stake: String,
        role: u8,
        ingress_url: Option<String>,
        metadata_url: Option<String>,
    ) {
        debug!("Processing registration for {} (role={})", address, role);

        let mut node = RelayerNode::new(address.clone(), sphinx_key, url, stake, role);
        node.ingress_url = ingress_url;
        node.metadata_url = metadata_url;

        let address_lower = address.to_lowercase();
        let primary_layer = nox_core::primary_layer_for_role(&address_lower, role);
        node.layer = primary_layer;

        for mut entry in self.layers.iter_mut() {
            entry
                .value_mut()
                .retain(|n| n.address.to_lowercase() != address_lower);
        }

        let capable_layers = nox_core::models::topology::layers_for_role(role);
        for &layer in capable_layers {
            let mut layer_node = node.clone();
            layer_node.layer = layer;
            self.layers.entry(layer).or_default().push(layer_node);
        }

        self.address_index
            .insert(address.to_lowercase(), node.clone());
        self.recompute_fingerprint();

        match serde_json::to_vec(&node) {
            Ok(bytes) => {
                let key = format!("peer:{}", address.to_lowercase());
                if let Err(e) = self.storage.put(key.as_bytes(), &bytes).await {
                    error!("Failed to persist peer {}: {:?}", address, e);
                } else {
                    info!("Topology update: added peer {}", address);
                }
            }
            Err(e) => error!("Serialization error: {}", e),
        }
    }

    async fn handle_removal(&self, address: String) {
        let key = format!("peer:{}", address.to_lowercase());
        if let Err(e) = self.storage.delete(key.as_bytes()).await {
            error!("Failed to remove peer {}: {:?}", address, e);
        } else {
            for mut entry in self.layers.iter_mut() {
                let addr_lower = address.to_lowercase();
                entry
                    .value_mut()
                    .retain(|n| n.address.to_lowercase() != addr_lower);
            }
            self.address_index.remove(&address.to_lowercase());
            self.recompute_fingerprint();
            info!("Topology update: removed peer {}", address);
        }
    }

    async fn handle_key_rotation(&self, address: String, new_sphinx_key: String) {
        let addr_lower = address.to_lowercase();

        if let Some(mut entry) = self.address_index.get_mut(&addr_lower) {
            entry.sphinx_key.clone_from(&new_sphinx_key);

            for mut layer_entry in self.layers.iter_mut() {
                for node in layer_entry.value_mut().iter_mut() {
                    if node.address.to_lowercase() == addr_lower {
                        node.sphinx_key.clone_from(&new_sphinx_key);
                    }
                }
            }

            let updated = entry.clone();
            let key = format!("peer:{addr_lower}");
            match serde_json::to_vec(&updated) {
                Ok(bytes) => {
                    if let Err(e) = self.storage.put(key.as_bytes(), &bytes).await {
                        error!("Failed to persist key rotation for {address}: {e:?}");
                    }
                }
                Err(e) => error!("Serialization error for {address}: {e}"),
            }
            info!(
                address = %address,
                new_key = %new_sphinx_key,
                "Topology update: sphinx key rotated"
            );
        } else {
            warn!(
                address = %address,
                "KeyRotated event for unknown node -- ignoring"
            );
        }
    }

    async fn handle_role_update(&self, address: String, new_role: u8) {
        let addr_lower = address.to_lowercase();

        if let Some(mut entry) = self.address_index.get_mut(&addr_lower) {
            let old_role = entry.role;
            entry.role = new_role;
            let node = entry.clone();
            drop(entry);

            for mut layer_entry in self.layers.iter_mut() {
                layer_entry
                    .value_mut()
                    .retain(|n| n.address.to_lowercase() != addr_lower);
            }

            let capable_layers = nox_core::models::topology::layers_for_role(new_role);
            for &layer in capable_layers {
                let mut layer_node = node.clone();
                layer_node.layer = layer;
                layer_node.role = new_role;
                self.layers.entry(layer).or_default().push(layer_node);
            }

            let key = format!("peer:{addr_lower}");
            let mut persisted_node = node;
            persisted_node.role = new_role;
            match serde_json::to_vec(&persisted_node) {
                Ok(bytes) => {
                    if let Err(e) = self.storage.put(key.as_bytes(), &bytes).await {
                        error!("Failed to persist role update for {address}: {e:?}");
                    }
                }
                Err(e) => error!("Serialization error for {address}: {e}"),
            }
            info!(
                address = %address,
                old_role = old_role,
                new_role = new_role,
                "Topology update: role changed"
            );
        } else {
            warn!(
                address = %address,
                "RoleUpdated event for unknown node -- ignoring"
            );
        }
    }

    async fn handle_url_update(&self, address: String, new_url: String) {
        let addr_lower = address.to_lowercase();

        if let Some(mut entry) = self.address_index.get_mut(&addr_lower) {
            entry.url.clone_from(&new_url);

            for mut layer_entry in self.layers.iter_mut() {
                for node in layer_entry.value_mut().iter_mut() {
                    if node.address.to_lowercase() == addr_lower {
                        node.url.clone_from(&new_url);
                    }
                }
            }

            let updated = entry.clone();
            let key = format!("peer:{addr_lower}");
            match serde_json::to_vec(&updated) {
                Ok(bytes) => {
                    if let Err(e) = self.storage.put(key.as_bytes(), &bytes).await {
                        error!("Failed to persist URL update for {address}: {e:?}");
                    }
                }
                Err(e) => error!("Serialization error for {address}: {e}"),
            }
            info!(
                address = %address,
                new_url = %new_url,
                "Topology update: URL changed"
            );
        } else {
            warn!(
                address = %address,
                "RelayerUpdated event for unknown node -- ignoring"
            );
        }
    }

    pub fn get_nodes_in_layer(&self, layer: u8) -> Vec<RelayerNode> {
        self.layers
            .get(&layer)
            .map(|l| l.clone())
            .unwrap_or_default()
    }

    pub fn get_all_nodes(&self) -> Vec<RelayerNode> {
        let mut all = self
            .address_index
            .iter()
            .map(|entry| entry.value().clone())
            .collect::<Vec<_>>();
        all.sort_by_key(|node| node.address.to_lowercase());
        all
    }

    #[must_use]
    pub fn lookup_by_address(&self, address: &str) -> Option<RelayerNode> {
        self.address_index
            .get(&address.to_lowercase())
            .map(|entry| entry.value().clone())
    }

    /// Replace the entire topology from a verified snapshot. Recomputes fingerprint and persists.
    ///
    /// Persisted peers absent from the snapshot are deleted too, otherwise the
    /// next restart would hydrate them again.
    pub async fn hydrate_from_snapshot(&self, nodes: Vec<RelayerNode>) {
        self.layers.clear();
        self.address_index.clear();

        for node in &nodes {
            for &layer in nox_core::models::topology::layers_for_role(node.role) {
                let mut layer_node = node.clone();
                layer_node.layer = layer;
                self.layers
                    .entry(layer)
                    .or_insert_with(Vec::new)
                    .push(layer_node);
            }
            self.address_index
                .insert(node.address.to_lowercase(), node.clone());
        }

        self.recompute_fingerprint();
        let fingerprint = self.get_current_fingerprint();

        match self.storage.scan(b"peer:").await {
            Ok(stored) => {
                for (key, _) in stored {
                    let address = String::from_utf8_lossy(&key["peer:".len()..]).to_lowercase();
                    if !self.address_index.contains_key(&address) {
                        if let Err(e) = self.storage.delete(&key).await {
                            warn!("Failed to drop stale persisted peer {address}: {e:?}");
                        }
                    }
                }
            }
            Err(e) => warn!("Failed to scan persisted peers during snapshot hydration: {e}"),
        }

        let mut persisted = 0usize;
        for node in &nodes {
            match serde_json::to_vec(node) {
                Ok(bytes) => {
                    let key = format!("peer:{}", node.address.to_lowercase());
                    if let Err(e) = self.storage.put(key.as_bytes(), &bytes).await {
                        error!(
                            "Failed to persist peer {} during hydration: {:?}",
                            node.address, e
                        );
                    } else {
                        persisted += 1;
                    }
                }
                Err(e) => error!("Serialization error for {}: {}", node.address, e),
            }
        }

        info!(
            "Topology hydrated from snapshot: {} nodes ({} persisted), fingerprint: {}",
            nodes.len(),
            persisted,
            hex::encode(fingerprint)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::{event_bus::TokioEventBus, storage::SledRepository};
    use nox_core::IEventSubscriber;

    #[tokio::test]
    async fn registry_ingress_is_never_synthesized_from_p2p_url() {
        let directory = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(SledRepository::new(directory.path()).expect("storage"));
        let bus = Arc::new(TokioEventBus::new(8));
        let subscriber: Arc<dyn IEventSubscriber> = bus;
        let manager = TopologyManager::new(storage, subscriber, None);
        let address = "0x1111111111111111111111111111111111111111".to_string();

        manager
            .handle_registration(
                address.clone(),
                "11".repeat(32),
                "/ip4/127.0.0.1/tcp/9000/p2p/test".to_string(),
                "0".to_string(),
                1,
                None,
                Some(String::new()),
            )
            .await;

        assert_eq!(
            manager.lookup_by_address(&address).unwrap().ingress_url,
            None
        );
    }

    const A: &str = "0x74486dc1ac551e5cd3f4eef80727cc9d50d3abe9";
    const B: &str = "0x8c9fb3e9fe537067c8430480f80a4a5b9a12be1a";
    const C: &str = "0x6774ca4baf6fff84f02898a3dee4299ed1f5ab4e";
    const STALE: &str = "0xd6831d3bd6e1c768564f5815f2d7a34312bd3067";

    fn manager_on(storage: Arc<SledRepository>) -> TopologyManager {
        let bus = Arc::new(TokioEventBus::new(8));
        let subscriber: Arc<dyn IEventSubscriber> = bus;
        TopologyManager::new(storage, subscriber, None)
    }

    async fn register(manager: &TopologyManager, address: &str) {
        manager
            .handle_registration(
                address.to_string(),
                "11".repeat(32),
                "/ip4/127.0.0.1/tcp/15000".to_string(),
                "0".to_string(),
                1,
                Some(String::new()),
                None,
            )
            .await;
    }

    fn expected(addresses: &[&str]) -> [u8; 32] {
        let owned: Vec<String> = addresses.iter().map(ToString::to_string).collect();
        TopologyManager::compute_topology_fingerprint(&owned)
    }

    fn snapshot_node(address: &str) -> RelayerNode {
        RelayerNode::new(
            address.to_string(),
            "11".repeat(32),
            "/ip4/127.0.0.1/tcp/15000".to_string(),
            "0".to_string(),
            1,
        )
    }

    #[tokio::test]
    async fn duplicate_registration_events_do_not_drift_fingerprint() {
        let directory = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(SledRepository::new(directory.path()).expect("storage"));
        let manager = manager_on(storage);

        for address in [A, B, C] {
            register(&manager, address).await;
        }
        assert_eq!(manager.get_current_fingerprint(), expected(&[A, B, C]));

        // A chain replay re-delivers a registration; an odd number of repeats
        // is what flipped the old XOR-toggle fingerprint.
        register(&manager, A).await;
        assert_eq!(manager.get_current_fingerprint(), expected(&[A, B, C]));

        // Casing differences must not create a second entry either.
        register(&manager, &B.to_uppercase().replacen("0X", "0x", 1)).await;
        assert_eq!(manager.get_all_nodes().len(), 3);
        assert_eq!(manager.get_current_fingerprint(), expected(&[A, B, C]));
    }

    #[tokio::test]
    async fn removals_of_unknown_or_already_removed_nodes_are_idempotent() {
        let directory = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(SledRepository::new(directory.path()).expect("storage"));
        let manager = manager_on(storage);

        register(&manager, A).await;
        register(&manager, B).await;
        manager.handle_removal(C.to_string()).await;
        assert_eq!(manager.get_current_fingerprint(), expected(&[A, B]));

        manager.handle_removal(A.to_string()).await;
        manager.handle_removal(A.to_string()).await;
        assert_eq!(manager.get_current_fingerprint(), expected(&[B]));

        manager.handle_removal(B.to_string()).await;
        assert_eq!(manager.get_current_fingerprint(), [0_u8; 32]);
    }

    /// The v0.2.5 production drift: restart hydrates persisted peers, then the
    /// observer replays events that were already applied.
    #[tokio::test]
    async fn restart_hydration_then_replay_matches_chain_fingerprint() {
        let directory = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(SledRepository::new(directory.path()).expect("storage"));
        {
            let first_boot = manager_on(storage.clone());
            for address in [A, B, C] {
                register(&first_boot, address).await;
            }
        }

        let second_boot = manager_on(storage);
        second_boot.hydrate_from_storage().await;
        assert_eq!(second_boot.get_current_fingerprint(), expected(&[A, B, C]));

        for address in [A, B, C] {
            register(&second_boot, address).await;
        }
        second_boot.handle_removal(B.to_string()).await;
        assert_eq!(second_boot.get_current_fingerprint(), expected(&[A, C]));
    }

    #[tokio::test]
    async fn snapshot_hydration_replaces_persisted_peers_and_survives_replay() {
        let directory = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(SledRepository::new(directory.path()).expect("storage"));
        {
            let old = manager_on(storage.clone());
            register(&old, STALE).await;
            register(&old, A).await;
        }

        let manager = manager_on(storage.clone());
        manager.hydrate_from_storage().await;
        manager
            .hydrate_from_snapshot(vec![snapshot_node(A), snapshot_node(B)])
            .await;
        assert_eq!(manager.get_current_fingerprint(), expected(&[A, B]));

        register(&manager, A).await;
        register(&manager, B).await;
        assert_eq!(manager.get_current_fingerprint(), expected(&[A, B]));

        let restarted = manager_on(storage);
        restarted.hydrate_from_storage().await;
        assert!(restarted.lookup_by_address(STALE).is_none());
        assert_eq!(restarted.get_current_fingerprint(), expected(&[A, B]));
    }

    #[tokio::test]
    async fn canonical_snapshot_uses_primary_layers_and_stable_address_order() {
        let directory = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(SledRepository::new(directory.path()).expect("storage"));
        let bus = Arc::new(TokioEventBus::new(8));
        let subscriber: Arc<dyn IEventSubscriber> = bus;
        let manager = TopologyManager::new(storage, subscriber, None);

        for address in [
            "0x3333333333333333333333333333333333333333",
            "0x1111111111111111111111111111111111111111",
            "0x2222222222222222222222222222222222222222",
        ] {
            manager
                .handle_registration(
                    address.to_string(),
                    "11".repeat(32),
                    "/ip4/127.0.0.1/tcp/9000/p2p/test".to_string(),
                    "0".to_string(),
                    1,
                    Some(String::new()),
                    Some(String::new()),
                )
                .await;
        }

        let nodes = manager.get_all_nodes();
        assert!(nodes
            .windows(2)
            .all(|pair| pair[0].address < pair[1].address));
        assert!(nodes.iter().all(|node| {
            node.layer == nox_core::primary_layer_for_role(&node.address, node.role)
        }));
    }
}
