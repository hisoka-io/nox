use dashmap::DashMap;
use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};
use nox_core::utils::{compute_topology_fingerprint, xor_into_fingerprint};
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use nox_core::{
    events::NoxEvent,
    models::topology::{RelayerNode, TopologyLiveness, TopologyLivenessStatus, TopologySnapshot},
    traits::{IEventSubscriber, IStorageRepository},
};

/// Snapshot schema without liveness (served while the chain position is unknown).
pub const TOPOLOGY_SCHEMA_V1: u8 = 1;
/// Snapshot schema that pins a block and carries one liveness record per member.
pub const TOPOLOGY_SCHEMA_V2: u8 = 2;

/// A node's full on-chain profile, as read from `NoxRegistry.relayers()` and
/// `getNodeRole()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryProfile {
    pub address: String,
    pub sphinx_key: String,
    pub url: String,
    pub ingress_url: Option<String>,
    pub metadata_url: Option<String>,
    pub stake: String,
    pub role: u8,
    pub frozen: bool,
}

/// Members indexed by the libp2p identity and IP in their registered P2P URL.
#[derive(Debug, Default)]
struct PeerIndex {
    by_peer: HashMap<PeerId, String>,
    member_ips: HashSet<IpAddr>,
    /// Members whose registered URL has no `/p2p/<peer id>` component.
    unbound: usize,
}

/// Extracts the libp2p identity from a registered P2P URL (`.../p2p/<peer id>`).
#[must_use]
pub fn peer_id_from_url(url: &str) -> Option<PeerId> {
    url.parse::<Multiaddr>().ok()?.iter().find_map(|p| match p {
        Protocol::P2p(peer) => Some(peer),
        _ => None,
    })
}

fn ip_from_url(url: &str) -> Option<IpAddr> {
    url.parse::<Multiaddr>().ok()?.iter().find_map(|p| match p {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

/// Single owner of the node's view of the registry: the node set, its routing
/// layers, the persisted `peer:*` records, and the P2P liveness of members.
pub struct TopologyManager {
    storage: Arc<dyn IStorageRepository>,
    bus: Arc<dyn IEventSubscriber>,
    /// Routing view: frozen members are left out.
    layers: Arc<DashMap<u8, Vec<RelayerNode>>>,
    /// Membership view keyed by lowercase address, frozen members included
    /// (they still count towards `relayerCount()` and the fingerprint).
    address_index: Arc<DashMap<String, RelayerNode>>,
    /// XOR(keccak256(addr)) for each registered node. Matches on-chain `NoxRegistry.topologyFingerprint`.
    fingerprint: RwLock<[u8; 32]>,
    frozen: DashMap<String, ()>,
    peer_index: RwLock<PeerIndex>,
    /// Unix time of the last sign of life (connection or ping) per connected peer.
    peer_seen: DashMap<PeerId, u64>,
    local_peer_id: RwLock<Option<PeerId>>,
    /// Set by the registry reconciler while the node set matches the chain.
    membership_verified: AtomicBool,
    resync: Arc<Notify>,
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
            frozen: DashMap::new(),
            peer_index: RwLock::new(PeerIndex::default()),
            peer_seen: DashMap::new(),
            local_peer_id: RwLock::new(None),
            membership_verified: AtomicBool::new(false),
            resync: Arc::new(Notify::new()),
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

    fn rebuild_peer_index(&self) {
        let mut index = PeerIndex::default();
        for entry in self.address_index.iter() {
            match peer_id_from_url(&entry.value().url) {
                Some(peer) => {
                    index.by_peer.insert(peer, entry.key().clone());
                }
                None => index.unbound += 1,
            }
            if let Some(ip) = ip_from_url(&entry.value().url) {
                index.member_ips.insert(ip);
            }
        }
        *self.peer_index.write() = index;
    }

    /// Derived state that follows the member set: fingerprint and peer index.
    fn membership_changed(&self) {
        self.recompute_fingerprint();
        self.rebuild_peer_index();
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

    /// Wakes the registry reconciler (lost or undecodable registry update).
    pub fn request_resync(&self) {
        self.resync.notify_one();
    }

    #[must_use]
    pub fn resync_signal(&self) -> Arc<Notify> {
        self.resync.clone()
    }

    pub fn set_membership_verified(&self, verified: bool) {
        let previous = self.membership_verified.swap(verified, Ordering::AcqRel);
        if previous != verified {
            info!(verified, "Registry membership verification changed");
        }
    }

    /// True while the last reconcile found the node set equal to the chain's.
    #[must_use]
    pub fn membership_verified(&self) -> bool {
        self.membership_verified.load(Ordering::Acquire)
    }

    /// Normalizes a node to its canonical layer and replaces its routing entries.
    /// Frozen nodes stay members but are not routed through.
    fn place_in_layers(&self, node: &RelayerNode) {
        let address_lower = node.address.to_lowercase();
        for mut entry in self.layers.iter_mut() {
            entry
                .value_mut()
                .retain(|n| n.address.to_lowercase() != address_lower);
        }
        if self.frozen.contains_key(&address_lower) {
            return;
        }
        for &layer in nox_core::models::topology::layers_for_role(node.role) {
            let mut layer_node = node.clone();
            layer_node.layer = layer;
            self.layers.entry(layer).or_default().push(layer_node);
        }
    }

    async fn persist(&self, node: &RelayerNode) {
        let key = format!("peer:{}", node.address.to_lowercase());
        match serde_json::to_vec(node) {
            Ok(bytes) => {
                if let Err(e) = self.storage.put(key.as_bytes(), &bytes).await {
                    error!("Failed to persist peer {}: {:?}", node.address, e);
                }
            }
            Err(e) => error!("Serialization error for {}: {}", node.address, e),
        }
    }

    /// Inserts or replaces a member with its canonical layer, then persists it.
    async fn upsert(&self, mut node: RelayerNode) {
        let address_lower = node.address.to_lowercase();
        node.layer = nox_core::primary_layer_for_role(&address_lower, node.role);
        self.place_in_layers(&node);
        self.address_index.insert(address_lower, node.clone());
        self.membership_changed();
        self.persist(&node).await;
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
                Ok(mut node) => {
                    let addr_lower = node.address.to_lowercase();
                    // Older versions persisted layer 0 for every peer; the layer
                    // is a function of address and role, so derive it again.
                    node.layer = nox_core::primary_layer_for_role(&addr_lower, node.role);
                    self.place_in_layers(&node);
                    self.address_index.insert(addr_lower, node);
                    count += 1;
                }
                Err(e) => {
                    warn!("Failed to deserialize persisted peer: {e}");
                }
            }
        }
        self.membership_changed();
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
                        Ok(event) => self.handle_event(event).await,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            warn!("Topology bus lagged by {} events; requesting registry resync.", n);
                            self.request_resync();
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

    async fn handle_event(&self, event: NoxEvent) {
        match event {
            NoxEvent::RelayerRegistered {
                address,
                sphinx_key,
                url,
                stake,
                role,
                ingress_url,
                metadata_url,
            } => {
                self.handle_registration(
                    address,
                    sphinx_key,
                    url,
                    stake,
                    role,
                    ingress_url,
                    metadata_url,
                )
                .await;
            }
            NoxEvent::RelayerProfileSynced {
                address,
                sphinx_key,
                url,
                ingress_url,
                metadata_url,
                stake,
                role,
                frozen,
            } => {
                self.apply_profile(RegistryProfile {
                    address,
                    sphinx_key,
                    url,
                    ingress_url,
                    metadata_url,
                    stake,
                    role,
                    frozen,
                })
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
                // The remaining stake is only known on-chain (a slash below the
                // minimum also deregisters), so re-read the profile.
                warn!(
                    address = %address,
                    amount = %amount,
                    slasher = %slasher,
                    "Relayer slashed -- requesting registry resync"
                );
                self.request_resync();
            }
            NoxEvent::RegistryPaused { by } => {
                warn!(by = %by, "NoxRegistry PAUSED -- exit nodes should stop submitting transactions");
            }
            NoxEvent::RegistryUnpaused { by } => {
                info!(by = %by, "NoxRegistry UNPAUSED -- normal operations resumed");
            }
            _ => {} // Ignore non-topology events
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

        // A registration always starts unfrozen on-chain.
        self.frozen.remove(&address.to_lowercase());
        self.upsert(node).await;
        info!("Topology update: added peer {}", address);
    }

    /// Replaces a member with the profile read from the registry.
    /// Returns `true` when the served node or its routing state changed.
    pub async fn apply_profile(&self, profile: RegistryProfile) -> bool {
        let address_lower = profile.address.to_lowercase();
        let mut node = RelayerNode::new(
            profile.address.clone(),
            profile.sphinx_key,
            profile.url,
            profile.stake,
            profile.role,
        );
        node.ingress_url = profile.ingress_url;
        node.metadata_url = profile.metadata_url;
        node.layer = nox_core::primary_layer_for_role(&address_lower, node.role);

        let was_frozen = self.frozen.contains_key(&address_lower);
        let unchanged = was_frozen == profile.frozen
            && self
                .address_index
                .get(&address_lower)
                .is_some_and(|current| *current == node);
        if unchanged {
            return false;
        }

        if profile.frozen {
            self.frozen.insert(address_lower, ());
        } else {
            self.frozen.remove(&address_lower);
        }
        if was_frozen != profile.frozen {
            info!(
                address = %profile.address,
                frozen = profile.frozen,
                "Topology update: freeze state changed"
            );
        }
        self.upsert(node).await;
        info!(address = %profile.address, "Topology update: profile synced from registry");
        true
    }

    pub async fn handle_removal(&self, address: String) {
        let key = format!("peer:{}", address.to_lowercase());
        if let Err(e) = self.storage.delete(key.as_bytes()).await {
            error!("Failed to remove peer {}: {:?}", address, e);
        } else {
            let addr_lower = address.to_lowercase();
            for mut entry in self.layers.iter_mut() {
                entry
                    .value_mut()
                    .retain(|n| n.address.to_lowercase() != addr_lower);
            }
            self.address_index.remove(&addr_lower);
            self.frozen.remove(&addr_lower);
            self.membership_changed();
            info!("Topology update: removed peer {}", address);
        }
    }

    async fn handle_key_rotation(&self, address: String, new_sphinx_key: String) {
        let Some(mut node) = self.lookup_by_address(&address) else {
            warn!(
                address = %address,
                "KeyRotated event for unknown node -- ignoring"
            );
            return;
        };
        node.sphinx_key.clone_from(&new_sphinx_key);
        self.upsert(node).await;
        info!(
            address = %address,
            new_key = %new_sphinx_key,
            "Topology update: sphinx key rotated"
        );
    }

    async fn handle_role_update(&self, address: String, new_role: u8) {
        let Some(mut node) = self.lookup_by_address(&address) else {
            warn!(
                address = %address,
                "RoleUpdated event for unknown node -- ignoring"
            );
            return;
        };
        let old_role = node.role;
        node.role = new_role;
        // `upsert` derives the layer from the new role.
        self.upsert(node).await;
        info!(
            address = %address,
            old_role = old_role,
            new_role = new_role,
            "Topology update: role changed"
        );
    }

    async fn handle_url_update(&self, address: String, new_url: String) {
        let Some(mut node) = self.lookup_by_address(&address) else {
            warn!(
                address = %address,
                "RelayerUpdated event for unknown node -- ignoring"
            );
            return;
        };
        node.url.clone_from(&new_url);
        self.upsert(node).await;
        info!(
            address = %address,
            new_url = %new_url,
            "Topology update: URL changed"
        );
    }

    /// Routing candidates for a layer. Frozen members are excluded.
    pub fn get_nodes_in_layer(&self, layer: u8) -> Vec<RelayerNode> {
        self.layers
            .get(&layer)
            .map(|l| l.clone())
            .unwrap_or_default()
    }

    /// Every registered member (frozen included) in canonical address order.
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

    #[must_use]
    pub fn is_frozen(&self, address: &str) -> bool {
        self.frozen.contains_key(&address.to_lowercase())
    }

    /// Lowercase addresses of every member, for the registry reconciler.
    #[must_use]
    pub fn member_addresses(&self) -> Vec<String> {
        self.address_index
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    #[must_use]
    pub fn member_count(&self) -> usize {
        self.address_index.len()
    }

    /// Lowercase address of the member registered with this libp2p identity.
    #[must_use]
    pub fn member_address_for_peer(&self, peer: &PeerId) -> Option<String> {
        self.peer_index.read().by_peer.get(peer).cloned()
    }

    #[must_use]
    pub fn is_member_peer(&self, peer: &PeerId) -> bool {
        self.peer_index.read().by_peer.contains_key(peer)
    }

    /// True when a member's registered P2P URL uses this IP.
    #[must_use]
    pub fn is_member_ip(&self, ip: &IpAddr) -> bool {
        self.peer_index.read().member_ips.contains(ip)
    }

    /// Members whose registered URL carries no libp2p identity, so their
    /// connections cannot be matched to the registry.
    #[must_use]
    pub fn unbound_member_count(&self) -> usize {
        self.peer_index.read().unbound
    }

    /// Registered P2P address of every other member, for keeping links up.
    #[must_use]
    pub fn member_dial_targets(&self) -> Vec<(PeerId, Multiaddr)> {
        let local = *self.local_peer_id.read();
        self.address_index
            .iter()
            .filter_map(|entry| {
                let addr = entry.value().url.parse::<Multiaddr>().ok()?;
                let peer = peer_id_from_url(&entry.value().url)?;
                (Some(peer) != local).then_some((peer, addr))
            })
            .collect()
    }

    pub fn set_local_peer_id(&self, peer: PeerId) {
        *self.local_peer_id.write() = Some(peer);
    }

    /// The member registered with this node's libp2p identity, if any.
    #[must_use]
    pub fn local_member(&self) -> Option<RelayerNode> {
        let local = (*self.local_peer_id.read())?;
        let address = self.member_address_for_peer(&local)?;
        self.lookup_by_address(&address)
    }

    /// Records a sign of life from a connected peer (connection or ping).
    pub fn record_peer_seen(&self, peer: PeerId, unix_secs: u64) {
        self.peer_seen.insert(peer, unix_secs);
    }

    /// Records that the last connection to a peer closed.
    pub fn record_peer_gone(&self, peer: &PeerId) {
        self.peer_seen.remove(peer);
    }

    fn liveness_of(
        &self,
        node: &RelayerNode,
        local: Option<PeerId>,
        now_unix: u64,
        window_secs: u64,
    ) -> (TopologyLivenessStatus, u64) {
        let Some(peer) = peer_id_from_url(&node.url) else {
            return (TopologyLivenessStatus::Offline, now_unix);
        };
        if Some(peer) == local {
            return (TopologyLivenessStatus::Online, now_unix);
        }
        match self.peer_seen.get(&peer).map(|seen| *seen) {
            Some(seen) if seen <= now_unix && now_unix - seen <= window_secs => {
                (TopologyLivenessStatus::Online, seen)
            }
            _ => (TopologyLivenessStatus::Offline, now_unix),
        }
    }

    /// True when the member is this node or answered on P2P within the window.
    #[must_use]
    pub fn is_live(&self, node: &RelayerNode, now_unix: u64, window_secs: u64) -> bool {
        let local = *self.local_peer_id.read();
        matches!(
            self.liveness_of(node, local, now_unix, window_secs).0,
            TopologyLivenessStatus::Online
        )
    }

    /// Builds the served snapshot. With a known chain position (a nonzero
    /// `block_number`) it is schema v2: members in canonical order, each with
    /// this node's P2P liveness observation. Without one it stays schema v1, since v2
    /// requires a pinned block. The block is read after the node set, so a
    /// node set is never reported at a block older than its newest change.
    #[must_use]
    pub fn snapshot(
        &self,
        block_number: impl FnOnce() -> u64,
        pow_difficulty: u32,
        now_unix: u64,
        liveness_window_secs: u64,
    ) -> TopologySnapshot {
        let nodes = self.get_all_nodes();
        let block_number = block_number();
        let addresses: Vec<String> = nodes.iter().map(|n| n.address.clone()).collect();
        let fingerprint = compute_topology_fingerprint(&addresses);
        let (schema_version, liveness) = if block_number == 0 {
            (TOPOLOGY_SCHEMA_V1, Vec::new())
        } else {
            let local = *self.local_peer_id.read();
            let liveness = nodes
                .iter()
                .map(|node| {
                    let (status, observed_at_unix) =
                        self.liveness_of(node, local, now_unix, liveness_window_secs);
                    TopologyLiveness {
                        address: node.address.clone(),
                        status,
                        observed_at_unix,
                    }
                })
                .collect();
            (TOPOLOGY_SCHEMA_V2, liveness)
        };
        TopologySnapshot {
            nodes,
            fingerprint: hex::encode(fingerprint),
            timestamp: now_unix,
            block_number,
            pow_difficulty,
            schema_version,
            liveness,
        }
    }

    /// Replace the entire topology from a verified snapshot. Recomputes fingerprint and persists.
    ///
    /// Persisted peers absent from the snapshot are deleted too, otherwise the
    /// next restart would hydrate them again.
    pub async fn hydrate_from_snapshot(&self, nodes: Vec<RelayerNode>) {
        self.layers.clear();
        self.address_index.clear();
        self.frozen.clear();

        let nodes: Vec<RelayerNode> = nodes
            .into_iter()
            .map(|mut node| {
                node.layer = nox_core::primary_layer_for_role(&node.address, node.role);
                node
            })
            .collect();

        for node in &nodes {
            self.place_in_layers(node);
            self.address_index
                .insert(node.address.to_lowercase(), node.clone());
        }

        self.membership_changed();
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

    fn peer(seed: u8) -> PeerId {
        let mut bytes = [seed; 32];
        let keypair = libp2p::identity::Keypair::ed25519_from_bytes(&mut bytes).expect("key");
        PeerId::from(keypair.public())
    }

    fn profile(address: &str, peer: PeerId, role: u8) -> RegistryProfile {
        RegistryProfile {
            address: address.to_string(),
            sphinx_key: "22".repeat(32),
            url: format!("/ip4/10.0.0.1/tcp/15000/p2p/{peer}"),
            ingress_url: Some("https://nox.example".to_string()),
            metadata_url: None,
            stake: "5".to_string(),
            role,
            frozen: false,
        }
    }

    #[tokio::test]
    async fn hydrate_from_storage_derives_layer_from_role() {
        let directory = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(SledRepository::new(directory.path()).expect("storage"));
        // What older versions persisted from the P2P path: layer 0 for an exit.
        let mut stale = snapshot_node(A);
        stale.role = 2;
        stale.layer = 0;
        storage
            .put(
                format!("peer:{A}").as_bytes(),
                &serde_json::to_vec(&stale).expect("json"),
            )
            .await
            .expect("put");

        let manager = manager_on(storage);
        manager.hydrate_from_storage().await;
        let served = manager.lookup_by_address(A).expect("member");
        assert_eq!(served.layer, 2);
        assert_eq!(manager.get_all_nodes()[0].layer, 2);
    }

    #[tokio::test]
    async fn snapshot_hydration_derives_layer_from_role() {
        let directory = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(SledRepository::new(directory.path()).expect("storage"));
        let manager = manager_on(storage);
        let mut exit = snapshot_node(A);
        exit.role = 2;
        exit.layer = 0;
        manager.hydrate_from_snapshot(vec![exit]).await;
        assert_eq!(manager.lookup_by_address(A).expect("member").layer, 2);
    }

    #[tokio::test]
    async fn role_update_moves_node_to_its_new_primary_layer() {
        let directory = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(SledRepository::new(directory.path()).expect("storage"));
        let manager = manager_on(storage);
        register(&manager, A).await;
        manager.handle_role_update(A.to_string(), 2).await;
        let node = manager.lookup_by_address(A).expect("member");
        assert_eq!(node.role, 2);
        assert_eq!(node.layer, 2);
        assert_eq!(manager.get_nodes_in_layer(2).len(), 1);
    }

    #[tokio::test]
    async fn profile_sync_replaces_every_field_and_tracks_freeze() {
        let directory = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(SledRepository::new(directory.path()).expect("storage"));
        let manager = manager_on(storage.clone());
        register(&manager, A).await;
        register(&manager, B).await;

        let mut updated = profile(A, peer(1), 1);
        assert!(manager.apply_profile(updated.clone()).await);
        assert!(!manager.apply_profile(updated.clone()).await, "idempotent");
        let node = manager.lookup_by_address(A).expect("member");
        assert_eq!(node.url, updated.url);
        assert_eq!(node.stake, "5");
        assert_eq!(node.ingress_url.as_deref(), Some("https://nox.example"));

        // Frozen: still a member (count and fingerprint), never a route.
        updated.frozen = true;
        assert!(manager.apply_profile(updated.clone()).await);
        assert!(manager.is_frozen(A));
        assert_eq!(manager.get_all_nodes().len(), 2);
        assert_eq!(manager.get_current_fingerprint(), expected(&[A, B]));
        for layer in 0..3 {
            assert!(manager
                .get_nodes_in_layer(layer)
                .iter()
                .all(|n| n.address != A));
        }

        updated.frozen = false;
        assert!(manager.apply_profile(updated).await);
        assert!(!manager.is_frozen(A));
        assert!(manager.get_nodes_in_layer(0).iter().any(|n| n.address == A));

        // Persisted record follows the synced profile.
        let restarted = manager_on(storage);
        restarted.hydrate_from_storage().await;
        assert_eq!(restarted.lookup_by_address(A).expect("member").stake, "5");
    }

    #[tokio::test]
    async fn slash_event_does_not_zero_the_stake() {
        let directory = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(SledRepository::new(directory.path()).expect("storage"));
        let manager = manager_on(storage);
        manager.apply_profile(profile(A, peer(1), 1)).await;
        manager
            .handle_event(NoxEvent::RelayerSlashed {
                address: A.to_string(),
                amount: "1".to_string(),
                slasher: B.to_string(),
            })
            .await;
        assert_eq!(manager.lookup_by_address(A).expect("member").stake, "5");
    }

    #[tokio::test]
    async fn peer_index_binds_registered_identities() {
        let directory = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(SledRepository::new(directory.path()).expect("storage"));
        let manager = manager_on(storage);
        manager.apply_profile(profile(A, peer(1), 1)).await;
        manager.apply_profile(profile(B, peer(2), 2)).await;
        manager.set_local_peer_id(peer(1));

        assert!(manager.is_member_peer(&peer(1)));
        assert!(manager.is_member_peer(&peer(2)));
        assert!(!manager.is_member_peer(&peer(3)));
        assert_eq!(
            manager.member_address_for_peer(&peer(2)).as_deref(),
            Some(B)
        );
        assert!(manager.is_member_ip(&"10.0.0.1".parse().expect("ip")));
        assert_eq!(manager.unbound_member_count(), 0);
        assert_eq!(manager.local_member().expect("self").address, A);

        let targets = manager.member_dial_targets();
        assert_eq!(targets.len(), 1, "never dials itself");
        assert_eq!(targets[0].0, peer(2));

        // A URL without /p2p/ cannot be bound to a connection.
        register(&manager, C).await;
        assert_eq!(manager.unbound_member_count(), 1);

        manager.handle_removal(B.to_string()).await;
        assert!(!manager.is_member_peer(&peer(2)));
    }

    #[tokio::test]
    async fn snapshot_is_v1_without_block_and_v2_with_liveness() {
        let directory = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(SledRepository::new(directory.path()).expect("storage"));
        let manager = manager_on(storage);
        manager.apply_profile(profile(B, peer(2), 2)).await;
        manager.apply_profile(profile(A, peer(1), 1)).await;
        manager.apply_profile(profile(C, peer(3), 3)).await;
        manager.set_local_peer_id(peer(1));
        manager.record_peer_seen(peer(2), 990);
        manager.record_peer_seen(peer(3), 900);

        let v1 = manager.snapshot(|| 0, 3, 1_000, 60);
        assert_eq!(v1.schema_version, TOPOLOGY_SCHEMA_V1);
        assert!(v1.liveness.is_empty());

        let v2 = manager.snapshot(|| 42, 3, 1_000, 60);
        assert_eq!(v2.schema_version, TOPOLOGY_SCHEMA_V2);
        assert_eq!(v2.block_number, 42);
        assert_eq!(v2.pow_difficulty, 3);
        assert_eq!(v2.fingerprint, hex::encode(expected(&[A, B, C])));
        let members: Vec<&str> = v2.nodes.iter().map(|n| n.address.as_str()).collect();
        let observed: Vec<&str> = v2.liveness.iter().map(|l| l.address.as_str()).collect();
        assert_eq!(members, vec![C, A, B], "canonical address order");
        assert_eq!(members, observed);
        for node in &v2.nodes {
            assert_eq!(
                node.layer,
                nox_core::primary_layer_for_role(&node.address, node.role)
            );
        }
        let status = |address: &str| {
            v2.liveness
                .iter()
                .find(|l| l.address == address)
                .map(|l| (l.status, l.observed_at_unix))
                .expect("record")
        };
        assert_eq!(status(A), (TopologyLivenessStatus::Online, 1_000), "self");
        assert_eq!(status(B), (TopologyLivenessStatus::Online, 990));
        assert_eq!(status(C), (TopologyLivenessStatus::Offline, 1_000), "stale");

        manager.record_peer_gone(&peer(2));
        let after = manager.snapshot(|| 42, 3, 1_000, 60);
        assert_eq!(after.liveness[2].status, TopologyLivenessStatus::Offline);
    }

    #[tokio::test]
    async fn lagged_bus_requests_a_registry_resync() {
        let directory = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(SledRepository::new(directory.path()).expect("storage"));
        let bus = Arc::new(TokioEventBus::new(1));
        let subscriber: Arc<dyn IEventSubscriber> = bus.clone();
        let manager = Arc::new(TopologyManager::new(storage, subscriber, None));
        let resync = manager.resync_signal();
        let runner = manager.clone();
        let handle = tokio::spawn(async move { runner.run().await });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        for _ in 0..8 {
            nox_core::IEventPublisher::publish(
                bus.as_ref(),
                NoxEvent::NodeStarted { timestamp: 0 },
            )
            .expect("publish");
        }
        tokio::time::timeout(std::time::Duration::from_secs(2), resync.notified())
            .await
            .expect("resync requested after lag");
        handle.abort();
    }
}
