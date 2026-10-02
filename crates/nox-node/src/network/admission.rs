//! Registry-based P2P admission.
//!
//! A peer is a member when its libp2p identity appears as `/p2p/<peer id>` in a
//! registered node's P2P URL. Noise authenticates that identity during the
//! connection handshake, so membership needs no extra protocol messages and
//! works unchanged with peers that run older versions.
//!
//! Enforcement only starts once the startup grace period has passed and the
//! registry reconciler has confirmed the node set against the chain; until then
//! (and in `monitor` mode) decisions are counted and logged only. Members are
//! never subject to IP bans or subnet caps.

use crate::config::{NetworkConfig, PeerAdmissionMode};
use crate::network::connection_filter::ConnectionFilter;
use crate::services::network_manager::TopologyManager;
use crate::telemetry::metrics::MetricsService;
use dashmap::DashMap;
use libp2p::core::Endpoint;
use libp2p::swarm::{
    dummy, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};
use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};
use std::net::IpAddr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Why a connection was refused.
#[derive(Debug, thiserror::Error)]
pub enum AdmissionDenied {
    #[error("peer {0} is not a registered node")]
    NotRegistered(PeerId),
    #[error("remote address {0} is banned or over its subnet limit")]
    Filtered(Multiaddr),
}

/// Registry-based admission policy shared by the swarm gate and `P2PService`.
pub struct PeerAdmission {
    mode: PeerAdmissionMode,
    grace: Duration,
    started: Instant,
    topology: Arc<TopologyManager>,
    filter: Arc<ConnectionFilter>,
    metrics: MetricsService,
    /// When each connected non-member was first seen without registry membership.
    non_member_since: DashMap<PeerId, Instant>,
}

fn remote_ip(addr: &Multiaddr) -> Option<IpAddr> {
    addr.iter().find_map(|p| match p {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

impl PeerAdmission {
    #[must_use]
    pub fn new(
        config: &NetworkConfig,
        topology: Arc<TopologyManager>,
        filter: Arc<ConnectionFilter>,
        metrics: MetricsService,
    ) -> Self {
        info!(
            mode = ?config.peer_admission,
            grace_secs = config.peer_admission_grace_secs,
            "P2P admission configured"
        );
        Self {
            mode: config.peer_admission,
            grace: Duration::from_secs(config.peer_admission_grace_secs),
            started: Instant::now(),
            topology,
            filter,
            metrics,
            non_member_since: DashMap::new(),
        }
    }

    #[must_use]
    pub fn mode(&self) -> PeerAdmissionMode {
        self.mode
    }

    /// Enforcement is live: `enforce` mode, past the startup grace period, and
    /// the node set verified against the registry with every member bound to a
    /// libp2p identity.
    #[must_use]
    pub fn enforcing(&self) -> bool {
        self.mode == PeerAdmissionMode::Enforce
            && self.started.elapsed() >= self.grace
            && self.topology.membership_verified()
            && self.topology.unbound_member_count() == 0
    }

    #[must_use]
    pub fn is_member(&self, peer: &PeerId) -> bool {
        self.topology.is_member_peer(peer)
    }

    fn record(&self, stage: &str, result: &str) {
        self.metrics
            .p2p_admission_total
            .get_or_create(&vec![
                ("stage".to_string(), stage.to_string()),
                ("result".to_string(), result.to_string()),
            ])
            .inc();
    }

    /// Decision for a peer outside the registry: refuse when enforcing,
    /// otherwise count what enforcement would have refused.
    fn refuse_non_member(&self, peer: &PeerId, stage: &str) -> bool {
        if self.is_member(peer) {
            return false;
        }
        if self.enforcing() {
            self.record(stage, "denied");
            true
        } else {
            if self.mode != PeerAdmissionMode::Off {
                self.record(stage, "would_deny");
            }
            false
        }
    }

    /// Accept an inbound packet from `peer`?
    #[must_use]
    pub fn allow_packet(&self, peer: &PeerId) -> bool {
        !self.refuse_non_member(peer, "packet")
    }

    /// Accept an established connection (either direction) with `peer`?
    #[must_use]
    pub fn allow_connection(&self, peer: &PeerId) -> bool {
        !self.refuse_non_member(peer, "connection")
    }

    /// IP bans and subnet caps for a not yet authenticated inbound connection.
    /// Addresses registered by members are exempt so a member is never locked
    /// out by a ban earned under load.
    #[must_use]
    pub fn allow_inbound_address(&self, remote: &Multiaddr) -> bool {
        if remote_ip(remote).is_some_and(|ip| self.topology.is_member_ip(&ip)) {
            return true;
        }
        if self.filter.is_allowed(remote) {
            return true;
        }
        if self.mode == PeerAdmissionMode::Enforce {
            self.record("address", "denied");
            false
        } else {
            debug!(addr = %remote, "Connection filter would refuse address (not enforced)");
            if self.mode == PeerAdmissionMode::Monitor {
                self.record("address", "would_deny");
            }
            true
        }
    }

    /// May the IP of `remote` be banned after abuse? Never for member addresses.
    #[must_use]
    pub fn may_ban(&self, remote: &Multiaddr) -> bool {
        !remote_ip(remote).is_some_and(|ip| self.topology.is_member_ip(&ip))
    }

    /// Connected peers to drop because they have been outside the registry for
    /// longer than the grace period (for example a node that deregistered).
    pub fn sweep(&self, connected: impl IntoIterator<Item = PeerId>) -> Vec<PeerId> {
        let mut seen = Vec::new();
        let mut evict = Vec::new();
        for peer in connected {
            seen.push(peer);
            if self.is_member(&peer) {
                self.non_member_since.remove(&peer);
                continue;
            }
            let since = *self
                .non_member_since
                .entry(peer)
                .or_insert_with(Instant::now);
            if since.elapsed() < self.grace {
                continue;
            }
            if self.enforcing() {
                self.record("sweep", "denied");
                warn!(peer = %peer, "Closing link to peer outside the registry");
                evict.push(peer);
            } else if self.mode != PeerAdmissionMode::Off {
                self.record("sweep", "would_deny");
            }
        }
        self.non_member_since.retain(|peer, _| seen.contains(peer));
        for peer in &evict {
            self.non_member_since.remove(peer);
        }
        evict
    }
}

/// Swarm-level gate: refuses filtered inbound addresses before the handshake
/// and non-members once their identity is known. Adds no wire protocol.
pub struct AdmissionGate {
    policy: Arc<PeerAdmission>,
}

impl AdmissionGate {
    #[must_use]
    pub fn new(policy: Arc<PeerAdmission>) -> Self {
        Self { policy }
    }

    fn check_peer(&self, peer: PeerId) -> Result<THandler<Self>, ConnectionDenied> {
        if self.policy.allow_connection(&peer) {
            Ok(dummy::ConnectionHandler)
        } else {
            Err(ConnectionDenied::new(AdmissionDenied::NotRegistered(peer)))
        }
    }
}

impl NetworkBehaviour for AdmissionGate {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = std::convert::Infallible;

    fn handle_pending_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        if self.policy.allow_inbound_address(remote_addr) {
            Ok(())
        } else {
            Err(ConnectionDenied::new(AdmissionDenied::Filtered(
                remote_addr.clone(),
            )))
        }
    }

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.check_peer(peer)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _addr: &Multiaddr,
        _role_override: Endpoint,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.check_peer(peer)
    }

    fn on_swarm_event(&mut self, _event: FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::{event_bus::TokioEventBus, storage::SledRepository};
    use crate::services::network_manager::RegistryProfile;
    use nox_core::IEventSubscriber;

    const MEMBER: &str = "0x74486dc1ac551e5cd3f4eef80727cc9d50d3abe9";

    fn peer(seed: u8) -> PeerId {
        let mut bytes = [seed; 32];
        let keypair = libp2p::identity::Keypair::ed25519_from_bytes(&mut bytes).expect("key");
        PeerId::from(keypair.public())
    }

    async fn topology_with_member(dir: &tempfile::TempDir) -> Arc<TopologyManager> {
        let storage = Arc::new(SledRepository::new(dir.path()).expect("storage"));
        let bus = Arc::new(TokioEventBus::new(8));
        let subscriber: Arc<dyn IEventSubscriber> = bus;
        let topology = Arc::new(TopologyManager::new(storage, subscriber, None));
        topology
            .apply_profile(RegistryProfile {
                address: MEMBER.to_string(),
                sphinx_key: "11".repeat(32),
                url: format!("/ip4/10.1.2.3/tcp/15000/p2p/{}", peer(1)),
                ingress_url: Some(String::new()),
                metadata_url: None,
                stake: "0".to_string(),
                role: 1,
                frozen: false,
            })
            .await;
        topology
    }

    fn policy(
        topology: Arc<TopologyManager>,
        mode: PeerAdmissionMode,
        grace_secs: u64,
    ) -> PeerAdmission {
        let config = NetworkConfig {
            peer_admission: mode,
            peer_admission_grace_secs: grace_secs,
            ..NetworkConfig::default()
        };
        PeerAdmission::new(
            &config,
            topology,
            Arc::new(ConnectionFilter::new()),
            MetricsService::new(),
        )
    }

    fn addr(ip: &str) -> Multiaddr {
        format!("/ip4/{ip}/tcp/4000").parse().expect("multiaddr")
    }

    #[tokio::test]
    async fn nothing_is_refused_until_membership_is_verified() {
        let dir = tempfile::tempdir().expect("tempdir");
        let topology = topology_with_member(&dir).await;
        let admission = policy(topology.clone(), PeerAdmissionMode::Enforce, 0);

        assert!(!admission.enforcing());
        assert!(admission.allow_connection(&peer(9)));
        assert!(admission.allow_packet(&peer(9)));

        topology.set_membership_verified(true);
        assert!(admission.enforcing());
        assert!(admission.allow_connection(&peer(1)));
        assert!(admission.allow_packet(&peer(1)));
        assert!(!admission.allow_connection(&peer(9)));
        assert!(!admission.allow_packet(&peer(9)));
    }

    #[tokio::test]
    async fn startup_grace_delays_enforcement() {
        let dir = tempfile::tempdir().expect("tempdir");
        let topology = topology_with_member(&dir).await;
        topology.set_membership_verified(true);
        let admission = policy(topology, PeerAdmissionMode::Enforce, 3_600);
        assert!(!admission.enforcing());
        assert!(admission.allow_packet(&peer(9)));
    }

    #[tokio::test]
    async fn monitor_and_off_never_refuse() {
        let dir = tempfile::tempdir().expect("tempdir");
        let topology = topology_with_member(&dir).await;
        topology.set_membership_verified(true);
        for mode in [PeerAdmissionMode::Monitor, PeerAdmissionMode::Off] {
            let admission = policy(topology.clone(), mode, 0);
            assert!(!admission.enforcing());
            assert!(admission.allow_connection(&peer(9)));
            assert!(admission.allow_packet(&peer(9)));
            assert!(admission.sweep([peer(9)]).is_empty());
        }
    }

    #[tokio::test]
    async fn unbound_member_url_keeps_enforcement_off() {
        let dir = tempfile::tempdir().expect("tempdir");
        let topology = topology_with_member(&dir).await;
        topology
            .apply_profile(RegistryProfile {
                address: "0x8c9fb3e9fe537067c8430480f80a4a5b9a12be1a".to_string(),
                sphinx_key: "33".repeat(32),
                url: "/ip4/10.9.9.9/tcp/15000".to_string(),
                ingress_url: Some(String::new()),
                metadata_url: None,
                stake: "0".to_string(),
                role: 2,
                frozen: false,
            })
            .await;
        topology.set_membership_verified(true);
        let admission = policy(topology, PeerAdmissionMode::Enforce, 0);
        assert!(!admission.enforcing());
        assert!(admission.allow_packet(&peer(9)));
    }

    #[tokio::test]
    async fn sweep_closes_links_that_left_the_registry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let topology = topology_with_member(&dir).await;
        topology.set_membership_verified(true);
        let admission = policy(topology.clone(), PeerAdmissionMode::Enforce, 0);

        assert!(admission.sweep([peer(1)]).is_empty());
        assert_eq!(admission.sweep([peer(1), peer(9)]), vec![peer(9)]);

        // Deregistration: the member becomes a non-member and is closed.
        topology.handle_removal(MEMBER.to_string()).await;
        topology.set_membership_verified(true);
        assert_eq!(admission.sweep([peer(1)]), vec![peer(1)]);
    }

    #[tokio::test]
    async fn member_addresses_are_never_filtered_or_banned() {
        let dir = tempfile::tempdir().expect("tempdir");
        let topology = topology_with_member(&dir).await;
        let filter = Arc::new(ConnectionFilter::new());
        let config = NetworkConfig::default();
        let admission =
            PeerAdmission::new(&config, topology, filter.clone(), MetricsService::new());

        let member = addr("10.1.2.3");
        let stranger = addr("10.200.0.1");
        filter.ban_ip(&member);
        filter.ban_ip(&stranger);

        assert!(admission.allow_inbound_address(&member));
        assert!(!admission.may_ban(&member));
        assert!(!admission.allow_inbound_address(&stranger));
        assert!(admission.may_ban(&stranger));
    }

    #[tokio::test]
    async fn address_filter_is_advisory_outside_enforce_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let topology = topology_with_member(&dir).await;
        let filter = Arc::new(ConnectionFilter::new());
        let config = NetworkConfig {
            peer_admission: PeerAdmissionMode::Monitor,
            ..NetworkConfig::default()
        };
        let admission =
            PeerAdmission::new(&config, topology, filter.clone(), MetricsService::new());
        let stranger = addr("10.200.0.1");
        filter.ban_ip(&stranger);
        assert!(admission.allow_inbound_address(&stranger));
    }
}
