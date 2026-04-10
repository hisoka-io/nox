use crate::config::NoxConfig;
use crate::infra::persistence::peer_registry::PeerRegistry;
use crate::telemetry::metrics::MetricsService;
use nox_core::{
    events::NoxEvent,
    models::topology::RelayerNode,
    traits::{IEventPublisher, IEventSubscriber, IStorageRepository, InfrastructureError},
};

use super::{
    behaviour::{NoxBehaviour, NoxBehaviourEvent, SphinxPacket, SystemMessage},
    connection_filter::ConnectionFilter,
    rate_limiter::{PeerRateLimiter, RateLimitResult},
};

use dashmap::DashMap;
use futures::StreamExt;
use libp2p::{identity, noise, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder};
use rand::RngCore;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// 65-byte secp256k1 signature over `keccak256(peer_id_bytes)`, returned as hex.
pub fn sign_peer_id(
    peer_id_bytes: &[u8],
    eth_private_key_hex: &str,
) -> Result<String, InfrastructureError> {
    use ethers::core::k256::ecdsa::SigningKey;
    use ethers::signers::LocalWallet;

    let key_bytes = hex::decode(eth_private_key_hex.trim_start_matches("0x"))
        .map_err(|e| InfrastructureError::Network(format!("Invalid ETH private key hex: {e}")))?;
    let signing_key = SigningKey::from_bytes(key_bytes.as_slice().into())
        .map_err(|e| InfrastructureError::Network(format!("Invalid secp256k1 key: {e}")))?;
    let wallet = LocalWallet::from(signing_key);

    let message_hash = ethers::core::utils::keccak256(peer_id_bytes);

    // Sign the raw hash (not EIP-191 personal_sign -- we want plain ecrecover)
    let signature = wallet
        .sign_hash(ethers::core::types::H256::from(message_hash))
        .map_err(|e| InfrastructureError::Network(format!("Signing failed: {e}")))?;

    Ok(hex::encode(signature.to_vec()))
}

#[derive(Debug, Clone)]
pub struct PeerHealth {
    pub last_rtt: Duration,
    pub last_ping: Instant,
    pub ping_count: u64,
}

impl Default for PeerHealth {
    fn default() -> Self {
        Self {
            last_rtt: Duration::ZERO,
            last_ping: Instant::now(),
            ping_count: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SessionState {
    pub ticket: [u8; 32],
    pub created_at: Instant,
    pub capabilities: nox_core::models::handshake::Capabilities,
    pub routing_key: String,
}

/// Like `SessionState` but uses Unix timestamp for sled persistence.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PersistedSession {
    ticket_hex: String,
    created_at_unix: u64,
    capabilities: u32,
    routing_key: String,
    eth_address: Option<String>,
    registry_verified: bool,
}

/// P2P network service with rate limiting, connection filtering, and health monitoring.
pub struct P2PService {
    swarm: Swarm<NoxBehaviour>,
    event_bus: Arc<dyn IEventPublisher>,
    bus_subscriber: Arc<dyn IEventSubscriber>,
    peer_registry: Arc<PeerRegistry>,
    storage: Arc<dyn IStorageRepository>,
    metrics: MetricsService,
    rate_limiter: PeerRateLimiter,
    connection_filter: ConnectionFilter,
    peer_addresses: Arc<DashMap<PeerId, Multiaddr>>,
    peer_health: Arc<DashMap<PeerId, PeerHealth>>,
    /// `Relaxed` ordering: monotonic counter, eventual consistency sufficient for metrics.
    rate_limited_count: std::sync::atomic::AtomicU64,
    session_cache: Arc<DashMap<PeerId, SessionState>>,
    session_ttl: Duration,
    listening_tx: Option<oneshot::Sender<(PeerId, Multiaddr)>>,
    topology_manager: Arc<crate::services::network_manager::TopologyManager>,
    topology_request_timestamps: Arc<DashMap<PeerId, Instant>>,
    cancel_token: Option<CancellationToken>,
}

impl P2PService {
    pub async fn new(
        config: &NoxConfig,
        event_bus: Arc<dyn IEventPublisher>,
        bus_subscriber: Arc<dyn IEventSubscriber>,
        storage: Arc<dyn IStorageRepository>,
        metrics: MetricsService,
        topology_manager: Arc<crate::services::network_manager::TopologyManager>,
    ) -> Result<Self, InfrastructureError> {
        let local_key = if config.p2p_private_key.is_empty() {
            load_or_generate_p2p_key(&config.p2p_identity_path)?
        } else {
            let mut bytes = hex::decode(&config.p2p_private_key)
                .map_err(|e| InfrastructureError::Network(format!("Invalid P2P Key Hex: {e}")))?;
            identity::Keypair::ed25519_from_bytes(&mut bytes)
                .map_err(|e| InfrastructureError::Network(format!("Invalid P2P Key Bytes: {e}")))?
        };
        let local_peer_id = PeerId::from(local_key.public());
        info!(peer_id = %local_peer_id, "Local Peer Identity initialized");

        let swarm = SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| InfrastructureError::Network(format!("Transport setup failed: {e}")))?
            .with_behaviour(|key| {
                NoxBehaviour::new(key.clone(), &config.network)
                    .map_err(Box::<dyn std::error::Error + Send + Sync>::from)
            })
            .map_err(|e| InfrastructureError::Network(format!("Behaviour setup failed: {e:?}")))?
            .with_swarm_config(|c| {
                c.with_idle_connection_timeout(Duration::from_secs(
                    config.network.idle_connection_timeout_secs,
                ))
                // Limit negotiating inbound streams to prevent SYN flood
                .with_max_negotiating_inbound_streams(128)
            })
            .build();

        info!(
            max_connections = config.network.max_connections,
            max_per_peer = config.network.max_connections_per_peer,
            max_per_subnet = config.network.connection_filter.max_per_subnet,
            rate_limit = "configured",
            "DoS protection enabled"
        );

        let mut service = Self {
            swarm,
            event_bus,
            bus_subscriber,
            peer_registry: Arc::new(PeerRegistry::new(storage.clone())),
            storage,
            metrics,
            rate_limiter: PeerRateLimiter::with_config(config.network.rate_limit.clone()),
            connection_filter: ConnectionFilter::with_config(
                config.network.connection_filter.clone(),
            ),
            peer_addresses: Arc::new(DashMap::new()),
            peer_health: Arc::new(DashMap::new()),
            rate_limited_count: std::sync::atomic::AtomicU64::new(0),
            session_cache: Arc::new(DashMap::new()),
            session_ttl: Duration::from_secs(config.network.session_ttl_secs),
            listening_tx: None,
            topology_manager,
            topology_request_timestamps: Arc::new(DashMap::new()),
            cancel_token: None,
        };

        let addr_str = format!("/ip4/{}/tcp/{}", config.p2p_listen_addr, config.p2p_port);
        let addr: Multiaddr = addr_str.parse().map_err(|e| {
            InfrastructureError::Network(format!("Invalid Listen Address '{addr_str}': {e}"))
        })?;

        service
            .swarm
            .listen_on(addr)
            .map_err(|e| InfrastructureError::Network(format!("Failed to bind listener: {e}")))?;

        Ok(service)
    }

    pub fn with_bind_signal(mut self, tx: oneshot::Sender<(PeerId, Multiaddr)>) -> Self {
        self.listening_tx = Some(tx);
        self
    }

    #[must_use]
    pub fn with_cancel_token(mut self, token: CancellationToken) -> Self {
        self.cancel_token = Some(token);
        self
    }

    pub fn rate_limited_count(&self) -> u64 {
        self.rate_limited_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub async fn run(&mut self) {
        self.bootstrap_peers().await;

        let mut bus_rx = self.bus_subscriber.subscribe();
        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(60));
        let cancel = self.cancel_token.clone().unwrap_or_default();
        info!("P2P Service Active.");

        loop {
            tokio::select! {
                swarm_event = self.swarm.next() => {
                    if let Some(event) = swarm_event {
                        self.handle_swarm_event(event).await;
                    } else {
                        warn!("Swarm stream ended unexpectedly.");
                        break;
                    }
                }
                bus_event = bus_rx.recv() => {
                    match bus_event {
                        Ok(event) => self.handle_bus_event(event).await,
                        Err(e) => warn!("Bus subscription error: {:?}", e),
                    }
                }
                _ = cleanup_interval.tick() => {
                    self.rate_limiter.cleanup_inactive(Duration::from_secs(600));
                    self.connection_filter.cleanup_expired();
                    let ttl = self.session_ttl;
                    self.session_cache.retain(|_, state| state.created_at.elapsed() < ttl);
                    self.topology_request_timestamps.retain(|_, ts| ts.elapsed() < Duration::from_secs(600));
                }
                () = cancel.cancelled() => {
                    info!("P2P Service shutting down (cancellation token).");
                    break;
                }
            }
        }
    }

    async fn bootstrap_peers(&mut self) {
        if let Ok(peers) = self.peer_registry.load_peers().await {
            for node in peers {
                if let Ok(addr) = Multiaddr::from_str(&node.url) {
                    if let Err(e) = self.dial(addr) {
                        debug!(url = %node.url, error = %e, "Bootstrap dial failed (will retry via discovery)");
                    }
                }
            }
        }
    }

    async fn handle_bus_event(&mut self, event: NoxEvent) {
        match event {
            NoxEvent::RelayerRegistered {
                url,
                address,
                sphinx_key,
                stake,
                role,
                ingress_url,
                metadata_url,
            } => {
                info!(address = %address, url = %url, role = role, "New Peer Discovered");

                let mut node =
                    RelayerNode::new(address.clone(), sphinx_key, url.clone(), stake, role);
                node.ingress_url = ingress_url;
                node.metadata_url = metadata_url;
                if let Err(e) = self.peer_registry.save_peer(&node).await {
                    warn!(error = %e, "Failed to persist peer to registry");
                }

                if let Ok(addr) = url.parse::<Multiaddr>() {
                    if let Err(e) = self.dial(addr) {
                        debug!(url = %url, error = %e, "Dial to new peer failed (will retry via discovery)");
                    }
                } else {
                    warn!(url = %url, "Invalid Multiaddr in Registry");
                }
            }
            NoxEvent::SendPacket {
                next_hop_peer_id,
                packet_id,
                data,
            } => {
                let peer_id_opt = if let Ok(pid) = PeerId::from_str(&next_hop_peer_id) {
                    Some(pid)
                } else if let Ok(addr) = next_hop_peer_id.parse::<Multiaddr>() {
                    addr.iter()
                        .find_map(|p| match p {
                            libp2p::multiaddr::Protocol::P2p(pid) => Some(pid),
                            _ => None,
                        })
                        .or_else(|| self.resolve_peer_by_addr(&addr))
                } else {
                    None
                };

                if let Some(peer) = peer_id_opt {
                    let sphinx_packet = SphinxPacket {
                        id: packet_id.clone(),
                        data,
                    };
                    let message = SystemMessage::Packet(sphinx_packet);

                    let request_id = self
                        .swarm
                        .behaviour_mut()
                        .direct_message
                        .send_request(&peer, message);

                    debug!(
                        packet_id = %packet_id,
                        peer = %peer,
                        request_id = %request_id,
                        "Outbound Packet sent"
                    );
                } else {
                    warn!(next_hop = %next_hop_peer_id, "Could not resolve PeerID for next hop");
                }
            }
            _ => {}
        }
    }

    async fn handle_swarm_event(&mut self, event: libp2p::swarm::SwarmEvent<NoxBehaviourEvent>) {
        match event {
            libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                info!(address = %address, "Listening on");
                if let Some(tx) = self.listening_tx.take() {
                    let pid = *self.swarm.local_peer_id();
                    // Intentional: receiver may have dropped (oneshot, non-critical)
                    let _ = tx.send((pid, address));
                }
            }
            libp2p::swarm::SwarmEvent::IncomingConnection {
                send_back_addr,
                local_addr,
                ..
            } => {
                if !self.connection_filter.is_allowed(&send_back_addr) {
                    debug!(addr = %send_back_addr, "Rejecting connection from filtered IP");
                    return;
                }
                debug!(
                    from = %send_back_addr,
                    local = %local_addr,
                    "Incoming connection"
                );
            }
            libp2p::swarm::SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                let remote_addr = endpoint.get_remote_address().clone();
                debug!(peer = %peer_id, addr = %remote_addr, "Connection established");

                self.peer_addresses.insert(peer_id, remote_addr.clone());
                self.connection_filter.register_connection(&remote_addr);

                if let Err(e) = self.event_bus.publish(NoxEvent::PeerConnected {
                    peer_id: peer_id.to_string(),
                }) {
                    debug!(peer = %peer_id, error = %e, "Failed to publish PeerConnected event");
                }
                self.metrics
                    .peers_connected
                    .get_or_create(&vec![("type".to_string(), "established".to_string())])
                    .inc();
            }
            libp2p::swarm::SwarmEvent::ConnectionClosed {
                peer_id, endpoint, ..
            } => {
                let remote_addr = endpoint.get_remote_address();
                debug!(peer = %peer_id, "Connection closed");

                self.connection_filter.unregister_connection(remote_addr);
                self.peer_addresses.remove(&peer_id);
                self.rate_limiter.remove_peer(&peer_id);
                self.peer_health.remove(&peer_id);
                self.session_cache.remove(&peer_id);
                self.topology_request_timestamps.remove(&peer_id);
                self.remove_persisted_session(&peer_id);

                if let Err(e) = self.event_bus.publish(NoxEvent::PeerDisconnected {
                    peer_id: peer_id.to_string(),
                }) {
                    debug!(peer = %peer_id, error = %e, "Failed to publish PeerDisconnected event");
                }
                self.metrics
                    .peers_disconnected
                    .get_or_create(&vec![("type".to_string(), "established".to_string())])
                    .inc();
            }
            libp2p::swarm::SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                debug!(peer = ?peer_id, error = %error, "Failed to connect to peer");
            }
            libp2p::swarm::SwarmEvent::Behaviour(event) => {
                self.handle_behaviour_event(event).await;
            }
            _ => {}
        }
    }

    async fn handle_behaviour_event(&mut self, event: NoxBehaviourEvent) {
        match event {
            NoxBehaviourEvent::DirectMessage(libp2p::request_response::Event::Message {
                message:
                    libp2p::request_response::Message::Request {
                        request, channel, ..
                    },
                peer,
                ..
            }) => {
                match request {
                    SystemMessage::Packet(packet) => {
                        // Truncate untrusted packet IDs to prevent log flooding
                        let log_id = if packet.id.len() > 16 {
                            packet.id[..16].to_string()
                        } else {
                            packet.id.clone()
                        };
                        match self.rate_limiter.check(&peer) {
                            RateLimitResult::Allowed => {
                                debug!(packet_id = %log_id, peer = %peer, "Packet received");
                                if let Err(e) = self.event_bus.publish(NoxEvent::PacketReceived {
                                    packet_id: packet.id,
                                    size_bytes: packet.data.len(),
                                    data: packet.data,
                                }) {
                                    error!(
                                        packet_id = %log_id,
                                        peer = %peer,
                                        error = %e,
                                        "Failed to publish PacketReceived -- inbound Sphinx packet dropped"
                                    );
                                    self.metrics
                                        .event_bus_publish_errors_total
                                        .get_or_create(&vec![
                                            ("event".into(), "PacketReceived".into()),
                                            ("caller".into(), "p2p_inbound".into()),
                                        ])
                                        .inc();
                                }
                                self.metrics
                                    .packets_received
                                    .get_or_create(&vec![("type".to_string(), "p2p".to_string())])
                                    .inc();
                                self.metrics
                                    .p2p_rate_limit_total
                                    .get_or_create(&vec![(
                                        "result".to_string(),
                                        "allowed".to_string(),
                                    )])
                                    .inc();
                                if self
                                    .swarm
                                    .behaviour_mut()
                                    .direct_message
                                    .send_response(channel, SystemMessage::Ack)
                                    .is_err()
                                {
                                    debug!(peer = %peer, "Ack send_response failed -- peer may have disconnected");
                                }
                            }
                            RateLimitResult::Denied => {
                                self.rate_limited_count
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                self.metrics
                                    .p2p_rate_limit_total
                                    .get_or_create(&vec![(
                                        "result".to_string(),
                                        "denied".to_string(),
                                    )])
                                    .inc();
                                warn!(peer = %peer, "Rate limit exceeded, dropping packet");
                                if self.rate_limiter.should_disconnect(&peer) {
                                    self.metrics.p2p_rate_limit_disconnects_total.inc();
                                    if let Some(addr) = self.peer_addresses.get(&peer) {
                                        self.connection_filter.ban_ip(&addr);
                                    }
                                    if self.swarm.disconnect_peer_id(peer).is_err() {
                                        debug!(peer = %peer, "disconnect_peer_id failed -- peer may already be gone");
                                    }
                                }
                            }
                        }
                    }
                    SystemMessage::Handshake(hs) => {
                        info!(peer = %peer, version = hs.version, eth_address = ?hs.eth_address, "Received handshake");

                        let (accepted, reason) = self.verify_handshake(&hs, &peer);

                        if accepted {
                            let mut ticket = [0u8; 32];
                            rand::rngs::OsRng.fill_bytes(&mut ticket);

                            let session_state = SessionState {
                                ticket,
                                created_at: Instant::now(),
                                capabilities: hs.capabilities,
                                routing_key: hs.routing_key.clone(),
                            };

                            let registry_verified = hs.eth_address.is_some();
                            self.persist_session(
                                &peer,
                                &session_state,
                                hs.eth_address.clone(),
                                registry_verified,
                            );

                            self.session_cache.insert(peer, session_state);

                            debug!(peer = %peer, caps = ?hs.capabilities, "Handshake accepted, session ticket issued");
                            if self
                                .swarm
                                .behaviour_mut()
                                .direct_message
                                .send_response(
                                    channel,
                                    SystemMessage::HandshakeAck {
                                        accepted: true,
                                        reason: None,
                                        session_ticket: Some(ticket.to_vec()),
                                    },
                                )
                                .is_err()
                            {
                                debug!(peer = %peer, "HandshakeAck send_response failed -- peer disconnected");
                            }
                        } else {
                            warn!(peer = %peer, reason = ?reason, "Handshake rejected");
                            if self
                                .swarm
                                .behaviour_mut()
                                .direct_message
                                .send_response(
                                    channel,
                                    SystemMessage::HandshakeAck {
                                        accepted: false,
                                        reason,
                                        session_ticket: None,
                                    },
                                )
                                .is_err()
                            {
                                debug!(peer = %peer, "HandshakeAck reject send_response failed -- peer disconnected");
                            }
                        }
                    }
                    SystemMessage::SessionResume { ticket } => {
                        let accepted = if ticket.len() == 32 {
                            if let Some(state) = self.session_cache.get(&peer) {
                                // Constant-time ticket comparison
                                let tickets_match = state
                                    .ticket
                                    .iter()
                                    .zip(ticket.iter())
                                    .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                                    == 0;
                                let within_ttl = state.created_at.elapsed() < self.session_ttl;
                                tickets_match && within_ttl
                            } else {
                                false
                            }
                        } else {
                            false
                        };

                        if accepted {
                            info!(peer = %peer, "Session resumed via ticket");
                            if self
                                .swarm
                                .behaviour_mut()
                                .direct_message
                                .send_response(
                                    channel,
                                    SystemMessage::HandshakeAck {
                                        accepted: true,
                                        reason: None,
                                        session_ticket: None,
                                    },
                                )
                                .is_err()
                            {
                                debug!(peer = %peer, "Session resume ack send_response failed -- peer disconnected");
                            }
                        } else {
                            info!(peer = %peer, "Session resume rejected -- full handshake required");
                            self.session_cache.remove(&peer);
                            if self
                                .swarm
                                .behaviour_mut()
                                .direct_message
                                .send_response(
                                    channel,
                                    SystemMessage::HandshakeAck {
                                        accepted: false,
                                        reason: Some("Session expired or invalid".to_string()),
                                        session_ticket: None,
                                    },
                                )
                                .is_err()
                            {
                                debug!(peer = %peer, "Session resume reject send_response failed -- peer disconnected");
                            }
                        }
                    }
                    SystemMessage::HandshakeAck {
                        accepted,
                        reason,
                        session_ticket,
                    } => {
                        if accepted {
                            if session_ticket.is_some() {
                                info!(peer = %peer, "Handshake acknowledged with session ticket");
                            } else {
                                info!(peer = %peer, "Handshake acknowledged");
                            }
                        } else {
                            warn!(peer = %peer, reason = ?reason, "Handshake rejected");
                        }
                    }
                    SystemMessage::Ack => {}

                    SystemMessage::TopologyRequest => {
                        // Rate limit: 1 topology request per 10s per peer
                        let now = Instant::now();
                        let min_interval = Duration::from_secs(10);
                        let allowed = match self.topology_request_timestamps.get(&peer) {
                            Some(last_time) => now.duration_since(*last_time) >= min_interval,
                            None => true,
                        };

                        if allowed {
                            self.topology_request_timestamps.insert(peer, now);
                            let nodes = self.topology_manager.get_all_nodes();
                            let fingerprint = self.topology_manager.get_current_fingerprint();
                            let timestamp = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            let snapshot = nox_core::models::topology::TopologySnapshot {
                                nodes,
                                fingerprint: hex::encode(fingerprint),
                                timestamp,
                                block_number: 0,
                                pow_difficulty: 0,
                            };
                            debug!(peer = %peer, nodes = snapshot.nodes.len(), "Serving topology request");
                            if self
                                .swarm
                                .behaviour_mut()
                                .direct_message
                                .send_response(channel, SystemMessage::TopologyResponse(snapshot))
                                .is_err()
                            {
                                warn!(peer = %peer, "Failed to send topology response -- channel closed");
                            }
                        } else {
                            warn!(peer = %peer, "Topology request rate limited (max 1/10s)");
                            if self
                                .swarm
                                .behaviour_mut()
                                .direct_message
                                .send_response(channel, SystemMessage::Ack)
                                .is_err()
                            {
                                debug!(peer = %peer, "Rate-limited topology ack send_response failed -- peer disconnected");
                            }
                        }
                    }
                    SystemMessage::TopologyResponse(_) => {
                        debug!(peer = %peer, "Received unsolicited TopologyResponse, ignoring");
                        if self
                            .swarm
                            .behaviour_mut()
                            .direct_message
                            .send_response(channel, SystemMessage::Ack)
                            .is_err()
                        {
                            debug!(peer = %peer, "Unsolicited topology ack send_response failed -- peer disconnected");
                        }
                    }
                }
            }
            NoxBehaviourEvent::Ping(libp2p::ping::Event { peer, result, .. }) => {
                match result {
                    Ok(rtt) => {
                        let rtt_secs = rtt.as_secs_f64();
                        debug!(peer = %peer, rtt_ms = rtt.as_millis(), "Ping success");

                        let mut health = self.peer_health.entry(peer).or_default();
                        health.last_rtt = rtt;
                        health.last_ping = Instant::now();
                        health.ping_count += 1;

                        // rtt_secs intentionally computed for future metrics integration
                        let _ = rtt_secs;
                    }
                    Err(e) => {
                        error!(peer = %peer, error = %e, "Ping failure - disconnecting peer");
                        let _reason = match &e {
                            libp2p::ping::Failure::Timeout => "ping_timeout",
                            libp2p::ping::Failure::Unsupported => "ping_unsupported",
                            libp2p::ping::Failure::Other { .. } => "ping_other",
                        };

                        self.peer_health.remove(&peer);
                        if self.swarm.disconnect_peer_id(peer).is_err() {
                            debug!(peer = %peer, "disconnect_peer_id after ping failure -- peer already gone");
                        }
                    }
                }
            }

            _ => {}
        }
    }

    /// Checks version, identity signature (ecrecover), and `NoxRegistry` lookup.
    /// All local data -- zero network calls.
    fn verify_handshake(
        &self,
        hs: &nox_core::models::handshake::Handshake,
        peer_id: &PeerId,
    ) -> (bool, Option<String>) {
        if !hs.is_compatible() {
            return (
                false,
                Some(format!(
                    "Incompatible protocol version {} (supported: {}-{})",
                    hs.version,
                    nox_core::models::handshake::MIN_SUPPORTED_VERSION,
                    nox_core::models::handshake::PROTOCOL_VERSION,
                )),
            );
        }

        let addr = match &hs.eth_address {
            Some(a) if !a.is_empty() => a,
            _ => {
                return (
                    false,
                    Some("Missing eth_address (required in v5+)".to_string()),
                );
            }
        };

        let sig_hex = match &hs.identity_sig {
            Some(s) if !s.is_empty() => s,
            _ => {
                return (
                    false,
                    Some("Missing identity_sig (required in v5+)".to_string()),
                );
            }
        };

        let sig_bytes = match hex::decode(sig_hex.trim_start_matches("0x")) {
            Ok(b) if b.len() == 65 => b,
            Ok(b) => {
                return (
                    false,
                    Some(format!(
                        "Invalid identity_sig length: {} (expected 65 bytes)",
                        b.len()
                    )),
                );
            }
            Err(e) => {
                return (false, Some(format!("Invalid identity_sig hex: {e}")));
            }
        };

        let peer_id_bytes = peer_id.to_bytes();
        let message_hash = ethers::core::utils::keccak256(&peer_id_bytes);
        let signature = match ethers::core::types::Signature::try_from(sig_bytes.as_slice()) {
            Ok(s) => s,
            Err(e) => {
                return (false, Some(format!("Invalid secp256k1 signature: {e}")));
            }
        };

        let recovered_address = match signature.recover(message_hash) {
            Ok(a) => a,
            Err(e) => {
                return (false, Some(format!("ecrecover failed: {e}")));
            }
        };

        let claimed_address = match addr.parse::<ethers::core::types::Address>() {
            Ok(a) => a,
            Err(e) => {
                return (false, Some(format!("Invalid eth_address format: {e}")));
            }
        };

        if recovered_address != claimed_address {
            warn!(
                claimed = %addr,
                recovered = ?recovered_address,
                "Identity signature does not match claimed eth_address"
            );
            return (
                false,
                Some(format!(
                    "Identity verification failed: signature recovers to {recovered_address:?}, not {addr}"
                )),
            );
        }

        if let Some(registered_node) = self.topology_manager.lookup_by_address(addr) {
            if registered_node.sphinx_key.to_lowercase() != hs.routing_key.to_lowercase() {
                warn!(
                    eth_address = %addr,
                    handshake_key = %hs.routing_key,
                    onchain_key = %registered_node.sphinx_key,
                    "Handshake routing key does not match on-chain sphinx_key"
                );
                return (
                    false,
                    Some(format!(
                        "Routing key mismatch: handshake key does not match on-chain sphinx_key for {addr}",
                    )),
                );
            }
            debug!(
                eth_address = %addr,
                layer = registered_node.layer,
                role = registered_node.role,
                "Handshake verified: identity signature + NoxRegistry match"
            );
            (true, None)
        } else {
            warn!(
                eth_address = %addr,
                "Peer address not found in NoxRegistry topology"
            );
            (
                false,
                Some(format!("Address {addr} not registered in NoxRegistry")),
            )
        }
    }

    /// Fire-and-forget background write to sled (`session:<peer_id>` key).
    fn persist_session(
        &self,
        peer_id: &PeerId,
        state: &SessionState,
        eth_address: Option<String>,
        registry_verified: bool,
    ) {
        let persisted = PersistedSession {
            ticket_hex: hex::encode(state.ticket),
            created_at_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            capabilities: state.capabilities.bits(),
            routing_key: state.routing_key.clone(),
            eth_address,
            registry_verified,
        };

        let key = format!("session:{peer_id}");
        let storage = self.storage.clone();
        let peer_str = peer_id.to_string();
        tokio::spawn(async move {
            match serde_json::to_vec(&persisted) {
                Ok(bytes) => {
                    if let Err(e) = storage.put(key.as_bytes(), &bytes).await {
                        warn!(peer = %peer_str, error = %e, "Failed to persist session to Sled");
                    } else {
                        debug!(peer = %peer_str, "Session persisted to Sled");
                    }
                }
                Err(e) => {
                    warn!(peer = %peer_str, error = %e, "Failed to serialize session for persistence");
                }
            }
        });
    }

    fn remove_persisted_session(&self, peer_id: &PeerId) {
        let key = format!("session:{peer_id}");
        let storage = self.storage.clone();
        let peer_str = peer_id.to_string();
        tokio::spawn(async move {
            if let Err(e) = storage.delete(key.as_bytes()).await {
                debug!(peer = %peer_str, error = %e, "Failed to remove persisted session (may not exist)");
            }
        });
    }

    /// Restores sessions from sled, pruning any that exceed `session_ttl`.
    pub async fn restore_sessions(
        storage: &dyn IStorageRepository,
        session_cache: &DashMap<PeerId, SessionState>,
        session_ttl: Duration,
    ) {
        let items = match storage.scan(b"session:").await {
            Ok(items) => items,
            Err(e) => {
                warn!(error = %e, "Failed to scan persisted sessions from Sled");
                return;
            }
        };

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let ttl_secs = session_ttl.as_secs();

        let mut restored = 0usize;
        let mut expired = 0usize;

        for (key, val) in &items {
            let Ok(persisted) = serde_json::from_slice::<PersistedSession>(val) else {
                continue;
            };

            if now_unix.saturating_sub(persisted.created_at_unix) > ttl_secs {
                expired += 1;
                if let Err(e) = storage.delete(key).await {
                    debug!(error = %e, "Failed to prune expired session");
                }
                continue;
            }

            let Ok(ticket_bytes) = hex::decode(&persisted.ticket_hex) else {
                continue;
            };
            if ticket_bytes.len() != 32 {
                continue;
            }
            let mut ticket = [0u8; 32];
            ticket.copy_from_slice(&ticket_bytes);

            let key_str = String::from_utf8_lossy(key);
            let peer_id_str = key_str.strip_prefix("session:").unwrap_or(&key_str);
            let Ok(peer_id) = PeerId::from_str(peer_id_str) else {
                continue;
            };

            let capabilities = nox_core::models::handshake::Capabilities::from_bits_truncate(
                persisted.capabilities,
            );

            session_cache.insert(
                peer_id,
                SessionState {
                    ticket,
                    created_at: Instant::now(), // Approximate -- exact time lost
                    capabilities,
                    routing_key: persisted.routing_key,
                },
            );
            restored += 1;
        }

        info!(
            restored = restored,
            expired = expired,
            "Session restore from Sled complete"
        );
    }

    pub fn dial(&mut self, addr: Multiaddr) -> Result<(), InfrastructureError> {
        self.swarm
            .dial(addr)
            .map_err(|e| InfrastructureError::Network(format!("Dial failed: {e}")))
    }

    /// Reverse-lookup: matches a bare multiaddr (no `/p2p/` component) against known peers.
    fn resolve_peer_by_addr(&self, target: &Multiaddr) -> Option<PeerId> {
        let count = self.peer_addresses.len();
        if count == 0 {
            debug!(
                target_addr = %target,
                "resolve_peer_by_addr: peer_addresses map is empty"
            );
            return None;
        }
        for entry in self.peer_addresses.iter() {
            let stored_addr = entry.value();
            let stored_base: Multiaddr = stored_addr
                .iter()
                .filter(|p| !matches!(p, libp2p::multiaddr::Protocol::P2p(_)))
                .collect();
            if stored_base == *target {
                debug!(
                    target_addr = %target,
                    peer_id = %entry.key(),
                    "resolve_peer_by_addr: resolved via reverse lookup"
                );
                return Some(*entry.key());
            }
        }
        debug!(
            target_addr = %target,
            known_count = count,
            "resolve_peer_by_addr: no match found"
        );
        None
    }

    pub fn peer_health_count(&self) -> usize {
        self.peer_health.len()
    }

    pub fn peer_address_count(&self) -> usize {
        self.peer_addresses.len()
    }

    pub fn peer_health_handle(&self) -> Arc<DashMap<PeerId, PeerHealth>> {
        self.peer_health.clone()
    }

    pub fn peer_addresses_handle(&self) -> Arc<DashMap<PeerId, Multiaddr>> {
        self.peer_addresses.clone()
    }

    pub fn rate_limiter_peer_count(&self) -> usize {
        self.rate_limiter.peer_count()
    }
}

/// Load or generate a P2P Ed25519 identity key (hex-encoded seed on disk).
fn load_or_generate_p2p_key(identity_path: &str) -> Result<identity::Keypair, InfrastructureError> {
    let id_path = std::path::Path::new(identity_path);
    if id_path.exists() {
        let hex_str = std::fs::read_to_string(id_path).map_err(|e| {
            InfrastructureError::Network(format!(
                "Failed to read P2P identity from {}: {e}",
                id_path.display()
            ))
        })?;
        let mut bytes = hex::decode(hex_str.trim()).map_err(|e| {
            InfrastructureError::Network(format!(
                "Invalid hex in P2P identity file {}: {e}",
                id_path.display()
            ))
        })?;
        info!(path = %id_path.display(), "Loaded P2P identity from file");
        identity::Keypair::ed25519_from_bytes(&mut bytes).map_err(|e| {
            InfrastructureError::Network(format!(
                "Invalid Ed25519 key in {}: {e}",
                id_path.display()
            ))
        })
    } else {
        let keypair = identity::Keypair::generate_ed25519();
        if let Some(parent) = id_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(ed_kp) = keypair.clone().try_into_ed25519() {
            // ed25519_from_bytes() expects 32-byte seed, not full 64-byte keypair
            let hex_key = hex::encode(&ed_kp.to_bytes()[..32]);
            if let Err(e) = std::fs::write(id_path, &hex_key) {
                warn!(
                    path = %id_path.display(),
                    "Failed to save generated P2P identity: {e}. \
                     PeerID will change on next restart."
                );
            } else {
                info!(path = %id_path.display(), "Generated and saved new P2P identity");
            }
        }
        Ok(keypair)
    }
}

#[cfg(test)]
mod tests {
    use crate::infra::{event_bus::TokioEventBus, storage::SledRepository};

    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_p2p_service_initialization() {
        let dir = tempdir().unwrap();
        let db = Arc::new(SledRepository::new(dir.path()).unwrap());
        let bus = TokioEventBus::new(10);
        let pub_bus = Arc::new(bus.clone());
        let sub_bus = Arc::new(bus.clone());

        let config = {
            let mut c = NoxConfig::default();
            c.p2p_listen_addr = "127.0.0.1".to_string();
            c.p2p_port = 0; // Random port
            c
        };

        let metrics = crate::telemetry::metrics::MetricsService::new();
        let tm = Arc::new(crate::services::network_manager::TopologyManager::new(
            db.clone(),
            sub_bus.clone(),
            None,
        ));
        let service = P2PService::new(&config, pub_bus, sub_bus, db, metrics, tm).await;
        assert!(service.is_ok());
    }

    #[tokio::test]
    async fn test_bootstrap_logic() {
        let dir = tempdir().unwrap();
        let db = Arc::new(SledRepository::new(dir.path()).unwrap());

        let peer_node = RelayerNode::new(
            "0x123".into(),
            "key".into(),
            "/ip4/127.0.0.1/tcp/9999".into(),
            "100".into(),
            3, // Full
        );
        let bytes = serde_json::to_vec(&peer_node).unwrap();
        db.put(b"peer:0x123", &bytes).await.unwrap();

        let bus = TokioEventBus::new(10);
        let config = {
            let mut c = NoxConfig::default();
            c.p2p_listen_addr = "127.0.0.1".to_string();
            c.p2p_port = 0;
            c
        };

        let sub_bus: Arc<dyn IEventSubscriber> = Arc::new(bus.clone());
        let metrics = crate::telemetry::metrics::MetricsService::new();
        let tm = Arc::new(crate::services::network_manager::TopologyManager::new(
            db.clone(),
            sub_bus.clone(),
            None,
        ));
        let mut service = P2PService::new(&config, Arc::new(bus.clone()), sub_bus, db, metrics, tm)
            .await
            .unwrap();

        service.bootstrap_peers().await;
    }
}
