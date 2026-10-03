use crate::config::NoxConfig;
use crate::services::network_manager::TopologyManager;
use crate::telemetry::metrics::MetricsService;
use dashmap::DashMap;
use nox_core::events::NoxEvent;
use nox_core::models::payloads::{
    decode_padded_relayer_payload_limited, encode_payload, RelayerPayload,
};
use nox_core::models::topology::RelayerNode;
use nox_core::traits::{IEventPublisher, IEventSubscriber};
use nox_crypto::sphinx::{build_multi_hop_packet, PathHop};
use rand::seq::SliceRandom;
use rand_distr::{Distribution, Exp};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use x25519_dalek::PublicKey;

/// Largest exit payload inspected for a returning loop (one Sphinx body).
const MAX_LOOP_PAYLOAD_BYTES: u64 = 64 * 1024;

/// A loop cover packet this node sent to itself and is waiting for.
#[derive(Debug, Clone)]
struct PendingLoop {
    sent_at: Instant,
    first_hop: String,
    second_hop: String,
}

/// Tracks self-addressed loop cover packets, so a node on the path that drops
/// traffic shows up as loops that never return (Loopix loop cover).
pub struct LoopTracker {
    pending: DashMap<u64, PendingLoop>,
    timeout: Duration,
    metrics: MetricsService,
}

impl LoopTracker {
    #[must_use]
    pub fn new(timeout: Duration, metrics: MetricsService) -> Self {
        Self {
            pending: DashMap::new(),
            timeout,
            metrics,
        }
    }

    fn hop_labels(first_hop: &str, second_hop: &str) -> Vec<(String, String)> {
        vec![
            ("first_hop".to_string(), first_hop.to_string()),
            ("second_hop".to_string(), second_hop.to_string()),
        ]
    }

    fn outcome(&self, outcome: &str) {
        self.metrics
            .cover_loop_outcomes_total
            .get_or_create(&vec![("outcome".to_string(), outcome.to_string())])
            .inc();
    }

    pub fn record_sent(&self, id: u64, first_hop: &str, second_hop: &str) {
        self.pending.insert(
            id,
            PendingLoop {
                sent_at: Instant::now(),
                first_hop: first_hop.to_string(),
                second_hop: second_hop.to_string(),
            },
        );
        self.metrics
            .cover_loop_sent_total
            .get_or_create(&Self::hop_labels(first_hop, second_hop))
            .inc();
        self.outcome("sent");
    }

    /// Returns `true` if `id` was an outstanding loop of this node.
    #[must_use]
    pub fn record_returned(&self, id: u64) -> bool {
        let Some((_, pending)) = self.pending.remove(&id) else {
            return false;
        };
        self.metrics
            .cover_loop_returned_total
            .get_or_create(&Self::hop_labels(&pending.first_hop, &pending.second_hop))
            .inc();
        self.metrics
            .cover_loop_rtt_seconds
            .observe(pending.sent_at.elapsed().as_secs_f64());
        self.outcome("returned");
        true
    }

    /// Counts loops older than the timeout as lost. Returns how many expired.
    pub fn expire(&self) -> usize {
        let mut expired = Vec::new();
        self.pending.retain(|_, pending| {
            if pending.sent_at.elapsed() >= self.timeout {
                expired.push(pending.clone());
                false
            } else {
                true
            }
        });
        for pending in &expired {
            debug!(
                first_hop = %pending.first_hop,
                second_hop = %pending.second_hop,
                "Loop cover packet did not return"
            );
            self.metrics
                .cover_loop_lost_total
                .get_or_create(&Self::hop_labels(&pending.first_hop, &pending.second_hop))
                .inc();
            self.outcome("lost");
        }
        expired.len()
    }

    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.pending.len()
    }
}

/// Loopix cover traffic generator: loop (heartbeat) and drop (volume hiding) streams.
pub struct TrafficShapingService {
    config: NoxConfig,
    topology: Arc<TopologyManager>,
    bus: Arc<dyn IEventPublisher>,
    metrics: MetricsService,
    cancel_token: CancellationToken,
    loops: Arc<LoopTracker>,
    /// When set, loop packets are addressed back to this node and their return
    /// is tracked from the bus.
    loop_returns: Option<Arc<dyn IEventSubscriber>>,
}

impl TrafficShapingService {
    pub fn new(
        config: NoxConfig,
        topology: Arc<TopologyManager>,
        bus: Arc<dyn IEventPublisher>,
        metrics: MetricsService,
    ) -> Self {
        let loops = Arc::new(LoopTracker::new(
            Duration::from_secs(config.relayer.cover_loop_timeout_secs),
            metrics.clone(),
        ));
        Self {
            config,
            topology,
            bus,
            metrics,
            cancel_token: CancellationToken::new(),
            loops,
            loop_returns: None,
        }
    }

    /// Sends loop cover around the mixnet back to this node and counts which
    /// loops return (`nox_cover_loop_*`). Without it, loop cover ends at an
    /// exit as before.
    #[must_use]
    pub fn with_loop_returns(mut self, subscriber: Arc<dyn IEventSubscriber>) -> Self {
        self.loop_returns = Some(subscriber);
        self
    }

    #[must_use]
    pub fn loop_tracker(&self) -> Arc<LoopTracker> {
        self.loops.clone()
    }

    #[must_use]
    pub fn with_cancel_token(mut self, token: CancellationToken) -> Self {
        self.cancel_token = token;
        self
    }

    pub async fn run(&self) {
        let loop_rate = self.config.relayer.cover_traffic_rate;
        let drop_rate = self.config.relayer.drop_traffic_rate;

        info!(
            "Starting Traffic Shaping. Loop Rate: {:.2} pkts/s, Drop Rate: {:.2} pkts/s",
            loop_rate, drop_rate
        );

        let mut handles = vec![];

        if loop_rate > 0.0 {
            let s = self.clone();
            handles.push(tokio::spawn(async move {
                s.run_loop_stream(loop_rate).await;
            }));
        }

        if drop_rate > 0.0 {
            let s = self.clone();
            handles.push(tokio::spawn(async move {
                s.run_drop_stream(drop_rate).await;
            }));
        }

        if loop_rate > 0.0 && self.loop_returns.is_some() {
            let s = self.clone();
            handles.push(tokio::spawn(async move {
                s.run_loop_monitor().await;
            }));
        }

        if handles.is_empty() {
            info!("Traffic Shaping disabled (both rates 0.0).");
            return;
        }

        for h in handles {
            if let Err(e) = h.await {
                if e.is_panic() {
                    error!("Cover traffic task panicked: {}", e);
                } else {
                    warn!("Cover traffic task cancelled: {}", e);
                }
            }
        }
    }

    async fn run_loop_stream(&self, rate: f64) {
        let exp = match Exp::new(rate) {
            Ok(e) => e,
            Err(e) => {
                error!("Invalid loop rate: {}. Stream disabled.", e);
                return;
            }
        };

        let mut degraded = false;

        loop {
            let delay_secs = {
                let mut rng = rand::rngs::OsRng;
                exp.sample(&mut rng)
            };
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs_f64(delay_secs)) => {}
                () = self.cancel_token.cancelled() => {
                    info!("Loop cover traffic stream shutting down.");
                    return;
                }
            }

            match self.generate_loop_packet().await {
                Ok(()) => {
                    self.metrics
                        .cover_traffic_generated_total
                        .get_or_create(&vec![("type".into(), "loop".into())])
                        .inc();
                    if degraded {
                        info!("Loop cover traffic resumed: topology available");
                        degraded = false;
                        self.metrics
                            .cover_traffic_degraded
                            .get_or_create(&vec![("type".into(), "loop".into())])
                            .set(0);
                    }
                }
                Err(e) => {
                    self.metrics
                        .cover_traffic_errors_total
                        .get_or_create(&vec![
                            ("type".into(), "loop".into()),
                            ("reason".into(), "topology_insufficient".into()),
                        ])
                        .inc();
                    if !degraded {
                        warn!("Loop cover traffic degraded: {}", e);
                        degraded = true;
                        self.metrics
                            .cover_traffic_degraded
                            .get_or_create(&vec![("type".into(), "loop".into())])
                            .set(1);
                    }
                }
            }
        }
    }

    async fn run_drop_stream(&self, rate: f64) {
        let exp = match Exp::new(rate) {
            Ok(e) => e,
            Err(e) => {
                error!("Invalid drop rate: {}. Stream disabled.", e);
                return;
            }
        };

        let mut degraded = false;

        loop {
            let delay_secs = {
                let mut rng = rand::rngs::OsRng;
                exp.sample(&mut rng)
            };
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs_f64(delay_secs)) => {}
                () = self.cancel_token.cancelled() => {
                    info!("Drop cover traffic stream shutting down.");
                    return;
                }
            }

            match self.generate_drop_packet().await {
                Ok(()) => {
                    self.metrics
                        .cover_traffic_generated_total
                        .get_or_create(&vec![("type".into(), "drop".into())])
                        .inc();
                    if degraded {
                        info!("Drop cover traffic resumed: topology available");
                        degraded = false;
                        self.metrics
                            .cover_traffic_degraded
                            .get_or_create(&vec![("type".into(), "drop".into())])
                            .set(0);
                    }
                }
                Err(e) => {
                    self.metrics
                        .cover_traffic_errors_total
                        .get_or_create(&vec![
                            ("type".into(), "drop".into()),
                            ("reason".into(), "topology_insufficient".into()),
                        ])
                        .inc();
                    if !degraded {
                        warn!("Drop cover traffic degraded: {}", e);
                        degraded = true;
                        self.metrics
                            .cover_traffic_degraded
                            .get_or_create(&vec![("type".into(), "drop".into())])
                            .set(1);
                    }
                }
            }
        }
    }

    /// Watches exit payloads for this node's own heartbeats and expires loops
    /// that did not come back.
    async fn run_loop_monitor(&self) {
        let Some(subscriber) = self.loop_returns.clone() else {
            return;
        };
        let mut rx = subscriber.subscribe();
        let sweep_every = (self.loops.timeout / 4).max(Duration::from_secs(1));
        let mut sweep = tokio::time::interval(sweep_every);
        loop {
            tokio::select! {
                event = rx.recv() => match event {
                    Ok(NoxEvent::PayloadDecrypted { payload, .. }) => {
                        if let Ok(RelayerPayload::Heartbeat { id, .. }) =
                            decode_padded_relayer_payload_limited(&payload, MAX_LOOP_PAYLOAD_BYTES)
                        {
                            if self.loops.record_returned(id) {
                                debug!(id, "Loop cover packet returned");
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!("Loop monitor lagged by {} events; some returns go uncounted.", n);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        return;
                    }
                },
                _ = sweep.tick() => {
                    self.loops.expire();
                }
                () = self.cancel_token.cancelled() => {
                    info!("Loop cover monitor shutting down.");
                    return;
                }
            }
        }
    }

    /// Picks the two other hops of a loop that starts and ends at `me`: one
    /// node in each of the other two layers, preferring members with a live
    /// P2P link. `None` if the topology cannot form such a loop.
    fn loop_hops(&self, me: &RelayerNode) -> Option<(RelayerNode, RelayerNode)> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let window = self.config.network.topology_liveness_window_secs;
        let me_lower = me.address.to_lowercase();
        let candidates = |layer: u8, exclude: &str| -> Vec<RelayerNode> {
            let all: Vec<RelayerNode> = self
                .topology
                .get_nodes_in_layer(layer)
                .into_iter()
                .filter(|n| {
                    let address = n.address.to_lowercase();
                    address != me_lower && address != exclude
                })
                .collect();
            let live: Vec<RelayerNode> = all
                .iter()
                .filter(|n| self.topology.is_live(n, now, window))
                .cloned()
                .collect();
            if live.is_empty() {
                all
            } else {
                live
            }
        };
        let mut rng = rand::rngs::OsRng;
        let first = candidates((me.layer + 1) % 3, "")
            .choose(&mut rng)
            .cloned()?;
        let second = candidates((me.layer + 2) % 3, &first.address.to_lowercase())
            .choose(&mut rng)
            .cloned()?;
        Some((first, second))
    }

    async fn generate_loop_packet(&self) -> anyhow::Result<()> {
        if self.loop_returns.is_some() {
            if let Some(me) = self.topology.local_member() {
                if let Some((first, second)) = self.loop_hops(&me) {
                    return self.send_self_loop(&me, &first, &second);
                }
            }
        }
        let (hop1, packet) = self.build_path_and_packet(true).await?;

        let pid = uuid::Uuid::new_v4().to_string();

        self.bus.publish(NoxEvent::SendPacket {
            next_hop_peer_id: hop1.address.clone(),
            packet_id: pid,
            data: packet,
        })?;

        debug!("Sent Loop Cover Packet via {}", hop1.address);
        Ok(())
    }

    /// Loop cover me -> first -> second -> me, carrying a heartbeat whose id is
    /// tracked until it returns or times out.
    fn send_self_loop(
        &self,
        me: &RelayerNode,
        first: &RelayerNode,
        second: &RelayerNode,
    ) -> anyhow::Result<()> {
        let id: u64 = rand::Rng::gen(&mut rand::rngs::OsRng);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let payload = encode_payload(&RelayerPayload::Heartbeat { id, timestamp })
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let path = vec![
            PathHop {
                public_key: PublicKey::from(parse_hex_key(&first.sphinx_key)?),
                address: first.url.clone(),
            },
            PathHop {
                public_key: PublicKey::from(parse_hex_key(&second.sphinx_key)?),
                address: second.url.clone(),
            },
            PathHop {
                public_key: PublicKey::from(parse_hex_key(&me.sphinx_key)?),
                address: me.url.clone(),
            },
        ];
        let packet = build_multi_hop_packet(&path, &payload, self.config.min_pow_difficulty)?;
        self.loops.record_sent(
            id,
            &first.address.to_lowercase(),
            &second.address.to_lowercase(),
        );
        self.bus.publish(NoxEvent::SendPacket {
            next_hop_peer_id: first.url.clone(),
            packet_id: uuid::Uuid::new_v4().to_string(),
            data: packet,
        })?;
        debug!("Sent self-addressed loop cover via {}", first.address);
        Ok(())
    }

    async fn generate_drop_packet(&self) -> anyhow::Result<()> {
        let (hop1, packet) = self.build_path_and_packet(false).await?;

        let pid = uuid::Uuid::new_v4().to_string();

        self.bus.publish(NoxEvent::SendPacket {
            next_hop_peer_id: hop1.address.clone(),
            packet_id: pid,
            data: packet,
        })?;

        debug!("Sent Drop Cover Packet via {}", hop1.address);
        Ok(())
    }

    async fn build_path_and_packet(&self, is_loop: bool) -> anyhow::Result<(PathHop, Vec<u8>)> {
        let l0 = self.topology.get_nodes_in_layer(0);
        let l1 = self.topology.get_nodes_in_layer(1);
        let l2 = self.topology.get_nodes_in_layer(2);

        if l0.is_empty() || l1.is_empty() || l2.is_empty() {
            return Err(anyhow::anyhow!(
                "Insufficient topology (E:{}, M:{}, X:{})",
                l0.len(),
                l1.len(),
                l2.len()
            ));
        }

        let mut rng = rand::rngs::OsRng;

        let node1 = l0
            .choose(&mut rng)
            .ok_or_else(|| anyhow::anyhow!("No Entry (layer 0) nodes"))?;

        let l1_filtered: Vec<_> = l1
            .iter()
            .filter(|n| n.address.to_lowercase() != node1.address.to_lowercase())
            .collect();
        let node2 = l1_filtered
            .choose(&mut rng)
            .copied()
            .or_else(|| l1.choose(&mut rng))
            .ok_or_else(|| anyhow::anyhow!("No Mix (layer 1) nodes"))?;

        let l2_filtered: Vec<_> = l2
            .iter()
            .filter(|n| {
                let addr = n.address.to_lowercase();
                addr != node1.address.to_lowercase() && addr != node2.address.to_lowercase()
            })
            .collect();
        let node3 = l2_filtered
            .choose(&mut rng)
            .copied()
            .or_else(|| l2.choose(&mut rng))
            .ok_or_else(|| anyhow::anyhow!("No Exit (layer 2) nodes"))?;

        let hop1 = PathHop {
            public_key: PublicKey::from(parse_hex_key(&node1.sphinx_key)?),
            address: node1.url.clone(),
        };
        let hop2 = PathHop {
            public_key: PublicKey::from(parse_hex_key(&node2.sphinx_key)?),
            address: node2.url.clone(),
        };
        let hop3 = PathHop {
            public_key: PublicKey::from(parse_hex_key(&node3.sphinx_key)?),
            address: node3.url.clone(),
        };

        let inner_payload = if is_loop {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;

            nox_core::models::payloads::RelayerPayload::Heartbeat {
                id: rand::Rng::gen(&mut rng),
                timestamp: now,
            }
        } else {
            let mut padding = vec![0u8; 256];
            rand::Rng::fill(&mut rng, &mut padding[..]);
            nox_core::models::payloads::RelayerPayload::Dummy { padding }
        };

        let payload_bytes = encode_payload(&inner_payload).map_err(|e| anyhow::anyhow!("{e}"))?;

        let path = vec![hop1.clone(), hop2, hop3];
        let packet = build_multi_hop_packet(&path, &payload_bytes, self.config.min_pow_difficulty)?;

        Ok((hop1, packet))
    }
}

impl Clone for TrafficShapingService {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            topology: self.topology.clone(),
            bus: self.bus.clone(),
            metrics: self.metrics.clone(),
            cancel_token: self.cancel_token.clone(),
            loops: self.loops.clone(),
            loop_returns: self.loop_returns.clone(),
        }
    }
}

fn parse_hex_key(hex: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex)?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid Key Length"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::{event_bus::TokioEventBus, storage::SledRepository};
    use crate::services::network_manager::RegistryProfile;
    use libp2p::PeerId;
    use nox_crypto::sphinx::{into_result, ProcessResult, SphinxHeader};
    use std::collections::HashMap;
    use x25519_dalek::StaticSecret;

    fn peer(seed: u8) -> PeerId {
        let mut bytes = [seed; 32];
        let keypair = libp2p::identity::Keypair::ed25519_from_bytes(&mut bytes).expect("key");
        PeerId::from(keypair.public())
    }

    #[test]
    fn loop_tracker_counts_returns_once_and_expires_the_rest() {
        let metrics = MetricsService::new();
        let tracker = LoopTracker::new(Duration::ZERO, metrics.clone());
        tracker.record_sent(1, "0xa", "0xb");
        tracker.record_sent(2, "0xa", "0xc");
        assert!(tracker.record_returned(1));
        assert!(!tracker.record_returned(1), "a duplicate return is ignored");
        assert!(!tracker.record_returned(99), "foreign heartbeat is ignored");
        assert_eq!(tracker.expire(), 1);
        assert_eq!(tracker.outstanding(), 0);

        let labels = |first: &str, second: &str| {
            vec![
                ("first_hop".to_string(), first.to_string()),
                ("second_hop".to_string(), second.to_string()),
            ]
        };
        assert_eq!(
            metrics
                .cover_loop_returned_total
                .get_or_create(&labels("0xa", "0xb"))
                .get(),
            1
        );
        assert_eq!(
            metrics
                .cover_loop_lost_total
                .get_or_create(&labels("0xa", "0xc"))
                .get(),
            1
        );
    }

    /// A loop built by the node travels first -> second -> self and its
    /// heartbeat is recognised on return.
    #[tokio::test]
    async fn self_addressed_loop_returns_to_sender() {
        let directory = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(SledRepository::new(directory.path()).expect("storage"));
        let bus = TokioEventBus::new(64);
        let subscriber: Arc<dyn IEventSubscriber> = Arc::new(bus.clone());
        let publisher: Arc<dyn IEventPublisher> = Arc::new(bus.clone());
        let topology = Arc::new(TopologyManager::new(storage, subscriber.clone(), None));

        // Exit (layer 2) sends; role-1 nodes cover layers 0 and 1.
        let members = [
            ("0x00000000000000000000000000000000000000aa", 2_u8, 1_u8),
            ("0x0000000000000000000000000000000000000001", 1, 2),
            ("0x0000000000000000000000000000000000000004", 1, 3),
        ];
        let mut secrets: HashMap<String, StaticSecret> = HashMap::new();
        for (address, role, seed) in members {
            let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
            let url = format!("/ip4/10.0.0.{seed}/tcp/15000/p2p/{}", peer(seed));
            topology
                .apply_profile(RegistryProfile {
                    address: address.to_string(),
                    sphinx_key: hex::encode(PublicKey::from(&secret).as_bytes()),
                    url: url.clone(),
                    ingress_url: Some(String::new()),
                    metadata_url: None,
                    stake: "0".to_string(),
                    role,
                    frozen: false,
                })
                .await;
            secrets.insert(url, secret);
        }
        topology.set_local_peer_id(peer(1));
        let me = topology.local_member().expect("self is a member");

        let mut config = NoxConfig::default();
        config.min_pow_difficulty = 0;
        let service =
            TrafficShapingService::new(config, topology.clone(), publisher, MetricsService::new())
                .with_loop_returns(subscriber);

        let mut events = bus.subscribe();
        service.generate_loop_packet().await.expect("loop sent");
        assert_eq!(service.loop_tracker().outstanding(), 1);

        let (mut hop, mut data) = loop {
            if let NoxEvent::SendPacket {
                next_hop_peer_id,
                data,
                ..
            } = events.recv().await.expect("event")
            {
                break (next_hop_peer_id, data);
            }
        };
        assert_ne!(hop, me.url, "the first hop is another node");

        let mut hops = vec![hop.clone()];
        let payload = loop {
            let secret = secrets.get(&hop).expect("hop is a member");
            let (header, body) = SphinxHeader::from_bytes(&data).expect("packet");
            match into_result(header.process(secret, body.to_vec()).expect("process")) {
                ProcessResult::Forward {
                    next_hop,
                    next_packet,
                    processed_body,
                } => {
                    data = next_packet.to_bytes(&processed_body);
                    hop = next_hop;
                    hops.push(hop.clone());
                }
                ProcessResult::Exit { payload } => break payload,
            }
        };
        assert_eq!(hops.len(), 3);
        assert_eq!(hops[2], me.url, "the loop ends at the sender");

        match decode_padded_relayer_payload_limited(&payload, MAX_LOOP_PAYLOAD_BYTES) {
            Ok(RelayerPayload::Heartbeat { id, .. }) => {
                assert!(service.loop_tracker().record_returned(id));
            }
            other => panic!("expected heartbeat, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn loop_cover_without_registry_identity_falls_back_to_exit_path() {
        let directory = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(SledRepository::new(directory.path()).expect("storage"));
        let bus = TokioEventBus::new(64);
        let subscriber: Arc<dyn IEventSubscriber> = Arc::new(bus.clone());
        let publisher: Arc<dyn IEventPublisher> = Arc::new(bus.clone());
        let topology = Arc::new(TopologyManager::new(storage, subscriber.clone(), None));
        for (address, seed) in [
            ("0x00000000000000000000000000000000000000aa", 1_u8),
            ("0x00000000000000000000000000000000000000bb", 2),
        ] {
            let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
            topology
                .apply_profile(RegistryProfile {
                    address: address.to_string(),
                    sphinx_key: hex::encode(PublicKey::from(&secret).as_bytes()),
                    url: format!("/ip4/10.0.0.{seed}/tcp/15000/p2p/{}", peer(seed)),
                    ingress_url: Some(String::new()),
                    metadata_url: None,
                    stake: "0".to_string(),
                    role: 3,
                    frozen: false,
                })
                .await;
        }
        let mut config = NoxConfig::default();
        config.min_pow_difficulty = 0;
        let service =
            TrafficShapingService::new(config, topology, publisher, MetricsService::new())
                .with_loop_returns(subscriber);
        service.generate_loop_packet().await.expect("loop sent");
        assert_eq!(
            service.loop_tracker().outstanding(),
            0,
            "not tracked when this node is not a member"
        );
    }
}
