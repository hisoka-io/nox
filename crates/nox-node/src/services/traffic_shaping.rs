use crate::config::NoxConfig;
use crate::services::network_manager::TopologyManager;
use crate::telemetry::metrics::MetricsService;
use nox_core::events::NoxEvent;
use nox_core::models::payloads::encode_payload;
use nox_core::traits::IEventPublisher;
use nox_crypto::sphinx::{build_multi_hop_packet, PathHop};
use rand_distr::{Distribution, Exp};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use x25519_dalek::PublicKey;

/// Loopix cover traffic generator: loop (heartbeat) and drop (volume hiding) streams.
pub struct TrafficShapingService {
    config: NoxConfig,
    topology: Arc<TopologyManager>,
    bus: Arc<dyn IEventPublisher>,
    metrics: MetricsService,
    cancel_token: CancellationToken,
}

impl TrafficShapingService {
    pub fn new(
        config: NoxConfig,
        topology: Arc<TopologyManager>,
        bus: Arc<dyn IEventPublisher>,
        metrics: MetricsService,
    ) -> Self {
        Self {
            config,
            topology,
            bus,
            metrics,
            cancel_token: CancellationToken::new(),
        }
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

    async fn generate_loop_packet(&self) -> anyhow::Result<()> {
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

        use rand::seq::SliceRandom;
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
        }
    }
}

fn parse_hex_key(hex: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex)?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid Key Length"))
}
