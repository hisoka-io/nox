use std::collections::HashSet;
use std::sync::Arc;
use tracing::{info, warn};

use crate::telemetry::metrics::MetricsService;
use nox_core::{events::NoxEvent, traits::IEventSubscriber};

pub struct MetricsAdapter {
    metrics: MetricsService,
    subscriber: Arc<dyn IEventSubscriber>,
}

impl MetricsAdapter {
    pub fn new(metrics: MetricsService, subscriber: Arc<dyn IEventSubscriber>) -> Self {
        Self {
            metrics,
            subscriber,
        }
    }

    pub async fn run(&self) {
        info!("Metrics Adapter started. Monitoring Event Bus.");
        let mut rx = self.subscriber.subscribe();

        // libp2p fires PeerConnected for both inbound/outbound, deduplicate here.
        let mut known_peers: HashSet<String> = HashSet::new();

        loop {
            match rx.recv().await {
                Ok(event) => {
                    let event_type = match &event {
                        NoxEvent::PacketReceived { .. } => "packet_received",
                        NoxEvent::SendPacket { .. } => "send_packet",
                        NoxEvent::PayloadDecrypted { .. } => "payload_decrypted",
                        NoxEvent::PeerConnected { .. } => "peer_connected",
                        NoxEvent::PeerDisconnected { .. } => "peer_disconnected",
                        NoxEvent::PacketProcessed { .. } => "packet_processed",
                        NoxEvent::NodeStarted { .. } => "node_started",
                        NoxEvent::RelayerRegistered { .. } => "relayer_registered",
                        NoxEvent::RelayerRemoved { .. } => "relayer_removed",
                        NoxEvent::HopTimingsRecorded { .. } => "hop_timings_recorded",
                        NoxEvent::RelayerKeyRotated { .. } => "relayer_key_rotated",
                        NoxEvent::RelayerRoleUpdated { .. } => "relayer_role_updated",
                        NoxEvent::RelayerUrlUpdated { .. } => "relayer_url_updated",
                        NoxEvent::RelayerSlashed { .. } => "relayer_slashed",
                        NoxEvent::RegistryPaused { .. } => "registry_paused",
                        NoxEvent::RegistryUnpaused { .. } => "registry_unpaused",
                    };
                    self.metrics
                        .event_bus_events_total
                        .get_or_create(&vec![("type".to_string(), event_type.to_string())])
                        .inc();

                    match event {
                        NoxEvent::PacketReceived { .. } => {
                            self.metrics.packets_received.get_or_create(&vec![]).inc();
                        }
                        NoxEvent::SendPacket { .. } => {
                            self.metrics.packets_forwarded.get_or_create(&vec![]).inc();
                        }
                        NoxEvent::PeerConnected { peer_id } => {
                            self.metrics.peers_connected.get_or_create(&vec![]).inc();
                            if known_peers.insert(peer_id) {
                                self.metrics.peer_connected();
                            }
                        }
                        NoxEvent::PeerDisconnected { peer_id } => {
                            self.metrics.peers_disconnected.get_or_create(&vec![]).inc();
                            if known_peers.remove(&peer_id) {
                                self.metrics.peer_disconnected();
                            }
                        }
                        NoxEvent::PacketProcessed { duration_ms, .. } => {
                            self.metrics
                                .processing_duration
                                .get_or_create(&vec![])
                                .observe(duration_ms as f64 / 1000.0);
                        }
                        _ => {}
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    warn!("Metrics bus lagged by {} events, continuing.", n);
                    self.metrics.event_bus_lag_total.inc_by(n);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    warn!("Metrics Adapter: event bus closed, shutting down.");
                    break;
                }
            }
        }
    }
}
