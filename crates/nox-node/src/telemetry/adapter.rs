use std::collections::HashSet;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::telemetry::metrics::MetricsService;
use nox_core::{events::NoxEvent, traits::IEventSubscriber};

pub struct MetricsAdapter {
    metrics: MetricsService,
    subscriber: Arc<dyn IEventSubscriber>,
    cancel: CancellationToken,
}

impl MetricsAdapter {
    pub fn new(metrics: MetricsService, subscriber: Arc<dyn IEventSubscriber>) -> Self {
        Self {
            metrics,
            subscriber,
            cancel: CancellationToken::new(),
        }
    }

    /// Stops the adapter when `token` is cancelled (node shutdown).
    #[must_use]
    pub fn with_cancel_token(mut self, token: CancellationToken) -> Self {
        self.cancel = token;
        self
    }

    pub async fn run(&self) {
        info!("Metrics Adapter started. Monitoring Event Bus.");
        let mut rx = self.subscriber.subscribe();

        // libp2p fires PeerConnected for both inbound/outbound, deduplicate here.
        let mut known_peers: HashSet<String> = HashSet::new();

        loop {
            let received = tokio::select! {
                received = rx.recv() => received,
                () = self.cancel.cancelled() => {
                    info!("Metrics Adapter stopped (shutdown).");
                    break;
                }
            };
            match received {
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
                        NoxEvent::RelayerProfileSynced { .. } => "relayer_profile_synced",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::event_bus::TokioEventBus;
    use std::time::Duration;

    #[tokio::test]
    async fn adapter_stops_on_cancellation() {
        let bus = TokioEventBus::new(16);
        let token = CancellationToken::new();
        let adapter = MetricsAdapter::new(MetricsService::new(), Arc::new(bus.clone()))
            .with_cancel_token(token.clone());
        let task = tokio::spawn(async move { adapter.run().await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!task.is_finished(), "adapter runs while the bus is open");
        token.cancel();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("adapter stops within 2s of cancellation")
            .expect("adapter task does not panic");
        drop(bus);
    }
}
