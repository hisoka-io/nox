use super::worker::{MixMessage, MixMessageKind};
use crate::telemetry::metrics::MetricsService;
use nox_core::{events::NoxEvent, traits::IEventPublisher};
use std::sync::Arc;
use tokio::sync::mpsc::Receiver;
use tracing::{error, info, warn};

pub struct EgressStage {
    egress_rx: Receiver<MixMessage>,
    event_bus: Arc<dyn IEventPublisher>,
    metrics: MetricsService,
}

impl EgressStage {
    pub fn new(
        egress_rx: Receiver<MixMessage>,
        event_bus: Arc<dyn IEventPublisher>,
        metrics: MetricsService,
    ) -> Self {
        Self {
            egress_rx,
            event_bus,
            metrics,
        }
    }

    pub async fn run(mut self) {
        info!("Relayer Egress Stage active.");

        while let Some(msg) = self.egress_rx.recv().await {
            let duration = msg.original_processing_start.elapsed().as_secs_f64();
            self.metrics
                .processing_duration
                .get_or_create(&vec![("stage".to_string(), "total".to_string())])
                .observe(duration);

            match msg.kind {
                MixMessageKind::Forward { next_hop, packet } => {
                    info!(
                        "Forwarding packet {} to next hop: {}.",
                        msg.packet_id, next_hop
                    );
                    self.metrics
                        .packets_forwarded
                        .get_or_create(&vec![("type".to_string(), "mix".to_string())])
                        .inc();
                    self.metrics
                        .egress_routed_total
                        .get_or_create(&vec![("type".to_string(), "forward".to_string())])
                        .inc();

                    if let Err(e) = self.event_bus.publish(NoxEvent::SendPacket {
                        next_hop_peer_id: next_hop,
                        packet_id: msg.packet_id.clone(),
                        data: packet,
                    }) {
                        error!(
                            packet_id = %msg.packet_id,
                            error = %e,
                            "Failed to publish SendPacket for forward -- packet dropped"
                        );
                        self.metrics
                            .event_bus_publish_errors_total
                            .get_or_create(&vec![
                                ("event".into(), "SendPacket".into()),
                                ("caller".into(), "egress_forward".into()),
                            ])
                            .inc();
                    }
                }
                MixMessageKind::Exit { payload } => {
                    info!("Packet {} reached exit destination.", msg.packet_id);
                    self.metrics
                        .egress_routed_total
                        .get_or_create(&vec![("type".to_string(), "exit".to_string())])
                        .inc();
                    if let Err(e) = self.event_bus.publish(NoxEvent::PayloadDecrypted {
                        packet_id: msg.packet_id.clone(),
                        payload,
                    }) {
                        error!(
                            packet_id = %msg.packet_id,
                            error = %e,
                            "Failed to publish PayloadDecrypted -- exit payload dropped"
                        );
                        self.metrics
                            .event_bus_publish_errors_total
                            .get_or_create(&vec![
                                ("event".into(), "PayloadDecrypted".into()),
                                ("caller".into(), "egress_exit".into()),
                            ])
                            .inc();
                    }
                }
            }

            #[cfg(feature = "hop-metrics")]
            if let Some(timings) = &msg.hop_timings {
                if let Err(e) = self.event_bus.publish(NoxEvent::HopTimingsRecorded {
                    packet_id: msg.packet_id.clone(),
                    ecdh_ns: timings.ecdh_ns,
                    key_derive_ns: timings.key_derive_ns,
                    mac_verify_ns: timings.mac_verify_ns,
                    routing_decrypt_ns: timings.routing_decrypt_ns,
                    body_decrypt_ns: timings.body_decrypt_ns,
                    blinding_ns: timings.blinding_ns,
                    total_sphinx_ns: timings.total_sphinx_ns,
                }) {
                    warn!(error = %e, "Failed to publish HopTimingsRecorded event");
                }
            }

            let duration_ms = (duration * 1000.0) as u64;
            if let Err(e) = self.event_bus.publish(NoxEvent::PacketProcessed {
                packet_id: msg.packet_id,
                duration_ms,
            }) {
                warn!(error = %e, "Failed to publish PacketProcessed tracing event");
                self.metrics
                    .event_bus_publish_errors_total
                    .get_or_create(&vec![
                        ("event".into(), "PacketProcessed".into()),
                        ("caller".into(), "egress_trace".into()),
                    ])
                    .inc();
            }
        }
    }
}
