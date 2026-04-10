use crate::telemetry::metrics::MetricsService;
use async_trait::async_trait;
use nox_core::models::payloads::RelayerPayload;
use nox_core::traits::service::{ServiceError, ServiceHandler};
use tracing::info;

pub struct TrafficHandler {
    pub metrics: MetricsService,
}

#[async_trait]
impl ServiceHandler for TrafficHandler {
    fn name(&self) -> &'static str {
        "traffic"
    }

    async fn handle(&self, _packet_id: &str, payload: &RelayerPayload) -> Result<(), ServiceError> {
        match payload {
            RelayerPayload::Dummy { padding } => {
                info!("Received Dummy payload of size {}", padding.len());
                self.metrics
                    .dummy_packets_dropped
                    .get_or_create(&vec![("type".to_string(), "dummy".to_string())])
                    .inc();
                Ok(())
            }
            RelayerPayload::Heartbeat { id, timestamp } => {
                info!("Received Heartbeat id: {} timestamp: {}", id, timestamp);
                // self.metrics.heartbeats_received.inc(); // If we had such a metric
                Ok(())
            }
            _ => Ok(()),
        }
    }
}
