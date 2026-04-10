use crate::config::NoxConfig;
use crate::telemetry::metrics::MetricsService;
use async_channel::Sender;
use nox_core::{
    events::NoxEvent,
    traits::{IEventSubscriber, IReplayProtection},
};
use nox_crypto::sphinx::SphinxHeader;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

pub struct IngestStage {
    config: NoxConfig,
    bus_subscriber: Arc<dyn IEventSubscriber>,
    replay_db: Arc<dyn IReplayProtection>,
    worker_tx: Sender<(SphinxHeader, Vec<u8>, String)>, // Header, Body, PacketID
    metrics: MetricsService,
    cancel_token: Option<CancellationToken>,
}

impl IngestStage {
    pub fn new(
        config: NoxConfig,
        bus_subscriber: Arc<dyn IEventSubscriber>,
        replay_db: Arc<dyn IReplayProtection>,
        worker_tx: Sender<(SphinxHeader, Vec<u8>, String)>,
        metrics: MetricsService,
    ) -> Self {
        Self {
            config,
            bus_subscriber,
            replay_db,
            worker_tx,
            metrics,
            cancel_token: None,
        }
    }

    #[must_use]
    pub fn with_cancel_token(mut self, token: CancellationToken) -> Self {
        self.cancel_token = Some(token);
        self
    }

    pub async fn run(self) {
        info!("Relayer Ingest Stage active.");
        let mut rx = self.bus_subscriber.subscribe();

        loop {
            tokio::select! {
                event = rx.recv() => {
                    match event {
                        Ok(NoxEvent::PacketReceived {
                            packet_id, data, ..
                        }) => {
                            self.handle_packet(packet_id, data).await;
                        }
                        Ok(_) => {} // Ignore other events
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            warn!("Ingest bus lagged by {} events, continuing.", n);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            warn!("Event bus closed, Ingest Stage shutting down.");
                            break;
                        }
                    }
                }
                () = async {
                    match &self.cancel_token {
                        Some(token) => token.cancelled().await,
                        None => std::future::pending().await,
                    }
                } => {
                    info!("Ingest stage: graceful shutdown via cancellation token");
                    break;
                }
            }
        }
    }

    async fn handle_packet(&self, packet_id: String, data: Vec<u8>) {
        let (header, body) = match SphinxHeader::from_bytes(&data) {
            Ok(res) => res,
            Err(e) => {
                warn!("Invalid Sphinx packet structure for {}: {}.", packet_id, e);
                self.metrics
                    .ingest_dropped_total
                    .get_or_create(&vec![("reason".to_string(), "parse_error".to_string())])
                    .inc();
                return;
            }
        };

        let replay_tag = header.compute_replay_tag();
        match self
            .replay_db
            .check_and_tag(&replay_tag, self.config.relayer.replay_window)
            .await
        {
            Ok(true) => {
                warn!("Duplicate packet detected: {}. Dropping.", packet_id);
                self.metrics
                    .ingest_dropped_total
                    .get_or_create(&vec![("reason".to_string(), "replay".to_string())])
                    .inc();
                self.metrics
                    .replay_checks_total
                    .get_or_create(&vec![("result".to_string(), "duplicate".to_string())])
                    .inc();
                return;
            }
            Err(e) => {
                error!("Replay DB error: {:?}.", e);
                self.metrics
                    .ingest_dropped_total
                    .get_or_create(&vec![("reason".to_string(), "replay_error".to_string())])
                    .inc();
                return;
            }
            _ => {
                self.metrics
                    .replay_checks_total
                    .get_or_create(&vec![("result".to_string(), "new".to_string())])
                    .inc();
            }
        }

        // PoW is enforced at HTTP ingress, not here (Sphinx header transforms per hop).
        if let Err(e) = self
            .worker_tx
            .try_send((header, body.to_vec(), packet_id.clone()))
        {
            if e.is_full() {
                warn!(
                    "Relayer Overload: Dropping packet {} due to backpressure.",
                    packet_id
                );
                self.metrics
                    .ingest_dropped_total
                    .get_or_create(&vec![("reason".to_string(), "backpressure".to_string())])
                    .inc();
            } else {
                error!("Worker channel closed: {:?}", e);
            }
        } else {
            self.metrics
                .relayer_worker_queue_depth
                .set(self.worker_tx.len() as i64);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::event_bus::TokioEventBus;

    #[tokio::test]
    async fn test_ingest_stops_on_cancellation() {
        let bus = TokioEventBus::new(64);
        let subscriber: Arc<dyn IEventSubscriber> = Arc::new(bus);
        let replay_db: Arc<dyn IReplayProtection> = Arc::new(
            crate::infra::persistence::rotational_bloom::RotationalBloomFilter::new(
                1000,
                0.01,
                std::time::Duration::from_secs(60),
            ),
        );
        let (worker_tx, _worker_rx) = async_channel::bounded(16);
        let metrics = MetricsService::new();
        let token = CancellationToken::new();

        let ingest = IngestStage::new(
            NoxConfig::default(),
            subscriber,
            replay_db,
            worker_tx,
            metrics,
        )
        .with_cancel_token(token.clone());

        let handle = tokio::spawn(async move {
            ingest.run().await;
        });

        // Give ingest time to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Cancel -- should exit gracefully
        token.cancel();

        let result = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
        assert!(
            result.is_ok(),
            "IngestStage should exit within 2s after cancellation"
        );
    }
}
