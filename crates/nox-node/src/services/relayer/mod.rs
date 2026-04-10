pub mod egress;
pub mod ingest;
pub mod mix_loop;
pub mod worker;

use crate::config::NoxConfig;
use nox_core::traits::{IEventPublisher, IEventSubscriber, IMixStrategy, IReplayProtection};
use std::sync::Arc;
use thiserror::Error;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;

#[derive(Debug, Error)]
pub enum RelayerError {
    #[error("Failed to load routing key: {0}")]
    RoutingKeyError(String),
}

use self::{
    egress::EgressStage,
    ingest::IngestStage,
    mix_loop::MixStage,
    worker::{MixMessage, WorkerStage},
};

pub struct RelayerService {
    config: NoxConfig,
    bus_subscriber: Arc<dyn IEventSubscriber>,
    event_bus: Arc<dyn IEventPublisher>,
    replay_db: Arc<dyn IReplayProtection>,
    mix_strategy: Arc<dyn IMixStrategy>,
    metrics: crate::telemetry::metrics::MetricsService,
    cancel_token: Option<CancellationToken>,
}

impl RelayerService {
    pub fn new(
        config: NoxConfig,
        bus_subscriber: Arc<dyn IEventSubscriber>,
        event_bus: Arc<dyn IEventPublisher>,
        replay_db: Arc<dyn IReplayProtection>,
        mix_strategy: Arc<dyn IMixStrategy>,
        metrics: crate::telemetry::metrics::MetricsService,
    ) -> Self {
        Self {
            config,
            bus_subscriber,
            event_bus,
            replay_db,
            mix_strategy,
            metrics,
            cancel_token: None,
        }
    }

    #[must_use]
    pub fn with_cancel_token(mut self, token: CancellationToken) -> Self {
        self.cancel_token = Some(token);
        self
    }

    pub async fn run(self) -> Result<Vec<JoinHandle<()>>, RelayerError> {
        info!("Initializing Relayer Pipeline...");

        let (worker_tx, worker_rx) = async_channel::bounded(self.config.relayer.queue_size);
        let (mix_tx, mix_rx) =
            tokio::sync::mpsc::channel::<MixMessage>(self.config.relayer.queue_size);
        let (egress_tx, egress_rx) =
            tokio::sync::mpsc::channel::<MixMessage>(self.config.relayer.queue_size);

        let mut handles = Vec::new();

        let mut ingest = IngestStage::new(
            self.config.clone(),
            self.bus_subscriber.clone(),
            self.replay_db.clone(),
            worker_tx,
            self.metrics.clone(),
        );
        if let Some(token) = &self.cancel_token {
            ingest = ingest.with_cancel_token(token.clone());
        }
        handles.push(tokio::spawn(ingest.run()));

        let node_sk = Arc::new(
            self.config
                .get_routing_key()
                .map_err(|e| RelayerError::RoutingKeyError(e.to_string()))?,
        );

        for _ in 0..self.config.relayer.worker_count {
            let worker = WorkerStage::new(
                worker_rx.clone(),
                mix_tx.clone(),
                Arc::clone(&node_sk),
                self.mix_strategy.clone(),
                self.metrics.clone(),
            );
            handles.push(tokio::spawn(worker.run()));
        }

        let mix = MixStage::new(mix_rx, egress_tx, self.metrics.clone());
        handles.push(tokio::spawn(mix.run()));

        let egress = EgressStage::new(egress_rx, self.event_bus.clone(), self.metrics.clone());
        handles.push(tokio::spawn(egress.run()));

        info!(
            "Relayer Pipeline fully operational with {} workers.",
            self.config.relayer.worker_count
        );
        Ok(handles)
    }
}
