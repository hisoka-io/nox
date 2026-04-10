use super::worker::MixMessage;
use crate::telemetry::metrics::MetricsService;
use futures::StreamExt;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_util::time::DelayQueue;
use tracing::{error, info};

pub struct MixStage {
    mix_rx: Receiver<MixMessage>,
    egress_tx: Sender<MixMessage>,
    metrics: MetricsService,
}

impl MixStage {
    #[must_use]
    pub fn new(
        mix_rx: Receiver<MixMessage>,
        egress_tx: Sender<MixMessage>,
        metrics: MetricsService,
    ) -> Self {
        Self {
            mix_rx,
            egress_tx,
            metrics,
        }
    }

    pub async fn run(mut self) {
        info!("Relayer Mix Stage active.");
        let mut delay_queue = DelayQueue::new();

        loop {
            tokio::select! {
                Some(msg) = self.mix_rx.recv() => {
                    let delay = msg.delay;
                    self.metrics.record_mix_delay(delay.as_secs_f64());
                    delay_queue.insert(msg, delay);
                    self.metrics.relayer_mix_queue_depth.set(delay_queue.len() as i64);
                }

                Some(expired) = delay_queue.next() => {
                    let msg = expired.into_inner();
                    self.metrics.relayer_mix_queue_depth.set(delay_queue.len() as i64);
                    if let Err(e) = self.egress_tx.send(msg).await {
                        error!("Egress channel closed: {:?}", e);
                        break;
                    }
                }

                else => {
                    if delay_queue.is_empty() {
                         info!("Mix Stage shutting down.");
                         break;
                    }
                }
            }
        }
    }
}
