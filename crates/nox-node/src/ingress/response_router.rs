//! `ResponseRouter` -- Routes SURB response payloads to the `ResponseBuffer`.
//!
//! Subscribes to the internal event bus and stores all `PayloadDecrypted`
//! events in the `ResponseBuffer`, keyed by `packet_id`. HTTP clients can
//! then poll `GET /api/v1/responses/:packet_id` to retrieve responses.
//!
//! Also runs periodic pruning of expired entries.

use crate::telemetry::metrics::MetricsService;
use nox_core::events::NoxEvent;
use nox_core::traits::interfaces::IEventSubscriber;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::response_buffer::ResponseBuffer;

/// Routes `PayloadDecrypted` events from the event bus to the `ResponseBuffer`.
pub struct ResponseRouter {
    subscriber: Arc<dyn IEventSubscriber>,
    response_buffer: Arc<ResponseBuffer>,
    metrics: MetricsService,
    prune_interval_secs: u64,
    cancel_token: Option<CancellationToken>,
}

impl ResponseRouter {
    pub fn new(
        subscriber: Arc<dyn IEventSubscriber>,
        response_buffer: Arc<ResponseBuffer>,
        prune_interval_secs: u64,
        metrics: MetricsService,
    ) -> Self {
        Self {
            subscriber,
            response_buffer,
            metrics,
            prune_interval_secs,
            cancel_token: None,
        }
    }

    /// Set a cancellation token for graceful shutdown.
    #[must_use]
    pub fn with_cancel_token(mut self, token: CancellationToken) -> Self {
        self.cancel_token = Some(token);
        self
    }

    /// Run the response routing loop.
    ///
    /// Subscribes to the event bus and stores `PayloadDecrypted` payloads
    /// in the `ResponseBuffer`. Runs until the event bus is closed or
    /// the cancellation token fires.
    pub async fn run(&self) {
        let mut rx = self.subscriber.subscribe();
        let mut prune_interval =
            tokio::time::interval(std::time::Duration::from_secs(self.prune_interval_secs));

        loop {
            tokio::select! {
                event = rx.recv() => {
                    match event {
                        Ok(NoxEvent::PayloadDecrypted { packet_id, payload }) => {
                            debug!(
                                packet_id = %packet_id,
                                bytes = payload.len(),
                                "ResponseRouter: buffering SURB response"
                            );
                            self.response_buffer.store_response(&packet_id, payload);
                            self.metrics.ingress_response_buffer_entries.inc();
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            warn!("ResponseRouter: bus lagged by {n} events");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            warn!("ResponseRouter: event bus closed");
                            break;
                        }
                        Ok(_) => {} // Ignore other events
                    }
                }
                _ = prune_interval.tick() => {
                    let pruned = self.response_buffer.prune_expired();
                    if pruned > 0 {
                        debug!("ResponseRouter: pruned {pruned} expired responses");
                        self.metrics.ingress_responses_pruned_total.inc_by(pruned as u64);
                        self.metrics.ingress_response_buffer_entries.set(
                            self.response_buffer.len() as i64,
                        );
                    }
                }
                () = async {
                    match &self.cancel_token {
                        Some(token) => token.cancelled().await,
                        None => std::future::pending().await,
                    }
                } => {
                    info!("ResponseRouter: graceful shutdown via cancellation token");
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
    use nox_core::traits::interfaces::IEventPublisher;

    #[tokio::test]
    async fn test_response_router_stores_payload() {
        let bus = TokioEventBus::new(64);
        let publisher: Arc<dyn IEventPublisher> = Arc::new(bus.clone());
        let subscriber: Arc<dyn IEventSubscriber> = Arc::new(bus);
        let buffer = Arc::new(ResponseBuffer::new());

        let metrics = MetricsService::new();
        let router = ResponseRouter::new(subscriber, buffer.clone(), 60, metrics);

        // Spawn router in background
        let handle = tokio::spawn(async move {
            router.run().await;
        });

        // Give router time to subscribe
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Publish a PayloadDecrypted event
        let _ = publisher.publish(NoxEvent::PayloadDecrypted {
            packet_id: "surb-resp-42".to_string(),
            payload: vec![1, 2, 3, 4],
        });

        // Give router time to process
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Verify response is in buffer
        let data = buffer.take_response("surb-resp-42");
        assert_eq!(data, Some(vec![1, 2, 3, 4]));

        handle.abort();
    }

    #[tokio::test]
    async fn test_response_router_ignores_other_events() {
        let bus = TokioEventBus::new(64);
        let publisher: Arc<dyn IEventPublisher> = Arc::new(bus.clone());
        let subscriber: Arc<dyn IEventSubscriber> = Arc::new(bus);
        let buffer = Arc::new(ResponseBuffer::new());

        let metrics = MetricsService::new();
        let router = ResponseRouter::new(subscriber, buffer.clone(), 60, metrics);

        let handle = tokio::spawn(async move {
            router.run().await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Publish a non-PayloadDecrypted event
        let _ = publisher.publish(NoxEvent::PacketReceived {
            packet_id: "pkt-1".to_string(),
            data: vec![0; 100],
            size_bytes: 100,
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Buffer should be empty
        assert!(buffer.is_empty());

        handle.abort();
    }

    #[tokio::test]
    async fn test_response_router_stops_on_cancellation() {
        let bus = TokioEventBus::new(64);
        let subscriber: Arc<dyn IEventSubscriber> = Arc::new(bus);
        let buffer = Arc::new(ResponseBuffer::new());
        let token = CancellationToken::new();

        let metrics = MetricsService::new();
        let router =
            ResponseRouter::new(subscriber, buffer, 60, metrics).with_cancel_token(token.clone());

        let handle = tokio::spawn(async move {
            router.run().await;
        });

        // Give router time to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Cancel -- router should exit gracefully
        token.cancel();

        // Wait for the task to complete (should not hang)
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
        assert!(
            result.is_ok(),
            "Router should exit within 2s after cancellation"
        );
    }
}
