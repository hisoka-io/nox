//! `ResponseRouter` -- Routes SURB response payloads to the `ResponseBuffer`.
//!
//! Subscribes to the internal event bus and stores the `PayloadDecrypted`
//! events that are SURB replies addressed to a client of this node, keyed by
//! `packet_id`. Clients then claim them by SURB ID (`/api/v1/responses/claim`,
//! WebSocket or SSE).
//!
//! Other `PayloadDecrypted` events are handled by the exit service and are
//! not stored here.
//!
//! Also runs periodic pruning of expired entries.

use crate::telemetry::metrics::MetricsService;
use nox_core::events::NoxEvent;
use nox_core::models::payloads::decode_padded_relayer_payload_limited;
use nox_core::traits::interfaces::IEventSubscriber;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::response_buffer::{surb_id_from_packet_id, ResponseBuffer};

/// Whether a decrypted payload is a SURB reply that a client of this node can claim.
///
/// It must carry a SURB ID in its `packet_id` and must not decode as a
/// `RelayerPayload`, which is handled by the exit service instead.
#[must_use]
pub fn is_claimable_surb_reply(packet_id: &str, payload: &[u8]) -> bool {
    if surb_id_from_packet_id(packet_id).is_none() {
        return false;
    }
    let limit = u64::try_from(payload.len()).unwrap_or(u64::MAX);
    decode_padded_relayer_payload_limited(payload, limit).is_err()
}

/// Routes `PayloadDecrypted` events from the event bus to the `ResponseBuffer`.
pub struct ResponseRouter {
    subscriber: Arc<dyn IEventSubscriber>,
    response_buffer: Arc<ResponseBuffer>,
    metrics: MetricsService,
    prune_interval_secs: u64,
    cancel_token: Option<CancellationToken>,
    buffer_all_payloads: bool,
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
            buffer_all_payloads: false,
        }
    }

    /// Benchmark harnesses only: buffer every decrypted payload so delivery
    /// latency can be measured by polling `packet_id`. Never enable this on a
    /// node that serves clients.
    #[must_use]
    pub fn with_buffer_all_payloads(mut self, enabled: bool) -> Self {
        self.buffer_all_payloads = enabled;
        self
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
                            if !self.buffer_all_payloads
                                && !is_claimable_surb_reply(&packet_id, &payload)
                            {
                                continue;
                            }
                            debug!(
                                packet_id = %packet_id,
                                bytes = payload.len(),
                                "ResponseRouter: buffering SURB response"
                            );
                            self.response_buffer.store_response(&packet_id, payload);
                            self.metrics
                                .ingress_response_buffer_entries
                                .set(self.response_buffer.len() as i64);
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
        let packet_id = format!("reply-42-{SURB_HEX}");
        let _ = publisher.publish(NoxEvent::PayloadDecrypted {
            packet_id: packet_id.clone(),
            payload: vec![0xA5; 64],
        });

        // Give router time to process
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Verify response is in buffer
        let data = buffer.take_response(&packet_id);
        assert_eq!(data, Some(vec![0xA5; 64]));

        handle.abort();
    }

    const SURB_HEX: &str = "00112233445566778899aabbccddeeff";

    fn relayer_payload() -> Vec<u8> {
        let mut bytes = nox_core::models::payloads::encode_payload(
            &nox_core::models::payloads::RelayerPayload::Heartbeat {
                id: 7,
                timestamp: 1,
            },
        )
        .expect("encode");
        bytes.resize(1024, 0);
        bytes
    }

    #[test]
    fn test_relayer_payloads_are_not_claimable() {
        let payload = relayer_payload();
        assert!(!is_claimable_surb_reply(
            &format!("reply-1-{SURB_HEX}"),
            &payload
        ));
        assert!(!is_claimable_surb_reply("http-00000000deadbeef", &payload));
    }

    #[test]
    fn test_reply_needs_surb_id_in_packet_id() {
        let ciphertext = vec![0xA5; 1024];
        assert!(is_claimable_surb_reply(
            &format!("rpc-1-{SURB_HEX}"),
            &ciphertext
        ));
        assert!(!is_claimable_surb_reply(
            "http-00000000deadbeef",
            &ciphertext
        ));
        assert!(!is_claimable_surb_reply("surb-resp-42", &ciphertext));
    }

    #[tokio::test]
    async fn test_response_router_buffers_only_surb_replies() {
        let bus = TokioEventBus::new(64);
        let publisher: Arc<dyn IEventPublisher> = Arc::new(bus.clone());
        let subscriber: Arc<dyn IEventSubscriber> = Arc::new(bus);
        let buffer = Arc::new(ResponseBuffer::new());
        let router = ResponseRouter::new(subscriber, buffer.clone(), 60, MetricsService::new());
        let handle = tokio::spawn(async move {
            router.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        for packet_id in [
            "http-00000000deadbeef".to_string(),
            format!("reply-1-{SURB_HEX}"),
        ] {
            let _ = publisher.publish(NoxEvent::PayloadDecrypted {
                packet_id,
                payload: relayer_payload(),
            });
        }
        let _ = publisher.publish(NoxEvent::PayloadDecrypted {
            packet_id: "http-00000000cafebabe".to_string(),
            payload: vec![0xA5; 1024],
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert!(buffer.is_empty());
        handle.abort();
    }

    #[tokio::test]
    async fn test_benchmark_router_buffers_everything() {
        let bus = TokioEventBus::new(64);
        let publisher: Arc<dyn IEventPublisher> = Arc::new(bus.clone());
        let subscriber: Arc<dyn IEventSubscriber> = Arc::new(bus);
        let buffer = Arc::new(ResponseBuffer::new());
        let router = ResponseRouter::new(subscriber, buffer.clone(), 60, MetricsService::new())
            .with_buffer_all_payloads(true);
        let handle = tokio::spawn(async move {
            router.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let _ = publisher.publish(NoxEvent::PayloadDecrypted {
            packet_id: "http-00000000deadbeef".to_string(),
            payload: relayer_payload(),
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert!(buffer.take_response("http-00000000deadbeef").is_some());
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
