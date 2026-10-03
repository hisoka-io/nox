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

use super::response_buffer::ResponseBuffer;
use nox_core::models::wire_id::{reply_wire_id, ReplyHandle};

/// Whether a decrypted payload is a SURB reply that a client of this node can claim.
///
/// It must have arrived over P2P with a reply handle and must not decode as a
/// `RelayerPayload`, which is handled by the exit service instead.
#[must_use]
pub fn is_claimable_surb_reply(reply_handle: Option<&ReplyHandle>, payload: &[u8]) -> bool {
    if reply_handle.is_none() {
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
                        Ok(NoxEvent::PayloadDecrypted { packet_id, payload, reply_handle }) => {
                            // Replies are filed as `reply-0-{surb id}`, the ID clients
                            // see when they claim them.
                            let key = if is_claimable_surb_reply(reply_handle.as_ref(), &payload) {
                                reply_handle.as_ref().map(reply_wire_id)
                            } else if self.buffer_all_payloads {
                                Some(packet_id)
                            } else {
                                None
                            };
                            let Some(key) = key else {
                                continue;
                            };
                            debug!("ResponseRouter: buffering SURB response");
                            self.response_buffer.store_response(&key, payload);
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
        let packet_id = format!("reply-0-{SURB_HEX}");
        let _ = publisher.publish(NoxEvent::PayloadDecrypted {
            packet_id: "0123456789abcdef0123456789abcdef".to_string(),
            payload: vec![0xA5; 64],
            reply_handle: Some(SURB),
        });

        // Give router time to process
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Verify response is in buffer
        let data = buffer.take_response(&packet_id);
        assert_eq!(data, Some(vec![0xA5; 64]));

        handle.abort();
    }

    const SURB_HEX: &str = "00112233445566778899aabbccddeeff";
    const SURB: ReplyHandle = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

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
        assert!(!is_claimable_surb_reply(Some(&SURB), &payload));
        assert!(!is_claimable_surb_reply(None, &payload));
    }

    #[test]
    fn test_reply_needs_a_handle() {
        let ciphertext = vec![0xA5; 1024];
        assert!(is_claimable_surb_reply(Some(&SURB), &ciphertext));
        assert!(!is_claimable_surb_reply(None, &ciphertext));
    }

    #[tokio::test]
    async fn test_reply_is_filed_under_its_handle_not_its_local_id() {
        let bus = TokioEventBus::new(64);
        let publisher: Arc<dyn IEventPublisher> = Arc::new(bus.clone());
        let subscriber: Arc<dyn IEventSubscriber> = Arc::new(bus);
        let buffer = Arc::new(ResponseBuffer::new());
        let router = ResponseRouter::new(subscriber, buffer.clone(), 60, MetricsService::new());
        let handle = tokio::spawn(async move {
            router.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // A local ID that looks like a reply ID must not matter.
        let _ = publisher.publish(NoxEvent::PayloadDecrypted {
            packet_id: "rpc-9-ffeeddccbbaa99887766554433221100".to_string(),
            payload: vec![0xA5; 1024],
            reply_handle: Some(SURB),
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let claimed = buffer.claim_by_surb_ids(&[SURB]);
        assert_eq!(
            claimed,
            vec![(format!("reply-0-{SURB_HEX}"), vec![0xA5; 1024])]
        );
        assert!(buffer.is_empty());
        handle.abort();
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

        // Exit-bound payloads, with or without a handle, are not replies.
        for reply_handle in [None, Some(SURB)] {
            let _ = publisher.publish(NoxEvent::PayloadDecrypted {
                packet_id: "http-00000000deadbeef".to_string(),
                payload: relayer_payload(),
                reply_handle,
            });
        }
        // Without a handle nothing is stored, whatever the local ID looks like.
        for packet_id in [
            "http-00000000cafebabe".to_string(),
            format!("reply-1-{SURB_HEX}"),
        ] {
            let _ = publisher.publish(NoxEvent::PayloadDecrypted {
                packet_id,
                payload: vec![0xA5; 1024],
                reply_handle: None,
            });
        }
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
            reply_handle: None,
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
            reply_handle: None,
            prev_peer: None,
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
