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
//! A format 2 reply (one that carries the authenticated format 2 flag at its
//! final hop and came over P2P) is filed under its delivery ID only, in a
//! separate bounded store. Nothing else creates delivery-keyed entries.
//!
//! Also runs periodic pruning of expired entries.

use crate::telemetry::metrics::MetricsService;
use nox_core::events::NoxEvent;
use nox_core::models::payloads::decode_padded_relayer_payload_limited;
use nox_core::traits::interfaces::IEventSubscriber;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::delivery_buffer::DeliveryStore;
use super::response_buffer::{ReplyStore, ResponseBuffer};
use nox_core::models::wire_id::{reply_wire_id, ReplyDelivery, ReplyHandle};

/// Whether a decrypted payload is a SURB reply that a client of this node can claim.
///
/// It must have arrived over P2P with a reply handle and must not decode as a
/// `RelayerPayload`, which is handled by the exit service instead.
#[must_use]
pub fn is_claimable_surb_reply(reply_handle: Option<&ReplyHandle>, payload: &[u8]) -> bool {
    reply_handle.is_some() && is_reply_ciphertext(payload)
}

/// Whether a decrypted payload is a ciphertext reply rather than a request
/// for the exit service.
fn is_reply_ciphertext(payload: &[u8]) -> bool {
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

    fn store_delivery(&self, delivery: ReplyDelivery, payload: Vec<u8>) {
        if !is_reply_ciphertext(&payload) {
            return;
        }
        match self
            .response_buffer
            .store_delivery(delivery.id, &delivery.source_peer, payload)
        {
            DeliveryStore::Stored { evicted } => self.count("delivery", None, evicted),
            DeliveryStore::Duplicate => self.count("delivery", Some("duplicate"), 0),
            DeliveryStore::SourceQuota => self.count("delivery", Some("source_quota"), 0),
            DeliveryStore::TooLarge => self.count("delivery", Some("too_large"), 0),
            DeliveryStore::Acked => self.count("delivery", Some("acked"), 0),
        }
    }

    /// Records a store attempt: `refused` is the reason when nothing was
    /// stored, `evicted` the number of older entries removed for room.
    fn count(&self, key: &str, refused: Option<&str>, evicted: usize) {
        match refused {
            None => {
                self.metrics
                    .response_store_total
                    .get_or_create(&vec![("key".into(), key.into())])
                    .inc();
            }
            Some(reason) => self.evicted(key, reason, 1),
        }
        self.evicted(key, "capacity", evicted);
        self.update_gauges();
    }

    fn evicted(&self, key: &str, reason: &str, n: usize) {
        if n > 0 {
            self.metrics
                .response_evicted_total
                .get_or_create(&vec![
                    ("key".into(), key.into()),
                    ("reason".into(), reason.into()),
                ])
                .inc_by(n as u64);
        }
    }

    fn update_gauges(&self) {
        let (handle_bytes, delivery_bytes) = self.response_buffer.bytes_by_key();
        self.metrics
            .ingress_response_buffer_entries
            .set(self.response_buffer.len() as i64);
        for (key, bytes) in [("handle", handle_bytes), ("delivery", delivery_bytes)] {
            self.metrics
                .response_buffer_bytes
                .get_or_create(&vec![("key".into(), key.into())])
                .set(i64::try_from(bytes).unwrap_or(i64::MAX));
        }
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
                        Ok(NoxEvent::PayloadDecrypted { delivery: Some(delivery), payload, .. }) => {
                            // A format 2 reply is filed under its delivery ID only,
                            // whatever its wire identifier said.
                            self.store_delivery(delivery, payload);
                        }
                        Ok(NoxEvent::PayloadDecrypted { packet_id, payload, reply_handle, delivery: None }) => {
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
                            match self.response_buffer.store_reply(&key, payload) {
                                ReplyStore::Stored { evicted } => self.count("handle", None, evicted),
                                ReplyStore::Duplicate => self.count("handle", Some("duplicate"), 0),
                                ReplyStore::Acked => self.count("handle", Some("acked"), 0),
                            }
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
                    let (handle, delivery) = self.response_buffer.prune_expired_by_key();
                    let pruned = handle + delivery;
                    if pruned > 0 {
                        debug!("ResponseRouter: pruned {pruned} expired responses");
                        self.metrics.ingress_responses_pruned_total.inc_by(pruned as u64);
                        self.evicted("handle", "ttl", handle);
                        self.evicted("delivery", "ttl", delivery);
                    }
                    self.update_gauges();
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
            delivery: None,
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
            delivery: None,
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
                delivery: None,
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
                delivery: None,
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
            delivery: None,
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

    async fn router_with_buffer() -> (
        Arc<dyn IEventPublisher>,
        Arc<ResponseBuffer>,
        MetricsService,
        tokio::task::JoinHandle<()>,
    ) {
        let bus = TokioEventBus::new(64);
        let publisher: Arc<dyn IEventPublisher> = Arc::new(bus.clone());
        let subscriber: Arc<dyn IEventSubscriber> = Arc::new(bus);
        let buffer = Arc::new(ResponseBuffer::new());
        let metrics = MetricsService::new();
        let router = ResponseRouter::new(subscriber, buffer.clone(), 60, metrics.clone());
        let handle = tokio::spawn(async move {
            router.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        (publisher, buffer, metrics, handle)
    }

    const DELIVERY: ReplyHandle = [0x44; 16];

    fn delivery() -> Option<ReplyDelivery> {
        Some(ReplyDelivery {
            id: DELIVERY,
            source_peer: "peer-a".into(),
        })
    }

    #[tokio::test]
    async fn test_v2_reply_is_filed_under_delivery_id_only() {
        let (publisher, buffer, metrics, handle) = router_with_buffer().await;
        // Even with a handle present, the delivery ID is the only key.
        let _ = publisher.publish(NoxEvent::PayloadDecrypted {
            packet_id: "local".into(),
            payload: vec![0xA5; 1024],
            reply_handle: Some(SURB),
            delivery: delivery(),
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert!(buffer.claim_by_surb_ids(&[SURB]).is_empty());
        let claimed = buffer.claim_by_surb_ids(&[DELIVERY]);
        assert_eq!(
            claimed,
            vec![(
                format!("reply-0-{}", hex::encode(DELIVERY)),
                vec![0xA5; 1024]
            )]
        );
        let mut text = String::new();
        prometheus_client::encoding::text::encode(&mut text, &metrics.get_registry().lock())
            .expect("encode");
        assert!(
            text.contains("nox_response_store_total{key=\"delivery\"} 1"),
            "{text}"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn test_v2_flagged_relayer_payload_is_not_stored() {
        let (publisher, buffer, _, handle) = router_with_buffer().await;
        let _ = publisher.publish(NoxEvent::PayloadDecrypted {
            packet_id: "local".into(),
            payload: relayer_payload(),
            reply_handle: None,
            delivery: delivery(),
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(buffer.is_empty());
        handle.abort();
    }
}
