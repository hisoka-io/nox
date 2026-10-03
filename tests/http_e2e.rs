//! HTTP E2E integration test: full ingress pipeline round-trip.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use nox_client::HttpPacketTransport;
use nox_core::events::NoxEvent;
use nox_core::traits::interfaces::{IEventPublisher, IEventSubscriber};
use nox_core::traits::transport::PacketTransport;
use nox_crypto::sphinx::packet::PACKET_SIZE;
use nox_node::ingress::http_server::{IngressServer, IngressState};
use nox_node::ingress::response_buffer::ResponseBuffer;
use nox_node::ingress::response_router::ResponseRouter;
use nox_node::telemetry::metrics::MetricsService;
use nox_node::TokioEventBus;
use tokio_util::sync::CancellationToken;

/// A deterministic 32-hex-character SURB ID.
fn surb_hex(seed: u8) -> String {
    hex::encode([seed; 16])
}

struct HttpTestHarness {
    entry_url: String,
    publisher: Arc<dyn IEventPublisher>,
    subscriber: Arc<dyn IEventSubscriber>,
    response_buffer: Arc<ResponseBuffer>,
    cancel_token: CancellationToken,
}

impl HttpTestHarness {
    async fn start() -> Self {
        let bus = TokioEventBus::new(1024);
        let publisher: Arc<dyn IEventPublisher> = Arc::new(bus.clone());
        let subscriber: Arc<dyn IEventSubscriber> = Arc::new(bus.clone());

        // 1s long-poll timeout (not 30s) so CI tests complete quickly
        let response_buffer = Arc::new(ResponseBuffer::new());
        let metrics = MetricsService::new();
        let ingress_state = Arc::new(IngressState {
            event_publisher: publisher.clone(),
            response_buffer: response_buffer.clone(),
            metrics: metrics.clone(),
            long_poll_timeout: Duration::from_secs(1),
            min_pow_difficulty: 0,
        });

        let router = IngressServer::router(ingress_state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind random port");
        let port = listener.local_addr().expect("no local addr").port();
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, router).await {
                eprintln!("Ingress server error: {e}");
            }
        });

        let cancel_token = CancellationToken::new();
        let response_router =
            ResponseRouter::new(subscriber.clone(), response_buffer.clone(), 300, metrics)
                .with_cancel_token(cancel_token.clone());
        tokio::spawn(async move {
            response_router.run().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        Self {
            entry_url: format!("http://127.0.0.1:{port}"),
            publisher,
            subscriber,
            response_buffer,
            cancel_token,
        }
    }
}

impl Drop for HttpTestHarness {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

/// Full round-trip: POST packet -> event bus -> simulate response -> GET response.
#[tokio::test]
async fn test_http_e2e_packet_injection_and_response_poll() {
    let harness = HttpTestHarness::start().await;
    let transport = HttpPacketTransport::new();

    let mut event_rx = harness.subscriber.subscribe();

    let packet = vec![0xAB_u8; PACKET_SIZE];
    transport
        .send_packet(&harness.entry_url, &packet)
        .await
        .expect("send_packet should succeed");

    let event = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
        .await
        .expect("timed out waiting for PacketReceived")
        .expect("bus closed");

    match &event {
        NoxEvent::PacketReceived {
            data, size_bytes, ..
        } => {
            assert_eq!(*size_bytes, PACKET_SIZE);
            assert_eq!(data.len(), PACKET_SIZE);
            assert_eq!(data[0], 0xAB);
        }
        other => panic!("Expected PacketReceived, got {other:?}"),
    }

    let test_request_id = &format!("reply-0-{}", surb_hex(42));
    let test_payload = vec![42, 43, 44, 45, 46];
    harness
        .publisher
        .publish(NoxEvent::PayloadDecrypted {
            packet_id: "0123456789abcdef0123456789abcdef".to_string(),
            payload: test_payload.clone(),
            reply_handle: Some([42; 16]),
        })
        .expect("publish PayloadDecrypted");

    tokio::time::sleep(Duration::from_millis(200)).await;

    let response = transport
        .recv_response(&harness.entry_url, test_request_id, Duration::from_secs(5))
        .await
        .expect("recv_response should succeed");

    assert_eq!(response, test_payload);
}

/// Batch response retrieval: a client claims exactly its own SURB responses.
#[tokio::test]
async fn test_http_e2e_batch_response_retrieval() {
    let harness = HttpTestHarness::start().await;
    let transport = HttpPacketTransport::new();

    for i in 0..4u8 {
        harness
            .publisher
            .publish(NoxEvent::PayloadDecrypted {
                packet_id: format!("{i:032x}"),
                payload: vec![0xA0 | i; 4],
                reply_handle: Some([i; 16]),
            })
            .expect("publish PayloadDecrypted");
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    let mine: Vec<String> = (0..3u8).map(surb_hex).collect();
    let responses = transport
        .recv_responses_batch(&harness.entry_url, &mine)
        .await
        .expect("batch claim should succeed");

    assert_eq!(responses.len(), 3);

    for i in 0..3u8 {
        let expected_id = format!("reply-0-{}", surb_hex(i));
        let found = responses
            .iter()
            .any(|(id, data)| id == &expected_id && *data == vec![0xA0 | i; 4]);
        assert!(found, "missing response for {expected_id}");
    }

    // The fourth response belongs to another client and stays buffered.
    assert_eq!(harness.response_buffer.len(), 1);
}

/// Only SURB replies are buffered.
#[tokio::test]
async fn test_http_e2e_only_surb_replies_buffered() {
    let harness = HttpTestHarness::start().await;
    let transport = HttpPacketTransport::new();

    let mut relayer_payload = nox_core::models::payloads::encode_payload(
        &nox_core::models::payloads::RelayerPayload::Heartbeat {
            id: 1,
            timestamp: 2,
        },
    )
    .expect("encode");
    relayer_payload.resize(1024, 0);

    harness
        .publisher
        .publish(NoxEvent::PayloadDecrypted {
            packet_id: format!("reply-9-{}", surb_hex(9)),
            payload: relayer_payload,
            reply_handle: Some([9; 16]),
        })
        .expect("publish");
    harness
        .publisher
        .publish(NoxEvent::PayloadDecrypted {
            packet_id: "http-00000000deadbeef".to_string(),
            payload: vec![0xA5; 64],
            reply_handle: None,
        })
        .expect("publish");
    // A local ID shaped like a reply ID carries no handle.
    harness
        .publisher
        .publish(NoxEvent::PayloadDecrypted {
            packet_id: format!("reply-9-{}", surb_hex(9)),
            payload: vec![0xA5; 64],
            reply_handle: None,
        })
        .expect("publish");
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(harness.response_buffer.is_empty());
    let responses = transport
        .recv_responses_batch(&harness.entry_url, &[surb_hex(9)])
        .await
        .expect("claim should succeed");
    assert!(responses.is_empty());
}

/// The legacy batch endpoint answers 410.
#[tokio::test]
async fn test_http_e2e_pending_endpoint_removed() {
    let harness = HttpTestHarness::start().await;
    harness
        .publisher
        .publish(NoxEvent::PayloadDecrypted {
            packet_id: format!("reply-1-{}", surb_hex(1)),
            payload: vec![0xA5; 8],
            reply_handle: Some([1; 16]),
        })
        .expect("publish");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = reqwest::Client::new()
        .get(format!("{}/api/v1/responses/pending", harness.entry_url))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status().as_u16(), 410);
    assert_eq!(harness.response_buffer.len(), 1);
}

/// Wrong-size packet is rejected with an error.
#[tokio::test]
async fn test_http_e2e_wrong_size_packet_rejected() {
    let harness = HttpTestHarness::start().await;
    let transport = HttpPacketTransport::new();

    let small_packet = vec![0u8; 100];
    let result = transport
        .send_packet(&harness.entry_url, &small_packet)
        .await;

    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("rejected") || err_msg.contains("400"),
        "unexpected error: {err_msg}"
    );
}

/// Health check endpoint responds 200.
#[tokio::test]
async fn test_http_e2e_health_check() {
    let harness = HttpTestHarness::start().await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/health", harness.entry_url))
        .send()
        .await
        .expect("health check request failed");

    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.text().await.expect("failed to read body");
    assert_eq!(body, "ok");
}

/// Server-side long-poll timeout: returns 204 after poll window (1s in test harness).
#[tokio::test]
async fn test_http_e2e_response_poll_timeout() {
    let harness = HttpTestHarness::start().await;

    let start = std::time::Instant::now();

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{}/api/v1/responses/nonexistent-id",
            harness.entry_url
        ))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("request should not fail");

    let elapsed = start.elapsed();

    assert_eq!(resp.status().as_u16(), 204);
    assert!(
        elapsed < Duration::from_secs(4),
        "long-poll took {elapsed:?}, expected <4s"
    );
}

/// Batch fetch returns empty when no responses are buffered.
#[tokio::test]
async fn test_http_e2e_batch_empty() {
    let harness = HttpTestHarness::start().await;
    let transport = HttpPacketTransport::new();

    let responses = transport
        .recv_responses_batch(&harness.entry_url, &[surb_hex(1)])
        .await
        .expect("batch fetch should succeed even when empty");

    assert!(responses.is_empty());
}
