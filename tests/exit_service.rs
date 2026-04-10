//! ExitService payload dispatch tests (simulation mode, no Ethereum handler).

use nox_core::{
    models::payloads::{encode_payload, RelayerPayload, ServiceRequest},
    IEventPublisher, IEventSubscriber, NoxEvent,
};
use nox_crypto::{PathHop, Surb};
use nox_node::{
    config::HttpConfig,
    services::{
        exit::ExitService,
        handlers::{echo::EchoHandler, traffic::TrafficHandler},
        response_packer::ResponsePacker,
    },
    telemetry::metrics::MetricsService,
    TokioEventBus,
};
use std::sync::Arc;
use std::time::Duration;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

fn make_bus() -> Arc<TokioEventBus> {
    Arc::new(TokioEventBus::new(256))
}

fn make_surbs(count: usize) -> Vec<Surb> {
    let mut rng = rand::thread_rng();
    let sk = X25519SecretKey::random_from_rng(&mut rng);
    let path = vec![PathHop {
        public_key: X25519PublicKey::from(&sk),
        address: "/ip4/127.0.0.1/tcp/9100".to_string(),
    }];
    (0..count)
        .map(|_| {
            let id: [u8; 16] = rand::random();
            let (surb, _) = Surb::new(&path, id, 0).expect("SURB creation failed");
            surb
        })
        .collect()
}

fn make_service() -> (ExitService, Arc<TokioEventBus>) {
    let bus = make_bus();
    let publisher: Arc<dyn IEventPublisher> = bus.clone();
    let subscriber: Arc<dyn IEventSubscriber> = bus.clone();

    let metrics = MetricsService::new();
    let packer = Arc::new(ResponsePacker::new());
    let echo = Arc::new(EchoHandler::new(packer.clone(), publisher.clone()));
    let traffic = Arc::new(TrafficHandler {
        metrics: metrics.clone(),
    });
    let http = Arc::new(nox_node::services::handlers::http::HttpHandler::new(
        HttpConfig::default(),
        packer.clone(),
        publisher.clone(),
        metrics.clone(),
    ));

    let svc =
        ExitService::simulation(subscriber, traffic, http, echo, metrics).with_publisher(publisher);

    (svc, bus)
}

fn anon_request(req: &ServiceRequest, surbs: Vec<Surb>) -> Vec<u8> {
    let inner = encode_payload(req).expect("encode inner");
    let payload = RelayerPayload::AnonymousRequest {
        inner,
        reply_surbs: surbs,
    };
    encode_payload(&payload).expect("encode outer")
}

/// Echo request through the full ExitService dispatch path produces `SendPacket`.
#[tokio::test]
async fn test_exit_service_echo_produces_send_packet() {
    let (svc, bus) = make_service();
    let mut rx = bus.subscribe();

    let cancel = tokio_util::sync::CancellationToken::new();
    let svc = svc.with_cancel_token(cancel.clone());
    tokio::spawn(async move { svc.run().await });
    tokio::time::sleep(Duration::from_millis(10)).await;

    let surbs = make_surbs(2);
    let payload_bytes = anon_request(
        &ServiceRequest::Echo {
            data: b"hello".to_vec(),
        },
        surbs,
    );

    bus.publish(NoxEvent::PayloadDecrypted {
        packet_id: "pkt-echo-1".to_string(),
        payload: payload_bytes,
    })
    .expect("publish");

    let event = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match rx.recv().await {
                Ok(NoxEvent::SendPacket { packet_id, .. }) if packet_id.starts_with("echo-") => {
                    return packet_id;
                }
                Ok(_) => continue,
                Err(_) => panic!("channel closed"),
            }
        }
    })
    .await
    .expect("timeout waiting for SendPacket");

    assert!(
        event.starts_with("echo-"),
        "expected echo- prefix, got: {event}"
    );
    cancel.cancel();
}

/// Dummy payload routes to traffic handler -- no `SendPacket` emitted.
#[tokio::test]
async fn test_exit_service_dummy_payload_no_send_packet() {
    let (svc, bus) = make_service();
    let mut rx = bus.subscribe();

    let cancel = tokio_util::sync::CancellationToken::new();
    let svc = svc.with_cancel_token(cancel.clone());
    tokio::spawn(async move { svc.run().await });
    tokio::time::sleep(Duration::from_millis(10)).await;

    let payload_bytes = encode_payload(&RelayerPayload::Dummy {
        padding: vec![0u8; 64],
    })
    .expect("encode");

    bus.publish(NoxEvent::PayloadDecrypted {
        packet_id: "pkt-dummy-1".to_string(),
        payload: payload_bytes,
    })
    .expect("publish");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut got_send_packet = false;
    while let Ok(event) = rx.try_recv() {
        if matches!(event, NoxEvent::SendPacket { .. }) {
            got_send_packet = true;
        }
    }
    assert!(
        !got_send_packet,
        "Dummy payload must not produce SendPacket"
    );
    cancel.cancel();
}

/// Heartbeat payload is handled without panicking or emitting `SendPacket`.
#[tokio::test]
async fn test_exit_service_heartbeat_no_send_packet() {
    let (svc, bus) = make_service();
    let mut rx = bus.subscribe();

    let cancel = tokio_util::sync::CancellationToken::new();
    let svc = svc.with_cancel_token(cancel.clone());
    tokio::spawn(async move { svc.run().await });
    tokio::time::sleep(Duration::from_millis(10)).await;

    let payload_bytes = encode_payload(&RelayerPayload::Heartbeat {
        id: 42,
        timestamp: 1_700_000_000,
    })
    .expect("encode");

    bus.publish(NoxEvent::PayloadDecrypted {
        packet_id: "pkt-hb-1".to_string(),
        payload: payload_bytes,
    })
    .expect("publish");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut got_send_packet = false;
    while let Ok(event) = rx.try_recv() {
        if matches!(event, NoxEvent::SendPacket { .. }) {
            got_send_packet = true;
        }
    }
    assert!(!got_send_packet, "Heartbeat must not produce SendPacket");
    cancel.cancel();
}

/// Garbage/undecodable payload is silently dropped -- no panic, no `SendPacket`.
#[tokio::test]
async fn test_exit_service_garbage_payload_ignored() {
    let (svc, bus) = make_service();
    let mut rx = bus.subscribe();

    let cancel = tokio_util::sync::CancellationToken::new();
    let svc = svc.with_cancel_token(cancel.clone());
    tokio::spawn(async move { svc.run().await });
    tokio::time::sleep(Duration::from_millis(10)).await;

    let garbage: Vec<u8> = (0..200).map(|_| rand::random::<u8>()).collect();

    bus.publish(NoxEvent::PayloadDecrypted {
        packet_id: "pkt-garbage-1".to_string(),
        payload: garbage,
    })
    .expect("publish");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut got_send_packet = false;
    while let Ok(event) = rx.try_recv() {
        if matches!(event, NoxEvent::SendPacket { .. }) {
            got_send_packet = true;
        }
    }
    assert!(
        !got_send_packet,
        "Garbage payload must not produce SendPacket"
    );
    cancel.cancel();
}

/// `ServiceResponse` (client-bound) is silently dropped at the exit node.
#[tokio::test]
async fn test_exit_service_service_response_ignored() {
    let (svc, bus) = make_service();
    let mut rx = bus.subscribe();

    let cancel = tokio_util::sync::CancellationToken::new();
    let svc = svc.with_cancel_token(cancel.clone());
    tokio::spawn(async move { svc.run().await });
    tokio::time::sleep(Duration::from_millis(10)).await;

    let resp = RelayerPayload::ServiceResponse {
        request_id: 99,
        fragment: nox_core::protocol::fragmentation::Fragment {
            message_id: 1,
            sequence: 0,
            total_fragments: 1,
            data: b"for client".to_vec(),
            fec: None,
        },
    };
    let payload_bytes = encode_payload(&resp).expect("encode");

    bus.publish(NoxEvent::PayloadDecrypted {
        packet_id: "pkt-resp-1".to_string(),
        payload: payload_bytes,
    })
    .expect("publish");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut got_send_packet = false;
    while let Ok(event) = rx.try_recv() {
        if matches!(event, NoxEvent::SendPacket { .. }) {
            got_send_packet = true;
        }
    }
    assert!(
        !got_send_packet,
        "ServiceResponse must not produce SendPacket"
    );
    cancel.cancel();
}

/// `NeedMoreSurbs` at the exit node is a routing anomaly -- silently dropped.
#[tokio::test]
async fn test_exit_service_need_more_surbs_ignored() {
    let (svc, bus) = make_service();
    let mut rx = bus.subscribe();

    let cancel = tokio_util::sync::CancellationToken::new();
    let svc = svc.with_cancel_token(cancel.clone());
    tokio::spawn(async move { svc.run().await });
    tokio::time::sleep(Duration::from_millis(10)).await;

    let payload_bytes = encode_payload(&RelayerPayload::NeedMoreSurbs {
        request_id: 7,
        fragments_remaining: 3,
    })
    .expect("encode");

    bus.publish(NoxEvent::PayloadDecrypted {
        packet_id: "pkt-nms-1".to_string(),
        payload: payload_bytes,
    })
    .expect("publish");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut got_send_packet = false;
    while let Ok(event) = rx.try_recv() {
        if matches!(event, NoxEvent::SendPacket { .. }) {
            got_send_packet = true;
        }
    }
    assert!(
        !got_send_packet,
        "NeedMoreSurbs must not produce SendPacket"
    );
    cancel.cancel();
}

/// Multiple Echo requests all produce `SendPacket` events.
#[tokio::test]
async fn test_exit_service_multiple_echo_requests() {
    let (svc, bus) = make_service();
    let mut rx = bus.subscribe();

    let cancel = tokio_util::sync::CancellationToken::new();
    let svc = svc.with_cancel_token(cancel.clone());
    tokio::spawn(async move { svc.run().await });
    tokio::time::sleep(Duration::from_millis(10)).await;

    const N: usize = 5;
    for i in 0..N {
        let surbs = make_surbs(1);
        let payload_bytes = anon_request(
            &ServiceRequest::Echo {
                data: format!("msg-{i}").into_bytes(),
            },
            surbs,
        );
        bus.publish(NoxEvent::PayloadDecrypted {
            packet_id: format!("pkt-multi-{i}"),
            payload: payload_bytes,
        })
        .expect("publish");
    }

    let mut count = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);

    while count < N {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(NoxEvent::SendPacket { packet_id, .. })) if packet_id.starts_with("echo-") => {
                count += 1;
            }
            Ok(Ok(_)) => {}
            Ok(Err(_)) | Err(_) => break,
        }
    }

    assert_eq!(count, N, "Expected {N} SendPacket events, got {count}");
    cancel.cancel();
}
