//! Exit node E2E: wiring, invalid payloads, ResponsePacker stress, fragment chaos.

use nox_core::{
    Fragmenter, IEventPublisher, IEventSubscriber, NoxEvent, RelayerPayload, ServiceHandler,
    ServiceRequest,
};
use nox_crypto::{PathHop, Surb};
use nox_node::services::handlers::echo::EchoHandler;
use nox_node::services::response_packer::ResponsePacker;
use nox_node::TokioEventBus;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

fn generate_test_surbs(count: usize) -> Vec<Surb> {
    let mut rng = rand::thread_rng();
    let sk = X25519SecretKey::random_from_rng(&mut rng);
    let path = vec![PathHop {
        public_key: X25519PublicKey::from(&sk),
        address: "/ip4/127.0.0.1/tcp/9000".to_string(),
    }];

    (0..count)
        .map(|_| {
            let id: [u8; 16] = rand::random();
            let (surb, _) = Surb::new(&path, id, 0).expect("SURB creation failed");
            surb
        })
        .collect()
}

#[tokio::test]
async fn test_end_to_end_echo_wiring() {
    let bus = Arc::new(TokioEventBus::new(100));
    let publisher: Arc<dyn IEventPublisher> = bus.clone();
    let subscriber: Arc<dyn IEventSubscriber> = bus.clone();

    let packer = Arc::new(ResponsePacker::new());
    let echo_handler = Arc::new(EchoHandler::new(packer.clone(), publisher.clone()));

    let data = b"Hello Network".to_vec();
    let surbs = generate_test_surbs(3);

    let request = ServiceRequest::Echo { data: data.clone() };
    let inner = bincode::serialize(&request).expect("serialize");

    let payload = RelayerPayload::AnonymousRequest {
        inner,
        reply_surbs: surbs,
    };

    let mut rx = subscriber.subscribe();

    let echo_result = echo_handler.handle("packet-123", &payload).await;
    assert!(echo_result.is_ok());

    let event = tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("timeout waiting for event")
        .expect("channel closed");

    match event {
        NoxEvent::SendPacket {
            packet_id,
            data: p_data,
            ..
        } => {
            assert!(packet_id.starts_with("echo-"));
            assert!(!p_data.is_empty());
        }
        _ => panic!("Wrong event type"),
    }
}

#[test]
fn test_invalid_payload_deserialization() {
    let garbage: Vec<u8> = (0..100).map(|_| rand::random::<u8>()).collect();

    let result: Result<RelayerPayload, _> = bincode::deserialize(&garbage);
    assert!(result.is_err());
}

#[test]
fn test_partial_payload_handling() {
    let valid = RelayerPayload::Dummy {
        padding: vec![0u8; 100],
    };
    let serialized = bincode::serialize(&valid).expect("serialization");
    let truncated = &serialized[..serialized.len() / 2];

    let result: Result<RelayerPayload, _> = bincode::deserialize(truncated);
    assert!(result.is_err());
}

#[test]
fn test_response_packer_stress() {
    let packer = ResponsePacker::new();

    let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();

    let surbs_needed = packer.surbs_needed(data.len());
    let surbs = generate_test_surbs(surbs_needed + 5);

    let start = Instant::now();
    let result = packer.pack_response(12345, &data, surbs);
    let elapsed = start.elapsed();

    assert!(result.is_ok());
    assert!(elapsed < Duration::from_secs(1));
}

#[tokio::test]
async fn test_concurrent_packer_access() {
    let packer = Arc::new(ResponsePacker::new());
    let completed = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();

    for i in 0..20 {
        let packer = Arc::clone(&packer);
        let completed = Arc::clone(&completed);

        handles.push(tokio::spawn(async move {
            let data: Vec<u8> = (0..10_000).map(|j| ((i + j) % 256) as u8).collect();
            let surbs = generate_test_surbs(2);

            let result = packer.pack_response(i as u64, &data, surbs);
            if result.is_ok() {
                completed.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    for handle in handles {
        handle.await.expect("task should complete");
    }

    assert_eq!(completed.load(Ordering::SeqCst), 20);
}

#[test]
fn test_fragment_chaos_resilience() {
    use nox_core::{Reassembler, ReassemblerConfig};
    use rand::seq::SliceRandom;

    let fragmenter = Fragmenter::new();

    let original: Vec<u8> = (0..200_000).map(|i| (i % 256) as u8).collect();

    let fragments = fragmenter
        .fragment(999, &original, 30_000)
        .expect("fragmentation");

    let mut shuffled = fragments.clone();
    shuffled.shuffle(&mut rand::thread_rng());

    let mut reassembler = Reassembler::new(ReassemblerConfig::default());
    let mut result = None;

    for frag in shuffled {
        if let Ok(Some(data)) = reassembler.add_fragment(frag) {
            result = Some(data);
        }
    }

    let reassembled = result.expect("should reassemble");
    assert_eq!(reassembled, original);
}
