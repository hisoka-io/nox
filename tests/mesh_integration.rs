//! Multi-node mesh integration: Sphinx packet routing through simulated event bus mesh.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use nox_core::events::NoxEvent;
use nox_core::traits::interfaces::{
    IEventPublisher, IEventSubscriber, IMixStrategy, IReplayProtection,
};
use nox_crypto::{build_multi_hop_packet, PathHop};
use nox_node::services::relayer::RelayerService;
use nox_node::telemetry::metrics::MetricsService;
use nox_node::{NoxConfig, TokioEventBus};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::broadcast;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

struct TestNode {
    #[allow(dead_code)]
    id: usize,
    pk: X25519PublicKey,
    address: String,
    bus: Arc<TokioEventBus>,
    _storage_dir: TempDir,
}

struct ZeroDelayMix;
impl IMixStrategy for ZeroDelayMix {
    fn get_delay(&self) -> Duration {
        Duration::from_millis(0)
    }
}

async fn spawn_node(id: usize) -> TestNode {
    let dir = TempDir::new().expect("tempdir");
    let storage = Arc::new(nox_node::SledRepository::new(dir.path()).expect("sled"));
    let bus = Arc::new(TokioEventBus::new(256));

    let mut rng = rand::thread_rng();
    let sk = X25519SecretKey::random_from_rng(&mut rng);
    let pk = X25519PublicKey::from(&sk);
    let address = format!("/ip4/127.0.0.1/tcp/{}", 10000 + id);

    let mut config = NoxConfig::default();
    config.routing_private_key = hex::encode(sk.to_bytes());
    config.relayer.worker_count = 1;
    config.relayer.queue_size = 64;
    config.min_pow_difficulty = 0; // no PoW for tests

    let metrics = MetricsService::new();
    let subscriber: Arc<dyn IEventSubscriber> = bus.clone();
    let publisher: Arc<dyn IEventPublisher> = bus.clone();
    let replay: Arc<dyn IReplayProtection> = storage.clone();
    let mix: Arc<dyn IMixStrategy> = Arc::new(ZeroDelayMix);

    let relayer = RelayerService::new(config, subscriber, publisher, replay, mix, metrics);

    tokio::spawn(async move {
        let _ = relayer.run().await;
    });

    tokio::time::sleep(Duration::from_millis(20)).await;

    TestNode {
        id,
        pk,
        address,
        bus,
        _storage_dir: dir,
    }
}

fn wire_forwarding(nodes: &[TestNode]) -> Vec<tokio::task::JoinHandle<()>> {
    let address_to_bus: Arc<HashMap<String, Arc<TokioEventBus>>> = Arc::new(
        nodes
            .iter()
            .map(|n| (n.address.clone(), n.bus.clone()))
            .collect(),
    );

    nodes
        .iter()
        .map(|node| {
            let sub: Arc<dyn IEventSubscriber> = node.bus.clone();
            let mut rx = sub.subscribe();
            let routing = address_to_bus.clone();

            tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(NoxEvent::SendPacket {
                            next_hop_peer_id,
                            data,
                            packet_id,
                        }) => {
                            if let Some(target_bus) = routing.get(&next_hop_peer_id) {
                                let pub_target: Arc<dyn IEventPublisher> = target_bus.clone();
                                let size = data.len();
                                let _ = pub_target.publish(NoxEvent::PacketReceived {
                                    packet_id,
                                    data,
                                    size_bytes: size,
                                });
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            eprintln!("forwarder lagged by {n}");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                        _ => {}
                    }
                }
            })
        })
        .collect()
}

/// Sphinx body is zero-padded to full capacity; callers compare only the prefix.
async fn collect_exit_payloads(
    bus: &Arc<TokioEventBus>,
    expected: usize,
    timeout: Duration,
) -> Vec<Vec<u8>> {
    let sub: Arc<dyn IEventSubscriber> = bus.clone();
    let mut rx = sub.subscribe();
    let mut results = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Ok(NoxEvent::PayloadDecrypted { payload, .. })) => {
                results.push(payload);
                if results.len() >= expected {
                    break;
                }
            }
            Ok(Ok(_)) | Ok(Err(broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(broadcast::error::RecvError::Closed)) | Err(_) => break,
        }
    }

    results
}

fn payload_matches(body: &[u8], expected: &[u8]) -> bool {
    body.len() >= expected.len() && body[..expected.len()] == *expected
}

/// 3-hop packet delivery: entry -> mix -> exit.
#[tokio::test]
async fn test_3_hop_packet_delivery() {
    let nodes: Vec<TestNode> = futures::future::join_all((0..3).map(spawn_node)).await;

    let _forwarders = wire_forwarding(&nodes);

    let payload = b"Hello 3-hop mesh".to_vec();
    let path: Vec<PathHop> = nodes
        .iter()
        .map(|n| PathHop {
            public_key: n.pk,
            address: n.address.clone(),
        })
        .collect();

    let exit_bus = nodes[2].bus.clone();
    let collector =
        tokio::spawn(
            async move { collect_exit_payloads(&exit_bus, 1, Duration::from_secs(3)).await },
        );

    let packet = build_multi_hop_packet(&path, &payload, 0).expect("build packet");
    let size = packet.len();
    let publisher: Arc<dyn IEventPublisher> = nodes[0].bus.clone();
    publisher
        .publish(NoxEvent::PacketReceived {
            packet_id: "test-3hop-1".to_string(),
            data: packet,
            size_bytes: size,
        })
        .expect("inject packet");

    let results = collector.await.expect("collector");
    assert_eq!(results.len(), 1);
    assert!(payload_matches(&results[0], &payload));
}

/// Multiple concurrent packets: all delivered, no cross-contamination.
#[tokio::test]
async fn test_concurrent_packets_no_cross_contamination() {
    let nodes: Vec<TestNode> = futures::future::join_all((0..3).map(spawn_node)).await;

    let _forwarders = wire_forwarding(&nodes);

    let path: Vec<PathHop> = nodes
        .iter()
        .map(|n| PathHop {
            public_key: n.pk,
            address: n.address.clone(),
        })
        .collect();

    let n_packets = 5usize;
    let exit_bus = nodes[2].bus.clone();
    let collector = tokio::spawn(async move {
        collect_exit_payloads(&exit_bus, n_packets, Duration::from_secs(5)).await
    });

    let publisher: Arc<dyn IEventPublisher> = nodes[0].bus.clone();

    for i in 0..n_packets {
        let payload = format!("packet-{i}").into_bytes();
        let packet = build_multi_hop_packet(&path, &payload, 0).expect("build");
        let size = packet.len();
        publisher
            .publish(NoxEvent::PacketReceived {
                packet_id: format!("concurrent-{i}"),
                data: packet,
                size_bytes: size,
            })
            .expect("inject");
    }

    let results = collector.await.expect("collector");
    assert_eq!(results.len(), n_packets);

    let expected: Vec<Vec<u8>> = (0..n_packets)
        .map(|i| format!("packet-{i}").into_bytes())
        .collect();
    for exp in &expected {
        assert!(
            results.iter().any(|r| payload_matches(r, exp)),
            "payload {:?} missing from results",
            String::from_utf8_lossy(exp)
        );
    }
}

/// 2-hop path (direct entry -> exit).
#[tokio::test]
async fn test_2_hop_path_delivery() {
    let nodes: Vec<TestNode> = futures::future::join_all((0..2).map(spawn_node)).await;

    let _forwarders = wire_forwarding(&nodes);

    let payload = b"Direct 2-hop".to_vec();
    let path: Vec<PathHop> = nodes
        .iter()
        .map(|n| PathHop {
            public_key: n.pk,
            address: n.address.clone(),
        })
        .collect();

    let exit_bus = nodes[1].bus.clone();
    let collector =
        tokio::spawn(
            async move { collect_exit_payloads(&exit_bus, 1, Duration::from_secs(3)).await },
        );

    let packet = build_multi_hop_packet(&path, &payload, 0).expect("build");
    let size = packet.len();
    let publisher: Arc<dyn IEventPublisher> = nodes[0].bus.clone();
    publisher
        .publish(NoxEvent::PacketReceived {
            packet_id: "test-2hop".to_string(),
            data: packet,
            size_bytes: size,
        })
        .expect("inject");

    let results = collector.await.expect("collector");
    assert_eq!(results.len(), 1);
    assert!(payload_matches(&results[0], &payload));
}

/// 1-hop path (single node, immediate exit).
#[tokio::test]
async fn test_1_hop_single_node_exit() {
    let nodes: Vec<TestNode> = futures::future::join_all((0..1).map(spawn_node)).await;

    let _forwarders = wire_forwarding(&nodes);

    let payload = b"Single-hop exit".to_vec();
    let path: Vec<PathHop> = vec![PathHop {
        public_key: nodes[0].pk,
        address: nodes[0].address.clone(),
    }];

    let exit_bus = nodes[0].bus.clone();
    let collector =
        tokio::spawn(
            async move { collect_exit_payloads(&exit_bus, 1, Duration::from_secs(3)).await },
        );

    let packet = build_multi_hop_packet(&path, &payload, 0).expect("build");
    let size = packet.len();
    let publisher: Arc<dyn IEventPublisher> = nodes[0].bus.clone();
    publisher
        .publish(NoxEvent::PacketReceived {
            packet_id: "test-1hop".to_string(),
            data: packet,
            size_bytes: size,
        })
        .expect("inject");

    let results = collector.await.expect("collector");
    assert_eq!(results.len(), 1);
    assert!(payload_matches(&results[0], &payload));
}
