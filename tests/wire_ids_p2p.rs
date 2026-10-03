//! Packet identifiers across real P2P links.
//!
//! Three `P2PService`s (A -> B -> C) on loopback. A plays the previous hop,
//! B relays, C receives. C runs in passthrough mode where noted, so the
//! identifier it reports is the one B put on the wire.

use libp2p::multiaddr::Protocol;
use nox_core::models::topology::RelayerNode;
use nox_core::models::wire_id::{reply_wire_id, PacketOrigin, ReplyHandle};
use nox_core::{IEventPublisher, IEventSubscriber, NoxEvent};
use nox_node::config::WireIdMode;
use nox_node::network::service::P2PService;
use nox_node::services::network_manager::TopologyManager;
use nox_node::telemetry::metrics::MetricsService;
use nox_node::{NoxConfig, SledRepository, TokioEventBus};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::oneshot;

const HANDLE: ReplyHandle = [0x6b; 16];

struct Node {
    bus: TokioEventBus,
    topology: Arc<TopologyManager>,
    metrics: MetricsService,
    addr: String,
    peer: String,
    _dir: TempDir,
}

async fn start(wire_ids: WireIdMode) -> Node {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = Arc::new(SledRepository::new(dir.path()).expect("db"));
    let bus = TokioEventBus::new(256);
    let publisher: Arc<dyn IEventPublisher> = Arc::new(bus.clone());
    let subscriber: Arc<dyn IEventSubscriber> = Arc::new(bus.clone());
    let mut config = NoxConfig::default();
    config.p2p_port = 0;
    config.p2p_listen_addr = "127.0.0.1".into();
    config.p2p_identity_path = dir.path().join("id.key").to_string_lossy().into_owned();
    config.relayer.wire_ids = wire_ids;
    config.benchmark_mode = wire_ids == WireIdMode::Passthrough;

    let metrics = MetricsService::new();
    let topology = Arc::new(TopologyManager::new(db.clone(), subscriber.clone(), None));
    let (tx, rx) = oneshot::channel();
    let mut service = P2PService::new(
        &config,
        publisher,
        subscriber,
        db,
        metrics.clone(),
        topology.clone(),
    )
    .await
    .expect("p2p service")
    .with_bind_signal(tx);
    tokio::spawn(async move { service.run().await });
    let (peer, addr) = rx.await.expect("bind");
    Node {
        bus,
        topology,
        metrics,
        addr: addr.with(Protocol::P2p(peer)).to_string(),
        peer: peer.to_string(),
        _dir: dir,
    }
}

fn member(index: usize, node: &Node, role: u8) -> RelayerNode {
    RelayerNode::new(
        format!("0x{:040x}", 0xa0_0000 + index),
        "00".repeat(32),
        node.addr.clone(),
        "1000".into(),
        role,
    )
}

/// Starts A, B and C, registers them with each other (A with `role_of_a`)
/// and waits until A-B and B-C are connected.
async fn mesh(role_of_a: u8, c_mode: WireIdMode) -> (Node, Node, Node) {
    let a = start(WireIdMode::PerHop).await;
    let b = start(WireIdMode::PerHop).await;
    let c = start(c_mode).await;
    let members = vec![member(0, &a, role_of_a), member(1, &b, 1), member(2, &c, 1)];
    for node in [&a, &b, &c] {
        node.topology.hydrate_from_snapshot(members.clone()).await;
    }
    let mut b_events = b.bus.subscribe();
    for (from, to) in [(&a, &b), (&c, &b)] {
        from.bus
            .publish(NoxEvent::RelayerRegistered {
                address: "0xpeer".into(),
                sphinx_key: "00".into(),
                url: to.addr.clone(),
                stake: "1000".into(),
                role: 1,
                ingress_url: None,
                metadata_url: None,
            })
            .expect("publish");
    }
    let mut connected = std::collections::HashSet::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        while connected.len() < 2 {
            if let Ok(NoxEvent::PeerConnected { peer_id }) = b_events.recv().await {
                connected.insert(peer_id);
            }
        }
    })
    .await
    .expect("A and C connect to B");
    (a, b, c)
}

/// Next `PacketReceived` on `node`: (local id, handle, previous peer).
async fn next_received(
    rx: &mut tokio::sync::broadcast::Receiver<NoxEvent>,
) -> (String, Option<ReplyHandle>, Option<String>) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(NoxEvent::PacketReceived {
                packet_id,
                reply_handle,
                prev_peer,
                ..
            }) = rx.recv().await
            {
                return (packet_id, reply_handle, prev_peer);
            }
        }
    })
    .await
    .expect("packet received")
}

fn send(
    from: &Node,
    to: &Node,
    packet_id: &str,
    handle: Option<ReplyHandle>,
    origin: PacketOrigin,
) {
    from.bus
        .publish(NoxEvent::SendPacket {
            next_hop_peer_id: to.addr.clone(),
            packet_id: packet_id.into(),
            data: vec![0x42; 64],
            reply_handle: handle,
            origin,
        })
        .expect("publish");
}

fn is_fresh(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn label(key: &str, value: &str) -> Vec<(String, String)> {
    vec![(key.to_string(), value.to_string())]
}

#[tokio::test]
async fn reply_from_exit_keeps_its_handle_across_a_relay() {
    let (a, b, c) = mesh(2, WireIdMode::Passthrough).await;
    let mut b_rx = b.bus.subscribe();
    let mut c_rx = c.bus.subscribe();

    // A (an exit) sends a reply it built from a SURB.
    send(&a, &b, "exit-local", Some(HANDLE), PacketOrigin::Originated);
    let (b_local, b_handle, b_prev) = next_received(&mut b_rx).await;
    assert_eq!(b_handle, Some(HANDLE));
    assert_eq!(b_prev.as_deref(), Some(a.peer.as_str()));
    assert!(is_fresh(&b_local), "local id {b_local}");

    // B relays it to C, which sees the wire id B chose.
    send(
        &b,
        &c,
        &b_local,
        b_handle,
        PacketOrigin::Relayed { prev_peer: b_prev },
    );
    let (c_wire, c_handle, _) = next_received(&mut c_rx).await;
    assert_eq!(c_wire, reply_wire_id(&HANDLE));
    assert_eq!(c_handle, Some(HANDLE));
    assert_eq!(
        b.metrics
            .wire_ids_total
            .get_or_create(&label("kind", "legacy_handle"))
            .get(),
        1
    );
}

#[tokio::test]
async fn handle_from_a_relay_role_peer_is_replaced_with_a_fresh_id() {
    let (a, b, c) = mesh(1, WireIdMode::Passthrough).await;
    let mut b_rx = b.bus.subscribe();
    let mut c_rx = c.bus.subscribe();

    // A (relay role, for example an entry) puts a reply-shaped id on a forward packet.
    let planted = reply_wire_id(&HANDLE);
    send(
        &a,
        &b,
        &planted,
        None,
        PacketOrigin::Relayed { prev_peer: None },
    );
    let (b_local, b_handle, b_prev) = next_received(&mut b_rx).await;
    assert_eq!(b_handle, None, "A sent a fresh id, not the planted one");

    // Same again with A passing the handle on explicitly.
    send(&a, &b, "x", Some(HANDLE), PacketOrigin::Originated);
    let (b_local2, b_handle2, b_prev2) = next_received(&mut b_rx).await;
    assert_eq!(b_handle2, Some(HANDLE));

    for (local, handle, prev) in [(b_local, b_handle, b_prev), (b_local2, b_handle2, b_prev2)] {
        send(
            &b,
            &c,
            &local,
            handle,
            PacketOrigin::Relayed { prev_peer: prev },
        );
        let (c_wire, c_handle, _) = next_received(&mut c_rx).await;
        assert!(is_fresh(&c_wire), "wire id {c_wire}");
        assert_ne!(c_wire, local);
        assert_eq!(c_handle, None);
    }
    assert_eq!(
        b.metrics
            .wire_handle_dropped_total
            .get_or_create(&label("reason", "forward_direction"))
            .get(),
        1
    );
}

#[tokio::test]
async fn forward_packets_get_a_new_id_at_every_hop() {
    let (a, b, c) = mesh(3, WireIdMode::Passthrough).await;
    let mut b_rx = b.bus.subscribe();
    let mut c_rx = c.bus.subscribe();

    let mut seen = std::collections::HashSet::new();
    for i in 0..20 {
        let ingress_id = format!("http-{i:016x}");
        send(
            &a,
            &b,
            &ingress_id,
            None,
            PacketOrigin::Relayed { prev_peer: None },
        );
        let (b_local, b_handle, b_prev) = next_received(&mut b_rx).await;
        assert_eq!(b_handle, None);
        assert!(is_fresh(&b_local));
        send(
            &b,
            &c,
            &b_local,
            None,
            PacketOrigin::Relayed { prev_peer: b_prev },
        );
        let (c_wire, _, _) = next_received(&mut c_rx).await;
        assert!(is_fresh(&c_wire));
        assert_ne!(c_wire, ingress_id);
        assert_ne!(c_wire, b_local);
        assert!(seen.insert(c_wire));
    }
}

#[tokio::test]
async fn passthrough_keeps_the_ingress_id_end_to_end() {
    let a = start(WireIdMode::Passthrough).await;
    let b = start(WireIdMode::Passthrough).await;
    let members = vec![member(0, &a, 1), member(1, &b, 1)];
    for node in [&a, &b] {
        node.topology.hydrate_from_snapshot(members.clone()).await;
    }
    let mut b_events = b.bus.subscribe();
    a.bus
        .publish(NoxEvent::RelayerRegistered {
            address: "0xpeer".into(),
            sphinx_key: "00".into(),
            url: b.addr.clone(),
            stake: "1000".into(),
            role: 1,
            ingress_url: None,
            metadata_url: None,
        })
        .expect("publish");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(NoxEvent::PeerConnected { .. }) = b_events.recv().await {
                return;
            }
        }
    })
    .await
    .expect("connect");
    // PeerConnected can fire before A's outbound stream is usable, so
    // resend until B reports the packet.
    let b_local = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            send(
                &a,
                &b,
                "http-00000000deadbeef",
                None,
                PacketOrigin::Relayed { prev_peer: None },
            );
            let got = tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    if let Ok(NoxEvent::PacketReceived { packet_id, .. }) = b_events.recv().await {
                        return packet_id;
                    }
                }
            })
            .await;
            if let Ok(id) = got {
                return id;
            }
        }
    })
    .await
    .expect("packet received");
    assert_eq!(b_local, "http-00000000deadbeef");
}
