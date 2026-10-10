//! A large SURB reply crossing one P2P link (NOX-180).
//!
//! An exit hands every fragment of a reply to its P2P service at once. A
//! receiving node serves at most `network.max_concurrent_streams` inbound
//! streams per connection and drops the rest without telling the sender, so
//! the sender has to keep its own number of open requests below that.

use libp2p::multiaddr::Protocol;
use nox_core::models::topology::RelayerNode;
use nox_core::models::wire_id::PacketOrigin;
use nox_core::{IEventPublisher, IEventSubscriber, NoxEvent};
use nox_node::network::service::P2PService;
use nox_node::services::network_manager::TopologyManager;
use nox_node::telemetry::metrics::MetricsService;
use nox_node::{NoxConfig, SledRepository, TokioEventBus};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::{broadcast, oneshot};

/// Sphinx packet size on the wire.
const PACKET_BYTES: usize = 32_768;
/// An 8 MiB reply (the worker's `maxResponseBytes`) in 30 KiB SURB payloads,
/// plus FEC parity.
const REPLY_FRAGMENTS: usize = 300;
/// The receive limit of a node on the v0.4.0-rc.8 default config.
const RC8_MAX_CONCURRENT_STREAMS: usize = 100;

struct Node {
    bus: TokioEventBus,
    topology: Arc<TopologyManager>,
    addr: String,
    _dir: TempDir,
}

async fn start(max_concurrent_streams: usize) -> Node {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = Arc::new(SledRepository::new(dir.path()).expect("db"));
    let bus = TokioEventBus::new(4096);
    let publisher: Arc<dyn IEventPublisher> = Arc::new(bus.clone());
    let subscriber: Arc<dyn IEventSubscriber> = Arc::new(bus.clone());
    let mut config = NoxConfig::default();
    config.p2p_port = 0;
    config.p2p_listen_addr = "127.0.0.1".into();
    config.p2p_identity_path = dir.path().join("id.key").to_string_lossy().into_owned();
    config.network.max_concurrent_streams = max_concurrent_streams;
    // Only the stream limit is under test here, not the per-peer rate limit.
    let rate = &mut config.network.rate_limit;
    rate.burst_unknown = 10_000;
    rate.rate_unknown = 10_000;

    let topology = Arc::new(TopologyManager::new(db.clone(), subscriber.clone(), None));
    let (tx, rx) = oneshot::channel();
    let mut service = P2PService::new(
        &config,
        publisher,
        subscriber,
        db,
        MetricsService::new(),
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
        addr: addr.with(Protocol::P2p(peer)).to_string(),
        _dir: dir,
    }
}

fn member(index: usize, node: &Node) -> RelayerNode {
    RelayerNode::new(
        format!("0x{:040x}", 0xb0_0000 + index),
        "00".repeat(32),
        node.addr.clone(),
        "1000".into(),
        1,
    )
}

fn send(from: &Node, to: &Node, id: &str) {
    from.bus
        .publish(NoxEvent::SendPacket {
            next_hop_peer_id: to.addr.clone(),
            packet_id: id.into(),
            data: vec![0x42; PACKET_BYTES],
            reply_handle: None,
            origin: PacketOrigin::Originated,
        })
        .expect("publish");
}

async fn next_packet(rx: &mut broadcast::Receiver<NoxEvent>, within: Duration) -> Option<()> {
    tokio::time::timeout(within, async {
        loop {
            match rx.recv().await {
                Ok(NoxEvent::PacketReceived { .. }) => return Some(()),
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    panic!("test subscriber lagged by {n} events")
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// Connects `exit` to `hop` and waits until a packet gets through.
async fn link(exit: &Node, hop: &Node) {
    let members = vec![member(0, exit), member(1, hop)];
    for node in [exit, hop] {
        node.topology.hydrate_from_snapshot(members.clone()).await;
    }
    exit.bus
        .publish(NoxEvent::RelayerRegistered {
            address: "0xhop".into(),
            sphinx_key: "00".into(),
            url: hop.addr.clone(),
            stake: "1000".into(),
            role: 1,
            ingress_url: None,
            metadata_url: None,
        })
        .expect("publish");
    let mut rx = hop.bus.subscribe();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            send(exit, hop, "warm-up");
            if next_packet(&mut rx, Duration::from_millis(500))
                .await
                .is_some()
            {
                return;
            }
        }
    })
    .await
    .expect("exit reaches the hop");
}

/// Sends a reply of `REPLY_FRAGMENTS` packets in one burst and returns how
/// many the hop received.
async fn burst(exit: &Node, hop: &Node) -> usize {
    let mut rx = hop.bus.subscribe();
    for i in 0..REPLY_FRAGMENTS {
        send(exit, hop, &format!("fragment-{i}"));
    }
    let mut received = 0;
    while received < REPLY_FRAGMENTS {
        if next_packet(&mut rx, Duration::from_secs(5)).await.is_none() {
            break;
        }
        received += 1;
    }
    received
}

/// Two replies back to back from a node on the default config to a node
/// with the rc.8 receive limit: every fragment of both arrives.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reply_bursts_reach_an_rc8_hop_whole() {
    let exit = start(NoxConfig::default().network.max_concurrent_streams).await;
    let hop = start(RC8_MAX_CONCURRENT_STREAMS).await;
    link(&exit, &hop).await;

    for reply in 0..2 {
        assert_eq!(burst(&exit, &hop).await, REPLY_FRAGMENTS, "reply {reply}");
    }
}
