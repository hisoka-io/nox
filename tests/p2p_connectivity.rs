use libp2p::multiaddr::Protocol;
use nox_core::{IEventPublisher, IEventSubscriber, NoxEvent};
use nox_node::network::service::P2PService;
use nox_node::services::network_manager::TopologyManager;
use nox_node::{NoxConfig, SledRepository, TokioEventBus};
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::oneshot;

#[tokio::test]
async fn test_twin_node_handshake() -> anyhow::Result<()> {
    let dir_a = tempdir()?;
    let db_a = Arc::new(SledRepository::new(dir_a.path())?);
    let bus_a = TokioEventBus::new(100);
    let pub_a = Arc::new(bus_a.clone());
    let sub_a = Arc::new(bus_a.clone());

    let config_a = {
        let mut c = NoxConfig::default();
        c.p2p_port = 0;
        c.p2p_listen_addr = "127.0.0.1".to_string();
        c.p2p_identity_path = dir_a
            .path()
            .join("id.key")
            .to_str()
            .expect("valid UTF-8 path")
            .to_string();
        c
    };

    let (tx_a, rx_a) = oneshot::channel();
    let metrics_a = nox_node::telemetry::metrics::MetricsService::new();
    let tm_a = Arc::new(TopologyManager::new(db_a.clone(), sub_a.clone(), None));
    let mut service_a = P2PService::new(
        &config_a,
        pub_a.clone(),
        sub_a.clone(),
        db_a.clone(),
        metrics_a,
        tm_a,
    )
    .await?
    .with_bind_signal(tx_a);

    let dir_b = tempdir()?;
    let db_b = Arc::new(SledRepository::new(dir_b.path())?);
    let bus_b = TokioEventBus::new(100);
    let pub_b = Arc::new(bus_b.clone());
    let sub_b = Arc::new(bus_b.clone());

    let config_b = {
        let mut c = NoxConfig::default();
        c.p2p_port = 0;
        c.p2p_listen_addr = "127.0.0.1".to_string();
        c.p2p_identity_path = dir_b
            .path()
            .join("id.key")
            .to_str()
            .expect("valid UTF-8 path")
            .to_string();
        c
    };

    let (tx_b, rx_b) = oneshot::channel();
    let metrics_b = nox_node::telemetry::metrics::MetricsService::new();
    let tm_b = Arc::new(TopologyManager::new(db_b.clone(), sub_b.clone(), None));
    let mut service_b = P2PService::new(
        &config_b,
        pub_b.clone(),
        sub_b.clone(),
        db_b.clone(),
        metrics_b,
        tm_b,
    )
    .await?
    .with_bind_signal(tx_b);

    tokio::spawn(async move { service_a.run().await });
    tokio::spawn(async move { service_b.run().await });

    let (pid_a, addr_a) = rx_a.await?;
    let (pid_b, addr_b) = rx_b.await?;

    let full_addr_a = addr_a.with(Protocol::P2p(pid_a));
    let full_addr_b = addr_b.with(Protocol::P2p(pid_b));

    println!("Node A: {}", full_addr_a);
    println!("Node B: {}", full_addr_b);

    pub_a.publish(NoxEvent::RelayerRegistered {
        address: "0xNODE_B".into(),
        sphinx_key: "00".into(),
        url: full_addr_b.to_string(),
        stake: "1000".into(),
        role: 3, // Full
        ingress_url: None,
        metadata_url: None,
    })?;

    let mut rx_events_a = sub_a.subscribe();
    let timeout = tokio::time::timeout(Duration::from_secs(5), async {
        while let Ok(event) = rx_events_a.recv().await {
            if let NoxEvent::PeerConnected { peer_id } = event {
                println!("✅ Node A connected to: {}", peer_id);
                return;
            }
        }
    })
    .await;

    assert!(
        timeout.is_ok(),
        "Node A failed to report connection to Node B"
    );
    Ok(())
}

/// A running `P2PService` with its own bus and data directory.
struct TestPeer {
    peer_id: libp2p::PeerId,
    addr: libp2p::Multiaddr,
    publisher: Arc<TokioEventBus>,
    subscriber: Arc<TokioEventBus>,
    _dir: tempfile::TempDir,
}

async fn spawn_peer() -> anyhow::Result<TestPeer> {
    let dir = tempdir()?;
    let db = Arc::new(SledRepository::new(dir.path())?);
    let bus = TokioEventBus::new(1_024);
    let publisher = Arc::new(bus.clone());
    let subscriber = Arc::new(bus.clone());
    let mut config = NoxConfig::default();
    config.p2p_port = 0;
    config.p2p_listen_addr = "127.0.0.1".to_string();
    config.p2p_identity_path = dir
        .path()
        .join("id.key")
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("temp dir path is not UTF-8"))?
        .to_string();
    let (tx, rx) = oneshot::channel();
    let topology = Arc::new(TopologyManager::new(db.clone(), subscriber.clone(), None));
    let mut service = P2PService::new(
        &config,
        publisher.clone(),
        subscriber.clone(),
        db,
        nox_node::telemetry::metrics::MetricsService::new(),
        topology,
    )
    .await?
    .with_bind_signal(tx);
    tokio::spawn(async move { service.run().await });
    let (peer_id, addr) = rx.await?;
    Ok(TestPeer {
        peer_id,
        addr: addr.with(Protocol::P2p(peer_id)),
        publisher,
        subscriber,
        _dir: dir,
    })
}

fn registered(peer: &TestPeer, label: &str) -> NoxEvent {
    NoxEvent::RelayerRegistered {
        address: label.into(),
        sphinx_key: "00".into(),
        url: peer.addr.to_string(),
        stake: "1000".into(),
        role: 3,
        ingress_url: None,
        metadata_url: None,
    }
}

/// Re-announcing an already connected peer (a registry replay, or a chain
/// event for a peer first learned another way) dials it again. The per-peer
/// connection limit refuses that extra connection; no packet sent afterwards
/// may be lost because of it.
#[tokio::test]
async fn packets_survive_refused_duplicate_connections() -> anyhow::Result<()> {
    const PACKETS: usize = 40;
    let a = spawn_peer().await?;
    let b = spawn_peer().await?;

    let mut a_events = a.subscriber.subscribe();
    a.publisher.publish(registered(&b, "0xNODE_B"))?;
    b.publisher.publish(registered(&a, "0xNODE_A"))?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match a_events.recv().await {
                Ok(NoxEvent::PeerConnected { .. }) => return,
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("A never connected to B"))?;
    // Let both directions settle at the per-peer limit, then announce again.
    tokio::time::sleep(Duration::from_millis(500)).await;
    for _ in 0..3 {
        a.publisher.publish(registered(&b, "0xNODE_B"))?;
        b.publisher.publish(registered(&a, "0xNODE_A"))?;
    }
    tokio::time::sleep(Duration::from_secs(1)).await;

    let mut b_events = b.subscriber.subscribe();
    for i in 0..PACKETS {
        a.publisher.publish(NoxEvent::SendPacket {
            next_hop_peer_id: b.peer_id.to_string(),
            packet_id: format!("dup-conn-{i}"),
            data: vec![u8::try_from(i % 256)?; 64],
            reply_handle: None,
            origin: nox_core::models::wire_id::PacketOrigin::Originated,
        })?;
    }
    let mut received = 0usize;
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while received < PACKETS {
            match b_events.recv().await {
                Ok(NoxEvent::PacketReceived { .. }) => received += 1,
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    })
    .await;
    assert_eq!(
        received, PACKETS,
        "{received} of {PACKETS} packets reached B after duplicate connections were refused"
    );
    Ok(())
}
