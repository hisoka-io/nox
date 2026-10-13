use nox_core::NoxEvent;

use nox_core::{IEventPublisher, IEventSubscriber};
use nox_node::services::network_manager::TopologyManager;
use nox_node::services::traffic_shaping::TrafficShapingService;
use nox_node::telemetry::metrics::MetricsService;
use nox_node::NoxConfig;
use nox_node::SledRepository;
use nox_node::TokioEventBus;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::time::Duration;

#[tokio::test]
async fn test_stratified_assignment() {
    let dir = tempdir().unwrap();
    let db = Arc::new(SledRepository::new(dir.path()).unwrap());
    let bus = TokioEventBus::new(2000);
    let sub: Arc<dyn IEventSubscriber> = Arc::new(bus.clone());

    let tm = TopologyManager::new(db.clone(), sub.clone(), None);
    let tm_arc = Arc::new(tm);
    let tm_clone = tm_arc.clone();

    tokio::spawn(async move {
        tm_clone.run().await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    for i in 0..100 {
        let addr = format!("0xNode{}", i);
        bus.publish(NoxEvent::RelayerRegistered {
            address: addr,
            sphinx_key: "00".repeat(32),
            url: "127.0.0.1".into(),
            stake: "100".into(),
            role: 3, // Full
            ingress_url: None,
            metadata_url: None,
        })
        .unwrap();
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    let l0 = tm_arc.get_nodes_in_layer(0);
    let l1 = tm_arc.get_nodes_in_layer(1);
    let l2 = tm_arc.get_nodes_in_layer(2);

    println!(
        "Entry(0): {}, Mix(1): {}, Exit(2): {}",
        l0.len(),
        l1.len(),
        l2.len()
    );

    assert!(!l0.is_empty());
    assert!(!l1.is_empty());
    assert!(!l2.is_empty());

    assert_eq!(l0.len(), 100);
    assert_eq!(l1.len(), 100);
    assert_eq!(l2.len(), 100);

    let all = tm_arc.get_all_nodes();
    assert_eq!(all.len(), 100);
}

#[tokio::test]
async fn test_role_based_layer_assignment() {
    let dir = tempdir().unwrap();
    let db = Arc::new(SledRepository::new(dir.path()).unwrap());
    let bus = TokioEventBus::new(2000);
    let sub: Arc<dyn IEventSubscriber> = Arc::new(bus.clone());

    let tm = TopologyManager::new(db.clone(), sub.clone(), None);
    let tm_arc = Arc::new(tm);
    let tm_clone = tm_arc.clone();

    tokio::spawn(async move {
        tm_clone.run().await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    for i in 0..50 {
        bus.publish(NoxEvent::RelayerRegistered {
            address: format!("0xRelay{}", i),
            sphinx_key: "00".repeat(32),
            url: "127.0.0.1".into(),
            stake: "100".into(),
            role: 1, // Relay
            ingress_url: None,
            metadata_url: None,
        })
        .unwrap();
    }

    for i in 0..20 {
        bus.publish(NoxEvent::RelayerRegistered {
            address: format!("0xExit{}", i),
            sphinx_key: "00".repeat(32),
            url: "127.0.0.1".into(),
            stake: "100".into(),
            role: 2, // Exit
            ingress_url: None,
            metadata_url: None,
        })
        .unwrap();
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    let l0 = tm_arc.get_nodes_in_layer(0);
    let l1 = tm_arc.get_nodes_in_layer(1);
    let l2 = tm_arc.get_nodes_in_layer(2);

    println!(
        "Entry(0): {}, Mix(1): {}, Exit(2): {}",
        l0.len(),
        l1.len(),
        l2.len()
    );

    assert_eq!(l0.len(), 50 + 20);
    assert_eq!(l1.len(), 50 + 20);

    // Relay nodes cannot serve exit layer
    assert_eq!(l2.len(), 20);

    let all = tm_arc.get_all_nodes();
    assert_eq!(all.len(), 70);
}

#[tokio::test]
async fn test_traffic_shaping_loop_only() {
    let mut config = NoxConfig::default();
    config.relayer.cover_traffic_rate = 10.0; // Fast for test
    config.relayer.drop_traffic_rate = 0.0; // Disable drop

    let (tm_arc, bus) = setup_topology().await;
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let service =
        TrafficShapingService::new(config, tm_arc.clone(), bus.clone(), MetricsService::new());

    let mut rx = bus.subscribe();

    // Start service
    tokio::spawn(async move {
        service.run().await;
    });

    let mut count = 0;
    let start = std::time::Instant::now();
    while count < 5 {
        if let Ok(NoxEvent::SendPacket { .. }) = rx.try_recv() {
            count += 1;
        }
        if start.elapsed().as_millis() > 2000 {
            break; // Timed out
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    assert!(
        count >= 5,
        "only received {count}/5 cover packets before timeout"
    );
}

#[tokio::test]
async fn test_traffic_shaping_dual_streams() {
    let mut config = NoxConfig::default();
    config.relayer.cover_traffic_rate = 5.0; // Fast loop
    config.relayer.drop_traffic_rate = 5.0; // Fast drop

    let (tm_arc, bus) = setup_topology().await;
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let service =
        TrafficShapingService::new(config, tm_arc.clone(), bus.clone(), MetricsService::new());

    // Subscribe to catch events
    let mut rx = bus.subscribe();

    // Run service in background
    tokio::spawn(async move {
        service.run().await;
    });

    let mut count = 0;
    let start = tokio::time::Instant::now();

    while count < 10 {
        if let Ok(NoxEvent::SendPacket { .. }) = rx.recv().await {
            count += 1;
        }

        if start.elapsed().as_secs() > 5 {
            panic!("Timeout waiting for dual stream packets");
        }
    }
}

#[tokio::test]
async fn test_topology_node_role_propagation() {
    use nox_client::TopologyNode;
    use nox_core::RelayerNode;

    // Verify that role propagates correctly through from_relayer_node conversion
    let exit_node = RelayerNode {
        address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        sphinx_key: "aa".repeat(32),
        url: "/ip4/127.0.0.1/tcp/9000".to_string(),
        stake: "1000".to_string(),
        last_seen: 0,
        is_privileged: false,
        layer: 2,
        role: 2, // Exit
        ingress_url: None,
        metadata_url: None,
    };

    let relay_node = RelayerNode {
        address: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string(),
        sphinx_key: "bb".repeat(32),
        url: "/ip4/127.0.0.1/tcp/9001".to_string(),
        stake: "1000".to_string(),
        last_seen: 0,
        is_privileged: false,
        layer: 0,
        role: 1, // Relay
        ingress_url: None,
        metadata_url: None,
    };

    let full_node = RelayerNode {
        address: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        sphinx_key: "cc".repeat(32),
        url: "/ip4/127.0.0.1/tcp/9002".to_string(),
        stake: "1000".to_string(),
        last_seen: 0,
        is_privileged: false,
        layer: 1,
        role: 3, // Full
        ingress_url: None,
        metadata_url: None,
    };

    let topo_exit = TopologyNode::from_relayer_node(&exit_node).unwrap();
    let topo_relay = TopologyNode::from_relayer_node(&relay_node).unwrap();
    let topo_full = TopologyNode::from_relayer_node(&full_node).unwrap();

    assert_eq!(topo_exit.role, 2);
    assert_eq!(topo_relay.role, 1);
    assert_eq!(topo_full.role, 3);

    assert_eq!(topo_exit.layer, 2);
    assert_eq!(topo_relay.layer, 0);
    assert_eq!(topo_full.layer, 1);
}

async fn setup_topology() -> (Arc<TopologyManager>, Arc<TokioEventBus>) {
    let dir = tempdir().unwrap();
    let db = Arc::new(SledRepository::new(dir.path()).unwrap());
    let bus = Arc::new(TokioEventBus::new(2000));
    let sub: Arc<dyn IEventSubscriber> = bus.clone();

    let tm = TopologyManager::new(db.clone(), sub.clone(), None);
    let tm_arc = Arc::new(tm);
    let tm_run = tm_arc.clone();

    tokio::spawn(async move {
        tm_run.run().await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    for i in 0..30 {
        let _ = bus.publish(NoxEvent::RelayerRegistered {
            address: format!("node_{}", i),
            sphinx_key: "00".repeat(32),
            url: "127.0.0.1".into(),
            stake: "100".into(),
            role: 3, // Full
            ingress_url: None,
            metadata_url: None,
        });
    }

    (tm_arc, bus)
}
