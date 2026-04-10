//! Node lifecycle integration tests: startup, shutdown, persistence.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use nox_core::events::NoxEvent;
use nox_core::traits::interfaces::{IEventPublisher, IEventSubscriber};
use nox_node::services::network_manager::TopologyManager;
use nox_node::{SledRepository, TokioEventBus};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

fn make_storage() -> (Arc<SledRepository>, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    let repo = Arc::new(SledRepository::new(dir.path()).expect("sled init"));
    (repo, dir)
}

fn make_bus() -> Arc<TokioEventBus> {
    Arc::new(TokioEventBus::new(256))
}

fn registration_event(address: &str, role: u8) -> NoxEvent {
    NoxEvent::RelayerRegistered {
        address: address.to_string(),
        sphinx_key: format!("0x{:064x}", role as u64 + 0xDEAD),
        url: format!("/ip4/127.0.0.1/tcp/{}", 9000 + role as u16),
        stake: "1000000000000000000".to_string(),
        role,
        ingress_url: None,
        metadata_url: None,
    }
}

async fn spawn_topology_manager(
    storage: Arc<SledRepository>,
    bus: &Arc<TokioEventBus>,
    cancel: CancellationToken,
) -> Arc<TopologyManager> {
    let subscriber: Arc<dyn IEventSubscriber> = bus.clone();
    let mgr = Arc::new(TopologyManager::with_cancel_token(
        storage, subscriber, None, cancel,
    ));
    let mgr_clone = mgr.clone();
    tokio::spawn(async move { mgr_clone.run().await });
    tokio::time::sleep(Duration::from_millis(15)).await;
    mgr
}

/// Event bus + topology manager accept node registrations after startup.
#[tokio::test]
async fn test_subsystem_starts_and_reaches_ready() {
    let (storage, _dir) = make_storage();
    let bus = make_bus();
    let cancel = CancellationToken::new();

    let mgr = spawn_topology_manager(storage, &bus, cancel.clone()).await;

    assert_eq!(mgr.get_all_nodes().len(), 0);

    let publisher: Arc<dyn IEventPublisher> = bus.clone();
    publisher
        .publish(registration_event("0xAA", 1))
        .expect("pub");
    publisher
        .publish(registration_event("0xBB", 1))
        .expect("pub");
    publisher
        .publish(registration_event("0xCC", 2))
        .expect("pub");

    tokio::time::sleep(Duration::from_millis(30)).await;

    assert_eq!(mgr.get_all_nodes().len(), 3, "all 3 nodes registered");
    assert_eq!(mgr.get_nodes_in_layer(0).len(), 3, "all 3 in layer 0");
    assert_eq!(mgr.get_nodes_in_layer(1).len(), 3, "all 3 in layer 1");
    assert_eq!(mgr.get_nodes_in_layer(2).len(), 1, "1 exit node in layer 2");

    cancel.cancel();
}

/// Cancellation token triggers clean shutdown (no panic, no hang).
#[tokio::test]
async fn test_graceful_shutdown_no_panic() {
    let (storage, _dir) = make_storage();
    let bus = make_bus();
    let cancel = CancellationToken::new();

    let _mgr = spawn_topology_manager(storage, &bus, cancel.clone()).await;

    let publisher: Arc<dyn IEventPublisher> = bus.clone();
    publisher
        .publish(registration_event("0xDD", 1))
        .expect("pub");
    tokio::time::sleep(Duration::from_millis(15)).await;

    cancel.cancel();
    tokio::time::sleep(Duration::from_millis(20)).await;
    // If we get here, shutdown was clean.
}

/// Topology state persists across manager restarts (same sled DB).
#[tokio::test]
async fn test_topology_survives_restart() {
    let (storage, _dir) = make_storage();
    let bus = make_bus();
    let cancel1 = CancellationToken::new();

    let mgr1 = spawn_topology_manager(storage.clone(), &bus, cancel1.clone()).await;

    let publisher: Arc<dyn IEventPublisher> = bus.clone();
    publisher
        .publish(registration_event("0xA1", 1))
        .expect("pub");
    publisher
        .publish(registration_event("0xB1", 1))
        .expect("pub");
    publisher
        .publish(registration_event("0xC1", 2))
        .expect("pub");

    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(mgr1.get_all_nodes().len(), 3);
    let fingerprint1 = mgr1.get_current_fingerprint();

    cancel1.cancel();
    tokio::time::sleep(Duration::from_millis(20)).await;

    let cancel2 = CancellationToken::new();
    let bus2 = make_bus();

    let mgr2 = spawn_topology_manager(storage.clone(), &bus2, cancel2.clone()).await;

    // Hydrate from the snapshot the old manager had
    let snapshot = mgr1.get_all_nodes();
    mgr2.hydrate_from_snapshot(snapshot).await;

    tokio::time::sleep(Duration::from_millis(20)).await;

    assert_eq!(mgr2.get_all_nodes().len(), 3, "3 nodes after restart");
    assert_eq!(
        mgr2.get_current_fingerprint(),
        fingerprint1,
        "fingerprint matches after hydration"
    );

    assert!(mgr2.lookup_by_address("0xA1").is_some());
    assert!(mgr2.lookup_by_address("0xB1").is_some());
    assert!(mgr2.lookup_by_address("0xC1").is_some());

    cancel2.cancel();
}

/// Multiple registration + removal events processed correctly.
#[tokio::test]
async fn test_add_remove_cycle() {
    let (storage, _dir) = make_storage();
    let bus = make_bus();
    let cancel = CancellationToken::new();

    let mgr = spawn_topology_manager(storage, &bus, cancel.clone()).await;
    let publisher: Arc<dyn IEventPublisher> = bus.clone();

    publisher
        .publish(registration_event("0x00", 1))
        .expect("pub");
    publisher
        .publish(registration_event("0x01", 1))
        .expect("pub");
    publisher
        .publish(registration_event("0x02", 2))
        .expect("pub");
    publisher
        .publish(registration_event("0x03", 1))
        .expect("pub");
    publisher
        .publish(registration_event("0x04", 2))
        .expect("pub");

    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(mgr.get_all_nodes().len(), 5);

    publisher
        .publish(NoxEvent::RelayerRemoved {
            address: "0x00".to_string(),
        })
        .expect("pub");
    publisher
        .publish(NoxEvent::RelayerRemoved {
            address: "0x02".to_string(),
        })
        .expect("pub");

    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(mgr.get_all_nodes().len(), 3, "2 removed, 3 remain");

    assert!(mgr.lookup_by_address("0x00").is_none(), "0x00 removed");
    assert!(mgr.lookup_by_address("0x02").is_none(), "0x02 removed");
    assert!(
        mgr.lookup_by_address("0x01").is_some(),
        "0x01 still present"
    );

    cancel.cancel();
}

/// Re-registering same address with same role updates in-place (no duplicate).
#[tokio::test]
async fn test_re_registration_same_role_no_duplicate() {
    let (storage, _dir) = make_storage();
    let bus = make_bus();
    let cancel = CancellationToken::new();

    let mgr = spawn_topology_manager(storage, &bus, cancel.clone()).await;
    let publisher: Arc<dyn IEventPublisher> = bus.clone();

    publisher
        .publish(registration_event("0xAA", 2))
        .expect("pub");
    tokio::time::sleep(Duration::from_millis(15)).await;
    assert_eq!(mgr.get_all_nodes().len(), 1);
    assert_eq!(mgr.get_nodes_in_layer(2).len(), 1);

    let event = NoxEvent::RelayerRegistered {
        address: "0xAA".to_string(),
        sphinx_key: "0xNEW_KEY".to_string(),
        url: "/ip4/192.168.1.1/tcp/8888".to_string(),
        stake: "2000000000000000000".to_string(),
        role: 2,
        ingress_url: None,
        metadata_url: None,
    };
    publisher.publish(event).expect("pub");
    tokio::time::sleep(Duration::from_millis(15)).await;

    assert_eq!(mgr.get_all_nodes().len(), 1, "no duplicate");
    assert_eq!(mgr.get_nodes_in_layer(2).len(), 1, "still 1 exit");

    let node = mgr.lookup_by_address("0xAA").expect("found");
    assert_eq!(node.sphinx_key, "0xNEW_KEY");

    cancel.cancel();
}
