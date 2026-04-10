//! TopologyManager unit tests: registration, removal, fingerprints, hydration.

use nox_core::models::topology::RelayerNode;
use nox_core::{events::NoxEvent, IEventPublisher, IEventSubscriber};
use nox_node::{services::network_manager::TopologyManager, SledRepository, TokioEventBus};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

fn make_storage() -> (Arc<SledRepository>, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    let repo = Arc::new(SledRepository::new(dir.path()).expect("sled"));
    (repo, dir)
}

fn make_bus() -> Arc<TokioEventBus> {
    Arc::new(TokioEventBus::new(64))
}

fn registration_event(address: &str, role: u8) -> NoxEvent {
    NoxEvent::RelayerRegistered {
        address: address.to_string(),
        sphinx_key: "0xdeadbeef".to_string(),
        url: format!("/ip4/127.0.0.1/tcp/{}", 9000 + role as u16),
        stake: "1000000000000000000".to_string(),
        role,
        ingress_url: None,
        metadata_url: None,
    }
}

async fn spawn_manager() -> (
    Arc<TopologyManager>,
    Arc<TokioEventBus>,
    tokio_util::sync::CancellationToken,
    TempDir,
) {
    let bus = make_bus();
    let (storage, dir) = make_storage();
    let subscriber: Arc<dyn IEventSubscriber> = bus.clone();
    let cancel = tokio_util::sync::CancellationToken::new();

    let mgr = Arc::new(TopologyManager::with_cancel_token(
        storage,
        subscriber,
        None,
        cancel.clone(),
    ));

    let mgr_clone = mgr.clone();
    tokio::spawn(async move { mgr_clone.run().await });

    tokio::time::sleep(Duration::from_millis(10)).await;

    (mgr, bus, cancel, dir)
}

/// Registering a node makes it visible in `get_nodes_in_layer` and `lookup_by_address`.
#[tokio::test]
async fn test_topology_registration_adds_node() {
    let (mgr, bus, cancel, _dir) = spawn_manager().await;

    // role=2 -> always layer 2 (exit)
    bus.publish(registration_event(
        "0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa",
        2,
    ))
    .expect("publish");

    // Give the manager time to process
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(mgr.get_nodes_in_layer(0).len(), 1);
    assert_eq!(mgr.get_nodes_in_layer(1).len(), 1);
    assert_eq!(mgr.get_nodes_in_layer(2).len(), 1);
    assert_eq!(mgr.get_all_nodes().len(), 1);

    let by_addr = mgr.lookup_by_address("0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa");
    assert!(by_addr.is_some());

    cancel.cancel();
}

/// Removing a node via the event bus clears it from the layer map and address index.
#[tokio::test]
async fn test_topology_removal_clears_node() {
    let (mgr, bus, cancel, _dir) = spawn_manager().await;

    let addr = "0xBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBb";

    bus.publish(registration_event(addr, 2))
        .expect("publish register");
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(mgr.get_nodes_in_layer(0).len(), 1);
    assert_eq!(mgr.get_nodes_in_layer(1).len(), 1);
    assert_eq!(mgr.get_nodes_in_layer(2).len(), 1);

    bus.publish(NoxEvent::RelayerRemoved {
        address: addr.to_string(),
    })
    .expect("publish remove");
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert!(mgr.get_nodes_in_layer(0).is_empty());
    assert!(mgr.get_nodes_in_layer(1).is_empty());
    assert!(mgr.get_nodes_in_layer(2).is_empty());

    let by_addr = mgr.lookup_by_address(addr);
    assert!(by_addr.is_none());

    cancel.cancel();
}

/// XOR fingerprint is self-inverse: register then remove restores original.
#[tokio::test]
async fn test_topology_fingerprint_self_inverse() {
    let (mgr, bus, cancel, _dir) = spawn_manager().await;

    let initial_fp = mgr.get_current_fingerprint();

    let addr = "0xCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCc";

    bus.publish(registration_event(addr, 2)).expect("publish");
    tokio::time::sleep(Duration::from_millis(50)).await;
    let after_register = mgr.get_current_fingerprint();

    assert_ne!(initial_fp, after_register);

    bus.publish(NoxEvent::RelayerRemoved {
        address: addr.to_string(),
    })
    .expect("remove");
    tokio::time::sleep(Duration::from_millis(50)).await;
    let after_removal = mgr.get_current_fingerprint();

    assert_eq!(initial_fp, after_removal, "XOR self-inverse violated");

    cancel.cancel();
}

/// `compute_topology_fingerprint` is order-independent (XOR is commutative).
#[test]
fn test_compute_fingerprint_deterministic_and_order_independent() {
    let addrs = vec![
        "0x1111111111111111111111111111111111111111".to_string(),
        "0x2222222222222222222222222222222222222222".to_string(),
        "0x3333333333333333333333333333333333333333".to_string(),
    ];

    let fp_abc = TopologyManager::compute_topology_fingerprint(&addrs);

    let addrs_reversed = {
        let mut v = addrs.clone();
        v.reverse();
        v
    };
    let fp_cba = TopologyManager::compute_topology_fingerprint(&addrs_reversed);

    assert_eq!(fp_abc, fp_cba);

    let mut addrs_plus = addrs.clone();
    addrs_plus.push("0x4444444444444444444444444444444444444444".to_string());
    let fp_plus = TopologyManager::compute_topology_fingerprint(&addrs_plus);

    assert_ne!(fp_abc, fp_plus);
}

/// `hydrate_from_snapshot` replaces the entire topology atomically.
#[tokio::test]
async fn test_topology_hydrate_from_snapshot() {
    let (mgr, bus, cancel, _dir) = spawn_manager().await;

    bus.publish(registration_event(
        "0xOLDADDR00000000000000000000000000000000",
        2,
    ))
    .expect("publish");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let snapshot: Vec<RelayerNode> = vec![
        {
            let mut n = RelayerNode::new(
                "0x1111111111111111111111111111111111111111".to_string(),
                "0xkey1".to_string(),
                "/ip4/10.0.0.1/tcp/9001".to_string(),
                "1".to_string(),
                2,
            );
            n.layer = 2;
            n
        },
        {
            let mut n = RelayerNode::new(
                "0x2222222222222222222222222222222222222222".to_string(),
                "0xkey2".to_string(),
                "/ip4/10.0.0.2/tcp/9002".to_string(),
                "1".to_string(),
                2,
            );
            n.layer = 2;
            n
        },
        {
            let mut n = RelayerNode::new(
                "0x3333333333333333333333333333333333333333".to_string(),
                "0xkey3".to_string(),
                "/ip4/10.0.0.3/tcp/9003".to_string(),
                "1".to_string(),
                2,
            );
            n.layer = 2;
            n
        },
    ];

    mgr.hydrate_from_snapshot(snapshot.clone()).await;

    let old = mgr.lookup_by_address("0xOLDADDR00000000000000000000000000000000");
    assert!(old.is_none());

    let layer2 = mgr.get_nodes_in_layer(2);
    assert_eq!(layer2.len(), 3);

    let expected_fp = TopologyManager::compute_topology_fingerprint(
        &snapshot
            .iter()
            .map(|n| n.address.clone())
            .collect::<Vec<_>>(),
    );
    assert_eq!(mgr.get_current_fingerprint(), expected_fp);

    cancel.cancel();
}
