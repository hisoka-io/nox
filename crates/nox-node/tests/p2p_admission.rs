use libp2p::multiaddr::Protocol;
use nox_core::{IEventPublisher, IEventSubscriber, NoxEvent};
use nox_node::config::PeerAdmissionMode;
use nox_node::network::service::P2PService;
use nox_node::services::network_manager::{RegistryProfile, TopologyManager};
use nox_node::{NoxConfig, SledRepository, TokioEventBus};
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::sync::oneshot;

struct Node {
    publisher: Arc<TokioEventBus>,
    subscriber: Arc<TokioEventBus>,
    topology: Arc<TopologyManager>,
    url: String,
    _dir: TempDir,
}

async fn start_node() -> anyhow::Result<Node> {
    let dir = tempdir()?;
    let db = Arc::new(SledRepository::new(dir.path())?);
    let bus = TokioEventBus::new(100);
    let publisher = Arc::new(bus.clone());
    let subscriber = Arc::new(bus.clone());
    let mut config = NoxConfig::default();
    config.p2p_port = 0;
    config.p2p_listen_addr = "127.0.0.1".to_string();
    config.p2p_identity_path = dir
        .path()
        .join("id.key")
        .to_str()
        .expect("valid UTF-8 path")
        .to_string();
    config.network.peer_admission = PeerAdmissionMode::Enforce;
    config.network.peer_admission_grace_secs = 0;

    let topology = Arc::new(TopologyManager::new(db.clone(), subscriber.clone(), None));
    let (tx, rx) = oneshot::channel();
    let mut service = P2PService::new(
        &config,
        publisher.clone(),
        subscriber.clone(),
        db,
        nox_node::telemetry::metrics::MetricsService::new(),
        topology.clone(),
    )
    .await?
    .with_bind_signal(tx);
    tokio::spawn(async move { service.run().await });
    let (peer_id, addr) = rx.await?;
    Ok(Node {
        publisher,
        subscriber,
        topology,
        url: addr.with(Protocol::P2p(peer_id)).to_string(),
        _dir: dir,
    })
}

fn profile(address: &str, url: &str) -> RegistryProfile {
    RegistryProfile {
        address: address.to_string(),
        sphinx_key: "11".repeat(32),
        url: url.to_string(),
        ingress_url: Some(String::new()),
        metadata_url: None,
        stake: "0".to_string(),
        role: 1,
        frozen: false,
    }
}

/// Makes `from` dial `to` through the normal discovery path.
fn dial(from: &Node, to: &Node) -> anyhow::Result<()> {
    from.publisher.publish(NoxEvent::RelayerRegistered {
        address: "0x0000000000000000000000000000000000000001".into(),
        sphinx_key: "11".repeat(32),
        url: to.url.clone(),
        stake: "0".into(),
        role: 1,
        ingress_url: None,
        metadata_url: None,
    })?;
    Ok(())
}

async fn connected_within(
    mut events: tokio::sync::broadcast::Receiver<NoxEvent>,
    wait: Duration,
) -> bool {
    tokio::time::timeout(wait, async {
        loop {
            match events.recv().await {
                Ok(NoxEvent::PeerConnected { .. }) => return,
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    std::future::pending::<()>().await;
                }
            }
        }
    })
    .await
    .is_ok()
}

const A: &str = "0x74486dc1ac551e5cd3f4eef80727cc9d50d3abe9";
const B: &str = "0x8c9fb3e9fe537067c8430480f80a4a5b9a12be1a";

#[tokio::test]
async fn verified_registry_refuses_unregistered_peers() -> anyhow::Result<()> {
    let a = start_node().await?;
    let b = start_node().await?;

    // A knows only itself, and the set is verified: B is outside the registry.
    a.topology.apply_profile(profile(A, &a.url)).await;
    a.topology.set_membership_verified(true);

    let events = a.subscriber.subscribe();
    dial(&b, &a)?;
    assert!(
        !connected_within(events, Duration::from_secs(3)).await,
        "A accepted a peer that is not registered"
    );

    // Once B is registered, the same dial is accepted.
    a.topology.apply_profile(profile(B, &b.url)).await;
    let events = a.subscriber.subscribe();
    dial(&b, &a)?;
    assert!(
        connected_within(events, Duration::from_secs(5)).await,
        "A refused a registered peer"
    );
    Ok(())
}

#[tokio::test]
async fn unverified_registry_admits_everyone() -> anyhow::Result<()> {
    let a = start_node().await?;
    let b = start_node().await?;
    a.topology.apply_profile(profile(A, &a.url)).await;

    let events = a.subscriber.subscribe();
    dial(&b, &a)?;
    assert!(
        connected_within(events, Duration::from_secs(5)).await,
        "admission must stay permissive until verified"
    );
    Ok(())
}
