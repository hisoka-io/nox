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
