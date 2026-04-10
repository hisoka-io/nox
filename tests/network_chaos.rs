use futures::StreamExt;
use libp2p::{identity, noise, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder};
use nox_node::config::NetworkConfig;
use nox_node::network::service::P2PService;
use nox_node::services::network_manager::TopologyManager;
use nox_node::NoxConfig;
use nox_node::SledRepository;
use nox_node::TokioEventBus;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::time::sleep;

/// Helper to create a basic P2PService
async fn create_service() -> (P2PService, Multiaddr) {
    let dir = tempdir().unwrap();
    let db = Arc::new(SledRepository::new(dir.path()).unwrap());
    let bus = TokioEventBus::new(100);
    let pub_bus = Arc::new(bus.clone());
    let sub_bus = Arc::new(bus.clone());

    let config = {
        let mut c = NoxConfig::default();
        c.p2p_listen_addr = "127.0.0.1".to_string();
        c.p2p_port = 0; // Random port
        c.network = NetworkConfig {
            max_connections: 100,
            max_connections_per_peer: 10,
            ping_interval_secs: 1,
            ping_timeout_secs: 1,
            gossip_heartbeat_secs: 1,
            ..Default::default()
        };
        c
    };

    let (tx, _rx) = tokio::sync::oneshot::channel();
    let metrics = nox_node::telemetry::metrics::MetricsService::new();
    let tm = Arc::new(TopologyManager::new(db.clone(), sub_bus.clone(), None));
    let service = P2PService::new(&config, pub_bus, sub_bus, db, metrics, tm)
        .await
        .unwrap()
        .with_bind_signal(tx);

    (service, "/ip4/127.0.0.1/tcp/0".parse().unwrap())
}

/// Helper to start the service and get its real address
async fn start_service(service: P2PService) -> (tokio::task::JoinHandle<()>, PeerId, Multiaddr) {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut service = service.with_bind_signal(tx);

    let handle = tokio::spawn(async move {
        service.run().await;
    });

    let (peer_id, addr) = rx.await.expect("Service started");
    (handle, peer_id, addr)
}

/// Helper to create a client swarm
fn create_client_swarm() -> Swarm<libp2p::ping::Behaviour> {
    let local_key = identity::Keypair::generate_ed25519();
    SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|_| libp2p::ping::Behaviour::new(libp2p::ping::Config::new()))
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(5)))
        .build()
}

#[tokio::test]
async fn test_chaos_memory_leak_check() {
    let (service, _) = create_service().await;

    let health_map = service.peer_health_handle();
    let rate_limiter_count_check = service.rate_limiter_peer_count(); // Should be 0 initially
    assert_eq!(rate_limiter_count_check, 0);

    let (_handle, server_pid, server_addr) = start_service(service).await;
    println!("Server started at {} ({})", server_addr, server_pid);

    let mut client = create_client_swarm();

    for i in 1..=5 {
        println!("Iteration {}: Connecting...", i);
        client.dial(server_addr.clone()).unwrap();

        loop {
            tokio::select! {
                event = client.next() => {
                    if let Some(libp2p::swarm::SwarmEvent::ConnectionEstablished { .. }) = event {
                        break;
                    }
                }
                _ = sleep(Duration::from_secs(5)) => panic!("Timeout connecting"),
            }
        }

        sleep(Duration::from_secs(1)).await;

        println!("Iteration {}: Disconnecting...", i);
        client.disconnect_peer_id(server_pid).unwrap();

        loop {
            tokio::select! {
                event = client.next() => {
                    if let Some(libp2p::swarm::SwarmEvent::ConnectionClosed { .. }) = event {
                        break;
                    }
                }
                _ = sleep(Duration::from_secs(5)) => panic!("Timeout disconnecting"),
            }
        }

        sleep(Duration::from_millis(200)).await;

        assert_eq!(
            health_map.len(),
            0,
            "Leak detected! PeerHealth map not empty after disconnect"
        );
    }

    assert_eq!(health_map.len(), 0, "Final check: PeerHealth map not empty");
}
