use clap::Parser;
use ethers::prelude::*;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use libp2p::multiaddr::Protocol;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::tempdir;
use tokio::sync::oneshot;
use tracing::{info, Level};

use nox_core::models::payloads::encode_payload;
use nox_core::traits::interfaces::{IEventPublisher, IEventSubscriber};
use nox_core::{NoxEvent, RelayerPayload};
use nox_crypto::{build_multi_hop_packet, PathHop};
use nox_node::blockchain::executor::ChainExecutor;
use nox_node::blockchain::tx_manager::TransactionManager;
use nox_node::network::service::P2PService;
use nox_node::services::exit::ExitService;
use nox_node::services::mixing::PoissonMixStrategy;
use nox_node::services::network_manager::TopologyManager;
use nox_node::services::relayer::RelayerService;
use nox_node::{NoxConfig, SledRepository, TokioEventBus};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(short, long, default_value_t = 10)]
    nodes: usize,

    #[arg(short, long, default_value_t = 100)]
    packets: usize,

    #[arg(long, default_value_t = 0)]
    throttle_ms: u64,
}

struct VirtualNode {
    id: usize,
    multiaddr: String,
    public_key: X25519PublicKey,
    bus_publisher: Arc<dyn IEventPublisher>,
    bus_subscriber: Arc<dyn IEventSubscriber>,
    _eth_address: Address,
    // Keep handles
    _storage: Arc<SledRepository>,
    _db_dir: tempfile::TempDir,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Setup Logging (Info level to see stats)
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).ok();

    let args = Args::parse();
    info!("STARTING PERFORMANCE GAUNTLET");
    info!("Nodes: {}", args.nodes);
    info!("Packets: {}", args.packets);
    info!("Throttle: {}ms", args.throttle_ms);

    // 2. Spawn Nodes (Mock Mode)
    let mut nodes = Vec::new();
    for i in 0..args.nodes {
        let node = spawn_mock_node(i).await?;
        nodes.push(node);
        if i % 10 == 0 && i > 0 {
            info!("... spawned {} nodes", i);
        }
    }
    info!(" Network Online: {} Nodes", args.nodes);

    // 3. Interconnect
    info!("Building Mesh...");
    for target in &nodes {
        for source in &nodes {
            if source.id == target.id {
                continue;
            }
            source.bus_publisher.publish(NoxEvent::RelayerRegistered {
                address: format!("0xNode{}", target.id),
                sphinx_key: hex::encode(target.public_key.as_bytes()),
                url: target.multiaddr.clone(),
                stake: "1000".to_string(),
                role: 3, // Full
                ingress_url: None,
                metadata_url: None,
            })?;
        }
    }
    tokio::time::sleep(Duration::from_secs(2)).await;

    // 4. Run Traffic
    let mut futures = FuturesUnordered::new();
    let sent_count = Arc::new(Mutex::new(0));
    let success_count = Arc::new(Mutex::new(0));
    let fail_count = Arc::new(Mutex::new(0));
    let latencies = Arc::new(Mutex::new(Vec::new()));

    info!("FIRING PACKETS");
    let start_time = Instant::now();

    for i in 0..args.packets {
        if args.nodes < 2 {
            break;
        }

        // Random Pair
        let entry_idx = i % args.nodes;
        let exit_idx = (i + 1) % args.nodes;
        let entry_node = &nodes[entry_idx];
        let exit_node = &nodes[exit_idx];

        // Path: Entry -> Exit (Direct for stress, or add mid-hop?)
        // Let's do 1 hop: Entry -> Middle -> Exit to test routing
        let mid_idx = (i + 2) % args.nodes;
        let mid_node = &nodes[mid_idx];

        let path = vec![no_hop(entry_node), no_hop(mid_node), no_hop(exit_node)];

        // Create Payload
        let payload = RelayerPayload::SubmitTransaction {
            to: Address::random().0,
            data: vec![0xaa, 0xbb, 0xcc, 0xdd],
        };

        // Wrap payload into a Sphinx packet directly
        let payload_bytes =
            encode_payload(&payload).expect("RelayerPayload encode should not fail");
        let packet_bytes = build_multi_hop_packet(&path, &payload_bytes, 0)?;

        let bus = entry_node.bus_publisher.clone();
        let exit_sub = exit_node.bus_subscriber.clone();
        let tx_id = format!("stress_{}", i);

        let success_c = success_count.clone();
        let fail_c = fail_count.clone();
        let lat_c = latencies.clone();

        futures.push(tokio::spawn(async move {
            let p_start = Instant::now();
            let _ = bus.publish(NoxEvent::PacketReceived {
                packet_id: tx_id.clone(),
                data: packet_bytes,
                size_bytes: 1024,
            });

            // Listen for delivery at exit
            let mut rx = exit_sub.subscribe();
            let result = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    match rx.recv().await {
                        Ok(event) => {
                            if let NoxEvent::PayloadDecrypted { packet_id, .. } = event {
                                if packet_id == tx_id {
                                    return true;
                                }
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(lagged = n, "Broadcast receiver lagged, continuing");
                            continue;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            return false;
                        }
                    }
                }
            })
            .await;

            match result {
                Ok(true) => {
                    let mut s = success_c.lock().expect("success_count mutex poisoned");
                    *s += 1;
                    lat_c
                        .lock()
                        .expect("latencies mutex poisoned")
                        .push(p_start.elapsed().as_millis() as u64);
                }
                _ => {
                    let mut f = fail_c.lock().expect("fail_count mutex poisoned");
                    *f += 1;
                }
            }
        }));

        {
            let mut sc = sent_count.lock().expect("sent_count mutex poisoned");
            *sc += 1;
            if *sc % 100 == 0 {
                info!("Sent {} packets...", *sc);
            }
        }

        if args.throttle_ms > 0 {
            tokio::time::sleep(Duration::from_millis(args.throttle_ms)).await;
        }
    }

    while futures.next().await.is_some() {}

    let duration = start_time.elapsed();
    let sent = *sent_count.lock().expect("sent_count mutex poisoned");
    let success = *success_count.lock().expect("success_count mutex poisoned");
    let failed = *fail_count.lock().expect("fail_count mutex poisoned");
    let lats = latencies.lock().expect("latencies mutex poisoned").clone();

    let avg_lat = if !lats.is_empty() {
        lats.iter().sum::<u64>() / lats.len() as u64
    } else {
        0
    };
    let throughput = success as f64 / duration.as_secs_f64();

    info!("==================================");
    info!(" STRESS TEST REPORT");
    info!("==================================");
    info!("Duration:    {:.2}s", duration.as_secs_f64());
    info!("Total Sent:  {}", sent);
    info!("Success:     {}", success);
    info!("Failed:      {}", failed);
    info!("Throughput:  {:.2} PPS", throughput);
    info!("Avg Latency: {} ms", avg_lat);
    info!("==================================");

    Ok(())
}

fn no_hop(v: &VirtualNode) -> PathHop {
    PathHop {
        public_key: v.public_key,
        address: v.multiaddr.clone(),
    }
}

async fn spawn_mock_node(id: usize) -> anyhow::Result<VirtualNode> {
    let dir = tempdir()?;
    let db = Arc::new(SledRepository::new(dir.path())?);
    let event_bus = TokioEventBus::new(10000); // High capacity channel
    let pub_bus: Arc<dyn IEventPublisher> = Arc::new(event_bus.clone());
    let sub_bus: Arc<dyn IEventSubscriber> = Arc::new(event_bus.clone());

    let mut rng = rand::rngs::OsRng;
    let node_sk = X25519SecretKey::random_from_rng(rng);
    let node_pk = X25519PublicKey::from(&node_sk);
    let eth_wallet = LocalWallet::new(&mut rng);

    let config = {
        let mut c = NoxConfig::default();
        c.benchmark_mode = true; // ENABLE MOCK MODE
        c.p2p_port = 0;
        c.db_path = dir
            .path()
            .to_str()
            .expect("tempdir path should be valid UTF-8")
            .into();
        c.routing_private_key = hex::encode(node_sk.to_bytes());
        c.eth_wallet_private_key = hex::encode(eth_wallet.signer().to_bytes());
        c.min_profit_margin_percent = 0; // Accept everything in benchmark
        c.min_pow_difficulty = 0; // Disable PoW for benchmark
        c
    };

    // Services
    let topology = Arc::new(TopologyManager::new(db.clone(), sub_bus.clone(), None));
    let top_clone = topology.clone();
    tokio::spawn(async move { top_clone.run().await });

    // Setup P2P
    let metrics = nox_node::telemetry::metrics::MetricsService::new();
    let (tx, rx) = oneshot::channel();
    let mut p2p = P2PService::new(
        &config,
        pub_bus.clone(),
        sub_bus.clone(),
        db.clone(),
        metrics.clone(),
        topology.clone(),
    )
    .await?
    .with_bind_signal(tx);
    tokio::spawn(async move { p2p.run().await });
    let (pid, base_addr) = rx.await?;
    let full_addr = base_addr.with(Protocol::P2p(pid));

    // Important: Relayer Service
    let mix = Arc::new(PoissonMixStrategy::new(10.0)); // Fast mix
    let relayer = RelayerService::new(
        config.clone(),
        sub_bus.clone(),
        pub_bus.clone(),
        db.clone(),
        mix,
        metrics.clone(),
    );
    tokio::spawn(async move {
        if let Err(e) = relayer.run().await {
            eprintln!("Relayer failed to start: {}", e);
        }
    });

    // Chain & Exit
    let executor = Arc::new(ChainExecutor::new(&config).await?);
    let tx_manager =
        Arc::new(TransactionManager::new(executor.clone(), db.clone(), metrics.clone()).await?);

    // Wire up Exit
    // Mock Price Client
    let price_client = Arc::new(nox_node::price::client::PriceClient::new(
        "http://localhost:3000",
    ));

    let ethereum_handler = Arc::new(
        nox_node::services::handlers::ethereum::EthereumHandler::from_config(
            executor.clone(),
            tx_manager.clone(),
            metrics.clone(),
            0,
            price_client,
            &config.nox_reward_pool_address,
            config.max_broadcast_tx_size,
        )
        .expect("Failed to create EthereumHandler"),
    );
    let traffic_handler = Arc::new(nox_node::services::handlers::traffic::TrafficHandler {
        metrics: metrics.clone(),
    });
    let exit = ExitService::new(
        sub_bus.clone(),
        ethereum_handler,
        traffic_handler,
        metrics.clone(),
    );
    tokio::spawn(async move { exit.run().await });

    Ok(VirtualNode {
        id,
        multiaddr: full_addr.to_string(),
        public_key: node_pk,
        bus_publisher: pub_bus,
        bus_subscriber: sub_bus,
        _eth_address: eth_wallet.address(),
        _storage: db,
        _db_dir: dir,
    })
}
