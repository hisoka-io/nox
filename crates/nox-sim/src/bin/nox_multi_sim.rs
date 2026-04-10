//! Pure mixnet simulation -- no Ethereum, no ZK.
//!
//! Spins up N in-process NOX nodes with admin HTTP, cluster discovery on `:9000`,
//! and a live traffic generator (70% real URLs, 30% echo). Good for dashboard dev
//! and Sphinx routing validation.
//!
//! `cargo run --bin nox_multi_sim --features dev-node -- --nodes 15`

use anyhow::Result;
use clap::Parser;
use libp2p::multiaddr::Protocol;
use parking_lot::RwLock;
use rand::rngs::OsRng;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, warn, Level};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

use nox_client::{MixnetClient, MixnetClientConfig, TopologyNode};
use nox_core::events::NoxEvent;
use nox_core::traits::interfaces::{IEventPublisher, IEventSubscriber};
use nox_node::config::HttpConfig;
use nox_node::services::exit::ExitService;
use nox_node::services::mixing::PoissonMixStrategy;
use nox_node::services::network_manager::TopologyManager;
use nox_node::services::relayer::RelayerService;
use nox_node::services::response_packer::ResponsePacker;
use nox_node::services::traffic_shaping::TrafficShapingService;
use nox_node::telemetry::cluster::{spawn_cluster_api, NodeInfo};
use nox_node::telemetry::metrics::MetricsService;
use nox_node::{NodeRole, NoxConfig, NoxNode, SledRepository, TokioEventBus};

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "NOX Multi-Node Simulation -- cinematic 15-node mixnet for dashboard development"
)]
struct Args {
    /// Number of nodes to spawn (default 15, max 15). WSL2: use ≤10 to avoid OOM.
    #[arg(short, long, default_value_t = 15)]
    nodes: usize,

    /// Mix delay per hop in milliseconds (Poisson mean)
    #[arg(long, default_value_t = 50.0)]
    delay: f64,

    /// Proof-of-work difficulty (0 = disabled for sim)
    #[arg(long, default_value_t = 0)]
    pow_difficulty: u32,

    /// Admin port base (node-0 = base, node-1 = base+1, ...)
    #[arg(long, default_value_t = 9090)]
    admin_port_base: u16,

    /// Cluster discovery API port
    #[arg(long, default_value_t = 9000)]
    cluster_port: u16,
}

/// A complete NOX node running in-process.
#[allow(dead_code)]
struct VirtualNode {
    id: usize,
    multiaddr: String,
    public_key: X25519PublicKey,
    /// Loopix layer: 0=Entry, 1=Mix, 2=Exit
    layer: u8,
    /// Loopix role for registration: 1=Relay, 2=Exit
    role: u8,
    bus_publisher: Arc<dyn IEventPublisher>,
    bus_subscriber: Arc<dyn IEventSubscriber>,
    eth_address: String,
    topology_manager: Arc<TopologyManager>,
    /// Admin HTTP port (9090 + id)
    admin_port: u16,
    /// Ingress port (8080/8081/8082 for first 3 nodes, 0 otherwise)
    ingress_port: u16,
    // Keep alive
    _storage: Arc<SledRepository>,
    _db_dir: tempfile::TempDir,
}

/// Determine Loopix layer from node index and total node count.
/// - First 40%: layer 0 (Entry)
/// - Middle 30%: layer 1 (Mix)
/// - Last 30%: layer 2 (Exit/Full)
fn assign_layer(idx: usize, total: usize) -> u8 {
    let entry_end = (total as f64 * 0.4).ceil() as usize;
    let mix_end = entry_end + (total as f64 * 0.3).ceil() as usize;
    if idx < entry_end {
        0
    } else if idx < mix_end {
        1
    } else {
        2
    }
}

/// Spawn a single in-process NOX node (no Ethereum, no ZK).
#[allow(clippy::too_many_arguments)]
async fn spawn_virtual_node(
    id: usize,
    layer: u8,
    delay: f64,
    pow_difficulty: u32,
    admin_port: u16,
    ingress_port: u16,
) -> Result<VirtualNode> {
    let dir = tempdir()?;
    let db = Arc::new(SledRepository::new(dir.path())?);

    // Larger bus capacity for burst traffic during 15-node startup
    let event_bus = TokioEventBus::new(8192);
    let pub_bus: Arc<dyn IEventPublisher> = Arc::new(event_bus.clone());
    let sub_bus: Arc<dyn IEventSubscriber> = Arc::new(event_bus.clone());

    let rng = OsRng;
    let node_sk = X25519SecretKey::random_from_rng(rng);
    let node_pk = X25519PublicKey::from(&node_sk);

    // Generate a deterministic Ethereum-style address for identity
    let eth_bytes: [u8; 20] = rand::random();
    let eth_address = format!("0x{}", hex::encode(eth_bytes));

    let node_role = if layer == 2 {
        NodeRole::Exit
    } else {
        NodeRole::Relay
    };

    let config = {
        let mut c = NoxConfig::default();
        c.eth_rpc_url = "http://127.0.0.1:8545".into(); // placeholder, not used in sim
        c.p2p_listen_addr = "127.0.0.1".into();
        c.p2p_port = 0; // OS-assigned
        c.db_path = dir.path().to_str().unwrap_or_default().into();
        c.p2p_identity_path = dir
            .path()
            .join("id.key")
            .to_str()
            .unwrap_or_default()
            .into();
        c.routing_private_key = hex::encode(node_sk.to_bytes());
        // Placeholder wallet key -- not used since no EthereumHandler
        c.eth_wallet_private_key = hex::encode(rand::random::<[u8; 32]>());
        c.min_pow_difficulty = pow_difficulty;
        c.min_gas_balance = "0".into();
        // Zero address -> ChainObserver disabled (no registry contract)
        c.registry_contract_address = "0x0000000000000000000000000000000000000000".into();
        c.metrics_port = admin_port;
        c.ingress_port = ingress_port;
        c.node_role = node_role;
        // Cover traffic: low rate for sim clarity
        c.relayer.cover_traffic_rate = 0.02;
        c.relayer.drop_traffic_rate = 0.02;
        c
    };

    let metrics = MetricsService::new();

    // Topology Manager
    let topology = Arc::new(TopologyManager::new(db.clone(), sub_bus.clone(), None));
    let topo_clone = topology.clone();
    tokio::spawn(async move {
        topo_clone.run().await;
    });

    // P2P Service -- uses a oneshot to get the bound multiaddr
    let (tx, rx) = oneshot::channel();
    let mut p2p = nox_node::network::service::P2PService::new(
        &config,
        pub_bus.clone(),
        sub_bus.clone(),
        db.clone(),
        metrics.clone(),
        topology.clone(),
    )
    .await?
    .with_bind_signal(tx);
    tokio::spawn(async move {
        p2p.run().await;
    });
    let (pid, base_addr) = rx.await?;
    let full_addr = base_addr.with(Protocol::P2p(pid));

    // Cover Traffic (Loopix loop + drop messages)
    let cover = TrafficShapingService::new(
        config.clone(),
        topology.clone(),
        pub_bus.clone(),
        metrics.clone(),
    );
    tokio::spawn(async move {
        cover.run().await;
    });

    // Relayer Service (Sphinx decryption + mix delay + forwarding)
    let mix = Arc::new(PoissonMixStrategy::new(delay));
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
            error!("Relayer[{id}] failed: {e}");
        }
    });

    // Exit Service -- only exit-layer nodes process service requests
    if layer == 2 {
        let response_packer = Arc::new(ResponsePacker::new().with_metrics(metrics.clone()));

        // HTTP proxy handler (makes real internet requests)
        let http_config = HttpConfig {
            allowed_domains: None, // open web, SSRF still enforced
            allow_private_ips: false,
            request_timeout_secs: 15,
            max_response_bytes: 256 * 1024, // 256 KB truncation
        };
        let pending_map = ExitService::new_pending_map();
        let surb_acc = ExitService::new_surb_accumulator();
        let stash = ExitService::make_stash_closure(
            pending_map.clone(),
            surb_acc.clone(),
            response_packer.clone(),
            pub_bus.clone(),
        );
        let http_handler = Arc::new(
            nox_node::services::handlers::http::HttpHandler::new(
                http_config,
                response_packer.clone(),
                pub_bus.clone(),
                metrics.clone(),
            )
            .with_stash_remaining(stash),
        );

        // Echo handler (in-process round-trip testing)
        let echo_handler = Arc::new(nox_node::services::handlers::echo::EchoHandler::new(
            response_packer.clone(),
            pub_bus.clone(),
        ));

        // Traffic handler (cover traffic, drop packets)
        let traffic_handler = Arc::new(nox_node::services::handlers::traffic::TrafficHandler {
            metrics: metrics.clone(),
        });

        // ExitService::simulation() -- no Ethereum handler
        let exit = ExitService::simulation(
            sub_bus.clone(),
            traffic_handler,
            http_handler,
            echo_handler,
            metrics.clone(),
        )
        .with_pending_replenishments(pending_map)
        .with_surb_accumulator(surb_acc)
        .with_publisher(pub_bus.clone());
        tokio::spawn(async move {
            exit.run().await;
        });
    }

    // Admin HTTP server: /metrics, /topology, /events
    // node_id = Ethereum-style address (public identity, not privacy-sensitive)
    NoxNode::spawn_metrics(
        admin_port,
        sub_bus.clone(),
        topology.clone(),
        eth_address.clone(),
    );

    let role = if layer == 2 { 2u8 } else { 1u8 };

    info!(
        "[nox-{}] ({}) addr={} admin=:{} eth={}",
        id,
        match layer {
            0 => "Entry",
            1 => "Mix",
            _ => "Exit",
        },
        full_addr,
        admin_port,
        &eth_address[..10],
    );

    Ok(VirtualNode {
        id,
        multiaddr: full_addr.to_string(),
        public_key: node_pk,
        layer,
        role,
        bus_publisher: pub_bus,
        bus_subscriber: sub_bus,
        eth_address,
        topology_manager: topology,
        admin_port,
        ingress_port,
        _storage: db,
        _db_dir: dir,
    })
}

/// URLs to probe via the HTTP proxy handler (70% of traffic).
static HTTP_TARGETS: &[(&str, &str, &str)] = &[
    // CoinGecko (rate-limited to 1 req/5s -- handled by task sleep)
    ("GET", "https://api.coingecko.com/api/v3/ping", "coingecko"),
    // Binance ticker
    (
        "GET",
        "https://api.binance.com/api/v3/ticker/price?symbol=ETHUSDT",
        "binance",
    ),
    // Chuck Norris facts (fast, reliable)
    ("GET", "https://api.chucknorris.io/jokes/random", "chuck"),
    // Public Ethereum RPC (no-auth eth_blockNumber)
    ("GET", "https://eth.llamarpc.com", "llamarpc"),
    // Wikipedia random article summary (JSON endpoint, not HTML)
    (
        "GET",
        "https://en.wikipedia.org/api/rest_v1/page/random/summary",
        "wikipedia",
    ),
];

/// Spawn the traffic generator tasks. Injects packets into entry nodes via the mixnet.
///
/// Uses per-client `MixnetClient` instances, one per entry node, so load is balanced.
/// Responses arrive via SURB wiring but are not awaited -- fire-and-forget for the sim.
fn spawn_traffic_generator(
    nodes: &[VirtualNode],
    topology: Arc<RwLock<Vec<TopologyNode>>>,
    pow_difficulty: u32,
) {
    let entry_nodes: Vec<_> = nodes.iter().filter(|n| n.layer == 0).collect();
    if entry_nodes.is_empty() {
        warn!("No entry nodes -- traffic generator disabled");
        return;
    }

    // For each entry node, create a MixnetClient and spawn a traffic task
    for entry in &entry_nodes {
        let entry_pub = entry.bus_publisher.clone();
        let entry_pk = entry.public_key.to_bytes();
        let entry_sub = entry.bus_subscriber.clone();
        let entry_id = entry.id;
        let topo = topology.clone();

        let (response_tx, response_rx) = mpsc::channel::<(String, Vec<u8>)>(512);

        let config = MixnetClientConfig {
            timeout: Duration::from_secs(30),
            pow_difficulty,
            surbs_per_request: 5,
            entry_node_pubkey: Some(entry_pk),
            default_fec_ratio: 0.3,
            ..Default::default()
        };

        let client = Arc::new(MixnetClient::new(topo, entry_pub, response_rx, config));

        // SURB response wiring -- listen for decrypted payloads on this entry node
        let node_sub = entry_sub.clone();
        let resp_tx = response_tx.clone();
        tokio::spawn(async move {
            let mut rx = node_sub.subscribe();
            loop {
                match rx.recv().await {
                    Ok(NoxEvent::PayloadDecrypted { packet_id, payload }) => {
                        let _ = resp_tx.send((packet_id, payload)).await;
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!("SURB wiring on entry-{entry_id} lagged {n}");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        // Response loop
        let client_clone = client.clone();
        tokio::spawn(async move {
            client_clone.run_response_loop().await;
        });

        // Traffic task
        let client_clone = client.clone();
        tokio::spawn(async move {
            run_traffic_loop(client_clone, entry_id).await;
        });
    }

    info!(
        "Traffic generator started: {} entry nodes, 70% HTTP / 30% echo",
        entry_nodes.len()
    );
}

/// Single traffic loop for one `MixnetClient` -- runs until process exits.
async fn run_traffic_loop(client: Arc<MixnetClient>, entry_id: usize) {
    // Stagger start to avoid synchronized bursts
    tokio::time::sleep(Duration::from_millis((entry_id as u64 + 1) * 500)).await;

    let mut req_count = 0u64;

    loop {
        let use_echo = rand::random::<f64>() < 0.30;

        if use_echo {
            // Echo request -- fully in-process, guaranteed to work
            let data = format!("nox-sim echo #{req_count} from entry-{entry_id}");
            match client.send_echo(data.into_bytes()).await {
                Ok(_) => {}
                Err(e) => {
                    warn!("Echo error (entry-{entry_id}): {e}");
                }
            }
        } else {
            // Real HTTP request -- pick a random target
            let targets_len = HTTP_TARGETS.len();
            let idx = (rand::random::<usize>()) % targets_len;
            let (method, url, name) = HTTP_TARGETS[idx];

            // CoinGecko: enforce 1 req/5s ceiling
            let base_sleep_ms = if name == "coingecko" { 5000u64 } else { 200u64 };

            match client
                .send_http_request(url, method, vec![], vec![], 0)
                .await
            {
                Ok(_) => {
                    info!("[traffic/entry-{entry_id}] HTTP {name} ok (req #{req_count})");
                }
                Err(e) => {
                    // Network failures are expected (rate limits, DNS, etc.) -- don't crash
                    warn!("[traffic/entry-{entry_id}] HTTP {name} err: {e}");
                }
            }

            tokio::time::sleep(Duration::from_millis(base_sleep_ms)).await;
        }

        // Burst mode: 10% chance to fire 5 fast requests
        if rand::random::<f64>() < 0.10 {
            for _ in 0..5 {
                let burst_data = format!("burst-{req_count}");
                let _ = client.send_echo(burst_data.into_bytes()).await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }

        req_count += 1;

        // Random inter-request pause: 200ms-1s baseline, 2-10s occasional
        let pause_ms = if rand::random::<f64>() < 0.05 {
            2000 + (rand::random::<u64>() % 8000)
        } else {
            200 + (rand::random::<u64>() % 800)
        };
        tokio::time::sleep(Duration::from_millis(pause_ms)).await;
    }
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<()> {
    // Logging to stderr (stdout reserved for structured JSON output)
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber).ok();

    let args = Args::parse();
    let node_count = args.nodes.clamp(1, 15);

    info!("╔════════════════════════════════════════════════╗");
    info!("║  NOX MULTI-NODE SIM  ({node_count} nodes)            ║");
    info!(
        "║  Admin ports: {}-{}               ║",
        args.admin_port_base,
        args.admin_port_base + node_count as u16 - 1
    );
    info!(
        "║  Cluster API: http://localhost:{}/cluster  ║",
        args.cluster_port
    );
    info!("╚════════════════════════════════════════════════╝");

    // 1. Start cluster discovery API (returns shared state for registration)
    let cluster_state = spawn_cluster_api(args.cluster_port).await;

    // 2. Spawn all nodes concurrently
    info!("Spawning {node_count} nodes...");
    let mut handles = Vec::new();
    for i in 0..node_count {
        let layer = assign_layer(i, node_count);
        let admin_port = args.admin_port_base + i as u16;
        let ingress_port = if i < 3 { 8080 + i as u16 } else { 0 };
        let delay = args.delay;
        let pow = args.pow_difficulty;

        handles.push(tokio::spawn(async move {
            spawn_virtual_node(i, layer, delay, pow, admin_port, ingress_port).await
        }));
    }

    // Collect results -- fail fast if any node fails
    let mut nodes: Vec<VirtualNode> = Vec::new();
    for (i, handle) in handles.into_iter().enumerate() {
        match handle.await {
            Ok(Ok(node)) => nodes.push(node),
            Ok(Err(e)) => {
                error!("Node {i} failed to spawn: {e}");
                return Err(e);
            }
            Err(e) => {
                error!("Node {i} task panicked: {e}");
                return Err(anyhow::anyhow!("Node {i} panicked: {e}"));
            }
        }
    }

    // 3. Register all nodes in cluster state
    {
        let mut state = cluster_state.write().await;
        for node in &nodes {
            state.push(NodeInfo {
                id: format!("nox-{}", node.id),
                address: node.eth_address.clone(),
                role: node.role,
                layer: node.layer,
                admin_port: node.admin_port,
                ingress_port: node.ingress_port,
                p2p_addr: node.multiaddr.clone(),
            });
        }
    }
    info!("Registered {} nodes in cluster API", nodes.len());

    // 4. Mesh wiring -- publish RelayerRegistered to every node's bus for every other node
    // (including self -- so /topology returns the full set including itself)
    info!("Wiring mesh ({} connections)...", nodes.len() * nodes.len());
    for target in &nodes {
        for source in &nodes {
            source.bus_publisher.publish(NoxEvent::RelayerRegistered {
                address: target.eth_address.clone(),
                sphinx_key: hex::encode(target.public_key.as_bytes()),
                url: target.multiaddr.clone(),
                stake: "1000".to_string(),
                role: target.role,
                ingress_url: None,
                metadata_url: None,
            })?;
        }
    }

    // Wait for mesh stabilization
    info!("Waiting for mesh stabilization (3s)...");
    tokio::time::sleep(Duration::from_secs(3)).await;

    let entry_count = nodes.iter().filter(|n| n.layer == 0).count();
    let mix_count = nodes.iter().filter(|n| n.layer == 1).count();
    let exit_count = nodes.iter().filter(|n| n.layer == 2).count();
    info!("Mesh ready: {entry_count} Entry | {mix_count} Mix | {exit_count} Exit");

    // 5. Build shared topology for traffic generator clients.
    // TopologyNode.address = libp2p multiaddr (used for routing).
    // TopologyNode.eth_address = parsed Ethereum address (zero if parse fails).
    let shared_topology: Arc<RwLock<Vec<TopologyNode>>> = Arc::new(RwLock::new(
        nodes
            .iter()
            .map(|n| TopologyNode {
                id: format!("nox-{}", n.id),
                address: n.multiaddr.clone(),
                public_key: n.public_key.to_bytes(),
                layer: n.layer,
                eth_address: n.eth_address.parse().unwrap_or_default(),
                role: n.role,
            })
            .collect(),
    ));

    // 6. Start traffic generator
    spawn_traffic_generator(&nodes, shared_topology, args.pow_difficulty);

    // 7. Emit startup JSON to stdout for tooling / dashboard auto-discovery
    let nodes_json: Vec<serde_json::Value> = nodes
        .iter()
        .map(|n| {
            serde_json::json!({
                "id": format!("nox-{}", n.id),
                "address": n.eth_address,
                "layer": n.layer,
                "role": n.role,
                "admin_port": n.admin_port,
            })
        })
        .collect();
    println!(
        "{}",
        serde_json::json!({
            "cluster_port": args.cluster_port,
            "node_count": nodes.len(),
            "nodes": nodes_json
        })
    );

    info!("NOX simulation running. Press Ctrl+C to stop.");

    // 8. Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("Received Ctrl+C -- shutting down.");

    Ok(())
}
