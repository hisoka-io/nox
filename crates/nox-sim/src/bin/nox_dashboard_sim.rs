//! Full-stack dashboard simulation with on-chain topology discovery.
//!
//! Unlike `nox_multi_sim`, nodes here discover each other through `NoxRegistry`
//! events on-chain (`ChainObserver` -> `TopologyManager`), matching the production
//! code path. Spins up Anvil, registers N nodes, and generates mixed traffic.
//!
//! ```sh
//! cargo run -p nox-sim --bin nox_dashboard_sim --features dev-node -- --nodes 10
//! ```
//!
//! Cluster API on `:9000`, per-node admin on `:9090+`.

use anyhow::Result;
use clap::Parser;
use ethers::prelude::*;
use ethers::utils::Anvil;
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
use nox_node::services::handlers;
use nox_node::services::mixing::PoissonMixStrategy;
use nox_node::services::network_manager::TopologyManager;
use nox_node::services::relayer::RelayerService;
use nox_node::services::response_packer::ResponsePacker;
use nox_node::services::traffic_shaping::TrafficShapingService;
use nox_node::telemetry::cluster::{spawn_cluster_api, NodeInfo};
use nox_node::{NodeRole, NoxConfig, NoxNode, SledRepository, TokioEventBus};

use nox_node::blockchain::observer::ChainObserver;

use nox_test_infra::contracts::{MockERC20, NoxRegistry};

#[derive(Parser, Debug, Clone)]
#[command(
    author,
    version,
    about = "NOX Dashboard Simulation -- full-stack mesh with on-chain topology"
)]
struct Args {
    /// Number of nodes to spawn (5-50)
    #[arg(short, long, default_value_t = 10)]
    nodes: usize,

    /// Base port for node allocation (node-i uses base+i*10 for P2P, +1 metrics, +2 ingress, +3 topology API)
    #[arg(long, default_value_t = 15000)]
    base_port: u16,

    /// Cluster discovery API port
    #[arg(long, default_value_t = 9000)]
    cluster_port: u16,

    /// Mix delay per hop in milliseconds (Poisson mean)
    #[arg(long, default_value_t = 1.0)]
    mix_delay_ms: f64,

    /// Fraction of nodes assigned as entry (layer 0)
    #[arg(long, default_value_t = 0.3)]
    entry_ratio: f64,

    /// Fraction of nodes assigned as exit (layer 2)
    #[arg(long, default_value_t = 0.3)]
    exit_ratio: f64,

    /// Enable periodic admin churn (register/deregister random nodes)
    #[arg(long, default_value_t = false)]
    enable_churn: bool,

    /// Churn interval in seconds (only if --enable-churn)
    #[arg(long, default_value_t = 60)]
    churn_interval_secs: u64,

    /// Proof-of-work difficulty (0 = disabled for sim)
    #[arg(long, default_value_t = 0)]
    pow_difficulty: u32,

    /// Anvil block time in seconds (0 = instant mining)
    #[arg(long, default_value_t = 1)]
    block_time: u64,
}

/// Deployed contract addresses for the dashboard API (`NoxRegistry`, `NoxRewardPool`, etc.).
#[derive(Clone, serde::Serialize)]
struct DeployedAddresses {
    nox_registry: String,
    nox_reward_pool: String,
    mock_token: String,
    anvil_rpc: String,
    admin_address: String,
}

/// A single in-process NOX node with real `ChainObserver`.
#[allow(dead_code)]
struct DashboardNode {
    id: usize,
    multiaddr: String,
    public_key: X25519PublicKey,
    secret_key_bytes: [u8; 32],
    layer: u8,
    role: u8,
    eth_address: String,
    wallet_address: Address,
    bus_publisher: Arc<dyn IEventPublisher>,
    bus_subscriber: Arc<dyn IEventSubscriber>,
    topology_manager: Arc<TopologyManager>,
    admin_port: u16,
    ingress_port: u16,
    topology_api_port: u16,
    p2p_port: u16,
    _storage: Arc<SledRepository>,
    _db_dir: tempfile::TempDir,
}

/// Pre-generated identity for a node (created before spawn so we can register on-chain first).
#[allow(dead_code)]
struct NodeIdentity {
    id: usize,
    secret_key: X25519SecretKey,
    public_key: X25519PublicKey,
    eth_wallet: LocalWallet,
    layer: u8,
    role: u8,
    p2p_port: u16,
    admin_port: u16,
    ingress_port: u16,
    topology_api_port: u16,
}

fn assign_layer(idx: usize, total: usize, entry_ratio: f64, exit_ratio: f64) -> u8 {
    let entry_end = (total as f64 * entry_ratio).ceil() as usize;
    let mix_end = total - (total as f64 * exit_ratio).ceil() as usize;
    if idx < entry_end {
        0 // Entry
    } else if idx < mix_end {
        1 // Mix
    } else {
        2 // Exit
    }
}

async fn deploy_lightweight_contracts(
    anvil_rpc: &str,
) -> Result<(
    Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
    DeployedAddresses,
    NoxRegistry<SignerMiddleware<Provider<Http>, LocalWallet>>,
    MockERC20<SignerMiddleware<Provider<Http>, LocalWallet>>,
)> {
    info!("Phase 1: Deploying lightweight contracts...");

    let provider = Provider::<Http>::try_from(anvil_rpc)?.interval(Duration::from_millis(100));
    let chain_id = provider.get_chainid().await?.as_u64();

    // Use Anvil's first default account as admin
    let admin_wallet: LocalWallet =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse::<LocalWallet>()?
            .with_chain_id(chain_id);
    let admin_address = admin_wallet.address();

    let client = Arc::new(SignerMiddleware::new(provider, admin_wallet));

    // 1. Deploy MockERC20 (staking token)
    info!("  [1/3] Deploying MockERC20 (staking token)...");
    let token = MockERC20::deploy(
        client.clone(),
        ("NOX Stake Token".to_string(), "sNOX".to_string(), 18u8),
    )
    .map_err(|e| anyhow::anyhow!("MockERC20 deploy error: {e}"))?
    .send()
    .await
    .map_err(|e| anyhow::anyhow!("MockERC20 send error: {e}"))?;
    info!("         MockERC20 at: {:?}", token.address());

    // 2. Deploy NoxRewardPool
    info!("  [2/3] Deploying NoxRewardPool...");
    let reward_pool =
        nox_test_infra::contracts::NoxRewardPool::deploy(client.clone(), admin_address)
            .map_err(|e| anyhow::anyhow!("NoxRewardPool deploy error: {e}"))?
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("NoxRewardPool send error: {e}"))?;
    info!("         NoxRewardPool at: {:?}", reward_pool.address());

    // 3. Deploy NoxRegistry
    info!("  [3/3] Deploying NoxRegistry...");
    // Constructor: (admin, stakingToken, minStake, unstakeDelay)
    // minStake = 0 for sim (privileged registration doesn't need stake anyway)
    // unstakeDelay = 86400 (1 day minimum enforced by contract)
    let registry = NoxRegistry::deploy(
        client.clone(),
        (
            admin_address,
            token.address(),
            U256::zero(),      // minStake = 0 for sim
            U256::from(86400), // unstakeDelay = 1 day (contract minimum)
        ),
    )
    .map_err(|e| anyhow::anyhow!("NoxRegistry deploy error: {e}"))?
    .send()
    .await
    .map_err(|e| anyhow::anyhow!("NoxRegistry send error: {e}"))?;
    info!("         NoxRegistry at: {:?}", registry.address());

    // Enable token in reward pool
    reward_pool
        .set_asset_status(token.address(), true)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("set_asset_status error: {e}"))?;

    let addresses = DeployedAddresses {
        nox_registry: format!("{:?}", registry.address()),
        nox_reward_pool: format!("{:?}", reward_pool.address()),
        mock_token: format!("{:?}", token.address()),
        anvil_rpc: anvil_rpc.to_string(),
        admin_address: format!("{admin_address:?}"),
    };

    info!("Phase 1 complete: 3 contracts deployed.");
    Ok((client, addresses, registry, token))
}

async fn register_nodes_on_chain(
    registry: &NoxRegistry<SignerMiddleware<Provider<Http>, LocalWallet>>,
    nodes: &[DashboardNode],
) -> Result<()> {
    info!(
        "Phase 3: Admin agent registering {} nodes on-chain...",
        nodes.len()
    );

    for node in nodes {
        let sphinx_key_bytes: [u8; 32] = node.public_key.to_bytes();
        let on_chain_role = node.role;

        // Use the FULL multiaddr including PeerId so P2P can dial peers
        let url = node.multiaddr.clone();

        registry
            .register_privileged(node.wallet_address, sphinx_key_bytes, url, on_chain_role)
            .send()
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to register node {} ({:?}): {e}",
                    node.id,
                    node.wallet_address
                )
            })?;

        let layer_name = match node.layer {
            0 => "Entry",
            1 => "Mix",
            _ => "Exit",
        };
        info!(
            "  Registered node-{} as {layer_name} (layer {}) at {}",
            node.id, node.layer, node.multiaddr,
        );
    }

    // Verify on-chain count
    let count: U256 = registry
        .relayer_count()
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("relayer_count call failed: {e}"))?;
    let fingerprint: [u8; 32] = registry
        .topology_fingerprint()
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("topology_fingerprint call failed: {e}"))?;
    info!(
        "Phase 2 complete: {} nodes registered on-chain. Fingerprint: 0x{}",
        count,
        hex::encode(fingerprint)
    );

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn spawn_dashboard_node(
    ident: &NodeIdentity,
    anvil_rpc: &str,
    registry_address: &str,
    mix_delay_ms: f64,
    pow_difficulty: u32,
) -> Result<DashboardNode> {
    let dir = tempdir()?;
    let db = Arc::new(SledRepository::new(dir.path())?);

    let event_bus = TokioEventBus::new(8192);
    let pub_bus: Arc<dyn IEventPublisher> = Arc::new(event_bus.clone());
    let sub_bus: Arc<dyn IEventSubscriber> = Arc::new(event_bus.clone());

    let node_role = if ident.layer == 2 {
        NodeRole::Exit
    } else {
        NodeRole::Relay
    };

    let config = {
        let mut c = NoxConfig::default();
        c.eth_rpc_url = anvil_rpc.into();
        c.registry_contract_address = registry_address.into();
        c.p2p_listen_addr = "127.0.0.1".into();
        c.p2p_port = ident.p2p_port;
        c.db_path = dir.path().to_str().unwrap_or_default().into();
        c.p2p_identity_path = dir
            .path()
            .join("id.key")
            .to_str()
            .unwrap_or_default()
            .into();
        c.routing_private_key = hex::encode(ident.secret_key.to_bytes());
        c.eth_wallet_private_key = hex::encode(ident.eth_wallet.signer().to_bytes());
        c.min_pow_difficulty = pow_difficulty;
        c.min_gas_balance = "0".into();
        c.metrics_port = ident.admin_port;
        c.ingress_port = ident.ingress_port;
        c.topology_api_port = ident.topology_api_port;
        c.node_role = node_role;
        c.block_poll_interval_secs = 2; // Fast polling for sim
        c.relayer.cover_traffic_rate = 0.02;
        c.relayer.drop_traffic_rate = 0.02;
        c.relayer.mix_delay_ms = mix_delay_ms;
        c.benchmark_mode = true; // Enables mock ChainExecutor for exit nodes
        c
    };

    // Topology Manager (must be created before spawn_metrics which needs it)
    let topology = Arc::new(TopologyManager::new(db.clone(), sub_bus.clone(), None));
    let topo_run = topology.clone();
    tokio::spawn(async move {
        topo_run.run().await;
    });

    // Admin HTTP server: /metrics, /metrics/json, /topology, /events
    // MUST be created first -- returns the MetricsService that all services share.
    let metrics = NoxNode::spawn_metrics(
        ident.admin_port,
        sub_bus.clone(),
        topology.clone(),
        format!("{:?}", ident.eth_wallet.address()),
    );

    // Set node start time + spawn ProcessMonitor for uptime/health/mem/fds
    let start_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    metrics.node_start_time_seconds.set(start_epoch);

    let process_monitor =
        nox_node::telemetry::process::ProcessMonitor::new(metrics.clone(), start_epoch);
    let role_name = match ident.layer {
        0 => "entry",
        1 => "mix",
        _ => "exit",
    };
    process_monitor.record_build_info("dashboard-sim", role_name);
    tokio::spawn(async move {
        process_monitor.run().await;
    });

    // P2P Service
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

    // Cover Traffic
    let cover = TrafficShapingService::new(
        config.clone(),
        topology.clone(),
        pub_bus.clone(),
        metrics.clone(),
    );
    tokio::spawn(async move {
        cover.run().await;
    });

    // Relayer Service (Sphinx peel + mix delay + forwarding)
    let mix = Arc::new(PoissonMixStrategy::new(mix_delay_ms));
    let relayer = RelayerService::new(
        config.clone(),
        sub_bus.clone(),
        pub_bus.clone(),
        db.clone(),
        mix,
        metrics.clone(),
    );
    let node_id_for_relayer = ident.id;
    tokio::spawn(async move {
        if let Err(e) = relayer.run().await {
            error!("Relayer[{node_id_for_relayer}] failed: {e}");
        }
    });

    // Exit Service -- only exit-layer nodes
    if ident.layer == 2 {
        let response_packer = Arc::new(ResponsePacker::new().with_metrics(metrics.clone()));

        let http_config = HttpConfig {
            allowed_domains: None,
            allow_private_ips: true, // Anvil runs on localhost -- must allow for sim
            request_timeout_secs: 15,
            max_response_bytes: 128 * 1024 * 1024,
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
            handlers::http::HttpHandler::new(
                http_config,
                response_packer.clone(),
                pub_bus.clone(),
                metrics.clone(),
            )
            .with_stash_remaining(stash),
        );
        let echo_handler = Arc::new(handlers::echo::EchoHandler::new(
            response_packer.clone(),
            pub_bus.clone(),
        ));
        let traffic_handler = Arc::new(handlers::traffic::TrafficHandler {
            metrics: metrics.clone(),
        });

        // ExitService::simulation -- HTTP + Echo handlers only.
        // RPC requests from clients use rpc_call_via_http() which goes through the
        // HTTP handler path instead (avoids needing EthereumHandler dependency).
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

    // ChainObserver -- THE REAL PIPELINE: watches NoxRegistry events on-chain
    let registry_hex = config.registry_contract_address.clone();
    let observer = ChainObserver::new(
        &config,
        &registry_hex,
        pub_bus.clone(),
        db.clone() as Arc<dyn nox_core::traits::interfaces::IStorageRepository>,
        metrics.clone(),
    )
    .map_err(|e| anyhow::anyhow!("ChainObserver init error: {e}"))?;
    let observer_handle = observer.with_cancel_token(CancellationToken::new());
    tokio::spawn(async move {
        observer_handle.start().await;
    });

    // Ingress server for HTTP packet injection
    if ident.ingress_port > 0 {
        let response_buffer = Arc::new(
            nox_node::ingress::response_buffer::ResponseBuffer::with_ttl(Duration::from_secs(120)),
        );
        let ingress_state = Arc::new(nox_node::ingress::http_server::IngressState {
            event_publisher: pub_bus.clone(),
            response_buffer: response_buffer.clone(),
            metrics: metrics.clone(),
            long_poll_timeout: Duration::from_secs(30),
            min_pow_difficulty: 0,
        });
        let router = nox_node::ingress::http_server::IngressServer::router(ingress_state);
        let ingress_addr: std::net::SocketAddr =
            format!("0.0.0.0:{}", ident.ingress_port).parse()?;
        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(ingress_addr).await {
                Ok(listener) => {
                    if let Err(e) = axum::serve(listener, router).await {
                        error!("Ingress server error: {e}");
                    }
                }
                Err(e) => error!("Failed to bind ingress on {}: {e}", ingress_addr),
            }
        });

        // Response router: SURB responses -> buffer for HTTP polling
        let resp_router = nox_node::ingress::response_router::ResponseRouter::new(
            sub_bus.clone(),
            response_buffer,
            60, // prune_interval_secs
            metrics.clone(),
        );
        tokio::spawn(async move {
            resp_router.run().await;
        });
    }

    // Topology API (public seed endpoint) -- serves the same JSON as production nodes
    if ident.topology_api_port > 0 {
        let topo_api = topology.clone();
        let topo_port = ident.topology_api_port;
        tokio::spawn(async move {
            let app = axum::Router::new().route(
                "/topology",
                axum::routing::get({
                    let tm = topo_api.clone();
                    move || {
                        let tm = tm.clone();
                        async move {
                            let nodes = tm.get_all_nodes();
                            let fingerprint = hex::encode(tm.get_current_fingerprint());
                            axum::Json(serde_json::json!({
                                "nodes": nodes,
                                "fingerprint": fingerprint,
                                "timestamp": std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                                "block_number": 0u64,
                            }))
                        }
                    }
                }),
            );
            let addr: std::net::SocketAddr = ([0, 0, 0, 0], topo_port).into();
            match tokio::net::TcpListener::bind(addr).await {
                Ok(listener) => {
                    if let Err(e) = axum::serve(listener, app).await {
                        error!("Topology API error: {e}");
                    }
                }
                Err(e) => error!("Failed to bind topology API on {addr}: {e}"),
            }
        });
    }

    let layer_name = match ident.layer {
        0 => "Entry",
        1 => "Mix",
        _ => "Exit",
    };
    info!(
        "[node-{}] {} addr={} admin=:{} ingress=:{} topo_api=:{} eth={:?}",
        ident.id,
        layer_name,
        full_addr,
        ident.admin_port,
        ident.ingress_port,
        ident.topology_api_port,
        ident.eth_wallet.address(),
    );

    Ok(DashboardNode {
        id: ident.id,
        multiaddr: full_addr.to_string(),
        public_key: ident.public_key,
        secret_key_bytes: ident.secret_key.to_bytes(),
        layer: ident.layer,
        role: if ident.layer == 2 { 2 } else { 1 },
        eth_address: format!("{:?}", ident.eth_wallet.address()),
        wallet_address: ident.eth_wallet.address(),
        bus_publisher: pub_bus,
        bus_subscriber: sub_bus,
        topology_manager: topology,
        admin_port: ident.admin_port,
        ingress_port: ident.ingress_port,
        topology_api_port: ident.topology_api_port,
        p2p_port: ident.p2p_port,
        _storage: db,
        _db_dir: dir,
    })
}

use tokio_util::sync::CancellationToken;

async fn spawn_dashboard_api(
    cluster_port: u16,
    addresses: DeployedAddresses,
    args: Args,
) -> Arc<tokio::sync::RwLock<Vec<NodeInfo>>> {
    let cluster_state = spawn_cluster_api(cluster_port).await;

    // Extended endpoints on cluster_port + 1
    let addr_state = Arc::new(addresses);
    let args_state = Arc::new(args);

    let ext_app = axum::Router::new()
        .route(
            "/contracts",
            axum::routing::get({
                let addrs = addr_state.clone();
                move || {
                    let a = addrs.clone();
                    async move { axum::Json((*a).clone()) }
                }
            }),
        )
        .route(
            "/config",
            axum::routing::get({
                let cfg = args_state.clone();
                move || {
                    let c = cfg.clone();
                    async move {
                        axum::Json(serde_json::json!({
                            "nodes": c.nodes,
                            "base_port": c.base_port,
                            "mix_delay_ms": c.mix_delay_ms,
                            "entry_ratio": c.entry_ratio,
                            "exit_ratio": c.exit_ratio,
                            "enable_churn": c.enable_churn,
                            "churn_interval_secs": c.churn_interval_secs,
                            "pow_difficulty": c.pow_difficulty,
                            "block_time": c.block_time,
                        }))
                    }
                }
            }),
        );

    let ext_addr: std::net::SocketAddr = ([127, 0, 0, 1], cluster_port + 1).into();
    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(ext_addr).await {
            Ok(listener) => {
                info!(
                    "Extended dashboard API: http://{}/contracts, http://{}/config",
                    ext_addr, ext_addr
                );
                if let Err(e) = axum::serve(listener, ext_app).await {
                    error!("Extended API error: {e}");
                }
            }
            Err(e) => error!("Failed to bind extended API on {ext_addr}: {e}"),
        }
    });

    cluster_state
}

/// URLs for web2 HTTP proxy requests.
static HTTP_TARGETS: &[(&str, &str, &str)] = &[
    ("GET", "https://api.coingecko.com/api/v3/ping", "coingecko"),
    (
        "GET",
        "https://api.binance.com/api/v3/ticker/price?symbol=ETHUSDT",
        "binance",
    ),
    ("GET", "https://api.chucknorris.io/jokes/random", "chuck"),
    (
        "GET",
        "https://en.wikipedia.org/api/rest_v1/page/random/summary",
        "wikipedia",
    ),
    ("GET", "https://httpbin.org/bytes/512", "httpbin"),
];

/// Web3 RPC methods for anonymous reads (sent as HTTP POST to Anvil via the HTTP proxy).
static RPC_METHODS: &[(&str, &str)] = &[
    ("eth_blockNumber", "[]"),
    ("eth_chainId", "[]"),
    ("eth_gasPrice", "[]"),
    ("net_version", "[]"),
];

/// Spawn Client A: web2 HTTP reads through the mixnet.
fn spawn_web2_traffic(client: Arc<MixnetClient>, client_name: &'static str) {
    tokio::spawn(async move {
        // Stagger start
        tokio::time::sleep(Duration::from_secs(5)).await;
        info!("[{client_name}] Starting web2 HTTP traffic...");

        let mut req = 0u64;
        loop {
            let idx = (rand::random::<usize>()) % HTTP_TARGETS.len();
            let (method, url, name) = HTTP_TARGETS[idx];

            match client
                .send_http_request(url, method, vec![], vec![], 0)
                .await
            {
                Ok(resp) => {
                    info!(
                        "[{client_name}] HTTP {name} ok ({} bytes, req #{req})",
                        resp.len()
                    );
                }
                Err(e) => {
                    warn!("[{client_name}] HTTP {name} err: {e} (req #{req})");
                }
            }

            req += 1;
            let pause = 2000 + (rand::random::<u64>() % 8000);
            tokio::time::sleep(Duration::from_millis(pause)).await;
        }
    });
}

/// Public Ethereum RPC endpoints for anonymous web3 reads through the mixnet.
/// These are real mainnet/testnet endpoints -- the exit node's HTTP handler
/// proxies the JSON-RPC POST to them (no loopback SSRF issue).
static PUBLIC_RPC_ENDPOINTS: &[&str] = &[
    "https://eth.llamarpc.com",
    "https://rpc.ankr.com/eth",
    "https://ethereum-rpc.publicnode.com",
];

/// Spawn Client B: web3 RPC reads through the mixnet (via HTTP POST to public RPCs).
///
/// Uses `send_http_request` with JSON-RPC POST bodies routed through the exit's
/// HTTP handler to public Ethereum RPC endpoints.
fn spawn_web3_read_traffic(client: Arc<MixnetClient>, client_name: &'static str) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(8)).await;
        info!("[{client_name}] Starting web3 RPC read traffic (via HTTP proxy to public RPCs)...");

        let mut req = 0u64;
        let mut rpc_id = 1u64;
        loop {
            let idx = (rand::random::<usize>()) % RPC_METHODS.len();
            let (method, params_str) = RPC_METHODS[idx];

            // Round-robin through public RPC endpoints
            let rpc_url = PUBLIC_RPC_ENDPOINTS[req as usize % PUBLIC_RPC_ENDPOINTS.len()];

            // Build JSON-RPC request body
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "method": method,
                "params": serde_json::from_str::<serde_json::Value>(params_str)
                    .unwrap_or(serde_json::json!([])),
                "id": rpc_id,
            });
            let body_bytes = serde_json::to_vec(&body).unwrap_or_default();

            match client
                .send_http_request(
                    rpc_url,
                    "POST",
                    vec![("Content-Type".to_string(), "application/json".to_string())],
                    body_bytes,
                    0,
                )
                .await
            {
                Ok(resp) => {
                    let result_str = String::from_utf8_lossy(&resp);
                    let preview = if result_str.len() > 120 {
                        format!("{}...", &result_str[..120])
                    } else {
                        result_str.to_string()
                    };
                    info!(
                        "[{client_name}] RPC {method} ok ({} bytes, req #{req}): {preview}",
                        resp.len()
                    );
                }
                Err(e) => {
                    warn!("[{client_name}] RPC {method} err: {e} (req #{req})");
                }
            }

            req += 1;
            rpc_id += 1;
            let pause = 5000 + (rand::random::<u64>() % 10000);
            tokio::time::sleep(Duration::from_millis(pause)).await;
        }
    });
}

/// Spawn Client C: echo + mixed traffic (acts as a `DeFi` client placeholder).
fn spawn_echo_traffic(client: Arc<MixnetClient>, client_name: &'static str) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        info!("[{client_name}] Starting echo traffic...");

        let mut req = 0u64;
        loop {
            let payload = format!("{client_name} echo #{req}");
            match client.send_echo(payload.into_bytes()).await {
                Ok(_) => {
                    info!("[{client_name}] Echo ok (req #{req})");
                }
                Err(e) => {
                    warn!("[{client_name}] Echo err: {e} (req #{req})");
                }
            }

            req += 1;

            // Burst mode: 10% chance
            if rand::random::<f64>() < 0.10 {
                for b in 0..5 {
                    let burst = format!("{client_name} burst-{req}-{b}");
                    let _ = client.send_echo(burst.into_bytes()).await;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }

            let pause = 1000 + (rand::random::<u64>() % 4000);
            tokio::time::sleep(Duration::from_millis(pause)).await;
        }
    });
}

/// Wire a `MixnetClient` to an entry node's event bus for SURB response delivery.
fn create_wired_client(
    entry: &DashboardNode,
    topology: Arc<RwLock<Vec<TopologyNode>>>,
    pow_difficulty: u32,
) -> Arc<MixnetClient> {
    let (response_tx, response_rx) = mpsc::channel::<(String, Vec<u8>)>(512);

    let config = MixnetClientConfig {
        timeout: Duration::from_secs(30),
        pow_difficulty,
        surbs_per_request: 10,
        entry_node_pubkey: Some(entry.public_key.to_bytes()),
        default_fec_ratio: 0.3,
        ..Default::default()
    };

    let client = Arc::new(MixnetClient::new(
        topology,
        entry.bus_publisher.clone(),
        response_rx,
        config,
    ));

    // SURB response wiring
    let sub = entry.bus_subscriber.clone();
    let entry_id = entry.id;
    tokio::spawn(async move {
        let mut rx = sub.subscribe();
        loop {
            match rx.recv().await {
                Ok(NoxEvent::PayloadDecrypted { packet_id, payload }) => {
                    let _ = response_tx.send((packet_id, payload)).await;
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
    let client_run = client.clone();
    tokio::spawn(async move {
        client_run.run_response_loop().await;
    });

    client
}

fn spawn_churn_agent(
    registry: NoxRegistry<SignerMiddleware<Provider<Http>, LocalWallet>>,
    identities_info: Vec<(usize, Address, [u8; 32], u8, u16)>,
    interval_secs: u64,
) {
    tokio::spawn(async move {
        info!("[churn] Admin churn agent active (interval: {interval_secs}s)");
        tokio::time::sleep(Duration::from_secs(30)).await; // Let mesh stabilize first

        let mut deregistered: Vec<usize> = Vec::new();
        let all_indices: Vec<usize> = identities_info.iter().map(|(id, ..)| *id).collect();

        loop {
            tokio::time::sleep(Duration::from_secs(interval_secs)).await;

            if !deregistered.is_empty() && rand::random::<f64>() < 0.6 {
                // Re-register a previously removed node
                let pick = rand::random::<usize>() % deregistered.len();
                let node_idx = deregistered.remove(pick);
                let (_, addr, sphinx_key, role, p2p_port) = &identities_info[node_idx];

                let url = format!("/ip4/127.0.0.1/tcp/{p2p_port}");
                match registry
                    .register_privileged(*addr, *sphinx_key, url, *role)
                    .send()
                    .await
                {
                    Ok(_) => info!("[churn] Re-registered node-{node_idx} ({addr:?})"),
                    Err(e) => warn!("[churn] Failed to re-register node-{node_idx}: {e}"),
                }
            } else {
                // Deregister a random active node (never deregister the last entry or last exit)
                let active: Vec<usize> = all_indices
                    .iter()
                    .filter(|i| !deregistered.contains(i))
                    .copied()
                    .collect();
                if active.len() <= 3 {
                    info!(
                        "[churn] Too few active nodes ({}) -- skipping deregister",
                        active.len()
                    );
                    continue;
                }

                let pick = rand::random::<usize>() % active.len();
                let node_idx = active[pick];
                let (_, addr, ..) = &identities_info[node_idx];

                match registry.force_unregister(*addr).send().await {
                    Ok(_) => {
                        deregistered.push(node_idx);
                        info!(
                            "[churn] Deregistered node-{node_idx} ({addr:?}). Active: {}",
                            active.len() - 1
                        );
                    }
                    Err(e) => warn!("[churn] Failed to deregister node-{node_idx}: {e}"),
                }
            }
        }
    });
}

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<()> {
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber).ok();

    let args = Args::parse();
    let node_count = args.nodes.clamp(3, 50);

    info!("╔══════════════════════════════════════════════════════╗");
    info!("║  NOX DASHBOARD SIM  ({node_count} nodes, on-chain topology)  ║");
    info!(
        "║  Cluster API: http://localhost:{}/cluster       ║",
        args.cluster_port
    );
    info!(
        "║  Contracts:   http://localhost:{}/contracts     ║",
        args.cluster_port + 1
    );
    info!("╚══════════════════════════════════════════════════════╝");

    // Phase 0: Start Anvil
    // Always start with instant mining for fast contract deployment and node funding.
    // Block time is applied later via `evm_setIntervalMining` once the mesh is live.
    info!("Phase 0: Starting Anvil (instant mining for setup)...");
    let anvil = Anvil::new().spawn();
    let anvil_rpc = anvil.endpoint();
    info!("Anvil running at {anvil_rpc}");

    // Phase 1: Deploy Contracts
    let (client, addresses, registry, _token) = deploy_lightweight_contracts(&anvil_rpc).await?;

    // Start APIs immediately so dashboard can connect during setup
    info!(
        "Starting Cluster API on :{} and Contracts API on :{}...",
        args.cluster_port,
        args.cluster_port + 1
    );
    let cluster_state =
        spawn_dashboard_api(args.cluster_port, addresses.clone(), args.clone()).await;

    // Pre-generate node identities (so we can register on-chain before spawn)
    info!("Pre-generating {node_count} node identities...");
    let mut identities: Vec<NodeIdentity> = Vec::with_capacity(node_count);
    // First pass: generate keys, wallets, port assignments
    for i in 0..node_count {
        let rng = OsRng;
        let sk = X25519SecretKey::random_from_rng(rng);
        let pk = X25519PublicKey::from(&sk);
        let eth_wallet =
            LocalWallet::new(&mut rand::thread_rng()).with_chain_id(client.signer().chain_id());
        let layer = assign_layer(i, node_count, args.entry_ratio, args.exit_ratio);
        let role = if layer == 2 { 2u8 } else { 1u8 };

        // Port allocation: base + i*10 -> P2P, +1 -> metrics, +2 -> ingress, +3 -> topology API
        let p2p_port = args.base_port + (i as u16) * 10;
        let admin_port = p2p_port + 1;
        let ingress_port = if layer == 0 { p2p_port + 2 } else { 0 }; // Only entry nodes get ingress
        let topology_api_port = if i == 0 { p2p_port + 3 } else { 0 }; // Only first node serves topology API

        identities.push(NodeIdentity {
            id: i,
            secret_key: sk,
            public_key: pk,
            eth_wallet,
            layer,
            role,
            p2p_port,
            admin_port,
            ingress_port,
            topology_api_port,
        });
    }

    // Second pass: fund all wallets (fire TXs sequentially -- Anvil instant mines each)
    info!("Funding {} node wallets...", identities.len());
    for ident in &identities {
        let fund_tx = ethers::types::TransactionRequest::new()
            .to(ident.eth_wallet.address())
            .value(ethers::utils::parse_ether("10").unwrap_or_default());
        client
            .send_transaction(fund_tx, None)
            .await
            .map_err(|e| anyhow::anyhow!("Fund node-{} error: {e}", ident.id))?
            .await
            .map_err(|e| anyhow::anyhow!("Fund node-{} receipt error: {e}", ident.id))?;
    }
    info!("All {} wallets funded.", identities.len());

    // Phase 2: Spawn NOX nodes FIRST (ChainObservers start watching)
    info!("Phase 2: Spawning {node_count} NOX nodes with ChainObserver...");
    let registry_addr_str = format!("{:?}", registry.address());
    let mut nodes: Vec<DashboardNode> = Vec::new();
    for ident in &identities {
        match spawn_dashboard_node(
            ident,
            &anvil_rpc,
            &registry_addr_str,
            args.mix_delay_ms,
            args.pow_difficulty,
        )
        .await
        {
            Ok(node) => nodes.push(node),
            Err(e) => {
                error!("Node {} failed to spawn: {e}", ident.id);
                return Err(e);
            }
        }
    }

    // Brief pause to let all ChainObservers initialize and grab current block
    info!("Waiting for ChainObservers to initialize (2s)...");
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Phase 3: Register all nodes on-chain (observers pick up events live)
    register_nodes_on_chain(&registry, &nodes).await?;

    // Wait for ChainObserver to pick up all registrations
    info!("Waiting for topology convergence (5s)...");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Verify topology convergence
    let topo_nodes = nodes[0].topology_manager.get_all_nodes();
    let topo_fp = hex::encode(nodes[0].topology_manager.get_current_fingerprint());
    info!(
        "Topology convergence: node-0 sees {} nodes (expected {}). Fingerprint: {}...",
        topo_nodes.len(),
        node_count,
        &topo_fp[..16.min(topo_fp.len())],
    );

    // Phase 4: Register spawned nodes in cluster API
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
    info!(
        "Phase 4 complete: {} nodes registered in cluster API",
        nodes.len()
    );

    // Phase 5: Build shared topology for clients
    let shared_topology: Arc<RwLock<Vec<TopologyNode>>> = Arc::new(RwLock::new(
        nodes
            .iter()
            .map(|n| TopologyNode {
                id: format!("nox-{}", n.id),
                address: n.multiaddr.clone(),
                public_key: n.public_key.to_bytes(),
                layer: n.layer,
                eth_address: n.wallet_address,
                role: n.role,
            })
            .collect(),
    ));

    // Switch Anvil to block-time mining now that setup is done
    if args.block_time > 0 {
        info!(
            "Switching Anvil to {}s block time for realistic chain behavior...",
            args.block_time
        );
        let provider = Provider::<Http>::try_from(&anvil_rpc)?;
        // evm_setIntervalMining(interval_seconds) -- Anvil-specific RPC
        let _: bool = provider
            .request("evm_setIntervalMining", [args.block_time])
            .await
            .unwrap_or(false);
    }

    // Phase 6: Spawn traffic generators
    let entry_nodes: Vec<&DashboardNode> = nodes.iter().filter(|n| n.layer == 0).collect();
    if entry_nodes.is_empty() {
        error!("No entry nodes -- cannot start traffic generators");
        return Err(anyhow::anyhow!("No entry nodes in topology"));
    }

    // Client A: web2 HTTP reads (connected to first entry node)
    let client_a =
        create_wired_client(entry_nodes[0], shared_topology.clone(), args.pow_difficulty);
    spawn_web2_traffic(client_a, "client-A/web2");

    // Client B: web3 RPC reads (connected to second entry node, or first if only one)
    let entry_b = if entry_nodes.len() > 1 {
        entry_nodes[1]
    } else {
        entry_nodes[0]
    };
    let client_b = create_wired_client(entry_b, shared_topology.clone(), args.pow_difficulty);
    spawn_web3_read_traffic(client_b, "client-B/web3-read");

    // Client C: echo + burst traffic (connected to another entry if available)
    let entry_c = if entry_nodes.len() > 2 {
        entry_nodes[2]
    } else {
        entry_nodes[0]
    };
    let client_c = create_wired_client(entry_c, shared_topology.clone(), args.pow_difficulty);
    spawn_echo_traffic(client_c, "client-C/echo");

    // Phase 7: Admin churn agent
    if args.enable_churn {
        let churn_info: Vec<(usize, Address, [u8; 32], u8, u16)> = identities
            .iter()
            .map(|id| {
                (
                    id.id,
                    id.eth_wallet.address(),
                    id.public_key.to_bytes(),
                    if id.layer == 2 { 2u8 } else { 1u8 },
                    id.p2p_port,
                )
            })
            .collect();
        spawn_churn_agent(registry, churn_info, args.churn_interval_secs);
    }

    // Startup JSON to stdout
    let entry_count = nodes.iter().filter(|n| n.layer == 0).count();
    let mix_count = nodes.iter().filter(|n| n.layer == 1).count();
    let exit_count = nodes.iter().filter(|n| n.layer == 2).count();

    let nodes_json: Vec<serde_json::Value> = nodes
        .iter()
        .map(|n| {
            serde_json::json!({
                "id": format!("nox-{}", n.id),
                "eth_address": n.eth_address,
                "layer": n.layer,
                "role": n.role,
                "admin_port": n.admin_port,
                "ingress_port": n.ingress_port,
                "topology_api_port": n.topology_api_port,
                "p2p_port": n.p2p_port,
                "p2p_addr": n.multiaddr,
                "sphinx_key": hex::encode(n.public_key.as_bytes()),
            })
        })
        .collect();

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "cluster_port": args.cluster_port,
            "contracts_port": args.cluster_port + 1,
            "node_count": nodes.len(),
            "entry_nodes": entry_count,
            "mix_nodes": mix_count,
            "exit_nodes": exit_count,
            "contracts": {
                "nox_registry": addresses.nox_registry,
                "nox_reward_pool": addresses.nox_reward_pool,
                "mock_token": addresses.mock_token,
                "anvil_rpc": addresses.anvil_rpc,
            },
            "nodes": nodes_json
        }))?
    );

    // Write endpoint manifest to file
    let manifest_path = "dashboard_sim_endpoints.json";
    let mut node_endpoints: Vec<serde_json::Value> = Vec::new();
    for n in &nodes {
        let layer_name = match n.layer {
            0 => "entry",
            1 => "mix",
            _ => "exit",
        };
        let mut endpoints = serde_json::json!({
            "id": format!("nox-{}", n.id),
            "eth_address": n.eth_address,
            "layer": n.layer,
            "layer_name": layer_name,
            "role": n.role,
            "sphinx_key": hex::encode(n.public_key.as_bytes()),
            "p2p_addr": n.multiaddr,
            "endpoints": {
                "metrics": format!("http://127.0.0.1:{}/metrics", n.admin_port),
                "topology": format!("http://127.0.0.1:{}/topology", n.admin_port),
                "events_sse": format!("http://127.0.0.1:{}/events", n.admin_port),
            },
        });
        if n.ingress_port > 0 {
            endpoints["endpoints"]["ingress_packets"] =
                format!("http://127.0.0.1:{}/api/v1/packets", n.ingress_port).into();
            endpoints["endpoints"]["ingress_responses"] =
                format!("http://127.0.0.1:{}/api/v1/responses/claim", n.ingress_port).into();
            endpoints["endpoints"]["ingress_health"] =
                format!("http://127.0.0.1:{}/health", n.ingress_port).into();
        }
        if n.topology_api_port > 0 {
            endpoints["endpoints"]["topology_api"] =
                format!("http://127.0.0.1:{}/topology", n.topology_api_port).into();
        }
        node_endpoints.push(endpoints);
    }

    let manifest = serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "global_endpoints": {
            "cluster": format!("http://127.0.0.1:{}/cluster", args.cluster_port),
            "contracts": format!("http://127.0.0.1:{}/contracts", args.cluster_port + 1),
            "config": format!("http://127.0.0.1:{}/config", args.cluster_port + 1),
            "anvil_rpc": &addresses.anvil_rpc,
        },
        "contracts": {
            "nox_registry": &addresses.nox_registry,
            "nox_reward_pool": &addresses.nox_reward_pool,
            "mock_token": &addresses.mock_token,
            "admin_address": &addresses.admin_address,
        },
        "summary": {
            "total_nodes": nodes.len(),
            "entry_nodes": entry_count,
            "mix_nodes": mix_count,
            "exit_nodes": exit_count,
        },
        "nodes": node_endpoints,
    });

    match std::fs::write(
        manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap_or_default(),
    ) {
        Ok(()) => info!("Endpoint manifest written to {manifest_path}"),
        Err(e) => warn!("Failed to write endpoint manifest: {e}"),
    }

    info!("╔══════════════════════════════════════════════════════╗");
    info!("║  SIMULATION RUNNING                                  ║");
    info!("║  {entry_count} Entry | {mix_count} Mix | {exit_count} Exit nodes                   ║");
    info!("║  3 clients: web2 HTTP, web3 RPC, echo+burst          ║");
    if args.enable_churn {
        info!(
            "║  Admin churn: every {}s                              ║",
            args.churn_interval_secs
        );
    }
    info!("║  Endpoints: cat {manifest_path}                   ║");
    info!("║  Press Ctrl+C to stop                                ║");
    info!("╚══════════════════════════════════════════════════════╝");

    tokio::signal::ctrl_c().await?;
    info!("Received Ctrl+C -- shutting down.");

    // Anvil is dropped here (auto-killed)
    drop(anvil);
    Ok(())
}
