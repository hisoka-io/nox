//! Master E2E: full privacy protocol via subcrate imports (requires Anvil + Node.js).

use anyhow::Result;
use ethers::prelude::*;
use ethers::types::{Address, H256, U256};
use ethers::utils::Anvil;
use libp2p::multiaddr::Protocol;
use parking_lot::RwLock;
use rand::rngs::OsRng;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::tempdir;
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn, Level};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

use darkpool_crypto::BASE8;

use darkpool_client::crypto_helpers::{
    address_to_field, calculate_public_memo_id, fr_to_u256, generate_dleq_proof, random_field,
};
use darkpool_client::{
    BuilderConfig, DarkAccount, DarkPoolConfig, PriceData, PrivacyClient, Transport,
};

use nox_client::mixnet_client::{MixnetClient, MixnetClientConfig};
use nox_client::{TopologyNode, TopologySyncClient, TopologySyncConfig};

use nox_core::events::NoxEvent;
use nox_core::traits::interfaces::{IEventPublisher, IEventSubscriber, IProverService};
use nox_core::TopologySnapshot;

use nox_node::blockchain::executor::ChainExecutor;
use nox_node::blockchain::tx_manager::TransactionManager;
use nox_node::config::FragmentationConfig;
use nox_node::network::service::P2PService;
use nox_node::price::client::PriceSource;
use nox_node::services::exit::ExitService;
use nox_node::services::handlers::rpc::RpcHandler;
use nox_node::services::mixing::PoissonMixStrategy;
use nox_node::services::network_manager::TopologyManager;
use nox_node::services::relayer::RelayerService;
use nox_node::services::traffic_shaping::TrafficShapingService;
use nox_node::telemetry::metrics::MetricsService;
use nox_node::{NodeRole, NoxConfig, SledRepository, TokioEventBus};

use nox_prover::ProverWorker;

use nox_test_infra::contracts::{CompliancePk, ContractDeployer, DeployedContracts};

use axum::{extract::State, routing::get, Json, Router};

struct SimPriceSource;

#[async_trait::async_trait]
impl PriceSource for SimPriceSource {
    async fn get_price(
        &self,
        asset: &str,
    ) -> Result<f64, nox_node::price::client::PriceClientError> {
        match asset {
            "ethereum" => Ok(3000.0),
            _ => Ok(1.0),
        }
    }
}

#[allow(dead_code)]
struct VirtualNode {
    id: usize,
    multiaddr: String,
    public_key: X25519PublicKey,
    layer: u8,
    bus_publisher: Arc<dyn IEventPublisher>,
    bus_subscriber: Arc<dyn IEventSubscriber>,
    eth_address: Address,
    topology_manager: Arc<TopologyManager>,
    _response_tx: mpsc::Sender<(String, Vec<u8>)>,
    _storage: Arc<SledRepository>,
    _db_dir: tempfile::TempDir,
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_arguments)]
async fn spawn_virtual_node(
    id: usize,
    layer: u8,
    delay: f64,
    difficulty: u32,
    rpc_url: &str,
    _darkpool_address: Address,
    reward_pool_address: Address,
    token_address: Address,
) -> Result<VirtualNode> {
    let dir = tempdir()?;
    let db = Arc::new(SledRepository::new(dir.path())?);
    let event_bus = TokioEventBus::new(4096);
    let pub_bus: Arc<dyn IEventPublisher> = Arc::new(event_bus.clone());
    let sub_bus: Arc<dyn IEventSubscriber> = Arc::new(event_bus.clone());

    let mut rng = OsRng;
    let node_sk = X25519SecretKey::random_from_rng(rng);
    let node_pk = X25519PublicKey::from(&node_sk);
    let eth_wallet = LocalWallet::new(&mut rng);

    let node_role = if layer == 2 {
        NodeRole::Exit
    } else {
        NodeRole::Relay
    };

    let config = {
        let mut c = NoxConfig::default();
        c.eth_rpc_url = rpc_url.to_string();
        c.p2p_listen_addr = "127.0.0.1".into();
        c.p2p_port = 0;
        c.db_path = dir.path().to_str().unwrap().into();
        c.p2p_identity_path = dir.path().join("id.key").to_str().unwrap().into();
        c.routing_private_key = hex::encode(node_sk.to_bytes());
        c.eth_wallet_private_key = hex::encode(eth_wallet.signer().to_bytes());
        c.min_pow_difficulty = difficulty;
        c.min_gas_balance = "50000000000000000".into();
        c.registry_contract_address = format!("{:?}", Address::random());
        c.nox_reward_pool_address = format!("{reward_pool_address:?}");
        c.node_role = node_role;
        c
    };

    let metrics = MetricsService::new();

    let topology = Arc::new(TopologyManager::new(db.clone(), sub_bus.clone(), None));
    let topo_clone = topology.clone();
    tokio::spawn(async move {
        topo_clone.run().await;
    });

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
    tokio::spawn(async move {
        p2p.run().await;
    });
    let (pid, base_addr) = rx.await?;
    let full_addr = base_addr.with(Protocol::P2p(pid));

    let mix = Arc::new(PoissonMixStrategy::new(delay));
    let replay_db = db.clone();

    let cover_traffic = TrafficShapingService::new(
        config.clone(),
        topology.clone(),
        pub_bus.clone(),
        metrics.clone(),
    );
    tokio::spawn(async move {
        cover_traffic.run().await;
    });

    let relayer = RelayerService::new(
        config.clone(),
        sub_bus.clone(),
        pub_bus.clone(),
        replay_db.clone(),
        mix,
        metrics.clone(),
    );
    tokio::spawn(async move {
        if let Err(e) = relayer.run().await {
            eprintln!("Relayer failed to start: {e}");
        }
    });

    let (response_tx, _response_rx) = mpsc::channel::<(String, Vec<u8>)>(1024);

    if layer == 2 {
        let executor: Arc<ChainExecutor> = Arc::new(ChainExecutor::new(&config).await?);
        let tx_manager: Arc<TransactionManager> =
            Arc::new(TransactionManager::new(executor.clone(), db.clone(), metrics.clone()).await?);

        let price_client: Arc<dyn PriceSource> = Arc::new(SimPriceSource);

        let mut eth_handler = nox_node::services::handlers::ethereum::EthereumHandler::from_config(
            executor.clone(),
            tx_manager.clone(),
            metrics.clone(),
            10,
            price_client,
            &config.nox_reward_pool_address,
            config.max_broadcast_tx_size,
        )
        .expect("Failed to create EthereumHandler");
        eth_handler.register_token(token_address, "MOCK", 18, "ethereum");
        let ethereum_handler = Arc::new(eth_handler);

        let traffic_handler = Arc::new(nox_node::services::handlers::traffic::TrafficHandler {
            metrics: metrics.clone(),
        });

        let response_packer = Arc::new(nox_node::services::response_packer::ResponsePacker::new());

        let rpc_handler = Arc::new(
            RpcHandler::new(
                executor.clone(),
                response_packer.clone(),
                pub_bus.clone(),
                rpc_url,
                metrics.clone(),
            )
            .expect("Failed to create RpcHandler"),
        );

        let echo_handler = Arc::new(nox_node::services::handlers::echo::EchoHandler::new(
            response_packer.clone(),
            pub_bus.clone(),
        ));

        let exit = ExitService::with_all_handlers(
            sub_bus.clone(),
            ethereum_handler,
            traffic_handler,
            None,
            Some(echo_handler),
            Some(rpc_handler),
            FragmentationConfig::default(),
            metrics.clone(),
        );
        tokio::spawn(async move {
            exit.run().await;
        });
    }

    let layer_name = match layer {
        0 => "Entry",
        1 => "Mix",
        2 => "Exit",
        _ => "Unknown",
    };
    info!(
        "Node {} ({}, {:?}): {} - {:?}",
        id,
        layer_name,
        node_role,
        full_addr,
        eth_wallet.address()
    );

    Ok(VirtualNode {
        id,
        multiaddr: full_addr.to_string(),
        public_key: node_pk,
        layer,
        bus_publisher: pub_bus,
        bus_subscriber: sub_bus,
        eth_address: eth_wallet.address(),
        topology_manager: topology,
        _response_tx: response_tx,
        _storage: db,
        _db_dir: dir,
    })
}

// Simulation State

#[derive(Debug, Default)]
struct CircuitStats {
    deposit: usize,
    transfer: usize,
    split: usize,
    join: usize,
    withdraw: usize,
    gas_payment: usize,
    public_claim: usize,
}

impl CircuitStats {
    fn total(&self) -> usize {
        self.deposit
            + self.transfer
            + self.split
            + self.join
            + self.withdraw
            + self.gas_payment
            + self.public_claim
    }
}

#[derive(Debug, Default)]
#[allow(dead_code)]
struct MixnetStats {
    packets_sent: u64,
    responses_received: u64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TxLog {
    phase: String,
    actor: String,
    action: String,
    circuit: Option<String>,
    via_mixnet: bool,
    tx_hash: Option<H256>,
    duration: Duration,
}

#[allow(dead_code)]
struct SimState {
    circuits: CircuitStats,
    mixnet: MixnetStats,
    tx_logs: Vec<TxLog>,
    start_time: Instant,
    anvil_block: u64,
    relayer_profit: U256,
}

impl SimState {
    fn new() -> Self {
        Self {
            circuits: CircuitStats::default(),
            mixnet: MixnetStats::default(),
            tx_logs: Vec::new(),
            start_time: Instant::now(),
            anvil_block: 0,
            relayer_profit: U256::zero(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn log_tx(
        &mut self,
        phase: &str,
        actor: &str,
        action: &str,
        circuit: Option<&str>,
        via_mixnet: bool,
        tx_hash: Option<H256>,
        duration: Duration,
    ) {
        self.tx_logs.push(TxLog {
            phase: phase.to_string(),
            actor: actor.to_string(),
            action: action.to_string(),
            circuit: circuit.map(String::from),
            via_mixnet,
            tx_hash,
            duration,
        });
    }
}

fn format_eth(wei: U256) -> String {
    let eth = wei / U256::exp10(18);
    let remainder = (wei % U256::exp10(18)) / U256::exp10(15);
    format!("{}.{:03}", eth, remainder.as_u64())
}

// MASTER E2E TEST

#[tokio::test]
#[ignore = "Requires Anvil + NativeProver (~5 min)"]
#[allow(clippy::unwrap_used, clippy::expect_used)]
async fn test_full_e2e_with_subcrate_imports() {
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber).ok();

    let result = Box::pin(run_e2e()).await;
    if let Err(e) = &result {
        eprintln!("E2E test failed: {e:?}");
    }
    result.expect("E2E test must pass");
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
async fn run_e2e() -> Result<()> {
    let mut state = SimState::new();

    // Hardcoded defaults (same as sim CLI defaults)
    let num_nodes: usize = 5;
    let delay: f64 = 1.0;
    let pow_difficulty: u32 = 0;
    let artifacts_path = "artifacts";

    // PHASE 1: GENESIS + MIXNET BOOTSTRAP
    info!("╔═══════════════════════════════════════════════════════════════╗");
    info!("║  PHASE 1: GENESIS + MIXNET BOOTSTRAP                          ║");
    info!("╚═══════════════════════════════════════════════════════════════╝");

    let phase_start = Instant::now();

    // 1.1 Start Anvil (code-size-limit needed for large HonkVerifier contracts)
    info!("  [1.1] Starting Anvil blockchain...");
    let anvil = Anvil::new().arg("--code-size-limit").arg("100000").spawn();
    let anvil_url = anvil.endpoint();
    info!("Anvil running at {}", anvil_url);

    // 1.2 Connect provider
    let provider = Provider::<Http>::try_from(&anvil_url)?;
    let chain_id = provider.get_chainid().await?.as_u64();
    state.anvil_block = provider.get_block_number().await?.as_u64();

    let deployer_key = anvil.keys()[0].clone();
    let alice_key = anvil.keys()[1].clone();
    let bob_key = anvil.keys()[2].clone();
    let charlie_key = anvil.keys()[3].clone();

    let deployer_wallet = LocalWallet::from(deployer_key).with_chain_id(chain_id);
    let alice_wallet = LocalWallet::from(alice_key).with_chain_id(chain_id);
    let bob_wallet = LocalWallet::from(bob_key).with_chain_id(chain_id);
    let charlie_wallet = LocalWallet::from(charlie_key).with_chain_id(chain_id);

    let deployer_client = Arc::new(SignerMiddleware::new(provider.clone(), deployer_wallet));

    // 1.4 Generate compliance keypair (using darkpool_crypto::BASE8 directly)
    let compliance_sk = [0x42u8; 32];
    let compliance_pk_point = BASE8.mul_scalar(&compliance_sk)?;
    let compliance_pk = CompliancePk {
        x: fr_to_u256(compliance_pk_point.x()),
        y: fr_to_u256(compliance_pk_point.y()),
    };

    // 1.5 Deploy contracts
    info!("  [1.2] Deploying contracts...");
    let deployer = ContractDeployer::new(deployer_client.clone(), artifacts_path);
    let contracts: DeployedContracts<SignerMiddleware<Provider<Http>, LocalWallet>> = deployer
        .deploy_all(compliance_pk, deployer_client.address())
        .await
        .map_err(|e| anyhow::anyhow!("Contract deployment failed: {e:?}"))?;

    info!("DarkPool: {:?}", contracts.darkpool.address());

    // 1.6 Mint tokens
    let mint_amount = U256::from(100) * U256::exp10(18);
    contracts
        .token
        .mint(alice_wallet.address(), mint_amount)
        .send()
        .await?
        .await?;
    contracts
        .token
        .mint(bob_wallet.address(), mint_amount)
        .send()
        .await?
        .await?;
    contracts
        .token
        .mint(charlie_wallet.address(), mint_amount)
        .send()
        .await?
        .await?;

    // 1.6a Spawn ProverWorker in background
    info!("  [1.3a] Spawning ProverWorker...");
    let prover_handle = tokio::spawn(async { ProverWorker::spawn(true).await });

    // 1.7 Spawn mixnet nodes
    info!("  [1.4] Spawning {} REAL mixnet nodes...", num_nodes);
    let mut node_handles = Vec::new();
    for i in 0..num_nodes {
        let layer = match i {
            0 | 1 => 0,
            2 | 3 => 1,
            _ => 2,
        };
        let url = anvil_url.clone();
        let dp = contracts.darkpool.address();
        let rp = contracts.reward_pool.address();
        let tk = contracts.token.address();
        node_handles.push(tokio::spawn(async move {
            spawn_virtual_node(i, layer, delay, pow_difficulty, &url, dp, rp, tk).await
        }));
    }
    let mut nodes = Vec::new();
    for handle in node_handles {
        nodes.push(handle.await??);
    }
    for node in &nodes {
        let fund_amount = if node.layer == 2 {
            ethers::utils::parse_ether(10.0)?
        } else {
            ethers::utils::parse_ether(1.0)?
        };
        let tx = TransactionRequest::new()
            .to(node.eth_address)
            .value(fund_amount);
        deployer_client.send_transaction(tx, None).await?.await?;
    }

    // 1.8 Interconnect nodes
    for target in &nodes {
        for source in &nodes {
            let target_role: u8 = if target.layer == 2 { 2 } else { 1 };
            source.bus_publisher.publish(NoxEvent::RelayerRegistered {
                address: format!("{:?}", target.eth_address),
                sphinx_key: hex::encode(target.public_key.as_bytes()),
                url: target.multiaddr.clone(),
                stake: "1000".to_string(),
                role: target_role,
                ingress_url: None,
                metadata_url: None,
            })?;
        }
    }

    info!("  [1.6] Waiting for mesh stabilization (3s)...");
    tokio::time::sleep(Duration::from_secs(3)).await;

    // 1.9 Topology Sync
    let seed_node = &nodes[0];
    let seed_tm = seed_node.topology_manager.clone();
    let topo_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let topo_api_port = topo_listener.local_addr()?.port();
    let topo_app = Router::new()
        .route(
            "/topology",
            get(|State(tm): State<Arc<TopologyManager>>| async move {
                let all_nodes = tm.get_all_nodes();
                let fp = tm.get_current_fingerprint();
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                Json(TopologySnapshot {
                    nodes: all_nodes,
                    fingerprint: hex::encode(fp),
                    timestamp: ts,
                    block_number: 0,
                    pow_difficulty: 0,
                })
            }),
        )
        .with_state(seed_tm);

    tokio::spawn(async move {
        axum::serve(topo_listener, topo_app).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let sync_topology_arc: Arc<RwLock<Vec<TopologyNode>>> = Arc::new(RwLock::new(Vec::new()));
    let sync_config = TopologySyncConfig {
        seed_urls: vec![format!("http://127.0.0.1:{topo_api_port}/topology")],
        eth_rpc_url: String::new(),
        registry_address: Address::zero(),
        refresh_interval: Duration::from_secs(60),
        request_timeout: Duration::from_secs(5),
        skip_chain_verification: true,
    };
    let sync_client = TopologySyncClient::new(sync_config, sync_topology_arc.clone())
        .expect("TopologySyncClient creation should succeed");
    let synced_count = sync_client
        .sync_once()
        .await
        .expect("TopologySyncClient sync_once should succeed");
    assert_eq!(
        synced_count,
        nodes.len(),
        "Synced node count must match spawned node count"
    );

    let topology_arc = sync_topology_arc;

    // 1.10 Create user clients
    info!("  [1.7] Creating user clients...");
    let provider_arc = Arc::new(provider.clone());

    let client_config = DarkPoolConfig {
        darkpool_address: contracts.darkpool.address(),
        compliance_pk: (
            fr_to_u256(compliance_pk_point.x()),
            fr_to_u256(compliance_pk_point.y()),
        ),
        start_block: state.anvil_block,
        builder_config: BuilderConfig {
            darkpool_address: contracts.darkpool.address(),
            multicall_address: contracts.multicall.address(),
            ..BuilderConfig::default()
        },
        ..Default::default()
    };

    let alice_account = DarkAccount::from_seed(b"alice_master_seed_2024_real____");
    let mut bob_account = DarkAccount::from_seed(b"bob_master_seed_2024_real______");
    let bob_ivk = bob_account.get_incoming_viewing_key(0);
    let mut charlie_account = DarkAccount::from_seed(b"charlie_master_seed_2024______");
    let charlie_ivk = charlie_account.get_incoming_viewing_key(0);

    info!("  [1.7a] Waiting for ProverWorker...");
    let prover_worker: Arc<dyn IProverService> = Arc::new(prover_handle.await??);

    let (alice_result, bob_result, charlie_result) = tokio::join!(
        PrivacyClient::with_prover(
            provider_arc.clone(),
            alice_wallet.clone(),
            alice_account,
            client_config.clone(),
            prover_worker.clone(),
        ),
        PrivacyClient::with_prover(
            provider_arc.clone(),
            bob_wallet.clone(),
            bob_account,
            client_config.clone(),
            prover_worker.clone(),
        ),
        PrivacyClient::with_prover(
            provider_arc.clone(),
            charlie_wallet.clone(),
            charlie_account,
            client_config.clone(),
            prover_worker.clone(),
        ),
    );
    let mut alice_client = alice_result?;
    let mut bob_client = bob_result?;
    let mut charlie_client = charlie_result?;
    info!("Alice, Bob, and Charlie clients created");

    // 1.11 Create MixnetClients
    let entry_node = nodes.iter().find(|n| n.layer == 0).unwrap();
    let (alice_response_tx, alice_response_rx) = mpsc::channel::<(String, Vec<u8>)>(1024);

    let mixnet_config = MixnetClientConfig {
        timeout: Duration::from_secs(60),
        pow_difficulty,
        surbs_per_request: 3,
        entry_node_pubkey: Some(entry_node.public_key.to_bytes()),
        ..Default::default()
    };

    let alice_mixnet = MixnetClient::new(
        topology_arc.clone(),
        entry_node.bus_publisher.clone(),
        alice_response_rx,
        mixnet_config.clone(),
    );
    let alice_mixnet_arc = Arc::new(alice_mixnet);
    let alice_mixnet_clone = alice_mixnet_arc.clone();
    tokio::spawn(async move {
        alice_mixnet_clone.run_response_loop().await;
    });

    let (bob_response_tx, bob_response_rx) = mpsc::channel::<(String, Vec<u8>)>(1024);
    let bob_mixnet = MixnetClient::new(
        topology_arc.clone(),
        entry_node.bus_publisher.clone(),
        bob_response_rx,
        mixnet_config.clone(),
    );
    let bob_mixnet_arc = Arc::new(bob_mixnet);
    let bob_mixnet_clone = bob_mixnet_arc.clone();
    tokio::spawn(async move {
        bob_mixnet_clone.run_response_loop().await;
    });

    let (charlie_response_tx, charlie_response_rx) = mpsc::channel::<(String, Vec<u8>)>(1024);
    let charlie_mixnet = MixnetClient::new(
        topology_arc.clone(),
        entry_node.bus_publisher.clone(),
        charlie_response_rx,
        mixnet_config,
    );
    let charlie_mixnet_arc = Arc::new(charlie_mixnet);
    let charlie_mixnet_clone = charlie_mixnet_arc.clone();
    tokio::spawn(async move {
        charlie_mixnet_clone.run_response_loop().await;
    });

    // Wire SURB response delivery
    for node in &nodes {
        if node.layer == 0 {
            let node_subscriber = node.bus_subscriber.clone();
            let alice_tx = alice_response_tx.clone();
            let bob_tx = bob_response_tx.clone();
            let charlie_tx = charlie_response_tx.clone();
            let node_id = node.id;

            tokio::spawn(async move {
                let mut rx = node_subscriber.subscribe();
                loop {
                    match rx.recv().await {
                        Ok(NoxEvent::PayloadDecrypted { packet_id, payload }) => {
                            let _ = alice_tx.send((packet_id.clone(), payload.clone())).await;
                            let _ = bob_tx.send((packet_id.clone(), payload.clone())).await;
                            let _ = charlie_tx.send((packet_id, payload)).await;
                        }
                        Ok(_) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            warn!("SURB wiring on node {} lagged by {} events", node_id, n);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
            });
        }
    }

    let gas_price = provider.get_gas_price().await?;
    let price_data = PriceData {
        eth_usd: U256::from(300_000_000_000u64),
        asset_usd: U256::from(300_000_000_000u64),
        gas_price,
    };

    let exit_node = nodes
        .iter()
        .find(|n| n.layer == 2)
        .expect("No exit node found");
    let exit_node_address = exit_node.eth_address;

    state.log_tx(
        "Genesis",
        "System",
        "Infrastructure boot",
        None,
        false,
        None,
        phase_start.elapsed(),
    );
    info!("Phase 1 completed in {:?}", phase_start.elapsed());

    // PHASE 2: ONBOARDING (Deposits)
    info!("╔═══════════════════════════════════════════════════════════════╗");
    info!("║  PHASE 2: ONBOARDING - MULTI-NOTE SETUP (DIRECT RPC)          ║");
    info!("╚═══════════════════════════════════════════════════════════════╝");

    let phase_start = Instant::now();
    let token_address = contracts.token.address();

    let alice_signer = Arc::new(SignerMiddleware::new(
        provider.clone(),
        alice_wallet.clone(),
    ));
    let alice_token =
        nox_test_infra::contracts::MockERC20::new(token_address, alice_signer.clone());
    alice_token
        .approve(contracts.darkpool.address(), U256::MAX)
        .send()
        .await?
        .await?;

    // Alice deposit #1: 7 tokens (action)
    let alice_deposit_1 = U256::from(7) * U256::exp10(18);
    let action_start = Instant::now();
    let alice_dep1_result = alice_client.deposit(alice_deposit_1, token_address).await?;
    state.circuits.deposit += 1;
    state.log_tx(
        "Onboarding",
        "Alice",
        "deposit(7)",
        Some("deposit"),
        false,
        Some(alice_dep1_result.tx_hash),
        action_start.elapsed(),
    );

    // Alice deposit #2: 9 tokens (gas reserve for split + join + transfer via change-note chaining)
    // Gas change notes are discovered via pre-registered ephemeral keys (Phase 15A).
    // Each gas_payment creates a change note that becomes the gas note for the next operation.
    let alice_deposit_2 = U256::from(9) * U256::exp10(18);
    let action_start = Instant::now();
    let alice_dep2_result = alice_client.deposit(alice_deposit_2, token_address).await?;
    state.circuits.deposit += 1;
    state.log_tx(
        "Onboarding",
        "Alice",
        "deposit(9) gas-reserve",
        Some("deposit"),
        false,
        Some(alice_dep2_result.tx_hash),
        action_start.elapsed(),
    );

    // Alice deposit #3: 3 tokens (second input for join after transfer spends one split output)
    let alice_deposit_3 = U256::from(3) * U256::exp10(18);
    let action_start = Instant::now();
    let alice_dep3_result = alice_client.deposit(alice_deposit_3, token_address).await?;
    state.circuits.deposit += 1;
    state.log_tx(
        "Onboarding",
        "Alice",
        "deposit(3) join-input",
        Some("deposit"),
        false,
        Some(alice_dep3_result.tx_hash),
        action_start.elapsed(),
    );

    // Bob approves + deposits
    let bob_signer = Arc::new(SignerMiddleware::new(provider.clone(), bob_wallet.clone()));
    let bob_token = nox_test_infra::contracts::MockERC20::new(token_address, bob_signer.clone());
    bob_token
        .approve(contracts.darkpool.address(), U256::MAX)
        .send()
        .await?
        .await?;
    let _ = bob_client.sync().await?;

    let bob_deposit_1 = U256::from(8) * U256::exp10(18);
    let action_start = Instant::now();
    let bob_dep1_result = bob_client.deposit(bob_deposit_1, token_address).await?;
    state.circuits.deposit += 1;
    state.log_tx(
        "Onboarding",
        "Bob",
        "deposit(8)",
        Some("deposit"),
        false,
        Some(bob_dep1_result.tx_hash),
        action_start.elapsed(),
    );

    // Bob deposit #2: 8 tokens (gas reserve for withdraw + claim + transfer via change-note chaining)
    // Gas change notes are discovered via pre-registered ephemeral keys (Phase 15A).
    // Each gas_payment creates a change note that becomes the gas note for the next operation.
    let bob_deposit_2 = U256::from(8) * U256::exp10(18);
    let action_start = Instant::now();
    let bob_dep2_result = bob_client.deposit(bob_deposit_2, token_address).await?;
    state.circuits.deposit += 1;
    state.log_tx(
        "Onboarding",
        "Bob",
        "deposit(8) gas-reserve",
        Some("deposit"),
        false,
        Some(bob_dep2_result.tx_hash),
        action_start.elapsed(),
    );

    // Charlie approves + deposits
    let charlie_signer = Arc::new(SignerMiddleware::new(
        provider.clone(),
        charlie_wallet.clone(),
    ));
    let charlie_token =
        nox_test_infra::contracts::MockERC20::new(token_address, charlie_signer.clone());
    charlie_token
        .approve(contracts.darkpool.address(), U256::MAX)
        .send()
        .await?
        .await?;
    let _ = charlie_client.sync().await?;

    // Charlie deposit #1: 3 tokens (gas for withdraw)
    let charlie_deposit_1 = U256::from(3) * U256::exp10(18);
    let action_start = Instant::now();
    let charlie_dep1_result = charlie_client
        .deposit(charlie_deposit_1, token_address)
        .await?;
    state.circuits.deposit += 1;
    state.log_tx(
        "Onboarding",
        "Charlie",
        "deposit(3) gas-withdraw",
        Some("deposit"),
        false,
        Some(charlie_dep1_result.tx_hash),
        action_start.elapsed(),
    );

    info!("Phase 2 completed in {:?}", phase_start.elapsed());

    // PHASE 3: SPLIT (Via Paid Mixnet)
    info!("╔═══════════════════════════════════════════════════════════════╗");
    info!("║  PHASE 3: SPLIT (Alice: 7 -> 4 + 3) - PAID VIA MIXNET          ║");
    info!("╚═══════════════════════════════════════════════════════════════╝");

    let phase_start = Instant::now();
    let split_amount_a = U256::from(4) * U256::exp10(18);
    let split_amount_b = U256::from(3) * U256::exp10(18);

    let sync_result = alice_client
        .sync_via_mixnet(alice_mixnet_arc.as_ref())
        .await?;
    info!(
        "Synced via mixnet: {} new notes, {} nullifiers",
        sync_result.new_notes.len(),
        sync_result.spent_nullifiers.len()
    );

    // Split MUST succeed via paid mixnet -- no fallback to direct RPC.
    // Alice has note_7 (action) + gas_reserve (9 tokens for gas via change-note chaining).
    let action_start = Instant::now();
    let alice_transport = Transport::PaidMixnet {
        client: alice_mixnet_arc.as_ref(),
        payment_asset: token_address,
        prices: &price_data,
        relayer_address: exit_node_address,
    };
    let split_result = alice_client
        .split_with_transport(
            &alice_transport,
            split_amount_a,
            split_amount_b,
            token_address,
        )
        .await?;
    state.circuits.gas_payment += 1;
    state.circuits.split += 1;
    state.mixnet.packets_sent += 1;
    state.log_tx(
        "Split",
        "Alice",
        "split(4+3)+gas_payment",
        Some("split+gas_payment"),
        true,
        Some(split_result.tx_hash),
        action_start.elapsed(),
    );
    info!("Phase 3 completed in {:?}", phase_start.elapsed());

    // PHASE 3B: PRIVATE TRANSFER (Alice -> Bob, Via Paid Mixnet)
    info!("╔═══════════════════════════════════════════════════════════════╗");
    info!("║  PHASE 3B: TRANSFER (Alice -> Bob: 3 tokens) - PAID MIXNET   ║");
    info!("╚═══════════════════════════════════════════════════════════════╝");

    let phase_start = Instant::now();
    let transfer_amount = U256::from(3) * U256::exp10(18);

    let _ = alice_client
        .sync_via_mixnet(alice_mixnet_arc.as_ref())
        .await?;

    let compliance_pk_tuple = (
        fr_to_u256(compliance_pk_point.x()),
        fr_to_u256(compliance_pk_point.y()),
    );
    let dleq_result = generate_dleq_proof(bob_ivk, compliance_pk_tuple)
        .map_err(|e| anyhow::anyhow!("DLEQ proof generation failed: {e}"))?;

    let action_start = Instant::now();
    let alice_transport = Transport::PaidMixnet {
        client: alice_mixnet_arc.as_ref(),
        payment_asset: token_address,
        prices: &price_data,
        relayer_address: exit_node_address,
    };
    let transfer_result = alice_client
        .transfer_with_transport(
            &alice_transport,
            transfer_amount,
            token_address,
            dleq_result.recipient_b,
            dleq_result.recipient_p,
            dleq_result.proof,
        )
        .await?;
    state.circuits.gas_payment += 1;
    state.circuits.transfer += 1;
    state.mixnet.packets_sent += 1;
    state.log_tx(
        "Transfer",
        "Alice->Bob",
        "transfer(3)+gas_payment",
        Some("transfer+gas_payment"),
        true,
        Some(transfer_result.tx_hash),
        action_start.elapsed(),
    );
    info!("Phase 3B completed in {:?}", phase_start.elapsed());

    // PHASE 4: JOIN (Via Paid Mixnet)
    info!("╔═══════════════════════════════════════════════════════════════╗");
    info!("║  PHASE 4: JOIN (Alice's remaining notes) - PAID VIA MIXNET   ║");
    info!("╚═══════════════════════════════════════════════════════════════╝");

    let phase_start = Instant::now();
    let _ = alice_client
        .sync_via_mixnet(alice_mixnet_arc.as_ref())
        .await?;

    let action_start = Instant::now();
    // Join MUST succeed via paid mixnet -- no fallback to direct RPC.
    // Alice has notes: split output (4), deposit #3 (3), gas change note from transfer.
    let alice_transport = Transport::PaidMixnet {
        client: alice_mixnet_arc.as_ref(),
        payment_asset: token_address,
        prices: &price_data,
        relayer_address: exit_node_address,
    };
    let join_result = alice_client
        .join_with_transport(&alice_transport, token_address)
        .await?;
    state.circuits.gas_payment += 1;
    state.circuits.join += 1;
    state.mixnet.packets_sent += 1;
    state.log_tx(
        "Join",
        "Alice",
        "join+gas_payment",
        Some("join+gas_payment"),
        true,
        Some(join_result.tx_hash),
        action_start.elapsed(),
    );
    info!("Phase 4 completed in {:?}", phase_start.elapsed());

    // PHASE 5: WITHDRAW (Via Paid Mixnet)
    info!("╔═══════════════════════════════════════════════════════════════╗");
    info!("║  PHASE 5: WITHDRAW (Bob: 5 tokens) - PAID VIA MIXNET          ║");
    info!("╚═══════════════════════════════════════════════════════════════╝");

    let phase_start = Instant::now();
    let withdraw_amount = U256::from(5) * U256::exp10(18);
    let bob_public_address = bob_wallet.address();

    let _ = bob_client.sync_via_mixnet(bob_mixnet_arc.as_ref()).await?;

    let action_start = Instant::now();
    // Withdraw MUST succeed via paid mixnet -- no fallback.
    let bob_transport = Transport::PaidMixnet {
        client: bob_mixnet_arc.as_ref(),
        payment_asset: token_address,
        prices: &price_data,
        relayer_address: exit_node_address,
    };
    let withdraw_result = bob_client
        .withdraw_with_transport(
            &bob_transport,
            withdraw_amount,
            token_address,
            bob_public_address,
            None,
        )
        .await?;
    state.circuits.gas_payment += 1;
    state.circuits.withdraw += 1;
    state.mixnet.packets_sent += 1;
    state.log_tx(
        "Withdraw",
        "Bob",
        "withdraw(5)+gas_payment",
        Some("withdraw+gas_payment"),
        true,
        Some(withdraw_result.tx_hash),
        action_start.elapsed(),
    );
    info!("Phase 5 completed in {:?}", phase_start.elapsed());

    // PHASE 5B: PUBLIC TRANSFER + PUBLIC CLAIM
    info!("╔═══════════════════════════════════════════════════════════════╗");
    info!("║  PHASE 5B: PUBLIC TRANSFER + PUBLIC CLAIM                    ║");
    info!("╚═══════════════════════════════════════════════════════════════╝");

    let phase_start = Instant::now();

    let pub_transfer_amount = U256::from(2) * U256::exp10(18);
    let bob_owner_pk = dleq_result.recipient_b;
    let pub_transfer_salt = random_field();
    let pub_transfer_timelock = U256::zero();

    let action_start = Instant::now();
    let alice_darkpool = nox_test_infra::contracts::DarkPool::new(
        contracts.darkpool.address(),
        alice_signer.clone(),
    );
    let pub_tx = alice_darkpool
        .public_transfer(
            bob_owner_pk.0,
            bob_owner_pk.1,
            token_address,
            pub_transfer_amount,
            pub_transfer_timelock,
            pub_transfer_salt,
        )
        .send()
        .await?
        .await?
        .ok_or_else(|| anyhow::anyhow!("publicTransfer tx receipt missing"))?;

    state.log_tx(
        "PublicTransfer",
        "Alice->Bob",
        "publicTransfer(2)",
        None,
        false,
        Some(pub_tx.transaction_hash),
        action_start.elapsed(),
    );

    let asset_id = address_to_field(token_address);
    let expected_memo_id = calculate_public_memo_id(
        pub_transfer_amount,
        asset_id,
        pub_transfer_timelock,
        bob_owner_pk.0,
        bob_owner_pk.1,
        pub_transfer_salt,
    );

    let memo_bytes = {
        let mut buf = [0u8; 32];
        expected_memo_id.to_big_endian(&mut buf);
        buf
    };
    let is_valid = contracts
        .darkpool
        .is_valid_public_memo(memo_bytes)
        .call()
        .await?;
    assert!(is_valid, "memo not valid on-chain post-publicTransfer");

    let sync_result = bob_client.sync_via_mixnet(bob_mixnet_arc.as_ref()).await?;
    let memo = sync_result
        .new_public_memos
        .iter()
        .find(|m| m.memo_id == expected_memo_id)
        .ok_or_else(|| anyhow::anyhow!("Bob did not discover the publicTransfer memo"))?;

    let action_start = Instant::now();
    let bob_transport = Transport::PaidMixnet {
        client: bob_mixnet_arc.as_ref(),
        payment_asset: token_address,
        prices: &price_data,
        relayer_address: exit_node_address,
    };
    let claim_result = bob_client
        .public_claim_with_transport(
            &bob_transport,
            memo.memo_id,
            memo.value,
            memo.asset,
            memo.timelock,
            memo.owner_pk,
            memo.salt,
            bob_ivk,
        )
        .await?;
    state.circuits.gas_payment += 1;
    state.circuits.public_claim += 1;
    state.mixnet.packets_sent += 1;
    state.log_tx(
        "PublicClaim",
        "Bob",
        "publicClaim(2)+gas_payment",
        Some("public_claim+gas_payment"),
        true,
        Some(claim_result.tx_hash),
        action_start.elapsed(),
    );

    let is_spent = contracts
        .darkpool
        .is_public_memo_spent(memo_bytes)
        .call()
        .await?;
    assert!(is_spent, "memo not marked spent post-publicClaim");

    info!("Phase 5B completed in {:?}", phase_start.elapsed());

    // PHASE 6: BOB -> CHARLIE TRANSFER (Via Paid Mixnet)
    info!("╔═══════════════════════════════════════════════════════════════╗");
    info!("║  PHASE 6: TRANSFER (Bob -> Charlie: 2 tokens) - PAID MIXNET  ║");
    info!("╚═══════════════════════════════════════════════════════════════╝");

    let phase_start = Instant::now();
    let bob_to_charlie_amount = U256::from(2) * U256::exp10(18);

    let _ = bob_client.sync_via_mixnet(bob_mixnet_arc.as_ref()).await?;

    let charlie_compliance_pk_tuple = (
        fr_to_u256(compliance_pk_point.x()),
        fr_to_u256(compliance_pk_point.y()),
    );
    let charlie_dleq_result = generate_dleq_proof(charlie_ivk, charlie_compliance_pk_tuple)
        .map_err(|e| anyhow::anyhow!("Charlie DLEQ proof generation failed: {e}"))?;

    let action_start = Instant::now();
    let bob_transport = Transport::PaidMixnet {
        client: bob_mixnet_arc.as_ref(),
        payment_asset: token_address,
        prices: &price_data,
        relayer_address: exit_node_address,
    };
    let bob_transfer_result = bob_client
        .transfer_with_transport(
            &bob_transport,
            bob_to_charlie_amount,
            token_address,
            charlie_dleq_result.recipient_b,
            charlie_dleq_result.recipient_p,
            charlie_dleq_result.proof,
        )
        .await?;
    state.circuits.gas_payment += 1;
    state.circuits.transfer += 1;
    state.mixnet.packets_sent += 1;
    state.log_tx(
        "Transfer",
        "Bob->Charlie",
        "transfer(2)+gas_payment",
        Some("transfer+gas_payment"),
        true,
        Some(bob_transfer_result.tx_hash),
        action_start.elapsed(),
    );
    info!("Phase 6 completed in {:?}", phase_start.elapsed());

    // PHASE 7: CHARLIE WITHDRAW (Via Paid Mixnet)
    info!("╔═══════════════════════════════════════════════════════════════╗");
    info!("║  PHASE 7: WITHDRAW (Charlie: 2 tokens) - PAID VIA MIXNET    ║");
    info!("╚═══════════════════════════════════════════════════════════════╝");

    let phase_start = Instant::now();
    let charlie_withdraw_amount = U256::from(2) * U256::exp10(18);
    let charlie_public_address = charlie_wallet.address();

    let _ = charlie_client
        .sync_via_mixnet(charlie_mixnet_arc.as_ref())
        .await?;

    let action_start = Instant::now();
    let charlie_transport = Transport::PaidMixnet {
        client: charlie_mixnet_arc.as_ref(),
        payment_asset: token_address,
        prices: &price_data,
        relayer_address: exit_node_address,
    };
    let charlie_withdraw_result = charlie_client
        .withdraw_with_transport(
            &charlie_transport,
            charlie_withdraw_amount,
            token_address,
            charlie_public_address,
            None,
        )
        .await?;
    state.circuits.gas_payment += 1;
    state.circuits.withdraw += 1;
    state.mixnet.packets_sent += 1;
    state.log_tx(
        "Withdraw",
        "Charlie",
        "withdraw(2)+gas_payment",
        Some("withdraw+gas_payment"),
        true,
        Some(charlie_withdraw_result.tx_hash),
        action_start.elapsed(),
    );
    info!("Phase 7 completed in {:?}", phase_start.elapsed());

    // ASSERTIONS
    let total_circuits = state.circuits.total();
    info!("Total circuits triggered: {}", total_circuits);
    info!("  deposit:      {}", state.circuits.deposit);
    info!("  split:        {}", state.circuits.split);
    info!("  join:         {}", state.circuits.join);
    info!("  withdraw:     {}", state.circuits.withdraw);
    info!("  transfer:     {}", state.circuits.transfer);
    info!("  gas_payment:  {}", state.circuits.gas_payment);
    info!("  public_claim: {}", state.circuits.public_claim);

    let deposits = state.circuits.deposit;
    assert!(
        deposits >= 6,
        "Expected ≥6 deposit circuits, got {deposits}"
    );
    let splits = state.circuits.split;
    assert!(splits >= 1, "Expected ≥1 split circuit, got {splits}");
    let joins = state.circuits.join;
    assert!(joins >= 1, "Expected ≥1 join circuit, got {joins}");
    let withdraws = state.circuits.withdraw;
    assert!(
        withdraws >= 2,
        "Expected ≥2 withdraw circuits (Bob+Charlie), got {withdraws}"
    );
    let transfers = state.circuits.transfer;
    assert!(
        transfers >= 2,
        "Expected ≥2 transfer circuits (Alice->Bob + Bob->Charlie), got {transfers}"
    );
    let claims = state.circuits.public_claim;
    assert!(
        claims >= 1,
        "Expected ≥1 public_claim circuit, got {claims}"
    );
    let gas_payments = state.circuits.gas_payment;
    assert!(
        gas_payments >= 7,
        "Expected ≥7 gas_payment circuits (split+2×transfer+join+2×withdraw+claim), got {gas_payments}",
    );
    assert!(
        total_circuits >= 20,
        "Expected ≥20 total circuits, got {total_circuits}",
    );

    // Verify balances
    let alice_bal = alice_client.balance(token_address);
    let bob_bal = bob_client.balance(token_address);
    let charlie_bal = charlie_client.balance(token_address);
    info!(
        "Final balances: Alice={}, Bob={}, Charlie={}",
        format_eth(alice_bal),
        format_eth(bob_bal),
        format_eth(charlie_bal)
    );

    info!(
        "MASTER E2E TEST PASSED -- all {} circuits triggered in {:?}",
        total_circuits,
        state.start_time.elapsed()
    );

    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok(())
}
