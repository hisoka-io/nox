use anyhow::{bail, Context, Result};
use axum::{routing::get, Json, Router};
use clap::Parser;
use ethers::contract::abigen;
use ethers::providers::Middleware;
use ethers::signers::{LocalWallet, Signer};
use ethers::types::{Address, BlockId, BlockNumber, U256};
use libp2p::{identity, PeerId};
use nox_core::primary_layer_for_role;
use nox_core::{
    compute_topology_fingerprint, RelayerNode, TopologyLiveness, TopologyLivenessStatus,
    TopologySnapshot,
};
use nox_node::blockchain::executor::build_ethers_http1_provider;
use nox_node::config::{ChainDataFeeMode, NodeRole, NoxConfig, PaymentAdapterConfig, TokenConfig};
use nox_sim::process_mesh::{find_nox_binary, spawn_nox_process, wait_for_health, NoxProcess};
use rand::rngs::OsRng;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};
use zeroize::{Zeroize, Zeroizing};

const NODE_COUNT: usize = 3;
const EXIT_NODE_INDEX: usize = 2;
const MAX_RELAY_WALLET_ATTEMPTS: usize = 128;
const PAID_MESH_MAXIMUM_TRANSACTION_GAS: u64 = 12_000_000;
const PAID_MESH_MAXIMUM_OUTSTANDING_QUOTES: u32 = 64;
const PAID_MESH_MAXIMUM_PENDING_GAS: u64 =
    PAID_MESH_MAXIMUM_TRANSACTION_GAS * PAID_MESH_MAXIMUM_OUTSTANDING_QUOTES as u64;

abigen!(
    NoxRegistryFixture,
    r#"[
        function relayers(address) view returns (bytes32 sphinxKey, string url, string ingressUrl, string metadataUrl, uint256 stakedAmount, uint256 unlockTime, bool isRegistered, uint8 status, bool frozen)
        function getNodeRole(address) view returns (uint8)
        function relayerCount() view returns (uint256)
        function topologyFingerprint() view returns (bytes32)
    ]"#
);

#[derive(Parser, Debug)]
struct Cli {
    #[arg(long)]
    nox_binary: Option<String>,
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long, default_value_t = 16_000)]
    base_port: u16,
    #[arg(long, default_value_t = 60)]
    startup_timeout_secs: u64,
    #[arg(long, default_value_t = 3)]
    mesh_settle_secs: u64,
    #[arg(long)]
    rpc_url: String,
    #[arg(long)]
    chain_id: u64,
    #[arg(long)]
    registry_address: String,
    #[arg(long)]
    entry_point_address: String,
    #[arg(long)]
    payment_adapter_address: String,
    #[arg(long)]
    reward_pool_address: String,
    #[arg(long)]
    fee_asset_address: String,
    #[arg(long)]
    fee_asset_price_id: String,
    #[arg(long)]
    native_asset_price_id: String,
    #[arg(long)]
    native_price_e8: u128,
    #[arg(long)]
    fee_asset_price_e8: u128,
    #[arg(long, default_value_t = 16_100)]
    oracle_port: u16,
    #[arg(long, default_value = "NOX_PAID_MESH_EXIT_PRIVATE_KEY")]
    exit_private_key_env: String,
}

#[derive(Clone, Serialize)]
struct OracleEntry {
    price_e8: String,
    observed_at_unix: u64,
    asset_id: String,
    source: String,
}

#[derive(Clone)]
struct FixtureState {
    prices: Arc<RwLock<HashMap<String, OracleEntry>>>,
    topology: Arc<RwLock<Option<TopologySnapshot>>>,
}

#[derive(Serialize)]
struct MeshNodeInfo {
    id: usize,
    role: String,
    layer: u8,
    p2p_multiaddr: String,
    ingress_url: Option<String>,
    metrics_url: String,
    sphinx_public_key: String,
    peer_id: String,
    db_path: String,
}

#[derive(Serialize)]
struct SelectedExitInfo {
    address: String,
    node_id: usize,
    p2p_multiaddr: String,
    metrics_url: String,
    db_path: String,
}

#[derive(Serialize)]
struct PaidMeshInfo {
    entry_url: String,
    topology_urls: Vec<String>,
    selected_exit: SelectedExitInfo,
    chain_id: u64,
    rpc_url: String,
    entry_point_address: String,
    payment_adapter_address: String,
    reward_pool_address: String,
    fee_asset_address: String,
    native_asset_price_id: String,
    fee_asset_price_id: String,
    oracle_url: String,
    nodes: Vec<MeshNodeInfo>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationNode {
    address: String,
    sphinx_key: String,
    url: String,
    ingress_url: String,
    metadata_url: String,
    role: u8,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationManifest {
    kind: &'static str,
    chain_id: u64,
    rpc_url: String,
    registry_address: String,
    topology_fingerprint: String,
    nodes: Vec<RegistrationNode>,
}

struct GeneratedNode {
    process: NoxProcess,
    address: String,
    role: u8,
    layer: u8,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    if cli.data_dir.exists() {
        bail!(
            "paid mesh data directory already exists: {}",
            cli.data_dir.display()
        );
    }
    if cli.native_price_e8 == 0 || cli.fee_asset_price_e8 == 0 {
        bail!("paid mesh oracle prices must be positive E8 integers");
    }
    ensure_ports_available(cli.base_port, cli.oracle_port)?;
    std::fs::create_dir_all(&cli.data_dir)?;
    let exit_private_key =
        Zeroizing::new(std::env::var(&cli.exit_private_key_env).with_context(|| {
            format!(
                "missing funded exit key environment variable {}",
                cli.exit_private_key_env
            )
        })?);
    let chain_start_block = build_ethers_http1_provider(cli.rpc_url.as_str())?
        .get_block_number()
        .await?
        .as_u64();
    let oracle_url = format!("http://127.0.0.1:{}", cli.oracle_port);
    let (oracle, fixture_state) = start_fixture_api(&cli, cli.oracle_port).await?;
    let nox_binary = find_nox_binary(cli.nox_binary.as_deref())?;
    let shutdown = CancellationToken::new();
    let signal_task = spawn_shutdown_listener(shutdown.clone())?;

    let mut nodes = Vec::with_capacity(NODE_COUNT);
    for index in 0..NODE_COUNT {
        let role = if index == EXIT_NODE_INDEX { 2 } else { 1 };
        let (node_private_key, address, layer) = if index == EXIT_NODE_INDEX {
            let private_key = Zeroizing::new(exit_private_key.to_string());
            let wallet = LocalWallet::from_str(&private_key)
                .context("paid mesh exit private key is invalid")?
                .with_chain_id(cli.chain_id);
            (private_key, format!("{:?}", wallet.address()), 2)
        } else {
            generate_relay_identity(cli.chain_id, index as u8)?
        };
        let generated = tokio::select! {
            () = shutdown.cancelled() => None,
            result = generate_and_spawn_node(
                &cli,
                &nox_binary,
                &oracle_url,
                &node_private_key,
                index,
                role,
                layer,
                address,
                chain_start_block,
            )
            => Some(result),
        };
        match generated {
            Some(Ok(node)) => nodes.push(node),
            Some(Err(error)) => {
                terminate_runtime(&mut nodes, oracle, signal_task).await;
                return Err(error);
            }
            None => {
                terminate_runtime(&mut nodes, oracle, signal_task).await;
                return Ok(());
            }
        }
    }
    let startup = Duration::from_secs(cli.startup_timeout_secs);
    let startup_result = tokio::select! {
        () = shutdown.cancelled() => None,
        result = async {
            for node in &nodes {
                wait_for_health(node.process.metrics_port, startup).await?;
            }
            let registration = build_registration_manifest(&cli, &nodes)?;
            std::fs::write(
                cli.data_dir.join("registration_manifest.json"),
                serde_json::to_vec_pretty(&registration)?,
            )?;
            let registration_json = serde_json::to_string(&registration)?;
            ensure_public_output_excludes_secret(&registration_json, &exit_private_key)?;
            println!("{registration_json}");
            std::io::stdout().flush()?;
            let verified_block = wait_for_registry(&registration, startup).await?;
            wait_for_topology(&nodes, &registration.topology_fingerprint, startup).await?;
            tokio::time::sleep(Duration::from_secs(cli.mesh_settle_secs)).await;

            *fixture_state.topology.write().await = Some(build_fixture_topology(
                &registration,
                verified_block,
            )?);

            let mesh_info = build_mesh_info(&cli, &oracle_url, &nodes)?;
            let encoded = serde_json::to_string(&mesh_info)?;
            ensure_public_output_excludes_secret(&encoded, &exit_private_key)?;
            println!("{encoded}");
            std::fs::write(
                cli.data_dir.join("mesh_info.json"),
                serde_json::to_vec_pretty(&mesh_info)?,
            )?;
            info!("non-benchmark paid mesh ready");
            Ok::<(), anyhow::Error>(())
        } => Some(result),
    };

    let outcome = match startup_result {
        Some(Ok(())) => {
            shutdown.cancelled().await;
            Ok(())
        }
        Some(Err(error)) => Err(error),
        None => Ok(()),
    };
    terminate_runtime(&mut nodes, oracle, signal_task).await;
    outcome
}

fn ensure_ports_available(base_port: u16, oracle_port: u16) -> Result<()> {
    let mut listeners = Vec::new();
    for offset in [0_u16, 1, 2, 10, 11, 20, 21] {
        let port = base_port
            .checked_add(offset)
            .context("paid mesh port range exceeds u16")?;
        let listener = std::net::TcpListener::bind(("127.0.0.1", port))
            .with_context(|| format!("paid mesh port {port} is already occupied"))?;
        listeners.push(listener);
    }
    listeners.push(
        std::net::TcpListener::bind(("127.0.0.1", oracle_port))
            .with_context(|| format!("paid mesh oracle port {oracle_port} is already occupied"))?,
    );
    Ok(())
}

fn spawn_shutdown_listener(shutdown: CancellationToken) -> Result<tokio::task::JoinHandle<()>> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        Ok(tokio::spawn(async move {
            tokio::select! {
                result = tokio::signal::ctrl_c() => {
                    if let Err(error) = result {
                        warn!(%error, "paid mesh Ctrl-C listener failed");
                    }
                }
                _ = terminate.recv() => {}
            }
            shutdown.cancel();
        }))
    }
    #[cfg(not(unix))]
    {
        Ok(tokio::spawn(async move {
            if let Err(error) = tokio::signal::ctrl_c().await {
                warn!(%error, "paid mesh Ctrl-C listener failed");
            }
            shutdown.cancel();
        }))
    }
}

async fn terminate_runtime(
    nodes: &mut [GeneratedNode],
    oracle: tokio::task::JoinHandle<()>,
    signal_task: tokio::task::JoinHandle<()>,
) {
    signal_task.abort();
    let _ = signal_task.await;
    for node in nodes.iter_mut() {
        if node.process.child.id().is_some() {
            if let Err(error) = node.process.child.start_kill() {
                warn!(node = node.process.id, %error, "paid mesh process termination failed");
            }
        }
    }
    for node in nodes.iter_mut() {
        if let Err(error) = node.process.child.wait().await {
            warn!(node = node.process.id, %error, "paid mesh process wait failed");
        }
    }
    oracle.abort();
    let _ = oracle.await;
}

fn generate_relay_identity(
    chain_id: u64,
    required_layer: u8,
) -> Result<(Zeroizing<String>, String, u8)> {
    for _ in 0..MAX_RELAY_WALLET_ATTEMPTS {
        let wallet = LocalWallet::new(&mut OsRng).with_chain_id(chain_id);
        let address = format!("{:?}", wallet.address());
        let layer = primary_layer_for_role(&address, 1);
        if layer == required_layer {
            return Ok((
                Zeroizing::new(hex::encode(wallet.signer().to_bytes())),
                address,
                layer,
            ));
        }
    }
    bail!("could not generate relay wallet for topology layer {required_layer}")
}

async fn start_fixture_api(
    cli: &Cli,
    port: u16,
) -> Result<(tokio::task::JoinHandle<()>, FixtureState)> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut entries = HashMap::new();
    for (asset_id, price_e8) in [
        (&cli.native_asset_price_id, cli.native_price_e8),
        (&cli.fee_asset_price_id, cli.fee_asset_price_e8),
    ] {
        entries.insert(
            asset_id.clone(),
            OracleEntry {
                price_e8: price_e8.to_string(),
                observed_at_unix: now,
                asset_id: asset_id.clone(),
                source: "paid-mesh-fixture".to_string(),
            },
        );
    }
    let state = FixtureState {
        prices: Arc::new(RwLock::new(entries)),
        topology: Arc::new(RwLock::new(None)),
    };
    let app = Router::new()
        .route("/health", get(|| async { "Healthy" }))
        .route(
            "/prices",
            get(
                |axum::extract::State(state): axum::extract::State<FixtureState>| async move {
                    Json(state.prices.read().await.clone())
                },
            ),
        )
        .route(
            "/topology",
            get(
                |axum::extract::State(state): axum::extract::State<FixtureState>| async move {
                    state
                        .topology
                        .read()
                        .await
                        .clone()
                        .map(Json)
                        .ok_or(axum::http::StatusCode::SERVICE_UNAVAILABLE)
                },
            ),
        )
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    let task = tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app).await {
            tracing::error!(%error, "paid mesh oracle stopped");
        }
    });
    Ok((task, state))
}

#[allow(clippy::too_many_arguments)]
async fn generate_and_spawn_node(
    cli: &Cli,
    nox_binary: &Path,
    oracle_url: &str,
    eth_private_key: &str,
    index: usize,
    role: u8,
    layer: u8,
    address: String,
    chain_start_block: u64,
) -> Result<GeneratedNode> {
    let p2p_port = cli.base_port + u16::try_from(index)? * 10;
    let metrics_port = p2p_port + 1;
    let ingress_port = if index == 0 { p2p_port + 2 } else { 0 };
    let routing_secret = X25519SecretKey::random_from_rng(OsRng);
    let routing_public = X25519PublicKey::from(&routing_secret);
    let p2p_keypair = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(p2p_keypair.public());
    let p2p_secret = Zeroizing::new(
        p2p_keypair
            .try_into_ed25519()
            .map_err(|error| anyhow::anyhow!("ed25519 conversion failed: {error}"))?
            .to_bytes(),
    );
    let node_dir = cli.data_dir.join(format!("node_{index}"));
    std::fs::create_dir_all(&node_dir)?;
    let config_path = node_dir.join("config.toml");
    let mut config = NoxConfig::default();
    config.benchmark_mode = false;
    config.node_role = if role == 2 {
        NodeRole::Exit
    } else {
        NodeRole::Relay
    };
    config.eth_rpc_url = cli.rpc_url.clone();
    config.chain_id = cli.chain_id;
    config.chain_start_block = chain_start_block;
    config.registry_contract_address = cli.registry_address.clone();
    config.nox_reward_pool_address = cli.reward_pool_address.clone();
    config.nox_entry_point_address = cli.entry_point_address.clone();
    config.oracle_url = oracle_url.to_string();
    config.native_asset_price_id = cli.native_asset_price_id.clone();
    config.native_asset_decimals = 18;
    config.chain_data_fee_mode = ChainDataFeeMode::RpcGasEstimateIncludesDataFee;
    config.p2p_port = p2p_port;
    config.p2p_listen_addr = "127.0.0.1".to_string();
    config.metrics_port = metrics_port;
    config.ingress_port = ingress_port;
    config.topology_api_port = 0;
    config.db_path = node_dir.join("db").to_string_lossy().into_owned();
    config.p2p_identity_path = node_dir.join("p2p.key").to_string_lossy().into_owned();
    config.routing_private_key = hex::encode(routing_secret.to_bytes());
    config.p2p_private_key = hex::encode(&p2p_secret[..32]);
    config.eth_wallet_private_key = eth_private_key.to_string();
    config.min_pow_difficulty = 0;
    config.relayer.mix_delay_ms = 0.0;
    config.relayer.cover_traffic_rate = 0.0;
    config.relayer.drop_traffic_rate = 0.0;
    if role == 2 {
        config.quote_ttl_secs = 30;
        config.quote_network_fee_bps = 500;
        config.quote_maximum_transaction_gas = PAID_MESH_MAXIMUM_TRANSACTION_GAS;
        config.quote_max_outstanding = PAID_MESH_MAXIMUM_OUTSTANDING_QUOTES;
        config.quote_max_pending_sponsored_gas = PAID_MESH_MAXIMUM_PENDING_GAS;
        config.quote_rolling_loss_limit_native = "100000000000000000".to_string();
        config.quote_rolling_loss_window_secs = 3_600;
        config.payment_adapters = vec![PaymentAdapterConfig {
            address: cli.payment_adapter_address.clone(),
            fee_assets: vec![cli.fee_asset_address.clone()],
            maximum_payment_gas: 4_000_000,
        }];
        config.tokens = vec![TokenConfig {
            address: cli.fee_asset_address.clone(),
            symbol: "MESH-FEE".to_string(),
            decimals: 18,
            price_id: cli.fee_asset_price_id.clone(),
        }];
    }
    config.validate().map_err(|errors| {
        anyhow::anyhow!(
            "paid mesh node {index} config invalid: {}",
            errors.join("; ")
        )
    })?;
    let serialized = toml::to_string_pretty(&config)?;
    let with_secrets = Zeroizing::new(format!(
        "routing_private_key = \"{}\"\np2p_private_key = \"{}\"\neth_wallet_private_key = \"{}\"\n{serialized}",
        config.routing_private_key, config.p2p_private_key, config.eth_wallet_private_key,
    ));
    std::fs::write(&config_path, with_secrets.as_bytes())?;
    config.routing_private_key.zeroize();
    config.p2p_private_key.zeroize();
    config.eth_wallet_private_key.zeroize();
    let child = spawn_nox_process(index, nox_binary, &config_path).await?;
    Ok(GeneratedNode {
        process: NoxProcess {
            id: index,
            child,
            p2p_port,
            metrics_port,
            ingress_port,
            sphinx_public_key: routing_public,
            peer_id,
            config_path,
            data_path: node_dir,
        },
        address,
        role,
        layer,
    })
}

fn ensure_public_output_excludes_secret(output: &str, secret: &str) -> Result<()> {
    if secret.is_empty() || output.contains(secret) {
        bail!("paid mesh public manifest contains a private-key value")
    }
    Ok(())
}

fn build_registration_manifest(cli: &Cli, nodes: &[GeneratedNode]) -> Result<RegistrationManifest> {
    let registrations = nodes
        .iter()
        .map(|node| RegistrationNode {
            address: node.address.clone(),
            sphinx_key: hex::encode(node.process.sphinx_public_key.as_bytes()),
            url: format!(
                "/ip4/127.0.0.1/tcp/{}/p2p/{}",
                node.process.p2p_port, node.process.peer_id
            ),
            ingress_url: (node.process.ingress_port != 0)
                .then(|| format!("http://127.0.0.1:{}", node.process.ingress_port))
                .unwrap_or_default(),
            metadata_url: String::new(),
            role: node.role,
        })
        .collect::<Vec<_>>();
    let addresses = registrations
        .iter()
        .map(|node| node.address.clone())
        .collect::<Vec<_>>();
    validate_registration_nodes(&registrations)?;
    Ok(RegistrationManifest {
        kind: "registration_required",
        chain_id: cli.chain_id,
        rpc_url: cli.rpc_url.clone(),
        registry_address: cli.registry_address.clone(),
        topology_fingerprint: hex::encode(compute_topology_fingerprint(&addresses)),
        nodes: registrations,
    })
}

fn validate_registration_nodes(nodes: &[RegistrationNode]) -> Result<()> {
    if nodes.len() != NODE_COUNT {
        bail!(
            "paid mesh registration contains {} nodes; expected {NODE_COUNT}",
            nodes.len()
        );
    }
    let mut addresses = HashSet::with_capacity(nodes.len());
    for node in nodes {
        let address = node
            .address
            .parse::<Address>()
            .with_context(|| format!("paid mesh node address is invalid: {}", node.address))?;
        if !addresses.insert(address) {
            bail!("paid mesh registration contains duplicate address {address:?}");
        }
        if !matches!(node.role, 1..=3) {
            bail!("paid mesh registration contains unknown role {}", node.role);
        }
    }
    Ok(())
}

async fn wait_for_registry(manifest: &RegistrationManifest, timeout: Duration) -> Result<u64> {
    let provider = Arc::new(build_ethers_http1_provider(manifest.rpc_url.as_str())?);
    let registry_address = manifest
        .registry_address
        .parse::<Address>()
        .context("paid mesh registry address is invalid")?;
    let registry = NoxRegistryFixture::new(registry_address, provider.clone());
    let expected_fingerprint = hex::decode(&manifest.topology_fingerprint)?;
    let deadline = tokio::time::Instant::now() + timeout;

    while tokio::time::Instant::now() < deadline {
        let block_number = match provider.get_block_number().await {
            Ok(block) if !block.is_zero() => block,
            Ok(_) | Err(_) => {
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let block = BlockId::Number(BlockNumber::Number(block_number));
        let fingerprint = registry.topology_fingerprint().block(block).call().await;
        let count = registry.relayer_count().block(block).call().await;
        if let (Ok(fingerprint), Ok(count)) = (fingerprint, count) {
            if fingerprint.as_slice() == expected_fingerprint
                && count == U256::from(manifest.nodes.len())
                && registry_profiles_match(&registry, &manifest.nodes, block).await
            {
                return Ok(block_number.as_u64());
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    bail!(
        "paid mesh registry did not match registration_manifest.json within {timeout:?}; the current nine-field NoxRegistry profile ABI is required"
    )
}

fn build_fixture_topology(
    manifest: &RegistrationManifest,
    verified_block: u64,
) -> Result<TopologySnapshot> {
    let observed_at_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut nodes = manifest
        .nodes
        .iter()
        .map(|registration| RelayerNode {
            address: registration.address.clone(),
            sphinx_key: registration.sphinx_key.clone(),
            url: registration.url.clone(),
            stake: "0".to_string(),
            last_seen: 0,
            is_privileged: true,
            layer: primary_layer_for_role(&registration.address, registration.role),
            role: registration.role,
            ingress_url: Some(registration.ingress_url.clone()),
            metadata_url: Some(registration.metadata_url.clone()),
        })
        .collect::<Vec<_>>();
    nodes.sort_by(|left, right| left.address.cmp(&right.address));
    let addresses = nodes
        .iter()
        .map(|node| node.address.clone())
        .collect::<Vec<_>>();
    let fingerprint = hex::encode(compute_topology_fingerprint(&addresses));
    if fingerprint != manifest.topology_fingerprint {
        bail!("paid mesh fixture topology fingerprint does not match registration")
    }
    let liveness = nodes
        .iter()
        .map(|node| TopologyLiveness {
            address: node.address.clone(),
            status: TopologyLivenessStatus::Online,
            observed_at_unix,
        })
        .collect();
    Ok(TopologySnapshot {
        nodes,
        fingerprint,
        timestamp: observed_at_unix,
        block_number: verified_block,
        pow_difficulty: 0,
        schema_version: 2,
        liveness,
    })
}

async fn registry_profiles_match<M: ethers::providers::Middleware>(
    registry: &NoxRegistryFixture<M>,
    nodes: &[RegistrationNode],
    block: BlockId,
) -> bool {
    for node in nodes {
        let Ok(address) = node.address.parse::<Address>() else {
            return false;
        };
        let Ok(profile) = registry.relayers(address).block(block).call().await else {
            return false;
        };
        let Ok(role) = registry.get_node_role(address).block(block).call().await else {
            return false;
        };
        let Ok(sphinx_key) = hex::decode(&node.sphinx_key) else {
            return false;
        };
        if profile.0.as_slice() != sphinx_key
            || profile.1 != node.url
            || profile.2 != node.ingress_url
            || profile.3 != node.metadata_url
            || !profile.4.is_zero()
            || !profile.6
            || !matches!(profile.7, 1 | 2)
            || profile.8
            || role != node.role
        {
            return false;
        }
    }
    true
}

async fn wait_for_topology(
    nodes: &[GeneratedNode],
    expected_fingerprint: &str,
    timeout: Duration,
) -> Result<()> {
    let client = reqwest::Client::new();
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        let mut all_ready = true;
        for node in nodes {
            let url = format!("http://127.0.0.1:{}/topology", node.process.metrics_port);
            let snapshot = match client.get(&url).send().await {
                Ok(response) => response.json::<TopologySnapshot>().await,
                Err(error) => Err(error),
            };
            if !matches!(snapshot, Ok(snapshot) if snapshot.fingerprint == expected_fingerprint && snapshot.nodes.len() == nodes.len() && snapshot_has_paid_route(&snapshot))
            {
                all_ready = false;
                break;
            }
        }
        if all_ready {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    bail!("paid mesh nodes did not converge on the chain-registered topology within {timeout:?}")
}

fn snapshot_has_paid_route(snapshot: &TopologySnapshot) -> bool {
    snapshot.nodes.iter().any(|node| {
        nox_core::models::topology::layers_for_role(node.role).contains(&0)
            && node
                .ingress_url
                .as_deref()
                .is_some_and(|ingress| !ingress.is_empty())
    }) && snapshot
        .nodes
        .iter()
        .any(|node| nox_core::models::topology::layers_for_role(node.role).contains(&1))
        && snapshot.nodes.iter().any(|node| matches!(node.role, 2 | 3))
}

fn build_mesh_info(cli: &Cli, oracle_url: &str, nodes: &[GeneratedNode]) -> Result<PaidMeshInfo> {
    let node_info = nodes
        .iter()
        .map(|node| MeshNodeInfo {
            id: node.process.id,
            role: if node.role == 2 { "exit" } else { "relay" }.to_string(),
            layer: node.layer,
            p2p_multiaddr: format!(
                "/ip4/127.0.0.1/tcp/{}/p2p/{}",
                node.process.p2p_port, node.process.peer_id
            ),
            ingress_url: (node.process.ingress_port != 0)
                .then(|| format!("http://127.0.0.1:{}", node.process.ingress_port)),
            metrics_url: format!("http://127.0.0.1:{}", node.process.metrics_port),
            sphinx_public_key: hex::encode(node.process.sphinx_public_key.as_bytes()),
            peer_id: node.process.peer_id.to_string(),
            db_path: node
                .process
                .data_path
                .join("db")
                .to_string_lossy()
                .into_owned(),
        })
        .collect::<Vec<_>>();
    let exit = nodes
        .get(EXIT_NODE_INDEX)
        .context("paid mesh exit missing")?;
    Ok(PaidMeshInfo {
        entry_url: format!("http://127.0.0.1:{}", nodes[0].process.ingress_port),
        topology_urls: vec![format!("{oracle_url}/topology")],
        selected_exit: SelectedExitInfo {
            address: exit.address.clone(),
            node_id: exit.process.id,
            p2p_multiaddr: format!(
                "/ip4/127.0.0.1/tcp/{}/p2p/{}",
                exit.process.p2p_port, exit.process.peer_id
            ),
            metrics_url: format!("http://127.0.0.1:{}", exit.process.metrics_port),
            db_path: exit
                .process
                .data_path
                .join("db")
                .to_string_lossy()
                .into_owned(),
        },
        chain_id: cli.chain_id,
        rpc_url: cli.rpc_url.clone(),
        entry_point_address: cli.entry_point_address.clone(),
        payment_adapter_address: cli.payment_adapter_address.clone(),
        reward_pool_address: cli.reward_pool_address.clone(),
        fee_asset_address: cli.fee_asset_address.clone(),
        native_asset_price_id: cli.native_asset_price_id.clone(),
        fee_asset_price_id: cli.fee_asset_price_id.clone(),
        oracle_url: oracle_url.to_string(),
        nodes: node_info,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn occupied_mesh_port_fails_before_process_start() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind occupied port");
        let port = listener.local_addr().expect("occupied address").port();
        let error = ensure_ports_available(port, 0).unwrap_err().to_string();
        assert!(error.contains(&format!("paid mesh port {port} is already occupied")));
    }
}
