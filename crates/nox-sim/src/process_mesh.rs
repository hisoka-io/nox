//! Multi-process mesh infrastructure: spawns N real nox processes with wired topology.

use anyhow::{bail, Context, Result};
use libp2p::identity;
use libp2p::PeerId;
use rand::rngs::OsRng;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::process::Command;
use tracing::{info, warn};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

use nox_crypto::sphinx::packet::PACKET_SIZE;
use nox_crypto::{build_multi_hop_packet, PathHop};

/// Metadata for a running nox process.
pub struct NoxProcess {
    pub id: usize,
    pub child: tokio::process::Child,
    pub p2p_port: u16,
    pub metrics_port: u16,
    pub ingress_port: u16,
    pub sphinx_public_key: X25519PublicKey,
    pub peer_id: PeerId,
    #[allow(dead_code)]
    pub config_path: PathBuf,
    pub data_path: PathBuf,
}

/// Generate a TOML config file for one benchmark node.
#[allow(clippy::too_many_arguments)]
pub fn generate_node_config(
    id: usize,
    p2p_port: u16,
    metrics_port: u16,
    ingress_port: u16,
    data_dir: &Path,
    routing_private_key: &str,
    p2p_private_key_hex: &str,
    mix_delay_ms: f64,
    eth_rpc_url: &str,
) -> Result<(PathBuf, String)> {
    let node_dir = data_dir.join(format!("node_{id}"));
    std::fs::create_dir_all(&node_dir)?;

    let db_path = node_dir.join("db");
    let id_path = node_dir.join("id.key");
    let config_path = node_dir.join("config.toml");

    let mut config = nox_node::NoxConfig::default();
    config.benchmark_mode = true;
    config.p2p_port = p2p_port;
    config.p2p_listen_addr = "127.0.0.1".into();
    config.metrics_port = metrics_port;
    config.ingress_port = ingress_port;
    config.db_path = db_path.to_string_lossy().into_owned();
    config.p2p_identity_path = id_path.to_string_lossy().into_owned();
    config.routing_private_key = routing_private_key.into();
    config.eth_wallet_private_key = hex::encode(rand::random::<[u8; 32]>());
    config.eth_rpc_url = eth_rpc_url.into();
    config.min_pow_difficulty = 0;
    config.min_gas_balance = "0".into();
    config.relayer.mix_delay_ms = mix_delay_ms;
    config.relayer.cover_traffic_rate = 0.0;
    config.relayer.drop_traffic_rate = 0.0;
    // Generous limits for benchmark/stress-test workloads
    config.http.max_response_bytes = 128 * 1024 * 1024;
    config.http.request_timeout_secs = 120;
    config.http.allow_private_ips = true;
    config.network.max_concurrent_streams = 10_000;
    config.network.rate_limit.burst_unknown = 5_000;
    config.network.rate_limit.rate_unknown = 10_000;
    config.network.rate_limit.burst_trusted = 10_000;
    config.network.rate_limit.rate_trusted = 20_000;
    config.network.rate_limit.burst_penalized = 1_000;
    config.network.rate_limit.rate_penalized = 2_000;
    config.network.rate_limit.violations_before_disconnect = 1_000;

    // Secret fields have #[serde(skip_serializing)] -- prepend them before
    // any [table] sections so TOML parses them as top-level keys.
    let main_toml =
        toml::to_string_pretty(&config).context("Failed to serialize NoxConfig to TOML")?;

    let toml_string = format!(
        "# NOX Benchmark Node {id} (auto-generated)\n\
         routing_private_key = \"{}\"\n\
         p2p_private_key = \"{p2p_private_key_hex}\"\n\
         eth_wallet_private_key = \"{}\"\n\n\
         {main_toml}",
        config.routing_private_key, config.eth_wallet_private_key,
    );

    std::fs::write(&config_path, &toml_string)?;

    Ok((config_path, toml_string))
}

/// Find the nox binary, preferring release build over debug.
pub fn find_nox_binary(explicit: Option<&str>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        let p = PathBuf::from(path);
        if p.exists() {
            return Ok(p);
        }
        bail!("Specified nox binary not found: {path}");
    }

    let nox_pkg_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // nox-sim -> crates
        .and_then(|p| p.parent()) // crates -> nox
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);

    let search_paths = [
        nox_pkg_root.join("target/release/nox"),
        nox_pkg_root.join("target/debug/nox"),
    ];

    for path in &search_paths {
        if path.exists() {
            if path.to_string_lossy().contains("debug") {
                warn!("Using debug nox binary -- numbers will be slower than release");
            }
            return Ok(path.canonicalize().unwrap_or_else(|_| path.clone()));
        }
    }

    let searched: Vec<String> = search_paths
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    bail!(
        "nox binary not found. Build it first: cargo build --release -p nox\n\
         Searched:\n  {}",
        searched.join("\n  ")
    );
}

/// Spawn a single nox process with stdout/stderr redirected to `node.log`.
pub async fn spawn_nox_process(
    id: usize,
    nox_binary: &Path,
    config_path: &Path,
) -> Result<tokio::process::Child> {
    let log_path = config_path.parent().unwrap_or(config_path).join("node.log");
    let stdout_file = std::fs::File::create(&log_path)
        .with_context(|| format!("Failed to create log for node {id}: {}", log_path.display()))?;
    let stderr_file = stdout_file
        .try_clone()
        .with_context(|| format!("Failed to clone log file handle for node {id}"))?;

    let child = Command::new(nox_binary)
        .arg("--config")
        .arg(config_path)
        .stdout(std::process::Stdio::from(stdout_file))
        .stderr(std::process::Stdio::from(stderr_file))
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("Failed to spawn nox process {id}"))?;

    Ok(child)
}

/// Wait for a node's health endpoint to respond within `timeout`.
pub async fn wait_for_health(metrics_port: u16, timeout: Duration) -> Result<()> {
    let url = format!("http://127.0.0.1:{metrics_port}/topology");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?;
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline {
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            _ => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }

    bail!("Node on metrics port {metrics_port} did not become healthy within {timeout:?}");
}

/// Register a node in another node's topology via the admin API.
pub async fn register_topology(
    client: &reqwest::Client,
    target_metrics_port: u16,
    address: &str,
    sphinx_key_hex: &str,
    p2p_multiaddr: &str,
    ingress_url: Option<&str>,
) -> Result<()> {
    let url = format!("http://127.0.0.1:{target_metrics_port}/admin/topology/register");
    let mut body = serde_json::json!({
        "address": address,
        "sphinx_key": sphinx_key_hex,
        "url": p2p_multiaddr,
        "stake": "1000",
        "role": 3
    });
    if let Some(ingress) = ingress_url {
        body["ingress_url"] = serde_json::Value::String(ingress.to_string());
    }

    let resp = client.post(&url).json(&body).send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();
        bail!("Topology registration failed: HTTP {status} -- {body_text}");
    }
    Ok(())
}

/// A mesh of N real `nox` processes with wired topology.
pub struct ProcessMesh {
    pub nodes: Vec<NoxProcess>,
    pub http_client: reqwest::Client,
}

impl ProcessMesh {
    #[allow(clippy::too_many_arguments)]
    pub async fn build(
        node_count: usize,
        nox_binary: &Path,
        data_dir: &Path,
        base_port: u16,
        startup_timeout: Duration,
        mesh_settle: Duration,
        mix_delay_ms: f64,
        eth_rpc_url: &str,
    ) -> Result<Self> {
        if data_dir.exists() {
            std::fs::remove_dir_all(data_dir)?;
        }
        std::fs::create_dir_all(data_dir)?;

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(35))
            .build()?;

        info!("Generating configs for {node_count} nodes...");
        struct NodeInfo {
            id: usize,
            p2p_port: u16,
            metrics_port: u16,
            ingress_port: u16,
            sphinx_pk: X25519PublicKey,
            peer_id: PeerId,
            config_path: PathBuf,
            data_path: PathBuf,
        }

        let mut node_infos: Vec<NodeInfo> = Vec::new();

        for i in 0..node_count {
            let p2p_port = base_port + (i as u16) * 10;
            let metrics_port = p2p_port + 1;
            let ingress_port = p2p_port + 2;

            let sk = X25519SecretKey::random_from_rng(OsRng);
            let pk = X25519PublicKey::from(&sk);
            let sk_hex = hex::encode(sk.to_bytes());

            // Generate P2P key here so we know PeerId before the node starts
            let p2p_keypair = identity::Keypair::generate_ed25519();
            let peer_id = PeerId::from(p2p_keypair.public());
            // to_bytes() gives [u8; 64] (secret || public); first 32 are the seed
            let ed25519_kp = p2p_keypair
                .try_into_ed25519()
                .map_err(|e| anyhow::anyhow!("ed25519 conversion failed: {e}"))?;
            let kp_bytes = ed25519_kp.to_bytes();
            let p2p_secret_hex = hex::encode(&kp_bytes[..32]);

            let (config_path, _toml) = generate_node_config(
                i,
                p2p_port,
                metrics_port,
                ingress_port,
                data_dir,
                &sk_hex,
                &p2p_secret_hex,
                mix_delay_ms,
                eth_rpc_url,
            )?;

            let data_path = data_dir.join(format!("node_{i}"));
            node_infos.push(NodeInfo {
                id: i,
                p2p_port,
                metrics_port,
                ingress_port,
                sphinx_pk: pk,
                peer_id,
                config_path,
                data_path,
            });
        }

        info!("Spawning {node_count} nox processes...");
        let mut nodes = Vec::with_capacity(node_count);
        for info in &node_infos {
            let child = spawn_nox_process(info.id, nox_binary, &info.config_path).await?;
            nodes.push(NoxProcess {
                id: info.id,
                child,
                p2p_port: info.p2p_port,
                metrics_port: info.metrics_port,
                ingress_port: info.ingress_port,
                sphinx_public_key: info.sphinx_pk,
                peer_id: info.peer_id,
                config_path: info.config_path.clone(),
                data_path: info.data_path.clone(),
            });
        }

        info!("Waiting for {node_count} nodes to become healthy (timeout: {startup_timeout:?})...");
        let health_futures: Vec<_> = nodes
            .iter()
            .map(|n| wait_for_health(n.metrics_port, startup_timeout))
            .collect();
        let results = futures::future::join_all(health_futures).await;

        let mut failed = Vec::new();
        for (i, result) in results.into_iter().enumerate() {
            if let Err(e) = result {
                failed.push(format!("Node {i}: {e}"));
            }
        }
        if !failed.is_empty() {
            for node in &mut nodes {
                let _ = node.child.kill().await;
            }
            bail!("Nodes failed to start:\n{}", failed.join("\n"));
        }
        info!("All {node_count} nodes healthy.");

        info!("Registering topology ({node_count}x{node_count} entries)...");
        for target in &nodes {
            let target_addr = format!("0xBenchNode{}", target.id);
            let target_sphinx = hex::encode(target.sphinx_public_key.as_bytes());
            let target_p2p = format!(
                "/ip4/127.0.0.1/tcp/{}/p2p/{}",
                target.p2p_port, target.peer_id
            );
            let target_ingress = format!("http://127.0.0.1:{}", target.ingress_port);

            for source in &nodes {
                if let Err(e) = register_topology(
                    &http_client,
                    source.metrics_port,
                    &target_addr,
                    &target_sphinx,
                    &target_p2p,
                    Some(&target_ingress),
                )
                .await
                {
                    warn!(
                        "Topology registration node {} -> node {}: {e}",
                        source.id, target.id
                    );
                }
            }
        }

        info!("Mesh settling ({mesh_settle:?})...");
        tokio::time::sleep(mesh_settle).await;

        Ok(Self { nodes, http_client })
    }

    pub async fn teardown(&mut self) {
        info!("Tearing down {} nodes...", self.nodes.len());
        for node in &mut self.nodes {
            match node.child.kill().await {
                Ok(()) => info!("Node {} terminated.", node.id),
                Err(e) => warn!("Node {} kill failed: {e}", node.id),
            }
        }
        if std::env::var("NOX_KEEP_LOGS").as_deref() == Ok("1") {
            info!("NOX_KEEP_LOGS=1 -- preserving node data for debugging");
        } else if let Some(first) = self.nodes.first() {
            if let Some(parent) = first.data_path.parent() {
                let _ = std::fs::remove_dir_all(parent);
            }
        }
    }

    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

impl Drop for ProcessMesh {
    fn drop(&mut self) {
        for node in &mut self.nodes {
            let _ = node.child.start_kill();
        }
    }
}

/// Build a Sphinx packet for HTTP injection (always exactly `PACKET_SIZE` bytes).
pub fn build_padded_packet(path: &[PathHop], payload_bytes: &[u8]) -> Result<Vec<u8>> {
    let packet = build_multi_hop_packet(path, payload_bytes, 0)?;
    debug_assert_eq!(
        packet.len(),
        PACKET_SIZE,
        "build_multi_hop_packet must return exactly PACKET_SIZE bytes"
    );
    Ok(packet)
}

/// Inject a Sphinx packet and poll until delivery. Returns end-to-end latency.
pub async fn inject_and_measure(
    client: &reqwest::Client,
    entry_ingress_port: u16,
    exit_ingress_port: u16,
    packet_bytes: Vec<u8>,
    timeout: Duration,
) -> Result<Duration> {
    let start = Instant::now();

    let inject_url = format!("http://127.0.0.1:{entry_ingress_port}/api/v1/packets");
    let resp = client
        .post(&inject_url)
        .body(packet_bytes)
        .send()
        .await
        .context("Packet injection failed")?;

    if resp.status() != reqwest::StatusCode::ACCEPTED {
        bail!(
            "Injection rejected: HTTP {} -- {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }

    let packet_id = resp.text().await?.trim().to_string();
    let poll_url = format!("http://127.0.0.1:{exit_ingress_port}/api/v1/responses/{packet_id}");
    let deadline = start + timeout;

    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let poll_timeout = remaining.min(Duration::from_secs(30));

        match tokio::time::timeout(poll_timeout, client.get(&poll_url).send()).await {
            Ok(Ok(resp)) if resp.status() == reqwest::StatusCode::OK => {
                return Ok(start.elapsed());
            }
            Ok(Ok(resp)) if resp.status() == reqwest::StatusCode::NO_CONTENT => {}
            Ok(Ok(resp)) => {
                bail!("Unexpected response status: {}", resp.status());
            }
            Ok(Err(_)) | Err(_) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }

    bail!("Timeout waiting for E2E delivery (packet_id={packet_id})");
}

/// Fire-and-forget packet injection (no response wait).
pub async fn inject_packet(
    client: &reqwest::Client,
    ingress_port: u16,
    packet_bytes: Vec<u8>,
) -> Result<String> {
    let url = format!("http://127.0.0.1:{ingress_port}/api/v1/packets");
    let resp = client.post(&url).body(packet_bytes).send().await?;

    if resp.status() != reqwest::StatusCode::ACCEPTED {
        bail!("Injection rejected: HTTP {}", resp.status());
    }

    let packet_id = resp.text().await?;
    Ok(packet_id)
}
