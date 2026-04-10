//! Long-running multi-process mesh of real `nox` nodes for external SDK testing.
//! Prints connection JSON to stdout; Ctrl+C tears down all processes.

#![allow(clippy::expect_used)] // CLI binary: panicking on tracing/serde init is acceptable.

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use anyhow::Result;
use clap::Parser;
use nox_sim::process_mesh::{find_nox_binary, ProcessMesh};
use serde::Serialize;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{info, Level};

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "NOX Mesh Server -- spawn a real multi-process mixnet and keep it running"
)]
struct Cli {
    /// Number of nox processes to spawn.
    #[arg(short, long, default_value_t = 10)]
    nodes: usize,

    /// Path to the nox binary. Defaults to target/release/nox or target/debug/nox.
    #[arg(long)]
    nox_binary: Option<String>,

    /// Base directory for node data (configs, DBs, logs).
    #[arg(long, default_value = "/tmp/nox_mesh")]
    data_dir: String,

    /// Base port for P2P (node N gets base + N*10, metrics = base + N*10+1,
    /// ingress = base + N*10+2).
    #[arg(long, default_value_t = 14000)]
    base_port: u16,

    /// Seconds to wait for all nodes to become healthy.
    #[arg(long, default_value_t = 30)]
    startup_timeout: u64,

    /// Seconds to wait after topology injection for P2P mesh to stabilize.
    #[arg(long, default_value_t = 5)]
    mesh_settle_secs: u64,

    /// Poisson mix delay per hop in ms (0 = instant forwarding for testing).
    #[arg(long, default_value_t = 0.0)]
    mix_delay_ms: f64,

    /// Anvil RPC port. Nodes will connect to `http://127.0.0.1:<port>`.
    #[arg(long, default_value_t = 8545)]
    anvil_port: u16,
}

/// Connection info for a single node.
#[derive(Serialize)]
struct NodeInfo {
    id: usize,
    p2p_port: u16,
    metrics_port: u16,
    ingress_port: u16,
    sphinx_public_key: String,
    peer_id: String,
    p2p_multiaddr: String,
    layer: u8,
    role: u8,
}

/// Top-level connection info for the mesh.
#[derive(Serialize)]
struct MeshInfo {
    node_count: usize,
    entry_url: String,
    anvil_rpc_url: String,
    nodes: Vec<NodeInfo>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");

    let cli = Cli::parse();
    let nox_binary = find_nox_binary(cli.nox_binary.as_deref())?;
    info!("Using nox binary: {}", nox_binary.display());

    let data_dir = PathBuf::from(&cli.data_dir);
    let anvil_rpc_url = format!("http://127.0.0.1:{}", cli.anvil_port);
    let mut mesh = ProcessMesh::build(
        cli.nodes,
        &nox_binary,
        &data_dir,
        cli.base_port,
        Duration::from_secs(cli.startup_timeout),
        Duration::from_secs(cli.mesh_settle_secs),
        cli.mix_delay_ms,
        &anvil_rpc_url,
    )
    .await?;

    let nodes: Vec<NodeInfo> = mesh
        .nodes
        .iter()
        .map(|n| {
            let pk_hex = hex::encode(n.sphinx_public_key.as_bytes());
            let multiaddr = format!("/ip4/127.0.0.1/tcp/{}/p2p/{}", n.p2p_port, n.peer_id);
            NodeInfo {
                id: n.id,
                p2p_port: n.p2p_port,
                metrics_port: n.metrics_port,
                ingress_port: n.ingress_port,
                sphinx_public_key: pk_hex,
                peer_id: n.peer_id.to_string(),
                p2p_multiaddr: multiaddr,
                layer: (n.id % 3) as u8,
                role: 3,
            }
        })
        .collect();

    let entry_url = format!("http://127.0.0.1:{}", mesh.nodes[0].ingress_port);

    let mesh_info = MeshInfo {
        node_count: mesh.nodes.len(),
        entry_url,
        anvil_rpc_url,
        nodes,
    };

    println!(
        "{}",
        serde_json::to_string(&mesh_info).expect("serialize mesh info")
    );

    let info_path = data_dir.join("mesh_info.json");
    if let Ok(pretty) = serde_json::to_string_pretty(&mesh_info) {
        let _ = std::fs::write(&info_path, &pretty);
        info!("Mesh info written to {}", info_path.display());
    }

    info!(
        "Mesh ready: {} nodes, entry at http://127.0.0.1:{}",
        mesh.nodes.len(),
        mesh.nodes[0].ingress_port
    );
    info!("Press Ctrl+C to shut down the mesh.");

    tokio::signal::ctrl_c().await?;
    info!("Received SIGINT, tearing down mesh...");

    mesh.teardown().await;
    info!("Mesh teardown complete.");

    Ok(())
}
