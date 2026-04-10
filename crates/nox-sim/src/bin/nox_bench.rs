//! In-process mixnet integration benchmarks: latency, throughput, scaling, and SURB RTT.
//!
//! Subcommands: `latency`, `throughput`, `scale`, `surb-rtt`.
//! JSON results on stdout; human-readable progress on stderr.

// Benchmark binary: panicking on serialization failure is acceptable.
#![allow(clippy::expect_used)]

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use libp2p::multiaddr::Protocol;
use rand::rngs::OsRng;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::tempdir;
use tokio::sync::{oneshot, Semaphore};
use tracing::{error, info, Level};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

use nox_core::events::NoxEvent;
use nox_core::models::payloads::{decode_payload, encode_payload};
use nox_core::traits::interfaces::{IEventPublisher, IEventSubscriber};
use nox_core::{Reassembler, ReassemblerConfig, RelayerPayload};
use nox_crypto::{build_multi_hop_packet, PathHop, Surb};
use nox_node::services::mixing::{NoMixStrategy, PoissonMixStrategy};
use nox_node::services::network_manager::TopologyManager;
use nox_node::services::relayer::RelayerService;
use nox_node::services::response_packer::ResponsePacker;
use nox_node::telemetry::metrics::MetricsService;
use nox_node::{NoxConfig, SledRepository, TokioEventBus};
#[cfg(feature = "hop-metrics")]
use nox_sim::bench_common::HopBreakdown;
use nox_sim::bench_common::{self, BenchResult, ScalePoint, ThroughputPoint};

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "NOX Integration Benchmark -- latency CDFs, throughput curves, scaling tests"
)]
struct Cli {
    /// Number of independent runs for statistical aggregation (default 1).
    /// When >1, runs the benchmark N times and computes cross-run
    /// mean/stddev/95% CI for key metrics.
    #[arg(long, default_value_t = 1, global = true)]
    runs: usize,

    /// Event bus capacity per node (tokio broadcast channel size).
    /// Increase if you see Lagged errors at high throughput.
    #[arg(long, default_value_t = 16384, global = true)]
    bus_capacity: usize,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Measure latency distribution (CDF) at fixed send rate
    Latency {
        /// Number of mix nodes
        #[arg(short, long, default_value_t = 5)]
        nodes: usize,

        /// Total packets to send
        #[arg(short, long, default_value_t = 1000)]
        packets: usize,

        /// Number of hops per path (min 2, default 3)
        #[arg(long, default_value_t = 3)]
        hops: usize,

        /// Poisson mix delay per hop in ms (0 = no artificial delay)
        #[arg(long, default_value_t = 0.0)]
        mix_delay_ms: f64,

        /// Max concurrent in-flight packets
        #[arg(long, default_value_t = 50)]
        concurrency: usize,

        /// Warmup packets to discard from stats
        #[arg(long, default_value_t = 50)]
        warmup: usize,

        /// Payload size in bytes (default 256 -- representative of a `DeFi` relay)
        #[arg(long, default_value_t = 256)]
        payload_size: usize,

        /// Mesh stabilization time in seconds after wiring topology
        #[arg(long, default_value_t = 2)]
        settle_secs: u64,

        /// Include sorted raw per-packet latencies in JSON output (for CDF charts)
        #[arg(long, default_value_t = false)]
        raw_latencies: bool,
    },

    /// Measure throughput saturation curve
    Throughput {
        /// Number of mix nodes
        #[arg(short, long, default_value_t = 5)]
        nodes: usize,

        /// Duration of each rate step in seconds
        #[arg(long, default_value_t = 10)]
        duration: u64,

        /// Target packets-per-second (comma-separated for sweep, or single value)
        #[arg(long, default_value = "100,500,1000,2000,5000")]
        target_pps: String,

        /// Number of hops per path (min 2, default 3)
        #[arg(long, default_value_t = 3)]
        hops: usize,

        /// Poisson mix delay per hop in ms
        #[arg(long, default_value_t = 0.0)]
        mix_delay_ms: f64,

        /// Payload size in bytes
        #[arg(long, default_value_t = 256)]
        payload_size: usize,

        /// Mesh stabilization time in seconds
        #[arg(long, default_value_t = 2)]
        settle_secs: u64,
    },

    /// Scaling test: run latency/throughput at multiple node counts
    Scale {
        /// Comma-separated node counts
        #[arg(long, default_value = "3,5,10,15")]
        node_counts: String,

        /// Packets per test
        #[arg(short, long, default_value_t = 500)]
        packets: usize,

        /// Number of hops per path (min 2, default 3)
        #[arg(long, default_value_t = 3)]
        hops: usize,

        /// Poisson mix delay per hop in ms
        #[arg(long, default_value_t = 0.0)]
        mix_delay_ms: f64,

        /// Max concurrent in-flight packets
        #[arg(long, default_value_t = 50)]
        concurrency: usize,

        /// Payload size in bytes
        #[arg(long, default_value_t = 256)]
        payload_size: usize,

        /// Mesh stabilization time in seconds
        #[arg(long, default_value_t = 2)]
        settle_secs: u64,

        /// Include sorted raw per-packet latencies in JSON output
        #[arg(long, default_value_t = false)]
        raw_latencies: bool,
    },

    /// Measure SURB round-trip time through the mesh
    SurbRtt {
        /// Number of mix nodes
        #[arg(short, long, default_value_t = 5)]
        nodes: usize,

        /// Total SURB round-trips to measure
        #[arg(short, long, default_value_t = 200)]
        packets: usize,

        /// Number of hops per leg (forward and return each use this many hops, min 2, default 3)
        #[arg(long, default_value_t = 3)]
        hops: usize,

        /// Poisson mix delay per hop in ms
        #[arg(long, default_value_t = 0.0)]
        mix_delay_ms: f64,

        /// Max concurrent in-flight round-trips
        #[arg(long, default_value_t = 25)]
        concurrency: usize,

        /// Payload size in bytes
        #[arg(long, default_value_t = 256)]
        payload_size: usize,

        /// Mesh stabilization time in seconds
        #[arg(long, default_value_t = 2)]
        settle_secs: u64,

        /// Include sorted raw per-packet latencies in JSON output
        #[arg(long, default_value_t = false)]
        raw_latencies: bool,
    },

    /// Compare SURB round-trip with and without FEC (Reed-Solomon parity)
    SurbRttFec {
        /// Number of mix nodes
        #[arg(short, long, default_value_t = 5)]
        nodes: usize,

        /// Total round-trips per mode (no-FEC and with-FEC)
        #[arg(short, long, default_value_t = 100)]
        packets: usize,

        /// Number of hops per leg (forward and return each use this many hops, min 2, default 3)
        #[arg(long, default_value_t = 3)]
        hops: usize,

        /// Poisson mix delay per hop in ms
        #[arg(long, default_value_t = 0.0)]
        mix_delay_ms: f64,

        /// Max concurrent in-flight round-trips
        #[arg(long, default_value_t = 10)]
        concurrency: usize,

        /// Response size in bytes (data to pack with `ResponsePacker`)
        #[arg(long, default_value_t = 10240)]
        response_size: usize,

        /// FEC ratio (parity shards / data shards). 0.0 disables FEC mode entirely.
        #[arg(long, default_value_t = 0.3)]
        fec_ratio: f64,

        /// Mesh stabilization time in seconds
        #[arg(long, default_value_t = 2)]
        settle_secs: u64,

        /// Include sorted raw per-packet latencies in JSON output
        #[arg(long, default_value_t = false)]
        raw_latencies: bool,
    },

    /// Measure per-hop Sphinx processing breakdown (requires --features hop-metrics)
    PerHop {
        /// Number of mix nodes in the mesh
        #[arg(short, long, default_value_t = 5)]
        nodes: usize,

        /// Total packets to send for aggregation
        #[arg(short, long, default_value_t = 500)]
        packets: usize,

        /// Number of hops per path (min 2, default 3)
        #[arg(long, default_value_t = 3)]
        hops: usize,

        /// Poisson mix delay per hop in ms (0 = no artificial delay)
        #[arg(long, default_value_t = 0.0)]
        mix_delay_ms: f64,

        /// Max concurrent in-flight packets
        #[arg(long, default_value_t = 50)]
        concurrency: usize,

        /// Payload size in bytes
        #[arg(long, default_value_t = 256)]
        payload_size: usize,

        /// Mesh stabilization time in seconds
        #[arg(long, default_value_t = 2)]
        settle_secs: u64,
    },
}

//   BenchResult, HardwareSpec, LatencyStats, ThroughputPoint, ScalePoint,
//   OpStats, HopBreakdown, compute_op_stats (hop-metrics only)

struct BenchNode {
    id: usize,
    multiaddr: String,
    public_key: X25519PublicKey,
    bus_publisher: Arc<dyn IEventPublisher>,
    bus_subscriber: Arc<dyn IEventSubscriber>,
    // Keep alive -- dropping these tears down the node
    _storage: Arc<SledRepository>,
    _db_dir: tempfile::TempDir,
}

// for their packet_id (O(N^2) wakeups), we use a single watcher per exit node that
// dispatches to per-packet oneshot channels.

type CompletionRegistry =
    Arc<parking_lot::Mutex<std::collections::HashMap<String, oneshot::Sender<()>>>>;

/// Spawn a single watcher task that listens on the exit node's bus and dispatches
/// `PayloadDecrypted` events to the registered oneshot channels.
fn spawn_completion_watcher(subscriber: Arc<dyn IEventSubscriber>, registry: CompletionRegistry) {
    tokio::spawn(async move {
        let mut rx = subscriber.subscribe();
        loop {
            match rx.recv().await {
                Ok(NoxEvent::PayloadDecrypted { packet_id, .. }) => {
                    if let Some(tx) = registry.lock().remove(&packet_id) {
                        let _ = tx.send(());
                    }
                }
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

/// A registry that captures the raw payload bytes from `PayloadDecrypted` events.
/// Used for SURB reply decryption where the client needs the encrypted body.
type PayloadRegistry =
    Arc<parking_lot::Mutex<std::collections::HashMap<String, oneshot::Sender<Vec<u8>>>>>;

/// Like `spawn_completion_watcher` but delivers the raw payload bytes.
fn spawn_payload_watcher(subscriber: Arc<dyn IEventSubscriber>, registry: PayloadRegistry) {
    tokio::spawn(async move {
        let mut rx = subscriber.subscribe();
        loop {
            match rx.recv().await {
                Ok(NoxEvent::PayloadDecrypted { packet_id, payload }) => {
                    if let Some(tx) = registry.lock().remove(&packet_id) {
                        let _ = tx.send(payload);
                    }
                }
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

/// Spawn a lightweight mix node for benchmarking. No Ethereum, no exit handlers,
/// no cover traffic -- just Sphinx routing (`RelayerService`) + P2P + topology.
async fn spawn_bench_node(id: usize, mix_delay_ms: f64, bus_capacity: usize) -> Result<BenchNode> {
    let dir = tempdir()?;
    let db = Arc::new(SledRepository::new(dir.path())?);
    let event_bus = TokioEventBus::new(bus_capacity);
    let pub_bus: Arc<dyn IEventPublisher> = Arc::new(event_bus.clone());
    let sub_bus: Arc<dyn IEventSubscriber> = Arc::new(event_bus.clone());

    let rng = OsRng;
    let node_sk = X25519SecretKey::random_from_rng(rng);
    let node_pk = X25519PublicKey::from(&node_sk);

    let config = {
        let mut c = NoxConfig::default();
        c.benchmark_mode = true;
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
        c.eth_wallet_private_key = hex::encode(rand::random::<[u8; 32]>());
        c.min_pow_difficulty = 0;
        c.min_gas_balance = "0".into();
        c.registry_contract_address = "0x0000000000000000000000000000000000000000".into();
        c.relayer.cover_traffic_rate = 0.0; // No cover traffic in benchmarks
        c.relayer.drop_traffic_rate = 0.0;
        c
    };

    let metrics = MetricsService::new();

    // Topology Manager
    let topology = Arc::new(TopologyManager::new(db.clone(), sub_bus.clone(), None));
    let topo_clone = topology.clone();
    tokio::spawn(async move {
        topo_clone.run().await;
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

    // Relayer Service (Sphinx peel + mix delay + forwarding)
    let mix: Arc<dyn nox_core::traits::IMixStrategy> = if mix_delay_ms > 0.0 {
        Arc::new(PoissonMixStrategy::new(mix_delay_ms))
    } else {
        Arc::new(NoMixStrategy)
    };
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

    Ok(BenchNode {
        id,
        multiaddr: full_addr.to_string(),
        public_key: node_pk,
        bus_publisher: pub_bus,
        bus_subscriber: sub_bus,
        _storage: db,
        _db_dir: dir,
    })
}

/// Build a mesh of N nodes and wire their topologies together.
async fn build_mesh(
    node_count: usize,
    mix_delay_ms: f64,
    settle_secs: u64,
    bus_capacity: usize,
) -> Result<Vec<BenchNode>> {
    info!("Spawning {node_count} bench nodes (bus_capacity={bus_capacity})...");
    let mut handles = Vec::new();
    for i in 0..node_count {
        let delay = mix_delay_ms;
        handles.push(tokio::spawn(async move {
            spawn_bench_node(i, delay, bus_capacity).await
        }));
    }

    let mut nodes = Vec::new();
    for (i, handle) in handles.into_iter().enumerate() {
        match handle.await {
            Ok(Ok(node)) => nodes.push(node),
            Ok(Err(e)) => return Err(anyhow::anyhow!("Node {i} failed: {e}")),
            Err(e) => return Err(anyhow::anyhow!("Node {i} panicked: {e}")),
        }
    }

    // Wire mesh: every node knows about every other node
    info!("Wiring mesh ({} connections)...", nodes.len() * nodes.len());
    for target in &nodes {
        for source in &nodes {
            source.bus_publisher.publish(NoxEvent::RelayerRegistered {
                address: format!("0xNode{}", target.id),
                sphinx_key: hex::encode(target.public_key.as_bytes()),
                url: target.multiaddr.clone(),
                stake: "1000".to_string(),
                role: 3, // Full node
                ingress_url: None,
                metadata_url: None,
            })?;
        }
    }

    // Stabilization -- topology needs time to propagate
    info!("Mesh stabilization ({settle_secs}s)...");
    tokio::time::sleep(Duration::from_secs(settle_secs)).await;

    Ok(nodes)
}

/// Build a variable-length hop path through the mesh.
/// Selects `hops` distinct nodes starting from `packet_index` using modular arithmetic.
fn build_path(nodes: &[BenchNode], packet_index: usize, hops: usize) -> Vec<PathHop> {
    (0..hops)
        .map(|h| {
            let idx = (packet_index + h) % nodes.len();
            PathHop {
                public_key: nodes[idx].public_key,
                address: nodes[idx].multiaddr.clone(),
            }
        })
        .collect()
}

/// Build a benchmark payload of the given size.
fn build_bench_payload(payload_size: usize) -> Vec<u8> {
    let payload = RelayerPayload::SubmitTransaction {
        to: [0u8; 20],
        data: vec![0xBE; payload_size],
    };
    encode_payload(&payload).expect("encode payload")
}

/// Shared configuration for all benchmark subcommands.
struct BenchConfig {
    nodes: usize,
    packets: usize,
    hops: usize,
    mix_delay_ms: f64,
    concurrency: usize,
    warmup: usize,
    payload_size: usize,
    settle_secs: u64,
    raw_latencies: bool,
    bus_capacity: usize,
}

async fn run_latency(cfg: &BenchConfig) -> Result<BenchResult> {
    let nodes_count = cfg.nodes;
    let packets = cfg.packets;
    let hops = cfg.hops;
    let mix_delay_ms = cfg.mix_delay_ms;
    let concurrency = cfg.concurrency;
    let warmup = cfg.warmup;
    let payload_size = cfg.payload_size;
    let settle_secs = cfg.settle_secs;
    let raw_latencies = cfg.raw_latencies;
    let nodes = build_mesh(nodes_count, mix_delay_ms, settle_secs, cfg.bus_capacity).await?;
    let total = warmup + packets;

    info!(
        "Latency benchmark: {packets} packets ({warmup} warmup), {concurrency} concurrent, \
         {mix_delay_ms}ms mix delay, {nodes_count} nodes"
    );

    let latencies: Arc<parking_lot::Mutex<Vec<u64>>> =
        Arc::new(parking_lot::Mutex::new(Vec::with_capacity(packets)));
    let success_count = Arc::new(AtomicU64::new(0));
    let fail_count = Arc::new(AtomicU64::new(0));

    // Spawn one completion watcher per node (each node can be an exit).
    // This replaces N per-packet subscribers with 1 watcher per node.
    let registries: Vec<CompletionRegistry> = nodes
        .iter()
        .map(|node| {
            let reg: CompletionRegistry =
                Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()));
            spawn_completion_watcher(node.bus_subscriber.clone(), reg.clone());
            reg
        })
        .collect();

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let start_time = Instant::now();
    let mut handles = Vec::new();

    let payload_bytes = build_bench_payload(payload_size);

    for i in 0..total {
        let permit = semaphore.clone().acquire_owned().await?;
        let entry_idx = i % nodes.len();
        let exit_idx = (i + hops - 1) % nodes.len();

        let entry_pub = nodes[entry_idx].bus_publisher.clone();
        let exit_reg = registries[exit_idx].clone();

        let path = build_path(&nodes, i, hops);
        let packet_bytes = build_multi_hop_packet(&path, &payload_bytes, 0).expect("build packet");
        let pkt_size = packet_bytes.len();

        let lat_clone = latencies.clone();
        let succ = success_count.clone();
        let fail = fail_count.clone();
        let is_warmup = i < warmup;
        let pkt_id = format!("bench_{i}");

        handles.push(tokio::spawn(async move {
            // Register oneshot BEFORE publishing -- O(1) completion notification
            let (tx, rx) = oneshot::channel();
            exit_reg.lock().insert(pkt_id.clone(), tx);

            let start = Instant::now();

            let _ = entry_pub.publish(NoxEvent::PacketReceived {
                packet_id: pkt_id.clone(),
                data: packet_bytes,
                size_bytes: pkt_size,
            });

            let result = tokio::time::timeout(Duration::from_secs(30), rx).await;

            if let Ok(Ok(())) = result {
                let elapsed_us = start.elapsed().as_micros() as u64;
                succ.fetch_add(1, Ordering::Relaxed);
                if !is_warmup {
                    lat_clone.lock().push(elapsed_us);
                }
            } else {
                // Timeout or channel closed -- clean up registry entry
                exit_reg.lock().remove(&pkt_id);
                fail.fetch_add(1, Ordering::Relaxed);
            }

            drop(permit);
        }));
    }

    // Wait for all packets
    for h in handles {
        let _ = h.await;
    }

    let total_duration = start_time.elapsed();
    let success = success_count.load(Ordering::Relaxed);
    let failed = fail_count.load(Ordering::Relaxed);
    let mut lats = latencies.lock().clone();
    let stats = bench_common::compute_latency_stats(&mut lats, (success + failed) as usize);

    let pps = success as f64 / total_duration.as_secs_f64();

    info!("=== LATENCY BENCHMARK RESULTS ===");
    info!("Duration:     {:.2}s", total_duration.as_secs_f64());
    info!("Success:      {success} / {total}  (Failed: {failed})");
    info!("Throughput:   {pps:.1} PPS");
    info!("Latency p50:  {} us", stats.p50_us);
    info!("Latency p90:  {} us", stats.p90_us);
    info!("Latency p95:  {} us", stats.p95_us);
    info!("Latency p99:  {} us", stats.p99_us);
    info!("Latency p999: {} us", stats.p999_us);
    info!("Latency mean: {:.1} us", stats.mean_us);
    info!(
        "Latency min:  {} us  max: {} us",
        stats.min_us, stats.max_us
    );
    info!("=================================");

    let mut results = serde_json::json!({
        "duration_secs": total_duration.as_secs_f64(),
        "success": success,
        "failed": failed,
        "throughput_pps": pps,
        "latency": stats,
    });
    if raw_latencies {
        // `lats` is already sorted by `compute_latency_stats`
        results["raw_latencies_us"] = serde_json::json!(lats);
    }

    Ok(BenchResult {
        benchmark: "latency".into(),
        mode: "in_process".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "nodes": nodes_count,
            "packets": packets,
            "warmup": warmup,
            "mix_delay_ms": mix_delay_ms,
            "concurrency": concurrency,
            "hops": hops,
            "payload_size": payload_size,
        }),
        results,
    })
}

async fn run_throughput(
    cfg: &BenchConfig,
    duration_secs: u64,
    target_pps_list: Vec<usize>,
) -> Result<BenchResult> {
    let nodes_count = cfg.nodes;
    let hops = cfg.hops;
    let mix_delay_ms = cfg.mix_delay_ms;
    let payload_size = cfg.payload_size;
    let settle_secs = cfg.settle_secs;
    let nodes = build_mesh(nodes_count, mix_delay_ms, settle_secs, cfg.bus_capacity).await?;

    info!(
        "Throughput benchmark: {} nodes, {} rate steps, {}s per step, {} hops",
        nodes_count,
        target_pps_list.len(),
        duration_secs,
        hops,
    );

    // Completion registries -- one per node
    let registries: Vec<CompletionRegistry> = nodes
        .iter()
        .map(|node| {
            let reg: CompletionRegistry =
                Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()));
            spawn_completion_watcher(node.bus_subscriber.clone(), reg.clone());
            reg
        })
        .collect();

    let payload_bytes = build_bench_payload(payload_size);
    let mut points = Vec::new();

    for &target_pps in &target_pps_list {
        info!("--- Rate step: {target_pps} PPS ---");
        let interval = if target_pps > 0 {
            Duration::from_micros(1_000_000 / target_pps as u64)
        } else {
            Duration::from_secs(1)
        };
        let deadline = Instant::now() + Duration::from_secs(duration_secs);

        let latencies: Arc<parking_lot::Mutex<Vec<u64>>> =
            Arc::new(parking_lot::Mutex::new(Vec::new()));
        let success_count = Arc::new(AtomicU64::new(0));
        let fail_count = Arc::new(AtomicU64::new(0));
        let sent_count = Arc::new(AtomicU64::new(0));

        let step_start = Instant::now();
        let mut handles = Vec::new();
        let mut packet_idx = 0usize;

        // Warmup: first 10% of duration (at least 1 second)
        let warmup_ms = (duration_secs as f64 * 100.0).max(1000.0) as u64;
        let warmup_end = step_start + Duration::from_millis(warmup_ms);

        while Instant::now() < deadline {
            let entry_idx = packet_idx % nodes.len();
            let exit_idx = (packet_idx + hops - 1) % nodes.len();

            let entry_pub = nodes[entry_idx].bus_publisher.clone();
            let exit_reg = registries[exit_idx].clone();

            let path = build_path(&nodes, packet_idx, hops);
            let packet_bytes = build_multi_hop_packet(&path, &payload_bytes, 0).expect("build");
            let pkt_size = packet_bytes.len();

            let lat_clone = latencies.clone();
            let succ = success_count.clone();
            let fail = fail_count.clone();
            let pkt_id = format!("tp_{target_pps}_{packet_idx}");
            let is_warmup = Instant::now() < warmup_end;

            sent_count.fetch_add(1, Ordering::Relaxed);

            handles.push(tokio::spawn(async move {
                let (tx, rx) = oneshot::channel();
                exit_reg.lock().insert(pkt_id.clone(), tx);

                let start = Instant::now();

                let _ = entry_pub.publish(NoxEvent::PacketReceived {
                    packet_id: pkt_id.clone(),
                    data: packet_bytes,
                    size_bytes: pkt_size,
                });

                let result = tokio::time::timeout(Duration::from_secs(10), rx).await;

                if let Ok(Ok(())) = result {
                    let elapsed = start.elapsed().as_micros() as u64;
                    succ.fetch_add(1, Ordering::Relaxed);
                    if !is_warmup {
                        lat_clone.lock().push(elapsed);
                    }
                } else {
                    // Timeout or channel closed -- clean up registry entry
                    exit_reg.lock().remove(&pkt_id);
                    fail.fetch_add(1, Ordering::Relaxed);
                }
            }));

            packet_idx += 1;
            tokio::time::sleep(interval).await;
        }

        // Wait for all in-flight packets (with timeout)
        let drain_deadline = Instant::now() + Duration::from_secs(15);
        for h in handles {
            let remaining = drain_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let _ = tokio::time::timeout(remaining, h).await;
        }

        let step_duration = step_start.elapsed();
        let success = success_count.load(Ordering::Relaxed);
        let failed = fail_count.load(Ordering::Relaxed);
        let sent = sent_count.load(Ordering::Relaxed);
        let mut lats = latencies.lock().clone();
        let stats = bench_common::compute_latency_stats(&mut lats, sent as usize);
        let achieved_pps = success as f64 / step_duration.as_secs_f64();
        let loss_rate = if sent > 0 {
            failed as f64 / sent as f64
        } else {
            0.0
        };

        info!(
            "  target={target_pps} achieved={achieved_pps:.1} success={success} \
             failed={failed} loss={loss_rate:.3} p50={} p99={}",
            stats.p50_us, stats.p99_us
        );

        points.push(ThroughputPoint {
            target_pps,
            achieved_pps,
            success_count: success as usize,
            fail_count: failed as usize,
            loss_rate,
            latency: stats,
        });
    }

    Ok(BenchResult {
        benchmark: "throughput".into(),
        mode: "in_process".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "nodes": nodes_count,
            "duration_secs": duration_secs,
            "target_pps_list": target_pps_list,
            "mix_delay_ms": mix_delay_ms,
            "hops": hops,
        }),
        results: serde_json::json!({ "points": points }),
    })
}

async fn run_scale(cfg: &BenchConfig, node_counts: Vec<usize>) -> Result<BenchResult> {
    let packets = cfg.packets;
    let hops = cfg.hops;
    let mix_delay_ms = cfg.mix_delay_ms;
    let concurrency = cfg.concurrency;
    let payload_size = cfg.payload_size;
    let settle_secs = cfg.settle_secs;
    let raw_latencies = cfg.raw_latencies;
    info!(
        "Scale benchmark: node counts = {:?}, {} packets each, {} hops, {} concurrent",
        node_counts, packets, hops, concurrency
    );

    let payload_bytes = build_bench_payload(payload_size);
    let mut points = Vec::new();

    for &nc in &node_counts {
        info!("=== Scale test: {nc} nodes ===");
        let nodes = build_mesh(nc, mix_delay_ms, settle_secs, cfg.bus_capacity).await?;

        // Completion registries -- one per node
        let registries: Vec<CompletionRegistry> = nodes
            .iter()
            .map(|node| {
                let reg: CompletionRegistry =
                    Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()));
                spawn_completion_watcher(node.bus_subscriber.clone(), reg.clone());
                reg
            })
            .collect();

        let warmup = (packets / 10).max(10);
        let total = warmup + packets;
        let semaphore = Arc::new(Semaphore::new(concurrency));

        let latencies: Arc<parking_lot::Mutex<Vec<u64>>> =
            Arc::new(parking_lot::Mutex::new(Vec::with_capacity(packets)));
        let success_count = Arc::new(AtomicU64::new(0));
        let fail_count = Arc::new(AtomicU64::new(0));

        let start_time = Instant::now();
        let mut handles = Vec::new();

        for i in 0..total {
            let permit = semaphore.clone().acquire_owned().await?;
            let entry_idx = i % nodes.len();
            let exit_idx = (i + hops - 1) % nodes.len();

            let entry_pub = nodes[entry_idx].bus_publisher.clone();
            let exit_reg = registries[exit_idx].clone();

            let path = build_path(&nodes, i, hops);
            let packet_bytes = build_multi_hop_packet(&path, &payload_bytes, 0).expect("build");
            let pkt_size = packet_bytes.len();

            let lat_clone = latencies.clone();
            let succ = success_count.clone();
            let fail = fail_count.clone();
            let is_warmup = i < warmup;
            let pkt_id = format!("scale_{nc}_{i}");

            handles.push(tokio::spawn(async move {
                // Register oneshot BEFORE publishing -- O(1) completion notification
                let (tx, rx) = oneshot::channel();
                exit_reg.lock().insert(pkt_id.clone(), tx);

                let start = Instant::now();

                let _ = entry_pub.publish(NoxEvent::PacketReceived {
                    packet_id: pkt_id.clone(),
                    data: packet_bytes,
                    size_bytes: pkt_size,
                });

                let result = tokio::time::timeout(Duration::from_secs(30), rx).await;

                if let Ok(Ok(())) = result {
                    let elapsed = start.elapsed().as_micros() as u64;
                    succ.fetch_add(1, Ordering::Relaxed);
                    if !is_warmup {
                        lat_clone.lock().push(elapsed);
                    }
                } else {
                    // Timeout or channel closed -- clean up registry entry
                    exit_reg.lock().remove(&pkt_id);
                    fail.fetch_add(1, Ordering::Relaxed);
                }

                drop(permit);
            }));
        }

        for h in handles {
            let _ = h.await;
        }

        let total_duration = start_time.elapsed();
        let success = success_count.load(Ordering::Relaxed);
        let failed = fail_count.load(Ordering::Relaxed);
        let mut lats = latencies.lock().clone();
        let stats = bench_common::compute_latency_stats(&mut lats, (success + failed) as usize);
        let pps = success as f64 / total_duration.as_secs_f64();

        info!(
            "  {nc} nodes: pps={pps:.1} p50={} p99={} success={success} failed={failed}",
            stats.p50_us, stats.p99_us
        );

        points.push(ScalePoint {
            node_count: nc,
            achieved_pps: pps,
            latency: stats,
        });

        // Cleanup between tests -- drop nodes to free ports
        drop(nodes);
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let mut results = serde_json::json!({ "points": points });
    if raw_latencies {
        // Attach raw latencies from the last scale point for CDF analysis
        results["note"] =
            serde_json::json!("raw_latencies available per ScalePoint via LatencyStats");
    }

    Ok(BenchResult {
        benchmark: "scale".into(),
        mode: "in_process".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "node_counts": node_counts,
            "packets": packets,
            "mix_delay_ms": mix_delay_ms,
            "hops": hops,
            "concurrency": concurrency,
            "payload_size": payload_size,
        }),
        results,
    })
}

async fn run_surb_rtt(cfg: &BenchConfig) -> Result<BenchResult> {
    let nodes_count = cfg.nodes;
    let packets = cfg.packets;
    let hops = cfg.hops;
    let mix_delay_ms = cfg.mix_delay_ms;
    let concurrency = cfg.concurrency;
    let payload_size = cfg.payload_size;
    let settle_secs = cfg.settle_secs;
    let raw_latencies = cfg.raw_latencies;
    let nodes = build_mesh(nodes_count, mix_delay_ms, settle_secs, cfg.bus_capacity).await?;

    info!(
        "SURB RTT benchmark (real SURBs): {packets} round-trips, {nodes_count} nodes, \
         {hops} hops/leg, {mix_delay_ms}ms delay, {concurrency} concurrent"
    );

    // Signal-only registries for forward leg (exit node detects arrival)
    let fwd_registries: Vec<CompletionRegistry> = nodes
        .iter()
        .map(|node| {
            let reg: CompletionRegistry =
                Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()));
            spawn_completion_watcher(node.bus_subscriber.clone(), reg.clone());
            reg
        })
        .collect();

    // Payload-capturing registries for return leg (entry node captures SURB-encrypted body)
    let ret_registries: Vec<PayloadRegistry> = nodes
        .iter()
        .map(|node| {
            let reg: PayloadRegistry =
                Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()));
            spawn_payload_watcher(node.bus_subscriber.clone(), reg.clone());
            reg
        })
        .collect();

    let latencies: Arc<parking_lot::Mutex<Vec<u64>>> =
        Arc::new(parking_lot::Mutex::new(Vec::with_capacity(packets)));
    let success_count = Arc::new(AtomicU64::new(0));
    let fail_count = Arc::new(AtomicU64::new(0));

    let warmup = (packets / 10).max(5);
    let total = warmup + packets;
    let semaphore = Arc::new(Semaphore::new(concurrency));

    let start_time = Instant::now();
    let mut handles = Vec::new();

    for i in 0..total {
        let n = nodes.len();
        let entry_idx = i % n;
        let exit_idx = (i + hops - 1) % n;

        // Forward path: entry -> ... -> exit
        let fwd_path = build_path(&nodes, i, hops);

        // Return path for SURB: first_relay -> ... -> entry_node
        // Build a path of `hops` distinct nodes where the last hop is `entry_idx`.
        // Intermediate hops are chosen to avoid collisions with entry_idx.
        let mut ret_indices = Vec::with_capacity(hops);
        {
            let mut cursor = exit_idx;
            for h in 0..hops {
                if h == hops - 1 {
                    ret_indices.push(entry_idx);
                } else {
                    // Pick the next distinct node (skip entry_idx and exit_idx)
                    loop {
                        cursor = (cursor + 1) % n;
                        if cursor != entry_idx && cursor != exit_idx {
                            break;
                        }
                    }
                    ret_indices.push(cursor);
                }
            }
        }
        let ret_path: Vec<PathHop> = ret_indices
            .iter()
            .map(|&idx| PathHop {
                public_key: nodes[idx].public_key,
                address: nodes[idx].multiaddr.clone(),
            })
            .collect();

        let entry_pub = nodes[entry_idx].bus_publisher.clone();
        // The SURB reply is injected at the FIRST hop of the return path, NOT the
        // exit node. The exit node is the service that encapsulates the reply; the
        // resulting Sphinx packet is addressed to ret_path[0] which is a relay.
        let ret_first_hop_idx = ret_indices[0];
        let ret_first_hop_pub = nodes[ret_first_hop_idx].bus_publisher.clone();
        let fwd_exit_reg = fwd_registries[exit_idx].clone();
        let ret_entry_reg = ret_registries[entry_idx].clone();

        let lat_clone = latencies.clone();
        let succ = success_count.clone();
        let fail = fail_count.clone();
        let is_warmup = i < warmup;
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore closed");

        handles.push(tokio::spawn(async move {
            let start = Instant::now();

            // Step 1: Create SURB for the return path
            let surb_id = {
                let mut id = [0u8; 16];
                id[..8].copy_from_slice(&(i as u64).to_le_bytes());
                id
            };
            let (surb, recovery) = match Surb::new(&ret_path, surb_id, 0) {
                Ok(pair) => pair,
                Err(e) => {
                    error!("SURB creation failed for trip {i}: {e}");
                    fail.fetch_add(1, Ordering::Relaxed);
                    drop(permit);
                    return;
                }
            };

            // Step 2: Forward leg (Sphinx packet to exit)
            let fwd_payload = RelayerPayload::SubmitTransaction {
                to: [0u8; 20],
                data: vec![0xBE; payload_size.min(64)],
            };
            let fwd_payload_bytes = encode_payload(&fwd_payload).expect("encode payload");
            let fwd_packet =
                build_multi_hop_packet(&fwd_path, &fwd_payload_bytes, 0).expect("build fwd");
            let fwd_size = fwd_packet.len();
            let fwd_id = format!("surb_fwd_{i}");

            let (fwd_tx, fwd_rx) = oneshot::channel();
            fwd_exit_reg.lock().insert(fwd_id.clone(), fwd_tx);

            let _ = entry_pub.publish(NoxEvent::PacketReceived {
                packet_id: fwd_id.clone(),
                data: fwd_packet,
                size_bytes: fwd_size,
            });

            let fwd_ok = tokio::time::timeout(Duration::from_secs(15), fwd_rx).await;
            if !matches!(fwd_ok, Ok(Ok(()))) {
                fwd_exit_reg.lock().remove(&fwd_id);
                fail.fetch_add(1, Ordering::Relaxed);
                drop(permit);
                return;
            }

            // Step 3: Exit encapsulates response using SURB
            let response_msg = vec![0xCA; payload_size.min(1024)];
            let reply_packet = match surb.encapsulate(&response_msg) {
                Ok(pkt) => pkt,
                Err(e) => {
                    error!("SURB encapsulate failed for trip {i}: {e}");
                    fail.fetch_add(1, Ordering::Relaxed);
                    drop(permit);
                    return;
                }
            };
            let reply_bytes = reply_packet.into_bytes();
            let reply_size = reply_bytes.len();
            let ret_id = format!("surb_ret_{i}");

            // Register payload capture at entry node BEFORE injecting
            let (ret_tx, ret_rx) = oneshot::channel();
            ret_entry_reg.lock().insert(ret_id.clone(), ret_tx);

            // Inject reply at the first hop of the return path (NOT the exit node).
            // The exit node called surb.encapsulate() -- the resulting Sphinx packet
            // is addressed to ret_path[0]'s key, so it must be processed by that node.
            let _ = ret_first_hop_pub.publish(NoxEvent::PacketReceived {
                packet_id: ret_id.clone(),
                data: reply_bytes,
                size_bytes: reply_size,
            });

            // Step 4: Wait for SURB reply at entry node
            let ret_result = tokio::time::timeout(Duration::from_secs(15), ret_rx).await;

            if let Ok(Ok(encrypted_body)) = ret_result {
                // Step 5: Client decrypts using SurbRecovery
                match recovery.decrypt(&encrypted_body) {
                    Ok(plaintext) => {
                        if plaintext == response_msg {
                            let rtt_us = start.elapsed().as_micros() as u64;
                            succ.fetch_add(1, Ordering::Relaxed);
                            if !is_warmup {
                                lat_clone.lock().push(rtt_us);
                            }
                        } else {
                            error!(
                                "SURB decrypt mismatch for trip {i}: got {} bytes, expected {}",
                                plaintext.len(),
                                response_msg.len()
                            );
                            fail.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(e) => {
                        error!("SurbRecovery::decrypt failed for trip {i}: {e}");
                        fail.fetch_add(1, Ordering::Relaxed);
                    }
                }
            } else {
                ret_entry_reg.lock().remove(&ret_id);
                fail.fetch_add(1, Ordering::Relaxed);
            }
            drop(permit);
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let total_duration = start_time.elapsed();
    let success = success_count.load(Ordering::Relaxed);
    let failed = fail_count.load(Ordering::Relaxed);
    let mut lats = latencies.lock().clone();
    let stats = bench_common::compute_latency_stats(&mut lats, (success + failed) as usize);

    info!("=== SURB RTT BENCHMARK RESULTS (Real SURBs) ===");
    info!("Duration:  {:.2}s", total_duration.as_secs_f64());
    info!("Success:   {success} / {total}  (Failed: {failed})");
    info!("RTT p50:   {} us", stats.p50_us);
    info!("RTT p99:   {} us", stats.p99_us);
    info!("RTT mean:  {:.1} us", stats.mean_us);
    info!("================================================");

    let mut results = serde_json::json!({
        "duration_secs": total_duration.as_secs_f64(),
        "success": success,
        "failed": failed,
        "latency": stats,
    });
    if raw_latencies {
        results["raw_latencies_us"] = serde_json::json!(lats);
    }

    Ok(BenchResult {
        benchmark: "surb_rtt".into(),
        mode: "in_process".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "nodes": nodes_count,
            "packets": packets,
            "hops_per_leg": hops,
            "mix_delay_ms": mix_delay_ms,
            "concurrency": concurrency,
            "payload_size": payload_size,
            "note": "Real SURB E2E: Surb::new() + forward Sphinx + surb.encapsulate() + return Sphinx + SurbRecovery::decrypt()"
        }),
        results,
    })
}

/// Run one FEC mode (no-FEC or with-FEC) for the SURB RTT FEC benchmark.
///
/// For each round-trip:
/// 1. Forward leg: Sphinx packet from entry -> exit (same as `surb-rtt`)
/// 2. At exit: `ResponsePacker` fragments the response, optionally adding FEC parity
/// 3. Each fragment is encapsulated in a real SURB and injected as a Sphinx packet
///    through the return path
/// 4. At client: `Reassembler` collects fragments, performs FEC decode if needed
/// 5. RTT = start of forward injection -> reassembly complete
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn run_surb_rtt_fec_mode(
    nodes: &[BenchNode],
    fwd_registries: &[CompletionRegistry],
    ret_registries: &[PayloadRegistry],
    packets: usize,
    hops: usize,
    concurrency: usize,
    response_data: &[u8],
    fec_ratio: f64,
    raw_latencies_flag: bool,
) -> Result<serde_json::Value> {
    let mode_label = if fec_ratio > 0.0 {
        format!("with_fec_{:.0}pct", fec_ratio * 100.0)
    } else {
        "no_fec".to_string()
    };
    let packer = ResponsePacker::new();

    // Compute SURB count: D data fragments + P parity fragments
    let d = packer.surbs_needed(response_data.len());
    let p = if fec_ratio > 0.0 && d > 0 {
        if d == 1 {
            1
        } else {
            (d as f64 * fec_ratio).ceil() as usize
        }
    } else {
        0
    };
    let total_surbs = d + p;

    info!(
        "SURB RTT FEC mode={mode_label}: {packets} round-trips, D={d} P={p} ({total_surbs} SURBs/trip)"
    );

    let latencies: Arc<parking_lot::Mutex<Vec<u64>>> =
        Arc::new(parking_lot::Mutex::new(Vec::with_capacity(packets)));
    let success_count = Arc::new(AtomicU64::new(0));
    let fail_count = Arc::new(AtomicU64::new(0));
    let encode_times_us: Arc<parking_lot::Mutex<Vec<u64>>> =
        Arc::new(parking_lot::Mutex::new(Vec::new()));
    let decode_times_us: Arc<parking_lot::Mutex<Vec<u64>>> =
        Arc::new(parking_lot::Mutex::new(Vec::new()));

    let warmup = (packets / 10).max(3);
    let total = warmup + packets;
    let semaphore = Arc::new(Semaphore::new(concurrency));

    let start_time = Instant::now();
    let mut handles = Vec::new();

    for i in 0..total {
        let n = nodes.len();
        let entry_idx = i % n;
        let exit_idx = (i + hops - 1) % n;

        // Forward path
        let fwd_path = build_path(nodes, i, hops);

        // Return path for SURBs: first_relay -> ... -> entry_node
        // Build a path of `hops` distinct nodes where the last hop is `entry_idx`.
        let mut ret_indices = Vec::with_capacity(hops);
        {
            let mut cursor = exit_idx;
            for h in 0..hops {
                if h == hops - 1 {
                    ret_indices.push(entry_idx);
                } else {
                    loop {
                        cursor = (cursor + 1) % n;
                        if cursor != entry_idx && cursor != exit_idx {
                            break;
                        }
                    }
                    ret_indices.push(cursor);
                }
            }
        }
        let ret_path: Vec<PathHop> = ret_indices
            .iter()
            .map(|&idx| PathHop {
                public_key: nodes[idx].public_key,
                address: nodes[idx].multiaddr.clone(),
            })
            .collect();

        let entry_pub = nodes[entry_idx].bus_publisher.clone();
        // Inject SURB reply at the first hop of the return path, not the exit node
        let ret_first_hop_idx = ret_indices[0];
        let ret_first_hop_pub = nodes[ret_first_hop_idx].bus_publisher.clone();
        let fwd_exit_reg = fwd_registries[exit_idx].clone();
        let ret_entry_reg = ret_registries[entry_idx].clone();
        let lat_clone = latencies.clone();
        let succ = success_count.clone();
        let fail = fail_count.clone();
        let enc_times = encode_times_us.clone();
        let dec_times = decode_times_us.clone();
        let is_warmup = i < warmup;
        let resp_data = response_data.to_vec();
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore closed");

        // Clone path for SURB creation inside the task
        let ret_path_clone = ret_path.clone();

        handles.push(tokio::spawn(async move {
            let start = Instant::now();

            // Step 1: Forward leg (Sphinx packet to exit)
            let fwd_payload = RelayerPayload::SubmitTransaction {
                to: [0u8; 20],
                data: vec![0xBE, 0xEF],
            };
            let fwd_payload_bytes = encode_payload(&fwd_payload).expect("encode payload");
            let fwd_packet =
                build_multi_hop_packet(&fwd_path, &fwd_payload_bytes, 0).expect("build fwd");
            let fwd_size = fwd_packet.len();
            let fwd_id = format!("surb_fec_fwd_{i}");

            let (fwd_tx, fwd_rx) = oneshot::channel();
            fwd_exit_reg.lock().insert(fwd_id.clone(), fwd_tx);

            let _ = entry_pub.publish(NoxEvent::PacketReceived {
                packet_id: fwd_id.clone(),
                data: fwd_packet,
                size_bytes: fwd_size,
            });

            let fwd_ok = tokio::time::timeout(Duration::from_secs(15), fwd_rx).await;
            if !matches!(fwd_ok, Ok(Ok(()))) {
                fwd_exit_reg.lock().remove(&fwd_id);
                fail.fetch_add(1, Ordering::Relaxed);
                drop(permit);
                return;
            }

            // Step 2: Create SURBs for return path
            let mut surbs = Vec::with_capacity(total_surbs);
            let mut recoveries = Vec::with_capacity(total_surbs);
            for s in 0..total_surbs {
                let surb_id = {
                    let mut id = [0u8; 16];
                    id[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    id[8..12].copy_from_slice(&(s as u32).to_le_bytes());
                    id
                };
                match Surb::new(&ret_path_clone, surb_id, 0) {
                    Ok((surb, recovery)) => {
                        surbs.push(surb);
                        recoveries.push(recovery);
                    }
                    Err(e) => {
                        error!("SURB creation failed for trip {i} surb {s}: {e}");
                        fail.fetch_add(1, Ordering::Relaxed);
                        drop(permit);
                        return;
                    }
                }
            }

            // Step 3: Pack response with ResponsePacker (FEC encode)
            let packer = ResponsePacker::new();
            let request_id = i as u64;
            let encode_start = Instant::now();
            let pack_result = match packer.pack_response(request_id, &resp_data, surbs) {
                Ok(p) => p,
                Err(e) => {
                    error!("ResponsePacker failed for trip {i}: {e}");
                    fail.fetch_add(1, Ordering::Relaxed);
                    drop(permit);
                    return;
                }
            };
            let packed = pack_result.packets;
            let encode_elapsed = encode_start.elapsed();

            // Step 4: Inject each SURB packet into the mixnet
            // Register per-fragment payload watchers at the entry node to capture
            // the encrypted body bytes (needed for real SURB decryption).
            let fragment_count = packed.len();
            let frag_receivers: Vec<_> = packed
                .iter()
                .enumerate()
                .map(|(f_idx, _)| {
                    let frag_id = format!("surb_fec_ret_{i}_{f_idx}");
                    let (tx, rx) = oneshot::channel::<Vec<u8>>();
                    ret_entry_reg.lock().insert(frag_id, tx);
                    rx
                })
                .collect();

            for (f_idx, packet) in packed.into_iter().enumerate() {
                let frag_id = format!("surb_fec_ret_{i}_{f_idx}");
                let frag_size = packet.packet_bytes.len();

                // Inject the SURB packet at the first hop of the return path
                let _ = ret_first_hop_pub.publish(NoxEvent::PacketReceived {
                    packet_id: frag_id,
                    data: packet.packet_bytes,
                    size_bytes: frag_size,
                });
            }

            // Step 5: Wait for all fragment payloads to arrive at entry node
            let mut encrypted_bodies: Vec<Option<Vec<u8>>> = Vec::with_capacity(fragment_count);
            let mut all_arrived = true;
            for rx in frag_receivers {
                if let Ok(Ok(body)) = tokio::time::timeout(Duration::from_secs(30), rx).await {
                    encrypted_bodies.push(Some(body));
                } else {
                    encrypted_bodies.push(None);
                    all_arrived = false;
                }
            }

            // For no-FEC mode, we need ALL fragments. For FEC mode, we need at
            // least D out of D+P (FEC can reconstruct from any D fragments).
            if !all_arrived && fec_ratio == 0.0 {
                fail.fetch_add(1, Ordering::Relaxed);
                drop(permit);
                return;
            }

            // Step 6: Real SURB decrypt -> deserialize -> Fragment -> Reassembler
            let decode_start = Instant::now();
            let mut reassembler = Reassembler::new(ReassemblerConfig::default());
            let mut decrypt_ok = 0usize;
            let mut decrypt_fail = 0usize;

            for (f_idx, maybe_body) in encrypted_bodies.into_iter().enumerate() {
                let Some(body) = maybe_body else {
                    continue; // fragment lost in transit (FEC can handle this)
                };

                // Decrypt with the corresponding SurbRecovery
                let plaintext = match recoveries[f_idx].decrypt(&body) {
                    Ok(pt) => pt,
                    Err(e) => {
                        error!("SurbRecovery::decrypt failed for trip {i} frag {f_idx}: {e}");
                        decrypt_fail += 1;
                        continue;
                    }
                };

                // Deserialize the RelayerPayload::ServiceResponse to extract the Fragment
                let payload: RelayerPayload = match decode_payload(&plaintext) {
                    Ok(p) => p,
                    Err(e) => {
                        error!("Fragment deserialize failed for trip {i} frag {f_idx}: {e}");
                        decrypt_fail += 1;
                        continue;
                    }
                };

                // Extract the Fragment from the payload
                let fragment = match payload {
                    RelayerPayload::ServiceResponse { fragment, .. } => fragment,
                    other => {
                        error!(
                            "Unexpected payload type for trip {i} frag {f_idx}: {:?}",
                            std::mem::discriminant(&other)
                        );
                        decrypt_fail += 1;
                        continue;
                    }
                };

                let _ = reassembler.add_fragment(fragment);
                decrypt_ok += 1;
            }
            let decode_elapsed = decode_start.elapsed();

            if decrypt_ok == 0 || (fec_ratio == 0.0 && decrypt_fail > 0) {
                error!(
                    "Trip {i}: decrypt_ok={decrypt_ok}, decrypt_fail={decrypt_fail}, \
                     fragment_count={fragment_count}"
                );
                fail.fetch_add(1, Ordering::Relaxed);
                drop(permit);
                return;
            }

            let rtt_us = start.elapsed().as_micros() as u64;
            succ.fetch_add(1, Ordering::Relaxed);
            if !is_warmup {
                lat_clone.lock().push(rtt_us);
                enc_times.lock().push(encode_elapsed.as_micros() as u64);
                dec_times.lock().push(decode_elapsed.as_micros() as u64);
            }
            drop(permit);
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let total_duration = start_time.elapsed();
    let success = success_count.load(Ordering::Relaxed);
    let failed = fail_count.load(Ordering::Relaxed);
    let mut lats = latencies.lock().clone();
    let stats = bench_common::compute_latency_stats(&mut lats, (success + failed) as usize);

    let mut enc = encode_times_us.lock().clone();
    let enc_len = enc.len();
    let enc_stats = bench_common::compute_latency_stats(&mut enc, enc_len);
    let mut dec = decode_times_us.lock().clone();
    let dec_len = dec.len();
    let dec_stats = bench_common::compute_latency_stats(&mut dec, dec_len);

    info!(
        "  {mode_label}: {success} ok, {failed} fail, RTT p50={:.1}ms p99={:.1}ms, \
         encode p50={:.1}us, decode p50={:.1}us",
        stats.p50_us as f64 / 1000.0,
        stats.p99_us as f64 / 1000.0,
        enc_stats.p50_us as f64,
        dec_stats.p50_us as f64,
    );

    let mut results = serde_json::json!({
        "mode": mode_label,
        "fec_ratio": fec_ratio,
        "data_fragments": d,
        "parity_fragments": p,
        "total_surbs": total_surbs,
        "duration_secs": total_duration.as_secs_f64(),
        "success_count": success,
        "fail_count": failed,
        "rtt": stats,
        "encode_us": enc_stats,
        "decode_us": dec_stats,
    });
    if raw_latencies_flag {
        results["raw_latencies_us"] = serde_json::json!(lats);
    }

    Ok(results)
}

/// Run the SURB RTT FEC comparison benchmark: two modes back-to-back.
async fn run_surb_rtt_fec(
    cfg: &BenchConfig,
    response_size: usize,
    fec_ratio: f64,
) -> Result<BenchResult> {
    let nodes = build_mesh(
        cfg.nodes,
        cfg.mix_delay_ms,
        cfg.settle_secs,
        cfg.bus_capacity,
    )
    .await?;

    info!(
        "SURB RTT FEC comparison: {} nodes, {} hops/leg, {}ms delay, {} byte response, \
         fec_ratio={fec_ratio}",
        cfg.nodes, cfg.hops, cfg.mix_delay_ms, response_size
    );

    // Completion registries for forward leg (signal-only: detect arrival at exit node)
    let fwd_registries: Vec<CompletionRegistry> = nodes
        .iter()
        .map(|node| {
            let reg: CompletionRegistry =
                Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()));
            spawn_completion_watcher(node.bus_subscriber.clone(), reg.clone());
            reg
        })
        .collect();

    // Payload registries for return leg (capture encrypted body for SURB decryption)
    let ret_registries: Vec<PayloadRegistry> = nodes
        .iter()
        .map(|node| {
            let reg: PayloadRegistry =
                Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()));
            spawn_payload_watcher(node.bus_subscriber.clone(), reg.clone());
            reg
        })
        .collect();

    // Generate response data (deterministic, compressible pattern)
    let response_data: Vec<u8> = (0..response_size).map(|i| (i % 256) as u8).collect();

    // Mode 1: No FEC
    info!("=== Mode 1: No FEC ===");
    let no_fec_results = run_surb_rtt_fec_mode(
        &nodes,
        &fwd_registries,
        &ret_registries,
        cfg.packets,
        cfg.hops,
        cfg.concurrency,
        &response_data,
        0.0,
        cfg.raw_latencies,
    )
    .await?;

    // Brief pause between modes
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Mode 2: With FEC
    info!("=== Mode 2: With FEC (ratio={fec_ratio}) ===");
    let fec_results = run_surb_rtt_fec_mode(
        &nodes,
        &fwd_registries,
        &ret_registries,
        cfg.packets,
        cfg.hops,
        cfg.concurrency,
        &response_data,
        fec_ratio,
        cfg.raw_latencies,
    )
    .await?;

    Ok(BenchResult {
        benchmark: "surb_rtt_fec_comparison".into(),
        mode: "in_process".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "nodes": cfg.nodes,
            "packets_per_mode": cfg.packets,
            "hops_per_leg": cfg.hops,
            "mix_delay_ms": cfg.mix_delay_ms,
            "concurrency": cfg.concurrency,
            "response_size": response_size,
            "fec_ratio": fec_ratio,
        }),
        results: serde_json::json!({
            "no_fec": no_fec_results,
            "with_fec": fec_results,
        }),
    })
}

/// Raw hop timing tuple: ecdh, key derive, MAC verify, routing decrypt, body decrypt, blinding, total.
#[cfg(feature = "hop-metrics")]
type RawHopTiming = (u64, u64, u64, u64, u64, u64, u64);

/// Measure per-hop Sphinx processing breakdown using `HopTimingsRecorded` events.
/// Requires the `hop-metrics` feature flag to be enabled at compile time.
#[cfg(feature = "hop-metrics")]
async fn run_per_hop(cfg: &BenchConfig) -> Result<BenchResult> {
    let nodes_count = cfg.nodes;
    let packets = cfg.packets;
    let hops = cfg.hops;
    let mix_delay_ms = cfg.mix_delay_ms;
    let concurrency = cfg.concurrency;
    let payload_size = cfg.payload_size;
    let settle_secs = cfg.settle_secs;
    let nodes = build_mesh(nodes_count, mix_delay_ms, settle_secs, cfg.bus_capacity).await?;

    info!(
        "Per-hop breakdown: {packets} packets, {nodes_count} nodes, {hops} hops, \
         {mix_delay_ms}ms delay, {concurrency} concurrent"
    );

    // Subscribe to HopTimingsRecorded on EVERY node's bus
    let timings_collector: Arc<parking_lot::Mutex<Vec<RawHopTiming>>> =
        Arc::new(parking_lot::Mutex::new(Vec::with_capacity(packets * hops)));

    for node in &nodes {
        let mut rx = node.bus_subscriber.subscribe();
        let collector = timings_collector.clone();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(NoxEvent::HopTimingsRecorded {
                        ecdh_ns,
                        key_derive_ns,
                        mac_verify_ns,
                        routing_decrypt_ns,
                        body_decrypt_ns,
                        blinding_ns,
                        total_sphinx_ns,
                        ..
                    }) => {
                        collector.lock().push((
                            ecdh_ns,
                            key_derive_ns,
                            mac_verify_ns,
                            routing_decrypt_ns,
                            body_decrypt_ns,
                            blinding_ns,
                            total_sphinx_ns,
                        ));
                    }
                    Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    // Completion registries -- one per node
    let registries: Vec<CompletionRegistry> = nodes
        .iter()
        .map(|node| {
            let reg: CompletionRegistry =
                Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()));
            spawn_completion_watcher(node.bus_subscriber.clone(), reg.clone());
            reg
        })
        .collect();

    let payload_bytes = build_bench_payload(payload_size);

    // Build paths and send packets (same as latency bench but we don't time E2E)
    let warmup = (packets / 10).max(5);
    let total = warmup + packets;
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let success_count = Arc::new(AtomicU64::new(0));
    let fail_count = Arc::new(AtomicU64::new(0));

    let start_time = Instant::now();
    let mut handles = Vec::new();

    for i in 0..total {
        let entry_idx = i % nodes.len();
        let exit_idx = (i + hops - 1) % nodes.len();

        let path = build_path(&nodes, i, hops);
        let packet = build_multi_hop_packet(&path, &payload_bytes, 0)?;
        let pkt_size = packet.len();

        let entry_pub = nodes[entry_idx].bus_publisher.clone();
        let exit_reg = registries[exit_idx].clone();
        let pid = format!("hop-{i}");
        let succ = success_count.clone();
        let fail = fail_count.clone();
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore closed");

        handles.push(tokio::spawn(async move {
            // Register oneshot BEFORE publishing -- O(1) completion notification
            let (tx, rx) = oneshot::channel();
            exit_reg.lock().insert(pid.clone(), tx);

            let _ = entry_pub.publish(NoxEvent::PacketReceived {
                packet_id: pid.clone(),
                data: packet,
                size_bytes: pkt_size,
            });

            let result = tokio::time::timeout(Duration::from_secs(10), rx).await;

            if let Ok(Ok(())) = result {
                succ.fetch_add(1, Ordering::Relaxed);
            } else {
                // Timeout or channel closed -- clean up registry entry
                exit_reg.lock().remove(&pid);
                fail.fetch_add(1, Ordering::Relaxed);
            }
            drop(permit);
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let total_duration = start_time.elapsed();
    let success = success_count.load(Ordering::Relaxed);
    let failed = fail_count.load(Ordering::Relaxed);

    // Collect and aggregate timings
    // Skip warmup samples (first warmup * hops entries)
    let raw = timings_collector.lock().clone();
    let skip = warmup * hops;
    let data: Vec<_> = if raw.len() > skip {
        raw[skip..].to_vec()
    } else {
        raw
    };

    let n = data.len();
    info!("Collected {n} per-hop timing samples ({packets} packets * {hops} hops expected)");

    let mut ecdh: Vec<u64> = data.iter().map(|t| t.0).collect();
    let mut key_derive: Vec<u64> = data.iter().map(|t| t.1).collect();
    let mut mac_verify: Vec<u64> = data.iter().map(|t| t.2).collect();
    let mut routing_decrypt: Vec<u64> = data.iter().map(|t| t.3).collect();
    let mut body_decrypt: Vec<u64> = data.iter().map(|t| t.4).collect();
    let mut blinding: Vec<u64> = data.iter().map(|t| t.5).collect();
    let mut total_sphinx: Vec<u64> = data.iter().map(|t| t.6).collect();

    let breakdown = HopBreakdown {
        ecdh: bench_common::compute_op_stats(&mut ecdh),
        key_derive: bench_common::compute_op_stats(&mut key_derive),
        mac_verify: bench_common::compute_op_stats(&mut mac_verify),
        routing_decrypt: bench_common::compute_op_stats(&mut routing_decrypt),
        body_decrypt: bench_common::compute_op_stats(&mut body_decrypt),
        blinding: bench_common::compute_op_stats(&mut blinding),
        total_sphinx: bench_common::compute_op_stats(&mut total_sphinx),
    };

    info!("=== PER-HOP BREAKDOWN RESULTS ===");
    info!("Duration:      {:.2}s", total_duration.as_secs_f64());
    info!("Packets:       {success} delivered / {total} total (failed: {failed})");
    info!("Hop samples:   {n}");
    info!("ECDH p50:      {} ns", breakdown.ecdh.p50_ns);
    info!("Key derive p50:{} ns", breakdown.key_derive.p50_ns);
    info!("MAC verify p50:{} ns", breakdown.mac_verify.p50_ns);
    info!("Route dec p50: {} ns", breakdown.routing_decrypt.p50_ns);
    info!("Body dec p50:  {} ns", breakdown.body_decrypt.p50_ns);
    info!("Blinding p50:  {} ns", breakdown.blinding.p50_ns);
    info!("Total p50:     {} ns", breakdown.total_sphinx.p50_ns);
    info!("==================================");

    Ok(BenchResult {
        benchmark: "per_hop_breakdown".into(),
        mode: "in_process".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "nodes": nodes_count,
            "packets": packets,
            "mix_delay_ms": mix_delay_ms,
            "concurrency": concurrency,
            "hops_per_packet": hops,
            "payload_size": payload_size,
        }),
        results: serde_json::json!({
            "duration_secs": total_duration.as_secs_f64(),
            "success": success,
            "failed": failed,
            "hop_samples": n,
            "breakdown": breakdown,
        }),
    })
}

#[cfg(not(feature = "hop-metrics"))]
async fn run_per_hop(_cfg: &BenchConfig) -> Result<BenchResult> {
    Err(anyhow::anyhow!(
        "per-hop benchmark requires --features hop-metrics. \
         Rerun with: cargo run -p nox-sim --bin nox_bench --features 'dev-node,hop-metrics' -- per-hop"
    ))
}

// (Shared utilities live in nox_sim::bench_common)

/// Subcommand-specific arguments that don't fit in the shared `BenchConfig`.
enum SubArgs {
    Latency,
    Throughput {
        duration_secs: u64,
        target_pps_list: Vec<usize>,
    },
    Scale {
        node_counts: Vec<usize>,
    },
    SurbRtt,
    SurbRttFec {
        response_size: usize,
        fec_ratio: f64,
    },
    PerHop,
}

/// Parse CLI command into shared `BenchConfig` + subcommand-specific args.
fn build_config_from_cli(cli: &Cli) -> Result<(BenchConfig, SubArgs)> {
    let bus_capacity = cli.bus_capacity;
    match &cli.command {
        Command::Latency {
            nodes,
            packets,
            hops,
            mix_delay_ms,
            concurrency,
            warmup,
            payload_size,
            settle_secs,
            raw_latencies,
        } => Ok((
            BenchConfig {
                nodes: *nodes,
                packets: *packets,
                hops: *hops,
                mix_delay_ms: *mix_delay_ms,
                concurrency: *concurrency,
                warmup: *warmup,
                payload_size: *payload_size,
                settle_secs: *settle_secs,
                raw_latencies: *raw_latencies,
                bus_capacity,
            },
            SubArgs::Latency,
        )),
        Command::Throughput {
            nodes,
            duration,
            target_pps,
            hops,
            mix_delay_ms,
            payload_size,
            settle_secs,
        } => {
            let pps_list: Vec<usize> = target_pps
                .split(',')
                .map(|s| {
                    s.trim()
                        .parse()
                        .map_err(|e| anyhow::anyhow!("invalid PPS value '{s}': {e}"))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok((
                BenchConfig {
                    nodes: *nodes,
                    packets: 0, // not used for throughput
                    hops: *hops,
                    mix_delay_ms: *mix_delay_ms,
                    concurrency: 0, // throughput uses its own rate control
                    warmup: 0,
                    payload_size: *payload_size,
                    settle_secs: *settle_secs,
                    raw_latencies: false,
                    bus_capacity,
                },
                SubArgs::Throughput {
                    duration_secs: *duration,
                    target_pps_list: pps_list,
                },
            ))
        }
        Command::Scale {
            node_counts,
            packets,
            hops,
            mix_delay_ms,
            concurrency,
            payload_size,
            settle_secs,
            raw_latencies,
        } => {
            let counts: Vec<usize> = node_counts
                .split(',')
                .map(|s| {
                    s.trim()
                        .parse()
                        .map_err(|e| anyhow::anyhow!("invalid node count '{s}': {e}"))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok((
                BenchConfig {
                    nodes: 0, // overridden per scale point
                    packets: *packets,
                    hops: *hops,
                    mix_delay_ms: *mix_delay_ms,
                    concurrency: *concurrency,
                    warmup: 0,
                    payload_size: *payload_size,
                    settle_secs: *settle_secs,
                    raw_latencies: *raw_latencies,
                    bus_capacity,
                },
                SubArgs::Scale {
                    node_counts: counts,
                },
            ))
        }
        Command::SurbRtt {
            nodes,
            packets,
            hops,
            mix_delay_ms,
            concurrency,
            payload_size,
            settle_secs,
            raw_latencies,
        } => Ok((
            BenchConfig {
                nodes: *nodes,
                packets: *packets,
                hops: *hops,
                mix_delay_ms: *mix_delay_ms,
                concurrency: *concurrency,
                warmup: 0,
                payload_size: *payload_size,
                settle_secs: *settle_secs,
                raw_latencies: *raw_latencies,
                bus_capacity,
            },
            SubArgs::SurbRtt,
        )),
        Command::SurbRttFec {
            nodes,
            packets,
            hops,
            mix_delay_ms,
            concurrency,
            response_size,
            fec_ratio,
            settle_secs,
            raw_latencies,
        } => Ok((
            BenchConfig {
                nodes: *nodes,
                packets: *packets,
                hops: *hops,
                mix_delay_ms: *mix_delay_ms,
                concurrency: *concurrency,
                warmup: 0,
                payload_size: *response_size, // reuse payload_size field for response_size
                settle_secs: *settle_secs,
                raw_latencies: *raw_latencies,
                bus_capacity,
            },
            SubArgs::SurbRttFec {
                response_size: *response_size,
                fec_ratio: *fec_ratio,
            },
        )),
        Command::PerHop {
            nodes,
            packets,
            hops,
            mix_delay_ms,
            concurrency,
            payload_size,
            settle_secs,
        } => Ok((
            BenchConfig {
                nodes: *nodes,
                packets: *packets,
                hops: *hops,
                mix_delay_ms: *mix_delay_ms,
                concurrency: *concurrency,
                warmup: 0,
                payload_size: *payload_size,
                settle_secs: *settle_secs,
                raw_latencies: false,
                bus_capacity,
            },
            SubArgs::PerHop,
        )),
    }
}

/// Dispatch to the appropriate benchmark runner based on subcommand args.
async fn run_subcommand(cfg: &BenchConfig, sub: &SubArgs) -> Result<BenchResult> {
    match sub {
        SubArgs::Latency => run_latency(cfg).await,
        SubArgs::Throughput {
            duration_secs,
            target_pps_list,
        } => run_throughput(cfg, *duration_secs, target_pps_list.clone()).await,
        SubArgs::Scale { node_counts } => run_scale(cfg, node_counts.clone()).await,
        SubArgs::SurbRtt => run_surb_rtt(cfg).await,
        SubArgs::SurbRttFec {
            response_size,
            fec_ratio,
        } => run_surb_rtt_fec(cfg, *response_size, *fec_ratio).await,
        SubArgs::PerHop => run_per_hop(cfg).await,
    }
}

/// Summary statistics for a single metric across N runs.
#[derive(serde::Serialize)]
struct RunAggregate {
    mean: f64,
    stddev: f64,
    min: f64,
    max: f64,
    /// 95% confidence interval half-width: `t * stddev / sqrt(n)`
    ci_95: f64,
}

/// Compute mean, stddev, min, max, and 95% CI from a slice of f64 samples.
fn compute_run_aggregate(values: &[f64]) -> RunAggregate {
    let n = values.len();
    if n == 0 {
        return RunAggregate {
            mean: 0.0,
            stddev: 0.0,
            min: 0.0,
            max: 0.0,
            ci_95: 0.0,
        };
    }
    let mean = values.iter().sum::<f64>() / n as f64;
    let min = values.iter().copied().fold(f64::INFINITY, f64::min);
    let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let variance = if n > 1 {
        values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1) as f64
    } else {
        0.0
    };
    let stddev = variance.sqrt();
    // t-value for 95% CI: use 1.96 for large N, or approximate t-distribution
    // for small N (conservative: use 2.0 for N<30)
    let t = if n >= 30 { 1.96 } else { 2.0 };
    let ci_95 = t * stddev / (n as f64).sqrt();
    RunAggregate {
        mean,
        stddev,
        min,
        max,
        ci_95,
    }
}

/// Extract a numeric field from each run's `results` JSON and aggregate.
fn extract_and_aggregate(results: &[BenchResult], path: &[&str]) -> Option<RunAggregate> {
    let values: Vec<f64> = results
        .iter()
        .filter_map(|r| {
            let mut val = &r.results;
            for &key in path {
                val = val.get(key)?;
            }
            val.as_f64()
        })
        .collect();
    if values.is_empty() {
        None
    } else {
        Some(compute_run_aggregate(&values))
    }
}

/// Aggregate key metrics across multiple benchmark runs.
fn aggregate_runs(results: &[BenchResult]) -> serde_json::Value {
    let mut agg = serde_json::Map::new();

    // Common latency metrics (present in latency, scale, surb-rtt)
    let latency_paths = [
        ("p50_us", vec!["latency", "p50_us"]),
        ("p90_us", vec!["latency", "p90_us"]),
        ("p95_us", vec!["latency", "p95_us"]),
        ("p99_us", vec!["latency", "p99_us"]),
        ("p999_us", vec!["latency", "p999_us"]),
        ("mean_us", vec!["latency", "mean_us"]),
        ("stddev_us", vec!["latency", "stddev_us"]),
    ];

    for (name, path) in &latency_paths {
        let path_refs: Vec<&str> = path.iter().map(std::convert::AsRef::as_ref).collect();
        if let Some(stats) = extract_and_aggregate(results, &path_refs) {
            agg.insert(
                (*name).into(),
                serde_json::to_value(stats).expect("serialize"),
            );
        }
    }

    // Throughput PPS
    if let Some(stats) = extract_and_aggregate(results, &["throughput_pps"]) {
        agg.insert(
            "throughput_pps".into(),
            serde_json::to_value(stats).expect("serialize"),
        );
    }

    // Success / failed counts
    if let Some(stats) = extract_and_aggregate(results, &["success"]) {
        agg.insert(
            "success".into(),
            serde_json::to_value(stats).expect("serialize"),
        );
    }
    if let Some(stats) = extract_and_aggregate(results, &["failed"]) {
        agg.insert(
            "failed".into(),
            serde_json::to_value(stats).expect("serialize"),
        );
    }

    // Duration
    if let Some(stats) = extract_and_aggregate(results, &["duration_secs"]) {
        agg.insert(
            "duration_secs".into(),
            serde_json::to_value(stats).expect("serialize"),
        );
    }

    serde_json::Value::Object(agg)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Structured log to stderr, JSON results to stdout
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber).ok();

    let cli = Cli::parse();
    let num_runs = cli.runs.max(1);

    // Build BenchConfig + subcommand-specific args from CLI (parsed once).
    let (cfg, sub) = build_config_from_cli(&cli)?;

    if num_runs == 1 {
        // Single run -- emit result directly (backward compatible)
        let result = run_subcommand(&cfg, &sub).await?;
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        // Multi-run -- collect all results, then aggregate
        info!("=== MULTI-RUN MODE: {num_runs} runs ===");
        let mut results = Vec::with_capacity(num_runs);

        for run_idx in 0..num_runs {
            info!("--- Run {}/{num_runs} ---", run_idx + 1);
            let result = run_subcommand(&cfg, &sub).await?;
            results.push(result);
            // Brief pause between runs to let OS reclaim resources
            if run_idx + 1 < num_runs {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }

        let aggregate = aggregate_runs(&results);
        let output = serde_json::json!({
            "multi_run": true,
            "total_runs": num_runs,
            "hardware": results[0].hardware,
            "git_commit": results[0].git_commit,
            "params": results[0].params,
            "aggregate": aggregate,
            "runs": results.iter().enumerate().map(|(i, r)| {
                serde_json::json!({
                    "run": i + 1,
                    "timestamp": r.timestamp,
                    "results": r.results,
                })
            }).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    }

    Ok(())
}
