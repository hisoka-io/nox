//! Formal privacy metrics for the research paper (Tier 4).
//!
//! Measures anonymity set entropy, timing correlation resistance,
//! statistical unlinkability, FEC recovery rates, and attack resilience
//! across an in-process mixnet mesh.
//!
//! Subcommands: `timing-correlation`, `entropy`, `fec-recovery`,
//! `unlinkability`, `attack-sim`. Output: JSON to stdout.

// Benchmark binary: panicking on serialization failure is acceptable.
#![allow(clippy::expect_used)]

use anyhow::Result;
use clap::{Parser, Subcommand};
use libp2p::multiaddr::Protocol;
use rand::rngs::OsRng;
use rand::Rng;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::tempdir;
use tokio::sync::{oneshot, Semaphore};
use tracing::{error, info, Level};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

use nox_core::events::NoxEvent;
use nox_core::traits::interfaces::{IEventPublisher, IEventSubscriber, IReplayProtection};
use nox_core::RelayerPayload;
use nox_crypto::{build_multi_hop_packet, PathHop};
use nox_node::services::mixing::{NoMixStrategy, PoissonMixStrategy};
use nox_node::services::network_manager::TopologyManager;
use nox_node::services::relayer::RelayerService;
use nox_node::telemetry::metrics::MetricsService;
use nox_node::{NoxConfig, SledRepository, TokioEventBus};
use nox_sim::bench_common::{
    self, AttackResult, BenchResult, CombinedAnonymityPoint, CorrelationResult, CoverAnalysisPoint,
    CoverTrafficPoint, EntropyPoint, EntropyVsUsersPoint, FecOptimalRatio, FecRatioPoint,
    FecRecoveryPoint, FecVsArqPoint, PowDosResult, ReplayDetectionResult, TrafficLevelPoint,
    UnlinkabilityResult,
};

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "NOX Privacy Analytics -- anonymity metrics, timing correlation, FEC recovery, attack simulations"
)]
struct Cli {
    /// Event bus capacity per node (tokio broadcast channel size).
    #[arg(long, default_value_t = 16384, global = true)]
    bus_capacity: usize,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Measure timing correlation between packet input and output times (Tier 4.2.1-4.2.2).
    /// Computes Pearson r, Spearman rho, and mutual information.
    /// Emits (`input_us`, `output_us`) pairs for heatmap charting.
    TimingCorrelation {
        /// Number of mix nodes
        #[arg(short, long, default_value_t = 10)]
        nodes: usize,

        /// Total packets to send
        #[arg(short, long, default_value_t = 2000)]
        packets: usize,

        /// Number of hops per path (min 2, default 3)
        #[arg(long, default_value_t = 3)]
        hops: usize,

        /// Poisson mix delay per hop in ms
        #[arg(long, default_value_t = 1.0)]
        mix_delay_ms: f64,

        /// Max concurrent in-flight packets
        #[arg(long, default_value_t = 50)]
        concurrency: usize,

        /// Mesh stabilization time in seconds
        #[arg(long, default_value_t = 2)]
        settle_secs: u64,

        /// Include raw (input, output) timing pairs in JSON (for heatmap)
        #[arg(long, default_value_t = true)]
        raw_pairs: bool,
    },

    /// Measure Shannon entropy vs mixing delay (Tier 4.1.1-4.1.3).
    /// Sweeps delay parameter and computes anonymity set metrics at each point.
    Entropy {
        /// Number of mix nodes
        #[arg(short, long, default_value_t = 10)]
        nodes: usize,

        /// Packets per delay step
        #[arg(short, long, default_value_t = 1000)]
        packets: usize,

        /// Number of hops per path (min 2, default 3)
        #[arg(long, default_value_t = 3)]
        hops: usize,

        /// Max concurrent in-flight packets
        #[arg(long, default_value_t = 50)]
        concurrency: usize,

        /// Mesh stabilization time in seconds
        #[arg(long, default_value_t = 2)]
        settle_secs: u64,

        /// Comma-separated delay values to sweep (ms)
        #[arg(long, default_value = "0,0.5,1,2,5,10,20,50,100")]
        delays_ms: String,
    },

    /// Measure FEC recovery rate under simulated packet loss (Tier 4.5.1-4.5.3).
    /// Pure simulation: fragments + FEC encode + random drop + decode.
    FecRecovery {
        /// Number of data shards
        #[arg(long, default_value_t = 10)]
        data_shards: usize,

        /// FEC ratio (parity / data). E.g. 0.3 = 30% parity overhead
        #[arg(long, default_value_t = 0.3)]
        fec_ratio: f64,

        /// Number of trial runs per loss rate
        #[arg(long, default_value_t = 1000)]
        trials: usize,

        /// Response data size in bytes
        #[arg(long, default_value_t = 307_200)]
        response_size: usize,

        /// Comma-separated loss rates to sweep (0.0 to 1.0)
        #[arg(long, default_value = "0.0,0.05,0.1,0.15,0.2,0.25,0.3,0.4,0.5")]
        loss_rates: String,
    },

    /// Statistical unlinkability test (Tier 4.2.3-4.2.4).
    /// Computes KS and chi-squared tests for output time uniformity.
    Unlinkability {
        /// Number of mix nodes
        #[arg(short, long, default_value_t = 10)]
        nodes: usize,

        /// Total packets to send per traffic level
        #[arg(short, long, default_value_t = 2000)]
        packets: usize,

        /// Number of hops per path (min 2, default 3)
        #[arg(long, default_value_t = 3)]
        hops: usize,

        /// Max concurrent in-flight packets
        #[arg(long, default_value_t = 50)]
        concurrency: usize,

        /// Mesh stabilization time in seconds
        #[arg(long, default_value_t = 2)]
        settle_secs: u64,

        /// Comma-separated mix delay values (ms)
        #[arg(long, default_value = "0.5,1,5,10,50")]
        delays_ms: String,
    },

    /// FEC ratio sweep (Tier 4.5.4+4.5.6).
    /// Sweeps multiple FEC ratios at each loss rate to find the optimal P/D ratio
    /// for ≥99.9% delivery. Pure simulation -- no network needed.
    FecRatioSweep {
        /// Number of data shards (auto-detected from response size if 0)
        #[arg(long, default_value_t = 0)]
        data_shards: usize,

        /// Comma-separated FEC ratios to sweep (parity / data)
        #[arg(long, default_value = "0.1,0.2,0.3,0.4,0.5,0.6,0.8,1.0")]
        ratios: String,

        /// Comma-separated loss rates to sweep (0.0 to 1.0)
        #[arg(long, default_value = "0.05,0.1,0.15,0.2,0.25,0.3")]
        loss_rates: String,

        /// Number of trials per (ratio, `loss_rate`) pair
        #[arg(long, default_value_t = 2000)]
        trials: usize,

        /// Response data size in bytes
        #[arg(long, default_value_t = 307_200)]
        response_size: usize,

        /// Target delivery rate for optimal ratio determination
        #[arg(long, default_value_t = 0.999)]
        target_delivery: f64,
    },

    /// Cover traffic analysis (Tier 4.3.1-4.3.2).
    /// Measures bandwidth overhead and traffic pattern entropy at varying
    /// cover traffic rates. Uses in-process mesh with real Loopix cover traffic.
    CoverTraffic {
        /// Number of mix nodes
        #[arg(short, long, default_value_t = 10)]
        nodes: usize,

        /// Real packets to send per cover-rate step
        #[arg(short, long, default_value_t = 200)]
        packets: usize,

        /// Number of hops per path (min 2, default 3)
        #[arg(long, default_value_t = 3)]
        hops: usize,

        /// Measurement duration per cover-rate step in seconds
        #[arg(long, default_value_t = 15)]
        duration_secs: u64,

        /// Mesh stabilization time in seconds
        #[arg(long, default_value_t = 3)]
        settle_secs: u64,

        /// Comma-separated cover traffic rates to sweep (packets/sec)
        #[arg(long, default_value = "0,0.5,1,5,10,50")]
        cover_rates: String,
    },

    /// Attack simulations (Tier 4.4.1-4.4.3).
    /// Simulates n-1 attack, intersection attack, and compromised node scenarios.
    AttackSim {
        /// Number of mix nodes
        #[arg(short, long, default_value_t = 15)]
        nodes: usize,

        /// Packets per simulation round
        #[arg(short, long, default_value_t = 1000)]
        packets: usize,

        /// Number of hops per path (min 2, default 3)
        #[arg(long, default_value_t = 3)]
        hops: usize,

        /// Mix delay per hop in ms
        #[arg(long, default_value_t = 1.0)]
        mix_delay_ms: f64,

        /// Max concurrent in-flight packets
        #[arg(long, default_value_t = 50)]
        concurrency: usize,

        /// Mesh stabilization time in seconds
        #[arg(long, default_value_t = 2)]
        settle_secs: u64,

        /// Number of simulation rounds per attack type
        #[arg(long, default_value_t = 10)]
        rounds: usize,
    },

    /// Replay detection accuracy and throughput (Tier 4.4.4).
    /// Tests `RotationalBloomFilter` and Sled-based replay protection for
    /// false positives, false negatives, and throughput.
    ReplayDetection {
        /// Number of unique tags to insert
        #[arg(long, default_value_t = 100_000)]
        unique_tags: usize,

        /// Number of replay attempts (re-insert of already-seen tags)
        #[arg(long, default_value_t = 10_000)]
        replay_attempts: usize,

        /// Bloom filter capacity
        #[arg(long, default_value_t = 10_000_000)]
        bloom_capacity: usize,

        /// Bloom filter false positive rate target
        #[arg(long, default_value_t = 0.001)]
        bloom_fp_rate: f64,
    },

    /// PoW-based denial-of-service mitigation benchmark (Tier 4.4.5).
    /// Measures solve time, verify time, and asymmetry ratio at various difficulties.
    PowDos {
        /// Difficulties to sweep (comma-separated)
        #[arg(long, default_value = "0,4,8,12,16,20,24")]
        difficulties: String,

        /// Trials per difficulty level
        #[arg(long, default_value_t = 100)]
        trials: usize,
    },

    /// Entropy vs concurrent users (Tier 4.1.4).
    /// Measures how anonymity set size scales with the number of active senders.
    EntropyVsUsers {
        /// Number of mix nodes
        #[arg(short, long, default_value_t = 15)]
        nodes: usize,

        /// Total packets to send per user count
        #[arg(short, long, default_value_t = 1000)]
        packets: usize,

        /// Number of hops per path
        #[arg(long, default_value_t = 3)]
        hops: usize,

        /// Mix delay per hop in ms
        #[arg(long, default_value_t = 1.0)]
        mix_delay_ms: f64,

        /// Concurrency limit
        #[arg(long, default_value_t = 50)]
        concurrency: usize,

        /// Mesh stabilization time in seconds
        #[arg(long, default_value_t = 2)]
        settle_secs: u64,

        /// Comma-separated user counts to sweep
        #[arg(long, default_value = "2,3,5,8,10,15")]
        user_counts: String,
    },

    /// Entropy vs cover traffic ratio (Tier 4.1.5).
    /// Measures how cover traffic affects anonymity under GPA observation.
    EntropyVsCover {
        /// Number of mix nodes
        #[arg(short, long, default_value_t = 10)]
        nodes: usize,

        /// Real packets to send
        #[arg(short, long, default_value_t = 500)]
        packets: usize,

        /// Number of hops per path
        #[arg(long, default_value_t = 3)]
        hops: usize,

        /// Measurement duration in seconds per cover rate
        #[arg(long, default_value_t = 10)]
        duration_secs: u64,

        /// Mesh stabilization time in seconds
        #[arg(long, default_value_t = 2)]
        settle_secs: u64,

        /// Comma-separated cover ratios to test (`cover_rate` = `real_rate` * ratio)
        #[arg(long, default_value = "0,1,3,5,10")]
        cover_ratios: String,
    },

    /// FEC vs ARQ comparison (Tier 4.5.5).
    /// Compares one-shot FEC delivery vs stop-and-wait ARQ retransmission.
    FecVsArq {
        /// Data shards
        #[arg(long, default_value_t = 10)]
        data_shards: usize,

        /// FEC ratio (parity = data * ratio)
        #[arg(long, default_value_t = 0.5)]
        fec_ratio: f64,

        /// Response size in bytes (determines actual shard count)
        #[arg(long, default_value_t = 307_200)]
        response_size: usize,

        /// Max ARQ retransmission rounds
        #[arg(long, default_value_t = 5)]
        arq_max_retries: usize,

        /// Trials per loss rate
        #[arg(long, default_value_t = 10_000)]
        trials: usize,

        /// Comma-separated loss rates
        #[arg(
            long,
            default_value = "0.0,0.05,0.1,0.15,0.2,0.25,0.3,0.35,0.4,0.45,0.5"
        )]
        loss_rates: String,
    },

    /// Anonymity at varying traffic levels (Tier 4.2.5).
    /// Measures sender entropy at low, medium, and high traffic injection rates.
    /// Shows how anonymity changes under congestion vs low-load conditions.
    TrafficLevels {
        /// Number of mix nodes
        #[arg(short, long, default_value_t = 10)]
        nodes: usize,

        /// Total packets to send per traffic level
        #[arg(short, long, default_value_t = 1000)]
        packets: usize,

        /// Number of hops per path
        #[arg(long, default_value_t = 3)]
        hops: usize,

        /// Mix delay per hop in ms
        #[arg(long, default_value_t = 1.0)]
        mix_delay_ms: f64,

        /// Mesh stabilization time in seconds
        #[arg(long, default_value_t = 2)]
        settle_secs: u64,

        /// Comma-separated target traffic rates in packets/sec
        #[arg(long, default_value = "5,10,25,50,100,200,500")]
        traffic_rates: String,
    },

    /// Combined mixnet × UTXO anonymity analysis (Tier 4.1.7).
    /// Novel contribution: measures how mixnet-layer privacy (sender-IP unlinkability)
    /// composes with UTXO-layer privacy (sender-note unlinkability via ZK Merkle proofs).
    /// Sweeps UTXO pool sizes and mixnet sizes, computing independent, correlated,
    /// and partial composition scenarios.
    CombinedAnonymity {
        /// Comma-separated UTXO pool sizes (number of Merkle tree leaves)
        #[arg(long, default_value = "100,1000,10000,100000,1000000")]
        pool_sizes: String,

        /// Comma-separated mixnet node counts to sweep
        #[arg(long, default_value = "3,5,10,15")]
        mixnet_sizes: String,

        /// Packets per mixnet measurement
        #[arg(short, long, default_value_t = 1000)]
        packets: usize,

        /// Hops per path
        #[arg(long, default_value_t = 3)]
        hops: usize,

        /// Mix delay per hop in ms
        #[arg(long, default_value_t = 1.0)]
        mix_delay_ms: f64,

        /// Concurrency limit
        #[arg(long, default_value_t = 50)]
        concurrency: usize,

        /// Mesh stabilization time in seconds
        #[arg(long, default_value_t = 2)]
        settle_secs: u64,

        /// Assumed number of distinct recipients sharing the same `recipientP_x` tag
        /// (for partial composition). Fresh keys per tx means this is typically 1-2.
        #[arg(long, default_value_t = 2)]
        tag_reuse_count: usize,
    },

    /// Comprehensive cover traffic analysis (Tier 4.3.3-4.3.5).
    /// Combines: (1) active/idle distinguishability via KS/chi-squared on per-node
    /// timing, (2) observed vs configured Poisson lambda, (3) CPU/memory/bandwidth cost.
    CoverAnalysis {
        /// Number of mix nodes
        #[arg(short, long, default_value_t = 10)]
        nodes: usize,

        /// Real packets to inject per cover-rate step
        #[arg(short, long, default_value_t = 200)]
        packets: usize,

        /// Number of hops per path
        #[arg(long, default_value_t = 3)]
        hops: usize,

        /// Measurement duration per cover-rate step in seconds
        #[arg(long, default_value_t = 15)]
        duration_secs: u64,

        /// Mesh stabilization time in seconds
        #[arg(long, default_value_t = 3)]
        settle_secs: u64,

        /// Comma-separated cover traffic rates to sweep (packets/sec per node)
        #[arg(long, default_value = "0,0.5,1,2,5,10,20")]
        cover_rates: String,
    },
}

struct BenchNode {
    id: usize,
    multiaddr: String,
    public_key: X25519PublicKey,
    bus_publisher: Arc<dyn IEventPublisher>,
    bus_subscriber: Arc<dyn IEventSubscriber>,
    #[allow(dead_code)]
    storage: Arc<SledRepository>,
    _db_dir: tempfile::TempDir,
}

type CompletionRegistry = Arc<parking_lot::Mutex<HashMap<String, oneshot::Sender<()>>>>;

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
        c.p2p_port = 0;
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
        c.relayer.cover_traffic_rate = 0.0;
        c.relayer.drop_traffic_rate = 0.0;
        c
    };

    let metrics = MetricsService::new();
    let topology = Arc::new(TopologyManager::new(db.clone(), sub_bus.clone(), None));
    let topo_clone = topology.clone();
    tokio::spawn(async move { topo_clone.run().await });

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
    tokio::spawn(async move { p2p.run().await });
    let (pid, base_addr) = rx.await?;
    let full_addr = base_addr.with(Protocol::P2p(pid));

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
        storage: db,
        _db_dir: dir,
    })
}

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

    info!("Wiring mesh ({} connections)...", nodes.len() * nodes.len());
    for target in &nodes {
        for source in &nodes {
            source.bus_publisher.publish(NoxEvent::RelayerRegistered {
                address: format!("0xNode{}", target.id),
                sphinx_key: hex::encode(target.public_key.as_bytes()),
                url: target.multiaddr.clone(),
                stake: "1000".to_string(),
                role: 3,
                ingress_url: None,
                metadata_url: None,
            })?;
        }
    }

    info!("Mesh stabilization ({settle_secs}s)...");
    tokio::time::sleep(Duration::from_secs(settle_secs)).await;
    Ok(nodes)
}

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

/// Build a path with specified entry and exit, random intermediates.
/// For entropy measurement: the GPA must rely on timing, not route structure.
fn build_random_path(
    nodes: &[BenchNode],
    entry_idx: usize,
    exit_idx: usize,
    hops: usize,
) -> Vec<PathHop> {
    let mut rng = OsRng;
    let mut path = Vec::with_capacity(hops);

    // First hop is the entry node
    path.push(PathHop {
        public_key: nodes[entry_idx].public_key,
        address: nodes[entry_idx].multiaddr.clone(),
    });

    // Intermediate hops: random selection (may repeat, that's realistic)
    for _ in 1..hops.saturating_sub(1) {
        let idx = rng.gen_range(0..nodes.len());
        path.push(PathHop {
            public_key: nodes[idx].public_key,
            address: nodes[idx].multiaddr.clone(),
        });
    }

    // Last hop is the exit node (if hops > 1)
    if hops > 1 {
        path.push(PathHop {
            public_key: nodes[exit_idx].public_key,
            address: nodes[exit_idx].multiaddr.clone(),
        });
    }

    path
}

fn build_bench_payload(payload_size: usize) -> Vec<u8> {
    let payload = RelayerPayload::SubmitTransaction {
        to: [0u8; 20],
        data: vec![0xBE; payload_size],
    };
    bincode::serialize(&payload).expect("serialize")
}

/// Compute Pearson correlation coefficient for paired (x, y) data.
fn pearson_r(x: &[f64], y: &[f64]) -> f64 {
    let n = x.len() as f64;
    if n < 2.0 {
        return 0.0;
    }
    let mean_x: f64 = x.iter().sum::<f64>() / n;
    let mean_y: f64 = y.iter().sum::<f64>() / n;
    let mut cov = 0.0;
    let mut var_x = 0.0;
    let mut var_y = 0.0;
    for i in 0..x.len() {
        let dx = x[i] - mean_x;
        let dy = y[i] - mean_y;
        cov += dx * dy;
        var_x += dx * dx;
        var_y += dy * dy;
    }
    let denom = (var_x * var_y).sqrt();
    if denom < 1e-15 {
        return 0.0;
    }
    cov / denom
}

/// Approximate two-tailed p-value for Pearson r using Fisher's transformation.
/// For n > 30, the test statistic t = r * sqrt((n-2) / (1 - r^2)) is approximately
/// standard normal. We use a rough approximation of the normal CDF.
fn pearson_p_value(r: f64, n: usize) -> f64 {
    if n < 3 {
        return 1.0;
    }
    let r_clamped = r.abs().min(0.999_999);
    let t = r_clamped * ((n as f64 - 2.0) / (1.0 - r_clamped * r_clamped)).sqrt();
    // Two-tailed p-value via approximation: p ≈ 2 * erfc(t / sqrt(2)) / 2
    // Using a simple logistic approximation of the normal CDF tail
    let p = 2.0 * normal_cdf_complement(t);
    p.clamp(0.0, 1.0)
}

/// Complement of the standard normal CDF: P(X > x).
/// Uses the Abramowitz & Stegun rational approximation (error < 7.5e-8).
fn normal_cdf_complement(x: f64) -> f64 {
    if x < 0.0 {
        return 1.0 - normal_cdf_complement(-x);
    }
    let b0 = 0.231_641_9;
    let b1 = 0.319_381_53;
    let b2 = -0.356_563_782;
    let b3 = 1.781_477_937;
    let b4 = -1.821_255_978;
    let b5 = 1.330_274_429;
    let t = 1.0 / (1.0 + 0.231_641_9 * x);
    // Horner form for polynomial evaluation
    let inner = ((((b5 * t + b4) * t + b3) * t + b2) * t + b1) * t + b0;
    let phi = inner * (-x * x / 2.0).exp();
    phi.clamp(0.0, 1.0)
}

/// Compute Spearman rank correlation coefficient.
fn spearman_rho(x: &[f64], y: &[f64]) -> f64 {
    let n = x.len();
    if n < 2 {
        return 0.0;
    }
    let rank_x = compute_ranks(x);
    let rank_y = compute_ranks(y);
    pearson_r(&rank_x, &rank_y)
}

/// Compute fractional ranks for a slice (handles ties with average rank).
fn compute_ranks(values: &[f64]) -> Vec<f64> {
    let n = values.len();
    let mut indexed: Vec<(usize, f64)> = values.iter().copied().enumerate().collect();
    indexed.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    let mut ranks = vec![0.0; n];
    let mut i = 0;
    while i < n {
        let mut j = i;
        while j < n && (indexed[j].1 - indexed[i].1).abs() < 1e-15 {
            j += 1;
        }
        // Average rank for ties
        let avg_rank = (i + j) as f64 / 2.0 + 0.5;
        for k in i..j {
            ranks[indexed[k].0] = avg_rank;
        }
        i = j;
    }
    ranks
}

/// Estimate mutual information I(X;Y) using a simple binning approach.
/// Bins both X and Y into `num_bins` equal-width bins, computes the joint
/// and marginal probability distributions, then calculates:
///   `I(X;Y) = Sum_ij p(x_i,y_j) * log2(p(x_i,y_j) / (p(x_i) * p(y_j)))`
fn mutual_information(x: &[f64], y: &[f64], num_bins: usize) -> f64 {
    let n = x.len();
    if n == 0 || num_bins == 0 {
        return 0.0;
    }
    let x_min = x.iter().copied().reduce(f64::min).unwrap_or(0.0);
    let x_max = x.iter().copied().reduce(f64::max).unwrap_or(1.0);
    let y_min = y.iter().copied().reduce(f64::min).unwrap_or(0.0);
    let y_max = y.iter().copied().reduce(f64::max).unwrap_or(1.0);

    let x_range = (x_max - x_min).max(1e-15);
    let y_range = (y_max - y_min).max(1e-15);

    // Joint histogram
    let mut joint = vec![vec![0u64; num_bins]; num_bins];
    for i in 0..n {
        let bx = ((x[i] - x_min) / x_range * (num_bins as f64 - 1.0))
            .round()
            .max(0.0)
            .min((num_bins - 1) as f64) as usize;
        let by = ((y[i] - y_min) / y_range * (num_bins as f64 - 1.0))
            .round()
            .max(0.0)
            .min((num_bins - 1) as f64) as usize;
        joint[bx][by] += 1;
    }

    // Marginals
    let mut p_x = vec![0.0f64; num_bins];
    let mut p_y = vec![0.0f64; num_bins];
    let n_f = n as f64;
    for bx in 0..num_bins {
        for by in 0..num_bins {
            let p = joint[bx][by] as f64 / n_f;
            p_x[bx] += p;
            p_y[by] += p;
        }
    }

    // MI
    let mut mi = 0.0;
    for bx in 0..num_bins {
        for by in 0..num_bins {
            let p_xy = joint[bx][by] as f64 / n_f;
            if p_xy > 1e-15 && p_x[bx] > 1e-15 && p_y[by] > 1e-15 {
                mi += p_xy * (p_xy / (p_x[bx] * p_y[by])).log2();
            }
        }
    }
    mi.max(0.0)
}

/// Shannon entropy in bits: `H = -Sum(p_i * log2(p_i))`.
fn shannon_entropy(probs: &[f64]) -> f64 {
    let mut h = 0.0;
    for &p in probs {
        if p > 1e-15 {
            h -= p * p.log2();
        }
    }
    h
}

/// Min-entropy: `-log2(max(p_i))`. Worst-case measure.
fn min_entropy(probs: &[f64]) -> f64 {
    let max_p = probs
        .iter()
        .copied()
        .reduce(f64::max)
        .unwrap_or(1.0)
        .max(1e-15);
    -(max_p.log2())
}

/// Kolmogorov-Smirnov test statistic (one-sample, uniform distribution).
/// Returns (D, approximate p-value).
fn ks_test_uniform(data: &mut [f64]) -> (f64, f64) {
    let n = data.len();
    if n == 0 {
        return (0.0, 1.0);
    }
    data.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let d_min = data.iter().copied().reduce(f64::min).unwrap_or(0.0);
    let d_max = data.iter().copied().reduce(f64::max).unwrap_or(1.0);
    let range = (d_max - d_min).max(1e-15);

    // Normalise to [0, 1]
    let normalised: Vec<f64> = data.iter().map(|&v| (v - d_min) / range).collect();

    let n_f = n as f64;
    let mut d_stat = 0.0_f64;
    for (i, &v) in normalised.iter().enumerate() {
        let ecdf = (i + 1) as f64 / n_f;
        let d_plus = (ecdf - v).abs();
        let d_minus = (v - i as f64 / n_f).abs();
        d_stat = d_stat.max(d_plus).max(d_minus);
    }

    // Approximate p-value using the asymptotic Kolmogorov distribution
    // P(D_n > d) ≈ 2 * exp(-2 * n * d^2) for large n
    let p_value = (2.0 * (-2.0 * n_f * d_stat * d_stat).exp()).clamp(0.0, 1.0);

    (d_stat, p_value)
}

/// Chi-squared test for uniformity. Divides data into `num_bins` equal-width bins
/// and tests against a uniform distribution. Returns (chi2 statistic, approx `p-value`).
fn chi_squared_uniform(data: &[f64], num_bins: usize) -> (f64, f64) {
    let n = data.len();
    if n == 0 || num_bins == 0 {
        return (0.0, 1.0);
    }
    let d_min = data.iter().copied().reduce(f64::min).unwrap_or(0.0);
    let d_max = data.iter().copied().reduce(f64::max).unwrap_or(1.0);
    let range = (d_max - d_min).max(1e-15);

    let mut bins = vec![0u64; num_bins];
    for &v in data {
        let b = ((v - d_min) / range * (num_bins as f64 - 1.0))
            .round()
            .max(0.0)
            .min((num_bins - 1) as f64) as usize;
        bins[b] += 1;
    }

    let expected = n as f64 / num_bins as f64;
    let chi2: f64 = bins
        .iter()
        .map(|&observed| {
            let diff = observed as f64 - expected;
            diff * diff / expected
        })
        .sum();

    // Degrees of freedom = num_bins - 1
    let df = (num_bins - 1) as f64;
    // Approximate p-value using Wilson-Hilferty transformation:
    // Z = ((chi2/df)^(1/3) - (1 - 2/(9*df))) / sqrt(2/(9*df))
    // Then p = P(Z > z) ≈ normal_cdf_complement(z)
    let p_value = if df > 0.0 {
        let z =
            ((chi2 / df).powf(1.0 / 3.0) - (1.0 - 2.0 / (9.0 * df))) / (2.0 / (9.0 * df)).sqrt();
        normal_cdf_complement(z)
    } else {
        1.0
    };

    (chi2, p_value.clamp(0.0, 1.0))
}

/// Shared configuration for privacy analytics subcommands.
struct AnalyticsConfig {
    nodes: usize,
    packets: usize,
    hops: usize,
    mix_delay_ms: f64,
    concurrency: usize,
    settle_secs: u64,
    bus_capacity: usize,
}

async fn run_timing_correlation(cfg: &AnalyticsConfig, raw_pairs: bool) -> Result<BenchResult> {
    let nodes_count = cfg.nodes;
    let packets = cfg.packets;
    let hops = cfg.hops;
    let mix_delay_ms = cfg.mix_delay_ms;
    let concurrency = cfg.concurrency;
    let nodes = build_mesh(nodes_count, mix_delay_ms, cfg.settle_secs, cfg.bus_capacity).await?;
    let warmup = (packets / 10).max(10);
    let total = warmup + packets;

    info!(
        "Timing correlation: {packets} packets ({warmup} warmup), {nodes_count} nodes, \
         {hops} hops, {mix_delay_ms}ms delay, {concurrency} concurrent"
    );

    // Timing collection: (input_us, output_us) measured from a shared epoch
    let epoch = Instant::now();
    let timing_pairs: Arc<parking_lot::Mutex<Vec<(u64, u64)>>> =
        Arc::new(parking_lot::Mutex::new(Vec::with_capacity(packets)));

    // Completion registries
    let registries: Vec<CompletionRegistry> = nodes
        .iter()
        .map(|node| {
            let reg: CompletionRegistry = Arc::new(parking_lot::Mutex::new(HashMap::new()));
            spawn_completion_watcher(node.bus_subscriber.clone(), reg.clone());
            reg
        })
        .collect();

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let success_count = Arc::new(AtomicU64::new(0));
    let fail_count = Arc::new(AtomicU64::new(0));
    let payload_bytes = build_bench_payload(256);

    let mut handles = Vec::new();

    for i in 0..total {
        let permit = semaphore.clone().acquire_owned().await?;
        let entry_idx = i % nodes.len();
        let exit_idx = (i + hops - 1) % nodes.len();

        let entry_pub = nodes[entry_idx].bus_publisher.clone();
        let exit_reg = registries[exit_idx].clone();
        let path = build_path(&nodes, i, hops);
        let packet_bytes = build_multi_hop_packet(&path, &payload_bytes, 0)?;
        let pkt_size = packet_bytes.len();

        let pairs = timing_pairs.clone();
        let succ = success_count.clone();
        let fail = fail_count.clone();
        let is_warmup = i < warmup;
        let pkt_id = format!("tc_{i}");

        handles.push(tokio::spawn(async move {
            let (tx, rx) = oneshot::channel();
            exit_reg.lock().insert(pkt_id.clone(), tx);

            // Record input time (GPA observes packet entering the network)
            let input_us = epoch.elapsed().as_micros() as u64;

            let _ = entry_pub.publish(NoxEvent::PacketReceived {
                packet_id: pkt_id.clone(),
                data: packet_bytes,
                size_bytes: pkt_size,
            });

            let result = tokio::time::timeout(Duration::from_secs(30), rx).await;

            if let Ok(Ok(())) = result {
                // Record output time (GPA observes packet exiting the network)
                let output_us = epoch.elapsed().as_micros() as u64;
                succ.fetch_add(1, Ordering::Relaxed);
                if !is_warmup {
                    pairs.lock().push((input_us, output_us));
                }
            } else {
                exit_reg.lock().remove(&pkt_id);
                fail.fetch_add(1, Ordering::Relaxed);
            }
            drop(permit);
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let success = success_count.load(Ordering::Relaxed);
    let failed = fail_count.load(Ordering::Relaxed);
    let pairs = timing_pairs.lock().clone();

    info!(
        "Collected {} timing pairs ({} success, {} failed)",
        pairs.len(),
        success,
        failed
    );

    // Compute statistics
    let inputs: Vec<f64> = pairs.iter().map(|p| p.0 as f64).collect();
    let outputs: Vec<f64> = pairs.iter().map(|p| p.1 as f64).collect();

    let r = pearson_r(&inputs, &outputs);
    let p_val = pearson_p_value(r, pairs.len());
    let rho = spearman_rho(&inputs, &outputs);
    let num_bins = (pairs.len() as f64).sqrt().ceil() as usize;
    let mi = mutual_information(&inputs, &outputs, num_bins.max(10));

    let corr = CorrelationResult {
        pearson_r: r,
        pearson_p_value: p_val,
        spearman_rho: rho,
        mutual_information_bits: mi,
        sample_count: pairs.len(),
        mix_delay_ms,
        raw_pairs: if raw_pairs { Some(pairs) } else { None },
    };

    info!("=== TIMING CORRELATION RESULTS ===");
    info!(
        "Pearson r:          {:.6} (p={:.2e})",
        corr.pearson_r, corr.pearson_p_value
    );
    info!("Spearman rho:       {:.6}", corr.spearman_rho);
    info!(
        "Mutual information: {:.6} bits",
        corr.mutual_information_bits
    );
    info!(
        "Assessment:         {}",
        if r.abs() < 0.05 {
            "PASS -- timing correlation below 0.05 threshold"
        } else {
            "WARN -- timing correlation exceeds 0.05 threshold"
        }
    );
    info!("==================================");

    Ok(BenchResult {
        benchmark: "timing_correlation".into(),
        mode: "in_process".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "nodes": nodes_count,
            "packets": packets,
            "hops": hops,
            "mix_delay_ms": mix_delay_ms,
            "concurrency": concurrency,
        }),
        results: serde_json::json!(corr),
    })
}

async fn run_entropy(
    nodes_count: usize,
    packets: usize,
    hops: usize,
    concurrency: usize,
    settle_secs: u64,
    bus_capacity: usize,
    delays_ms: &[f64],
) -> Result<BenchResult> {
    info!(
        "Entropy sweep: {} delays, {} nodes, {} packets/step, {} hops",
        delays_ms.len(),
        nodes_count,
        packets,
        hops
    );

    let mut entropy_points: Vec<EntropyPoint> = Vec::with_capacity(delays_ms.len());

    for &delay in delays_ms {
        info!("--- Entropy measurement at {delay}ms delay ---");
        let nodes = build_mesh(nodes_count, delay, settle_secs, bus_capacity).await?;
        let warmup = (packets / 10).max(10);
        let total = warmup + packets;

        // For each packet, record which entry node it used and which exit node it appeared at.
        // A GPA observes: for each output at node E, what is the probability distribution over
        // possible senders (entry nodes)?
        //
        // Sender anonymity: for a given exit observation, how uncertain is the GPA
        // about which entry node sent the packet?
        //
        // Approach: send packets from uniformly random entry nodes, observe at exit.
        // For each exit node, build the empirical distribution of entry nodes that
        // produced outputs there. Shannon entropy of that distribution = sender anonymity.

        // exit_to_entries[exit_id] = list of entry_ids that produced packets there
        let exit_to_entries: Arc<parking_lot::Mutex<HashMap<usize, Vec<usize>>>> =
            Arc::new(parking_lot::Mutex::new(HashMap::new()));

        let registries: Vec<CompletionRegistry> = nodes
            .iter()
            .map(|node| {
                let reg: CompletionRegistry = Arc::new(parking_lot::Mutex::new(HashMap::new()));
                spawn_completion_watcher(node.bus_subscriber.clone(), reg.clone());
                reg
            })
            .collect();

        let semaphore = Arc::new(Semaphore::new(concurrency));
        let success_count = Arc::new(AtomicU64::new(0));
        let payload_bytes = build_bench_payload(256);
        let mut handles = Vec::new();

        let mut rng = OsRng;
        for i in 0..total {
            let permit = semaphore.clone().acquire_owned().await?;
            // Random entry and exit for entropy measurement -- the GPA cannot
            // exploit deterministic route structure; it must rely on timing.
            let entry_idx = rng.gen_range(0..nodes.len());
            let exit_idx = rng.gen_range(0..nodes.len());

            let entry_pub = nodes[entry_idx].bus_publisher.clone();
            let exit_reg = registries[exit_idx].clone();
            let path = build_random_path(&nodes, entry_idx, exit_idx, hops);
            let packet_bytes = build_multi_hop_packet(&path, &payload_bytes, 0)?;
            let pkt_size = packet_bytes.len();

            let e2e_map = exit_to_entries.clone();
            let succ = success_count.clone();
            let is_warmup = i < warmup;
            let pkt_id = format!("ent_{delay}_{i}");

            handles.push(tokio::spawn(async move {
                let (tx, rx) = oneshot::channel();
                exit_reg.lock().insert(pkt_id.clone(), tx);

                let _ = entry_pub.publish(NoxEvent::PacketReceived {
                    packet_id: pkt_id.clone(),
                    data: packet_bytes,
                    size_bytes: pkt_size,
                });

                let result = tokio::time::timeout(Duration::from_secs(30), rx).await;
                if let Ok(Ok(())) = result {
                    succ.fetch_add(1, Ordering::Relaxed);
                    if !is_warmup {
                        e2e_map.lock().entry(exit_idx).or_default().push(entry_idx);
                    }
                } else {
                    exit_reg.lock().remove(&pkt_id);
                }
                drop(permit);
            }));
        }

        for h in handles {
            let _ = h.await;
        }

        let success = success_count.load(Ordering::Relaxed);
        let map = exit_to_entries.lock().clone();

        // Compute per-exit-node entropy, then average
        let mut entropies = Vec::new();
        let mut min_entropies = Vec::new();
        let sender_count = nodes_count;

        for entry_ids in map.values() {
            if entry_ids.is_empty() {
                continue;
            }
            // Build probability distribution over senders
            let mut counts = vec![0u64; sender_count];
            for &eid in entry_ids {
                if eid < sender_count {
                    counts[eid] += 1;
                }
            }
            let total_obs = entry_ids.len() as f64;
            let probs: Vec<f64> = counts.iter().map(|&c| c as f64 / total_obs).collect();
            entropies.push(shannon_entropy(&probs));
            min_entropies.push(min_entropy(&probs));
        }

        let avg_entropy = if entropies.is_empty() {
            0.0
        } else {
            entropies.iter().sum::<f64>() / entropies.len() as f64
        };
        let avg_min_entropy = if min_entropies.is_empty() {
            0.0
        } else {
            min_entropies.iter().sum::<f64>() / min_entropies.len() as f64
        };
        let max_entropy = (sender_count as f64).log2();
        let normalised = if max_entropy > 0.0 {
            avg_entropy / max_entropy
        } else {
            0.0
        };

        let point = EntropyPoint {
            mix_delay_ms: delay,
            shannon_entropy_bits: avg_entropy,
            max_entropy_bits: max_entropy,
            normalised_entropy: normalised,
            effective_anonymity_set: 2.0_f64.powf(avg_entropy),
            min_entropy_bits: avg_min_entropy,
            packet_count: success as usize,
            sender_count,
        };

        info!(
            "  delay={delay:.1}ms: H={:.3} bits (max={:.3}), normalised={:.3}, \
             2^H={:.1}, min-H={:.3}",
            point.shannon_entropy_bits,
            point.max_entropy_bits,
            point.normalised_entropy,
            point.effective_anonymity_set,
            point.min_entropy_bits,
        );

        entropy_points.push(point);
    }

    info!("=== ENTROPY SWEEP COMPLETE ===");

    Ok(BenchResult {
        benchmark: "entropy_vs_delay".into(),
        mode: "in_process".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "nodes": nodes_count,
            "packets_per_step": packets,
            "hops": hops,
            "concurrency": concurrency,
            "delays_ms": delays_ms,
        }),
        results: serde_json::json!({
            "entropy_points": entropy_points,
        }),
    })
}

/// Pure simulation: fragment data, apply FEC, randomly drop fragments, attempt decode.
fn run_fec_recovery(
    data_shards: usize,
    fec_ratio: f64,
    trials: usize,
    response_size: usize,
    loss_rates: &[f64],
) -> Result<BenchResult> {
    use nox_core::protocol::fec;
    use nox_core::{
        FecInfo, Fragment, Fragmenter, Reassembler, ReassemblerConfig, SURB_PAYLOAD_SIZE,
    };

    info!(
        "FEC recovery: D={data_shards}, ratio={fec_ratio}, {trials} trials/rate, \
         {} loss rates, {response_size} bytes",
        loss_rates.len()
    );

    let response_data: Vec<u8> = (0..response_size).map(|i| (i % 256) as u8).collect();
    let fragmenter = Fragmenter::new();
    let base_fragments = fragmenter.fragment(1, &response_data, SURB_PAYLOAD_SIZE)?;
    let d = base_fragments.len();
    let p = if d == 1 {
        1
    } else {
        (d as f64 * fec_ratio).ceil() as usize
    };

    info!("  Base fragmentation: D={d} data shards, P={p} parity shards");

    // Pre-compute FEC-encoded fragments once (same data for all trials)
    let raw_chunks: Vec<Vec<u8>> = base_fragments.iter().map(|f| f.data.clone()).collect();
    let (padded, _pad_size) = fec::pad_to_uniform(&raw_chunks)?;
    let parity_shards = fec::encode_parity_shards(&padded, p)?;
    let fec_info = FecInfo {
        data_shard_count: d as u32,
        original_data_len: response_data.len() as u64,
    };

    // Build all fragments (data + parity) as Fragment objects
    let total_frags = (d + p) as u32;
    let mut all_fragments: Vec<Fragment> = Vec::with_capacity(d + p);
    for (i, frag) in base_fragments.iter().enumerate() {
        let mut f = frag.clone();
        f.data.clone_from(&padded[i]);
        f.total_fragments = total_frags;
        f.fec = Some(fec_info.clone());
        all_fragments.push(f);
    }
    for (pi, parity_data) in parity_shards.into_iter().enumerate() {
        all_fragments.push(Fragment::new_with_fec(
            1,
            total_frags,
            (d + pi) as u32,
            parity_data,
            fec_info.clone(),
        )?);
    }

    let mut rng = rand::thread_rng();
    let mut results: Vec<FecRecoveryPoint> = Vec::with_capacity(loss_rates.len());

    // Also run without FEC for comparison
    let no_fec_fragments: Vec<Fragment> = base_fragments;

    for &loss_rate in loss_rates {
        // With FEC
        let mut fec_successes = 0usize;
        let mut fec_total_received = 0usize;

        for _ in 0..trials {
            let mut reassembler = Reassembler::new(ReassemblerConfig::default());
            let mut received = 0usize;
            let mut completed = false;
            for frag in &all_fragments {
                if rng.gen::<f64>() >= loss_rate {
                    if let Ok(Some(_)) = reassembler.add_fragment(frag.clone()) {
                        completed = true;
                    }
                    received += 1;
                }
            }
            fec_total_received += received;
            if completed {
                fec_successes += 1;
            }
        }

        let fec_point = FecRecoveryPoint {
            loss_rate,
            data_shards: d,
            parity_shards: p,
            delivery_rate: fec_successes as f64 / trials as f64,
            trials,
            mean_fragments_received: fec_total_received as f64 / trials as f64,
        };

        // Without FEC
        let mut no_fec_successes = 0usize;
        let mut no_fec_total_received = 0usize;

        for _ in 0..trials {
            let mut reassembler = Reassembler::new(ReassemblerConfig::default());
            let mut received = 0usize;
            let mut completed = false;
            for frag in &no_fec_fragments {
                if rng.gen::<f64>() >= loss_rate {
                    if let Ok(Some(_)) = reassembler.add_fragment(frag.clone()) {
                        completed = true;
                    }
                    received += 1;
                }
            }
            no_fec_total_received += received;
            if completed {
                no_fec_successes += 1;
            }
        }

        let no_fec_point = FecRecoveryPoint {
            loss_rate,
            data_shards: d,
            parity_shards: 0,
            delivery_rate: no_fec_successes as f64 / trials as f64,
            trials,
            mean_fragments_received: no_fec_total_received as f64 / trials as f64,
        };

        info!(
            "  loss={:.0}%: FEC delivery={:.1}% (recv {:.1}/{}) | no-FEC delivery={:.1}% (recv {:.1}/{})",
            loss_rate * 100.0,
            fec_point.delivery_rate * 100.0,
            fec_point.mean_fragments_received,
            d + p,
            no_fec_point.delivery_rate * 100.0,
            no_fec_point.mean_fragments_received,
            d,
        );

        results.push(fec_point);
        results.push(no_fec_point);
    }

    info!("=== FEC RECOVERY SWEEP COMPLETE ===");

    Ok(BenchResult {
        benchmark: "fec_recovery".into(),
        mode: "simulation".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "data_shards": d,
            "parity_shards": p,
            "fec_ratio": fec_ratio,
            "trials_per_rate": trials,
            "response_size": response_size,
            "loss_rates": loss_rates,
        }),
        results: serde_json::json!({
            "points": results,
        }),
    })
}

fn run_fec_ratio_sweep(
    explicit_data_shards: usize,
    ratios: &[f64],
    loss_rates: &[f64],
    trials: usize,
    response_size: usize,
    target_delivery: f64,
) -> Result<BenchResult> {
    use nox_core::protocol::fec;
    use nox_core::{
        FecInfo, Fragment, Fragmenter, Reassembler, ReassemblerConfig, SURB_PAYLOAD_SIZE,
    };

    info!(
        "FEC ratio sweep: {} ratios × {} loss rates × {trials} trials, {response_size} bytes",
        ratios.len(),
        loss_rates.len()
    );

    // Fragment the response data to determine the natural data shard count.
    let response_data: Vec<u8> = (0..response_size).map(|i| (i % 256) as u8).collect();
    let fragmenter = Fragmenter::new();
    let base_fragments = fragmenter.fragment(1, &response_data, SURB_PAYLOAD_SIZE)?;
    let d = if explicit_data_shards > 0 {
        explicit_data_shards
    } else {
        base_fragments.len()
    };

    info!("  Data shards D={d} (from {response_size} bytes at {SURB_PAYLOAD_SIZE} bytes/shard)");

    let mut all_points: Vec<FecRatioPoint> = Vec::with_capacity(ratios.len() * loss_rates.len());
    let mut optimal_ratios: Vec<FecOptimalRatio> = Vec::with_capacity(loss_rates.len());
    let mut rng = rand::thread_rng();

    for &loss_rate in loss_rates {
        let mut best_ratio: Option<f64> = None;
        let mut best_parity: Option<usize> = None;

        for &ratio in ratios {
            let p = if d == 1 {
                1
            } else {
                (d as f64 * ratio).ceil() as usize
            };

            // Build FEC-encoded fragments for this ratio.
            let raw_chunks: Vec<Vec<u8>> = base_fragments.iter().map(|f| f.data.clone()).collect();
            let (padded, _pad_size) = fec::pad_to_uniform(&raw_chunks)?;
            let parity_shards = fec::encode_parity_shards(&padded, p)?;
            let fec_info = FecInfo {
                data_shard_count: d as u32,
                original_data_len: response_data.len() as u64,
            };

            let total_frags = (d + p) as u32;
            let mut all_fragments: Vec<Fragment> = Vec::with_capacity(d + p);
            for (i, frag) in base_fragments.iter().enumerate() {
                let mut f = frag.clone();
                f.data.clone_from(&padded[i]);
                f.total_fragments = total_frags;
                f.fec = Some(fec_info.clone());
                all_fragments.push(f);
            }
            for (pi, parity_data) in parity_shards.into_iter().enumerate() {
                all_fragments.push(Fragment::new_with_fec(
                    1,
                    total_frags,
                    (d + pi) as u32,
                    parity_data,
                    fec_info.clone(),
                )?);
            }

            // Run trials
            let mut successes = 0usize;
            for _ in 0..trials {
                let mut reassembler = Reassembler::new(ReassemblerConfig::default());
                let mut completed = false;
                for frag in &all_fragments {
                    if rng.gen::<f64>() >= loss_rate {
                        if let Ok(Some(_)) = reassembler.add_fragment(frag.clone()) {
                            completed = true;
                        }
                    }
                }
                if completed {
                    successes += 1;
                }
            }

            let delivery_rate = successes as f64 / trials as f64;
            let bandwidth_overhead = (d + p) as f64 / d as f64;

            all_points.push(FecRatioPoint {
                fec_ratio: ratio,
                loss_rate,
                data_shards: d,
                parity_shards: p,
                delivery_rate,
                bandwidth_overhead,
                trials,
            });

            info!(
                "  loss={:.0}% ratio={:.1}: P={p} delivery={:.2}% overhead={:.2}x",
                loss_rate * 100.0,
                ratio,
                delivery_rate * 100.0,
                bandwidth_overhead,
            );

            // Track optimal: first ratio that achieves ≥ target delivery
            if delivery_rate >= target_delivery && best_ratio.is_none() {
                best_ratio = Some(ratio);
                best_parity = Some(p);
            }
        }

        optimal_ratios.push(FecOptimalRatio {
            loss_rate,
            target_delivery,
            min_ratio: best_ratio,
            min_parity_shards: best_parity,
        });

        if let Some(r) = best_ratio {
            info!(
                "  -> Optimal at loss={:.0}%: ratio={r:.1} (P={}) for ≥{:.1}% delivery",
                loss_rate * 100.0,
                best_parity.unwrap_or(0),
                target_delivery * 100.0,
            );
        } else {
            info!(
                "  -> No ratio achieved ≥{:.1}% delivery at loss={:.0}%",
                target_delivery * 100.0,
                loss_rate * 100.0,
            );
        }
    }

    info!("=== FEC RATIO SWEEP COMPLETE ===");

    Ok(BenchResult {
        benchmark: "fec_ratio_sweep".into(),
        mode: "simulation".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "data_shards": d,
            "ratios": ratios,
            "loss_rates": loss_rates,
            "trials_per_pair": trials,
            "response_size": response_size,
            "target_delivery": target_delivery,
        }),
        results: serde_json::json!({
            "points": all_points,
            "optimal_ratios": optimal_ratios,
        }),
    })
}

async fn run_cover_traffic(
    nodes_count: usize,
    real_packets: usize,
    hops: usize,
    duration_secs: u64,
    settle_secs: u64,
    bus_capacity: usize,
    cover_rates: &[f64],
) -> Result<BenchResult> {
    use nox_node::services::traffic_shaping::TrafficShapingService;
    use tokio_util::sync::CancellationToken;

    info!(
        "Cover traffic analysis: {} rates, {} nodes, {} real packets, {}s per step",
        cover_rates.len(),
        nodes_count,
        real_packets,
        duration_secs,
    );

    let mut results: Vec<CoverTrafficPoint> = Vec::with_capacity(cover_rates.len());

    for &cover_rate in cover_rates {
        info!("--- Cover rate: {cover_rate} pkt/s ---");

        // Build mesh with cover traffic DISABLED (we manage it ourselves).
        let nodes = build_mesh(nodes_count, 1.0, settle_secs, bus_capacity).await?;

        // Per-node packet counters: track SendPacket events on each node's bus.
        let node_send_counts: Vec<Arc<AtomicU64>> = (0..nodes.len())
            .map(|_| Arc::new(AtomicU64::new(0)))
            .collect();

        // Per-node completion registries for real packet delivery tracking.
        let registries: Vec<CompletionRegistry> = (0..nodes.len())
            .map(|_| Arc::new(parking_lot::Mutex::new(HashMap::new())))
            .collect();
        for (i, node) in nodes.iter().enumerate() {
            spawn_completion_watcher(node.bus_subscriber.clone(), registries[i].clone());
        }

        // Spawn per-node packet counters that watch the event bus.
        let cancel_token = CancellationToken::new();
        for (i, node) in nodes.iter().enumerate() {
            let counter = node_send_counts[i].clone();
            let subscriber = node.bus_subscriber.clone();
            let cancel = cancel_token.clone();
            tokio::spawn(async move {
                let mut rx = subscriber.subscribe();
                loop {
                    tokio::select! {
                        () = cancel.cancelled() => break,
                        msg = rx.recv() => {
                            match msg {
                                Ok(NoxEvent::SendPacket { .. }) => {
                                    counter.fetch_add(1, Ordering::Relaxed);
                                }
                                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                            }
                        }
                    }
                }
            });
        }

        // If cover_rate > 0, spawn TrafficShapingService on each node.
        let mut cover_cancels: Vec<CancellationToken> = Vec::new();
        let mut cover_dirs: Vec<tempfile::TempDir> = Vec::new();
        if cover_rate > 0.0 {
            for node in &nodes {
                let mut config = NoxConfig::default();
                config.benchmark_mode = true;
                config.relayer.cover_traffic_rate = cover_rate;
                config.relayer.drop_traffic_rate = cover_rate;

                let cover_cancel = CancellationToken::new();
                cover_cancels.push(cover_cancel.clone());

                // Each TrafficShapingService gets its own TopologyManager with a fresh DB.
                let cover_dir = tempdir()?;
                let cover_db = Arc::new(SledRepository::new(cover_dir.path())?);
                let cover_bus = TokioEventBus::new(bus_capacity);
                let cover_pub: Arc<dyn IEventPublisher> = Arc::new(cover_bus.clone());
                let cover_sub: Arc<dyn IEventSubscriber> = Arc::new(cover_bus.clone());

                let topo = Arc::new(TopologyManager::new(cover_db, cover_sub.clone(), None));

                // Spawn topology manager FIRST so it subscribes to the bus before
                // we publish registrations (broadcast channel is not replayed).
                let topo_clone = topo.clone();
                tokio::spawn(async move { topo_clone.run().await });

                // Yield to ensure the topology manager task starts and subscribes.
                tokio::task::yield_now().await;
                tokio::time::sleep(Duration::from_millis(50)).await;

                // Register all nodes with role=3 (Full). Topology manager assigns layers
                // via SHA256(address) % 3. Using hex addresses `0x{j:040x}` ensures
                // deterministic layer distribution across layers 0/1/2.
                for (j, target) in nodes.iter().enumerate() {
                    let _ = cover_pub.publish(NoxEvent::RelayerRegistered {
                        address: format!("0x{j:040x}"),
                        sphinx_key: hex::encode(target.public_key.as_bytes()),
                        url: target.multiaddr.clone(),
                        stake: "1000".to_string(),
                        role: 3,
                        ingress_url: None,
                        metadata_url: None,
                    });
                }

                // Wait for topology to process all registrations.
                tokio::time::sleep(Duration::from_millis(200)).await;

                let metrics = MetricsService::new();
                let ts =
                    TrafficShapingService::new(config, topo, node.bus_publisher.clone(), metrics)
                        .with_cancel_token(cover_cancel.clone());

                tokio::spawn(async move {
                    ts.run().await;
                });

                cover_dirs.push(cover_dir);
            }

            // Let cover traffic ramp up
            tokio::time::sleep(Duration::from_secs(2)).await;
        }

        // Reset counters after ramp-up
        for counter in &node_send_counts {
            counter.store(0, Ordering::Relaxed);
        }

        let measurement_start = Instant::now();

        // Inject real packets
        let semaphore = Arc::new(Semaphore::new(50));
        let real_success = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();

        for i in 0..real_packets {
            let permit = semaphore.clone().acquire_owned().await?;
            let n = nodes.len();
            let entry_idx = i % n;
            let real_exit_idx = (i + hops - 1) % n;

            let path = build_path(&nodes, i, hops);
            let payload_bytes = build_bench_payload(32);

            let packet_bytes = nox_crypto::build_multi_hop_packet(&path, &payload_bytes, 0)?;

            let publisher = nodes[entry_idx].bus_publisher.clone();
            let exit_reg = registries[real_exit_idx].clone();
            let succ = real_success.clone();

            handles.push(tokio::spawn(async move {
                let packet_id = format!("cover-bench-{i:06}");
                let (tx, rx) = oneshot::channel();
                exit_reg.lock().insert(packet_id.clone(), tx);

                let _ = publisher.publish(NoxEvent::PacketReceived {
                    packet_id: packet_id.clone(),
                    data: packet_bytes,
                    size_bytes: 0,
                });

                match tokio::time::timeout(Duration::from_secs(30), rx).await {
                    Ok(Ok(())) => {
                        succ.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        // Timeout or error -- clean up
                        exit_reg.lock().remove(&packet_id);
                    }
                }

                drop(permit);
            }));

            // Space out real packets to simulate realistic traffic
            if real_packets > 1 {
                let interval = Duration::from_secs(duration_secs) / real_packets as u32;
                tokio::time::sleep(interval.min(Duration::from_millis(50))).await;
            }
        }

        // Wait for remaining duration
        let elapsed_so_far = measurement_start.elapsed();
        let total_duration = Duration::from_secs(duration_secs);
        if let Some(remaining) = total_duration.checked_sub(elapsed_so_far) {
            tokio::time::sleep(remaining).await;
        }

        // Wait for all real packet tasks
        for h in handles {
            let _ = h.await;
        }

        let measurement_duration = measurement_start.elapsed();

        // Cancel cover traffic
        for cancel in &cover_cancels {
            cancel.cancel();
        }
        cancel_token.cancel();
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Collect results
        let total_send_packets: u64 = node_send_counts
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum();
        let real_delivered = real_success.load(Ordering::Relaxed) as usize;

        // Per-node traffic entropy: Shannon entropy over per-node send counts.
        let per_node_counts: Vec<f64> = node_send_counts
            .iter()
            .map(|c| c.load(Ordering::Relaxed) as f64)
            .collect();
        let total_f64: f64 = per_node_counts.iter().sum();
        let traffic_entropy = if total_f64 > 0.0 {
            let mut h = 0.0_f64;
            for &count in &per_node_counts {
                if count > 0.0 {
                    let p = count / total_f64;
                    h -= p * p.log2();
                }
            }
            h
        } else {
            0.0
        };
        let max_entropy = (nodes_count as f64).log2();
        let normalised = if max_entropy > 0.0 {
            traffic_entropy / max_entropy
        } else {
            0.0
        };

        // Cover packets = total sends across all nodes minus real forwarding.
        // Each real 3-hop packet generates (hops - 1) SendPacket events:
        // entry -> forward (SendPacket), mid -> forward (SendPacket), exit -> decrypt (PayloadDecrypted).
        let forwards_per_real = (hops as u64).saturating_sub(1).max(1);
        let estimated_real_sends = real_delivered as u64 * forwards_per_real;
        let cover_packets = total_send_packets.saturating_sub(estimated_real_sends) as usize;
        let bandwidth_overhead = if estimated_real_sends > 0 {
            total_send_packets as f64 / estimated_real_sends as f64
        } else if total_send_packets > 0 {
            f64::INFINITY
        } else {
            1.0
        };

        let real_rate = real_delivered as f64 / measurement_duration.as_secs_f64();

        info!(
            "  cover_rate={cover_rate}: total_sends={total_send_packets}, real_delivered={real_delivered}, \
             cover~={cover_packets}, overhead={bandwidth_overhead:.2}x, \
             entropy={traffic_entropy:.3} bits ({normalised:.2} normalised)",
        );

        results.push(CoverTrafficPoint {
            cover_rate_pps: cover_rate,
            real_rate_pps: real_rate,
            total_packets: total_send_packets as usize,
            real_packets: real_delivered,
            cover_packets,
            bandwidth_overhead,
            traffic_entropy_bits: traffic_entropy,
            normalised_entropy: normalised,
            duration_secs: measurement_duration.as_secs_f64(),
        });
    }

    info!("=== COVER TRAFFIC ANALYSIS COMPLETE ===");

    Ok(BenchResult {
        benchmark: "cover_traffic".into(),
        mode: "in_process".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "node_count": nodes_count,
            "real_packets": real_packets,
            "hops": hops,
            "duration_secs": duration_secs,
            "cover_rates": cover_rates,
        }),
        results: serde_json::json!({
            "points": results,
        }),
    })
}

async fn run_unlinkability(
    nodes_count: usize,
    packets: usize,
    hops: usize,
    concurrency: usize,
    settle_secs: u64,
    bus_capacity: usize,
    delays_ms: &[f64],
) -> Result<BenchResult> {
    info!(
        "Unlinkability test: {} delays, {} nodes, {} packets/step",
        delays_ms.len(),
        nodes_count,
        packets
    );

    let mut results: Vec<UnlinkabilityResult> = Vec::with_capacity(delays_ms.len());

    for &delay in delays_ms {
        info!("--- Unlinkability at {delay}ms delay ---");
        let nodes = build_mesh(nodes_count, delay, settle_secs, bus_capacity).await?;
        let warmup = (packets / 10).max(10);
        let total = warmup + packets;

        // GPA model: record the time offset between when a packet enters the network
        // and when it exits. Under perfect mixing, this offset should appear uniformly
        // distributed within a window (not correlated with input order).
        //
        // Test: are output times (relative to the batch start) uniformly distributed?
        let epoch = Instant::now();
        let output_times: Arc<parking_lot::Mutex<Vec<f64>>> =
            Arc::new(parking_lot::Mutex::new(Vec::with_capacity(packets)));

        let registries: Vec<CompletionRegistry> = nodes
            .iter()
            .map(|node| {
                let reg: CompletionRegistry = Arc::new(parking_lot::Mutex::new(HashMap::new()));
                spawn_completion_watcher(node.bus_subscriber.clone(), reg.clone());
                reg
            })
            .collect();

        let semaphore = Arc::new(Semaphore::new(concurrency));
        let success_count = Arc::new(AtomicU64::new(0));
        let payload_bytes = build_bench_payload(256);
        let mut handles = Vec::new();

        let send_start = Instant::now();
        for i in 0..total {
            let permit = semaphore.clone().acquire_owned().await?;
            let entry_idx = i % nodes.len();
            let exit_idx = (i + hops - 1) % nodes.len();

            let entry_pub = nodes[entry_idx].bus_publisher.clone();
            let exit_reg = registries[exit_idx].clone();
            let path = build_path(&nodes, i, hops);
            let packet_bytes = build_multi_hop_packet(&path, &payload_bytes, 0)?;
            let pkt_size = packet_bytes.len();

            let ot = output_times.clone();
            let succ = success_count.clone();
            let is_warmup = i < warmup;
            let pkt_id = format!("ul_{delay}_{i}");

            handles.push(tokio::spawn(async move {
                let (tx, rx) = oneshot::channel();
                exit_reg.lock().insert(pkt_id.clone(), tx);

                let _ = entry_pub.publish(NoxEvent::PacketReceived {
                    packet_id: pkt_id.clone(),
                    data: packet_bytes,
                    size_bytes: pkt_size,
                });

                let result = tokio::time::timeout(Duration::from_secs(30), rx).await;
                if let Ok(Ok(())) = result {
                    succ.fetch_add(1, Ordering::Relaxed);
                    if !is_warmup {
                        let out_us = epoch.elapsed().as_micros() as f64;
                        ot.lock().push(out_us);
                    }
                } else {
                    exit_reg.lock().remove(&pkt_id);
                }
                drop(permit);
            }));
        }

        for h in handles {
            let _ = h.await;
        }

        let duration = send_start.elapsed();
        let success = success_count.load(Ordering::Relaxed);
        let traffic_pps = success as f64 / duration.as_secs_f64();
        let mut ots = output_times.lock().clone();

        // KS test for uniformity of output times
        let (ks_d, ks_p) = ks_test_uniform(&mut ots);
        // Chi-squared test
        let chi_bins = (ots.len() as f64).sqrt().ceil() as usize;
        let (chi2, chi2_p) = chi_squared_uniform(&ots, chi_bins.max(10));

        let res = UnlinkabilityResult {
            mix_delay_ms: delay,
            traffic_pps,
            ks_statistic: ks_d,
            ks_p_value: ks_p,
            chi_squared_statistic: chi2,
            chi_squared_p_value: chi2_p,
            sample_count: ots.len(),
        };

        info!(
            "  delay={delay:.1}ms: KS D={:.4} (p={:.3}), chi2={:.1} (p={:.3}), pps={:.0}",
            res.ks_statistic,
            res.ks_p_value,
            res.chi_squared_statistic,
            res.chi_squared_p_value,
            res.traffic_pps
        );
        info!(
            "  Assessment: {}",
            if res.ks_p_value > 0.05 {
                "PASS -- cannot reject uniform output distribution"
            } else {
                "INFO -- output times not uniform (expected at low delay)"
            }
        );

        results.push(res);
    }

    info!("=== UNLINKABILITY TEST COMPLETE ===");

    Ok(BenchResult {
        benchmark: "unlinkability".into(),
        mode: "in_process".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "nodes": nodes_count,
            "packets_per_step": packets,
            "hops": hops,
            "concurrency": concurrency,
            "delays_ms": delays_ms,
        }),
        results: serde_json::json!({
            "points": results,
        }),
    })
}

async fn run_attack_sim(cfg: &AnalyticsConfig, rounds: usize) -> Result<BenchResult> {
    let nodes_count = cfg.nodes;
    let packets = cfg.packets;
    let hops = cfg.hops;
    let mix_delay_ms = cfg.mix_delay_ms;
    let concurrency = cfg.concurrency;

    info!(
        "Attack simulations: {} nodes, {} packets/round, {} rounds, {hops} hops, {mix_delay_ms}ms delay",
        nodes_count, packets, rounds
    );

    let mut attack_results: Vec<AttackResult> = Vec::new();

    // Baseline: measure entropy with no attack
    info!("--- Baseline (no attack) ---");
    let baseline_entropy = measure_sender_entropy(
        nodes_count,
        packets,
        hops,
        mix_delay_ms,
        concurrency,
        cfg.settle_secs,
        cfg.bus_capacity,
    )
    .await?;
    info!("  Baseline entropy: {baseline_entropy:.3} bits");

    // Attack 1: n-1 attack
    // The adversary controls all entry nodes except one. They flood the network with
    // their own known packets, then observe the exit. Any unknown output must come
    // from the target. We simulate by making all but 1 entry node use a tagged payload,
    // then checking if the target's packets can be identified.
    info!("--- Attack 1: n-1 attack ---");
    let mut n1_successes = 0usize;
    for round in 0..rounds {
        let nodes =
            build_mesh(nodes_count, mix_delay_ms, cfg.settle_secs, cfg.bus_capacity).await?;

        let registries: Vec<CompletionRegistry> = nodes
            .iter()
            .map(|node| {
                let reg: CompletionRegistry = Arc::new(parking_lot::Mutex::new(HashMap::new()));
                spawn_completion_watcher(node.bus_subscriber.clone(), reg.clone());
                reg
            })
            .collect();

        // Target is node 0. All other nodes are adversary-controlled.
        let target_entry = 0;

        // Track which packets at each exit came from the target
        let exit_observations: Arc<parking_lot::Mutex<Vec<(usize, bool)>>> =
            Arc::new(parking_lot::Mutex::new(Vec::new()));

        let semaphore = Arc::new(Semaphore::new(concurrency));
        let payload_bytes = build_bench_payload(256);
        let mut handles = Vec::new();

        for i in 0..packets {
            let permit = semaphore.clone().acquire_owned().await?;
            // Target sends 1 packet for every (nodes-1) adversary packets
            let is_target = (i % nodes_count) == 0;
            let entry_idx = if is_target {
                target_entry
            } else {
                (i % (nodes_count - 1)) + 1
            };
            // Pick an exit that's offset from the entry so the path has distinct hops
            let exit_idx = (entry_idx + hops - 1) % nodes.len();

            let entry_pub = nodes[entry_idx].bus_publisher.clone();
            let exit_reg = registries[exit_idx].clone();
            // Build path starting from entry_idx so Sphinx keys match the receiving node
            let path = build_path(&nodes, entry_idx, hops);
            let packet_bytes = build_multi_hop_packet(&path, &payload_bytes, 0)?;
            let pkt_size = packet_bytes.len();

            let obs = exit_observations.clone();
            let pkt_id = format!("n1_{round}_{i}");

            handles.push(tokio::spawn(async move {
                let (tx, rx) = oneshot::channel();
                exit_reg.lock().insert(pkt_id.clone(), tx);

                let _ = entry_pub.publish(NoxEvent::PacketReceived {
                    packet_id: pkt_id.clone(),
                    data: packet_bytes,
                    size_bytes: pkt_size,
                });

                // Short timeout -- most valid packets complete in <1s; corrupted ones fail immediately
                let result = tokio::time::timeout(Duration::from_secs(5), rx).await;
                if let Ok(Ok(())) = result {
                    obs.lock().push((exit_idx, is_target));
                } else {
                    exit_reg.lock().remove(&pkt_id);
                }
                drop(permit);
            }));
        }

        for h in handles {
            let _ = h.await;
        }

        // n-1 attack succeeds if the adversary can identify all target packets.
        // They know their own packets -> any "unknown" output is the target's.
        // Count: does the adversary correctly attribute all outputs?
        let obs = exit_observations.lock();
        let total_outputs = obs.len();
        let target_outputs = obs.iter().filter(|o| o.1).count();
        let adversary_outputs = total_outputs - target_outputs;
        // If the adversary sees exactly (packets - target_count) of their own packets,
        // they can deduce the rest are the target's.
        let expected_adversary = packets - (packets / nodes_count);
        // Success = adversary can account for all their packets (within 10% tolerance)
        let attribution_error = (adversary_outputs as f64 - expected_adversary as f64).abs()
            / (expected_adversary as f64).max(1.0);
        if attribution_error < 0.1 {
            n1_successes += 1;
        }
    }

    let n1_success_rate = n1_successes as f64 / rounds as f64;
    // Under n-1 attack, entropy collapses to 0 if successful (target identified)
    let n1_entropy = baseline_entropy * (1.0 - n1_success_rate);

    attack_results.push(AttackResult {
        attack_type: "n-1".into(),
        params: serde_json::json!({
            "target_node": 0,
            "adversary_nodes": nodes_count - 1,
            "rounds": rounds,
        }),
        entropy_under_attack: n1_entropy,
        baseline_entropy,
        entropy_reduction: 1.0 - (n1_entropy / baseline_entropy).min(1.0),
        success_probability: n1_success_rate,
        rounds,
    });

    info!(
        "  n-1 attack: success={:.1}%, entropy {baseline_entropy:.3} -> {n1_entropy:.3} bits",
        n1_success_rate * 100.0
    );

    // Attack 2: Intersection attack over epochs
    // Over multiple observation epochs, the adversary intersects the set of active senders.
    // The anonymity set shrinks as epochs increase.
    info!("--- Attack 2: Intersection attack ---");
    let epochs = [1, 2, 5, 10, 20];
    for &num_epochs in &epochs {
        // Simulate: in each epoch, a random subset of nodes are "active".
        // The target is always active. The adversary intersects active sets.
        let mut rng = rand::thread_rng();
        let mut cumulative_success = 0usize;

        for _ in 0..rounds {
            let mut intersection: Vec<bool> = vec![true; nodes_count];

            for _ in 0..num_epochs {
                // Each non-target node is active with probability 0.7
                let mut active = vec![false; nodes_count];
                active[0] = true; // Target is always active
                for slot in active.iter_mut().skip(1) {
                    *slot = rng.gen::<f64>() < 0.7;
                }
                // Intersect
                for (inter, &act) in intersection.iter_mut().zip(active.iter()) {
                    *inter = *inter && act;
                }
            }

            let remaining = intersection.iter().filter(|&&b| b).count();
            if remaining == 1 {
                cumulative_success += 1;
            }
        }

        let intersection_success = cumulative_success as f64 / rounds as f64;
        let remaining_set = nodes_count as f64 * (1.0 - intersection_success);
        let intersection_entropy = remaining_set.max(1.0).log2();

        attack_results.push(AttackResult {
            attack_type: "intersection".into(),
            params: serde_json::json!({
                "epochs": num_epochs,
                "activity_probability": 0.7,
                "rounds": rounds,
            }),
            entropy_under_attack: intersection_entropy,
            baseline_entropy,
            entropy_reduction: 1.0 - (intersection_entropy / baseline_entropy).min(1.0),
            success_probability: intersection_success,
            rounds,
        });

        info!(
            "  intersection (epochs={num_epochs}): success={:.1}%, entropy={intersection_entropy:.3}",
            intersection_success * 100.0
        );
    }

    // Attack 3: Compromised nodes
    // 1, 2, or 3 nodes out of N are adversary-controlled. They log all packet metadata.
    // Entropy loss depends on how many hops the adversary controls in each path.
    info!("--- Attack 3: Compromised nodes ---");
    let compromised_counts = [1, 2, 3];
    for &num_compromised in &compromised_counts {
        if num_compromised >= nodes_count {
            continue;
        }
        // Simulation: the adversary controls nodes 0..num_compromised.
        // For each packet path, compute probability that the adversary observes
        // BOTH entry and exit (full deanonymisation).
        let mut full_deanon_count = 0usize;
        let mut partial_obs_count = 0usize;
        let total_paths = rounds * packets;

        for r in 0..rounds {
            for i in 0..packets {
                let path_nodes: Vec<usize> = (0..hops)
                    .map(|h| (r * packets + i + h) % nodes_count)
                    .collect();
                let entry = path_nodes[0];
                let exit = path_nodes[hops - 1];
                let entry_compromised = entry < num_compromised;
                let exit_compromised = exit < num_compromised;
                let any_compromised = path_nodes.iter().any(|&n| n < num_compromised);

                if entry_compromised && exit_compromised {
                    full_deanon_count += 1;
                } else if any_compromised {
                    partial_obs_count += 1;
                }
            }
        }

        let full_deanon_rate = full_deanon_count as f64 / total_paths as f64;
        let partial_rate = partial_obs_count as f64 / total_paths as f64;
        // Entropy reduction: fraction of packets fully deanonymised
        let compromised_entropy = baseline_entropy * (1.0 - full_deanon_rate);

        attack_results.push(AttackResult {
            attack_type: "compromised_nodes".into(),
            params: serde_json::json!({
                "compromised_count": num_compromised,
                "total_nodes": nodes_count,
                "hops": hops,
                "partial_observation_rate": partial_rate,
            }),
            entropy_under_attack: compromised_entropy,
            baseline_entropy,
            entropy_reduction: full_deanon_rate,
            success_probability: full_deanon_rate,
            rounds,
        });

        info!(
            "  compromised={num_compromised}/{nodes_count}: full_deanon={:.1}%, partial={:.1}%, \
             entropy={compromised_entropy:.3}",
            full_deanon_rate * 100.0,
            partial_rate * 100.0,
        );
    }

    info!("=== ATTACK SIMULATIONS COMPLETE ===");

    Ok(BenchResult {
        benchmark: "attack_simulation".into(),
        mode: "in_process".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "nodes": nodes_count,
            "packets_per_round": packets,
            "hops": hops,
            "mix_delay_ms": mix_delay_ms,
            "rounds": rounds,
        }),
        results: serde_json::json!({
            "baseline_entropy": baseline_entropy,
            "attacks": attack_results,
        }),
    })
}

/// Helper: measure sender entropy for a given mesh configuration.
/// Returns average Shannon entropy across exit nodes.
async fn measure_sender_entropy(
    nodes_count: usize,
    packets: usize,
    hops: usize,
    mix_delay_ms: f64,
    concurrency: usize,
    settle_secs: u64,
    bus_capacity: usize,
) -> Result<f64> {
    let nodes = build_mesh(nodes_count, mix_delay_ms, settle_secs, bus_capacity).await?;

    let exit_to_entries: Arc<parking_lot::Mutex<HashMap<usize, Vec<usize>>>> =
        Arc::new(parking_lot::Mutex::new(HashMap::new()));

    let registries: Vec<CompletionRegistry> = nodes
        .iter()
        .map(|node| {
            let reg: CompletionRegistry = Arc::new(parking_lot::Mutex::new(HashMap::new()));
            spawn_completion_watcher(node.bus_subscriber.clone(), reg.clone());
            reg
        })
        .collect();

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let success_count = Arc::new(AtomicU64::new(0));
    let payload_bytes = build_bench_payload(256);
    let mut handles = Vec::new();

    let mut rng = OsRng;
    for i in 0..packets {
        let permit = semaphore.clone().acquire_owned().await?;
        // Random entry and exit for sender entropy -- same model as run_entropy
        let entry_idx = rng.gen_range(0..nodes.len());
        let exit_idx = rng.gen_range(0..nodes.len());

        let entry_pub = nodes[entry_idx].bus_publisher.clone();
        let exit_reg = registries[exit_idx].clone();
        let path = build_random_path(&nodes, entry_idx, exit_idx, hops);
        let packet_bytes = build_multi_hop_packet(&path, &payload_bytes, 0)?;
        let pkt_size = packet_bytes.len();

        let e2e_map = exit_to_entries.clone();
        let succ = success_count.clone();
        let pkt_id = format!("base_{i}");

        handles.push(tokio::spawn(async move {
            let (tx, rx) = oneshot::channel();
            exit_reg.lock().insert(pkt_id.clone(), tx);

            let _ = entry_pub.publish(NoxEvent::PacketReceived {
                packet_id: pkt_id.clone(),
                data: packet_bytes,
                size_bytes: pkt_size,
            });

            let result = tokio::time::timeout(Duration::from_secs(30), rx).await;
            if let Ok(Ok(())) = result {
                succ.fetch_add(1, Ordering::Relaxed);
                e2e_map.lock().entry(exit_idx).or_default().push(entry_idx);
            } else {
                exit_reg.lock().remove(&pkt_id);
            }
            drop(permit);
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let map = exit_to_entries.lock().clone();
    let mut entropies = Vec::new();

    for entry_ids in map.values() {
        if entry_ids.is_empty() {
            continue;
        }
        let mut counts = vec![0u64; nodes_count];
        for &eid in entry_ids {
            if eid < nodes_count {
                counts[eid] += 1;
            }
        }
        let total_obs = entry_ids.len() as f64;
        let probs: Vec<f64> = counts.iter().map(|&c| c as f64 / total_obs).collect();
        entropies.push(shannon_entropy(&probs));
    }

    if entropies.is_empty() {
        Ok(0.0)
    } else {
        Ok(entropies.iter().sum::<f64>() / entropies.len() as f64)
    }
}

async fn run_replay_detection(
    unique_tags: usize,
    replay_attempts: usize,
    bloom_capacity: usize,
    bloom_fp_rate: f64,
) -> Result<BenchResult> {
    use nox_node::infra::persistence::rotational_bloom::RotationalBloomFilter;

    info!(
        "Replay detection: {unique_tags} unique tags, {replay_attempts} replay attempts, \
         bloom capacity={bloom_capacity}, FP rate={bloom_fp_rate}"
    );

    let mut results: Vec<ReplayDetectionResult> = Vec::new();

    // Test 1: RotationalBloomFilter
    {
        let bloom =
            RotationalBloomFilter::new(bloom_capacity, bloom_fp_rate, Duration::from_secs(3600));
        let ttl = 3600_u64;

        // Phase 1: Insert unique tags and measure throughput
        let insert_start = Instant::now();
        let mut false_positives = 0usize;

        for i in 0..unique_tags {
            let tag = format!("replay_test_tag_{i:012}");
            match bloom.check_and_tag(tag.as_bytes(), ttl).await {
                Ok(true) => false_positives += 1, // fresh tag falsely reported as seen
                Ok(false) => {}                   // correctly identified as fresh
                Err(e) => error!("Bloom insert error: {e}"),
            }
        }
        let insert_elapsed = insert_start.elapsed();
        let insert_ops = unique_tags as f64 / insert_elapsed.as_secs_f64();

        // Phase 2: Re-insert same tags (replay detection)
        let check_start = Instant::now();
        let mut false_negatives = 0usize;

        for i in 0..replay_attempts {
            // Use tags from the already-inserted set
            let tag_idx = i % unique_tags;
            let tag = format!("replay_test_tag_{tag_idx:012}");
            match bloom.check_and_tag(tag.as_bytes(), ttl).await {
                Ok(true) => {}                     // correctly detected as replay
                Ok(false) => false_negatives += 1, // missed replay!
                Err(e) => error!("Bloom check error: {e}"),
            }
        }
        let check_elapsed = check_start.elapsed();
        let check_ops = replay_attempts as f64 / check_elapsed.as_secs_f64();

        let fp_rate = false_positives as f64 / unique_tags as f64;
        let fn_rate = false_negatives as f64 / replay_attempts as f64;

        info!("=== BLOOM FILTER RESULTS ===");
        info!("  False positives: {false_positives}/{unique_tags} (rate={fp_rate:.6})");
        info!("  False negatives: {false_negatives}/{replay_attempts} (rate={fn_rate:.6})");
        info!("  Insert throughput: {insert_ops:.0} ops/s");
        info!("  Check throughput: {check_ops:.0} ops/s");

        results.push(ReplayDetectionResult {
            implementation: "rotational_bloom".into(),
            unique_tags,
            replay_attempts,
            false_negatives,
            false_positives,
            false_positive_rate: fp_rate,
            false_negative_rate: fn_rate,
            insert_throughput_ops: insert_ops,
            check_throughput_ops: check_ops,
            capacity: bloom_capacity,
            configured_fp_rate: bloom_fp_rate,
        });
    }

    // Test 2: Sled-based replay protection
    {
        let db_dir = tempdir()?;
        let sled_db = SledRepository::new(db_dir.path())?;
        let ttl = 3600_u64;

        // Phase 1: Insert unique tags
        let insert_start = Instant::now();
        let mut false_positives = 0usize;

        for i in 0..unique_tags {
            let tag = format!("sled_replay_tag_{i:012}");
            match sled_db.check_and_tag(tag.as_bytes(), ttl).await {
                Ok(true) => false_positives += 1,
                Ok(false) => {}
                Err(e) => error!("Sled insert error: {e}"),
            }
        }
        let insert_elapsed = insert_start.elapsed();
        let insert_ops = unique_tags as f64 / insert_elapsed.as_secs_f64();

        // Phase 2: Re-insert (replay detection)
        let check_start = Instant::now();
        let mut false_negatives = 0usize;

        for i in 0..replay_attempts {
            let tag_idx = i % unique_tags;
            let tag = format!("sled_replay_tag_{tag_idx:012}");
            match sled_db.check_and_tag(tag.as_bytes(), ttl).await {
                Ok(true) => {}
                Ok(false) => false_negatives += 1,
                Err(e) => error!("Sled check error: {e}"),
            }
        }
        let check_elapsed = check_start.elapsed();
        let check_ops = replay_attempts as f64 / check_elapsed.as_secs_f64();

        let fp_rate = false_positives as f64 / unique_tags as f64;
        let fn_rate = false_negatives as f64 / replay_attempts as f64;

        info!("=== SLED RESULTS ===");
        info!("  False positives: {false_positives}/{unique_tags} (rate={fp_rate:.6})");
        info!("  False negatives: {false_negatives}/{replay_attempts} (rate={fn_rate:.6})");
        info!("  Insert throughput: {insert_ops:.0} ops/s");
        info!("  Check throughput: {check_ops:.0} ops/s");

        results.push(ReplayDetectionResult {
            implementation: "sled".into(),
            unique_tags,
            replay_attempts,
            false_negatives,
            false_positives,
            false_positive_rate: fp_rate,
            false_negative_rate: fn_rate,
            insert_throughput_ops: insert_ops,
            check_throughput_ops: check_ops,
            capacity: 0, // N/A for sled
            configured_fp_rate: 0.0,
        });
    }

    info!("=== REPLAY DETECTION COMPLETE ===");

    Ok(BenchResult {
        benchmark: "replay_detection".into(),
        mode: "simulation".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "unique_tags": unique_tags,
            "replay_attempts": replay_attempts,
            "bloom_capacity": bloom_capacity,
            "bloom_fp_rate": bloom_fp_rate,
        }),
        results: serde_json::json!({
            "implementations": results,
        }),
    })
}

fn run_pow_dos(difficulties: &[u32], trials: usize) -> Result<BenchResult> {
    use nox_crypto::{PowSolver, Sha256Pow};

    info!(
        "PoW DoS mitigation: {} difficulties, {trials} trials each",
        difficulties.len()
    );

    let solver = PowSolver::new(Sha256Pow, 0); // 0 = use all cores
    let mut results: Vec<PowDosResult> = Vec::with_capacity(difficulties.len());

    for &difficulty in difficulties {
        info!("--- Difficulty d={difficulty} ---");

        // Phase 1: Measure solve times
        let mut solve_times_us: Vec<u64> = Vec::with_capacity(trials);
        let header_data = b"benchmark_header_data_for_pow_testing_1234567890";

        for trial in 0..trials {
            // Vary the header per trial so each solve is fresh
            let trial_header = format!("{}{trial}", String::from_utf8_lossy(header_data));
            let start = Instant::now();
            let _nonce = solver
                .solve(trial_header.as_bytes(), difficulty, 0)
                .map_err(|e| anyhow::anyhow!("PoW solve failed: {e:?}"))?;
            let elapsed_us = start.elapsed().as_micros() as u64;
            solve_times_us.push(elapsed_us);
        }

        // Phase 2: Measure verify times
        let mut verify_times_ns: Vec<u64> = Vec::with_capacity(trials);
        // Pre-solve a batch of nonces for verification
        let verify_header = b"verify_header_data";
        let nonce = solver
            .solve(verify_header, difficulty, 0)
            .map_err(|e| anyhow::anyhow!("PoW solve failed: {e:?}"))?;

        for _ in 0..trials {
            let start = Instant::now();
            let _valid = solver.verify(verify_header, nonce, difficulty);
            let elapsed_ns = start.elapsed().as_nanos() as u64;
            verify_times_ns.push(elapsed_ns);
        }

        // Compute statistics
        solve_times_us.sort_unstable();
        verify_times_ns.sort_unstable();

        let mean_solve = solve_times_us.iter().sum::<u64>() as f64 / trials as f64;
        let p50_solve = solve_times_us[trials / 2] as f64;
        let p99_solve = solve_times_us[(trials as f64 * 0.99) as usize] as f64;
        let mean_verify = verify_times_ns.iter().sum::<u64>() as f64 / trials as f64;
        let solve_throughput = 1_000_000.0 / mean_solve; // solves per second
        let verify_throughput = 1_000_000_000.0 / mean_verify; // verifies per second
        let asymmetry = (mean_solve * 1000.0) / mean_verify; // solve(us->ns) / verify(ns)

        info!(
            "  d={difficulty}: solve p50={p50_solve:.0}us p99={p99_solve:.0}us, \
             verify={mean_verify:.0}ns, asymmetry={asymmetry:.0}x"
        );

        results.push(PowDosResult {
            difficulty,
            algorithm: "SHA-256".into(),
            mean_solve_us: mean_solve,
            p50_solve_us: p50_solve,
            p99_solve_us: p99_solve,
            mean_verify_ns: mean_verify,
            solve_throughput,
            verify_throughput,
            asymmetry_ratio: asymmetry,
            trials,
        });
    }

    info!("=== POW DOS MITIGATION COMPLETE ===");

    Ok(BenchResult {
        benchmark: "pow_dos_mitigation".into(),
        mode: "simulation".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "difficulties": difficulties,
            "trials": trials,
            "algorithm": "SHA-256",
        }),
        results: serde_json::json!({
            "points": results,
        }),
    })
}

async fn run_entropy_vs_users(cfg: &AnalyticsConfig, user_counts: &[usize]) -> Result<BenchResult> {
    let nodes_count = cfg.nodes;
    let packets = cfg.packets;
    let hops = cfg.hops;
    let mix_delay_ms = cfg.mix_delay_ms;
    let concurrency = cfg.concurrency;
    let settle_secs = cfg.settle_secs;
    let bus_capacity = cfg.bus_capacity;

    info!(
        "Entropy vs concurrent users: {} user counts, {} nodes, {} packets each",
        user_counts.len(),
        nodes_count,
        packets
    );

    let mut results: Vec<EntropyVsUsersPoint> = Vec::with_capacity(user_counts.len());

    for &num_users in user_counts {
        let actual_users = num_users.min(nodes_count);
        info!("--- {actual_users} concurrent users ---");

        let nodes = build_mesh(nodes_count, mix_delay_ms, settle_secs, bus_capacity).await?;

        // Only use first `actual_users` nodes as entry points (senders)
        let registries: Vec<CompletionRegistry> = nodes
            .iter()
            .map(|node| {
                let reg: CompletionRegistry = Arc::new(parking_lot::Mutex::new(HashMap::new()));
                spawn_completion_watcher(node.bus_subscriber.clone(), reg.clone());
                reg
            })
            .collect();

        // Track which entry node each packet at each exit came from
        let exit_to_entries: Arc<parking_lot::Mutex<HashMap<usize, Vec<usize>>>> =
            Arc::new(parking_lot::Mutex::new(HashMap::new()));

        let semaphore = Arc::new(Semaphore::new(concurrency));
        let success_count = Arc::new(AtomicU64::new(0));
        let fail_count = Arc::new(AtomicU64::new(0));
        let payload_bytes = build_bench_payload(256);
        let mut handles = Vec::new();

        let mut rng = OsRng;
        for i in 0..packets {
            let permit = semaphore.clone().acquire_owned().await?;
            // Restrict entry nodes to first `actual_users`, random exit
            let entry_idx = rng.gen_range(0..actual_users);
            let exit_idx = rng.gen_range(0..nodes.len());

            let entry_pub = nodes[entry_idx].bus_publisher.clone();
            let exit_reg = registries[exit_idx].clone();
            let path = build_random_path(&nodes, entry_idx, exit_idx, hops);
            let packet_bytes = build_multi_hop_packet(&path, &payload_bytes, 0)?;
            let pkt_size = packet_bytes.len();

            let e2e_map = exit_to_entries.clone();
            let succ = success_count.clone();
            let fail = fail_count.clone();
            let pkt_id = format!("evu_{num_users}_{i}");

            handles.push(tokio::spawn(async move {
                let (tx, rx) = oneshot::channel();
                exit_reg.lock().insert(pkt_id.clone(), tx);

                let _ = entry_pub.publish(NoxEvent::PacketReceived {
                    packet_id: pkt_id.clone(),
                    data: packet_bytes,
                    size_bytes: pkt_size,
                });

                let result = tokio::time::timeout(Duration::from_secs(30), rx).await;
                if let Ok(Ok(())) = result {
                    succ.fetch_add(1, Ordering::Relaxed);
                    e2e_map.lock().entry(exit_idx).or_default().push(entry_idx);
                } else {
                    exit_reg.lock().remove(&pkt_id);
                    fail.fetch_add(1, Ordering::Relaxed);
                }
                drop(permit);
            }));
        }

        for h in handles {
            let _ = h.await;
        }

        let success = success_count.load(Ordering::Relaxed);
        let failed = fail_count.load(Ordering::Relaxed);
        let delivery_rate = success as f64 / packets as f64;

        // Compute sender entropy from GPA perspective
        let map = exit_to_entries.lock().clone();
        let mut entropies = Vec::new();

        for entry_ids in map.values() {
            if entry_ids.is_empty() {
                continue;
            }
            let mut counts = vec![0u64; nodes_count];
            for &eid in entry_ids {
                if eid < nodes_count {
                    counts[eid] += 1;
                }
            }
            let total_obs = entry_ids.len() as f64;
            let probs: Vec<f64> = counts.iter().map(|&c| c as f64 / total_obs).collect();
            entropies.push(shannon_entropy(&probs));
        }

        let avg_entropy = if entropies.is_empty() {
            0.0
        } else {
            entropies.iter().sum::<f64>() / entropies.len() as f64
        };
        let max_entropy = (actual_users as f64).log2();
        let normalised = if max_entropy > 0.0 {
            avg_entropy / max_entropy
        } else {
            0.0
        };
        let effective_set = 2.0_f64.powf(avg_entropy);

        info!(
            "  users={actual_users}: entropy={avg_entropy:.3} bits (max={max_entropy:.3}), \
             normalised={normalised:.3}, set={effective_set:.1}, delivery={delivery_rate:.3}, \
             success={success}, failed={failed}"
        );

        results.push(EntropyVsUsersPoint {
            concurrent_users: actual_users,
            shannon_entropy_bits: avg_entropy,
            max_entropy_bits: max_entropy,
            normalised_entropy: normalised,
            effective_anonymity_set: effective_set,
            delivery_rate,
        });
    }

    info!("=== ENTROPY VS USERS COMPLETE ===");

    Ok(BenchResult {
        benchmark: "entropy_vs_users".into(),
        mode: "in_process".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "nodes": nodes_count,
            "packets": packets,
            "hops": hops,
            "mix_delay_ms": mix_delay_ms,
            "user_counts": user_counts,
        }),
        results: serde_json::json!({
            "points": results,
        }),
    })
}

async fn run_entropy_vs_cover(
    nodes_count: usize,
    real_packets: usize,
    hops: usize,
    duration_secs: u64,
    settle_secs: u64,
    bus_capacity: usize,
    cover_ratios: &[f64],
) -> Result<BenchResult> {
    use nox_node::services::traffic_shaping::TrafficShapingService;
    use tokio_util::sync::CancellationToken;

    info!(
        "Entropy vs cover traffic ratio: {} ratios, {} nodes, {} real packets",
        cover_ratios.len(),
        nodes_count,
        real_packets,
    );

    let mut results: Vec<EntropyVsUsersPoint> = Vec::with_capacity(cover_ratios.len());

    for &cover_ratio in cover_ratios {
        info!("--- Cover ratio: {cover_ratio}:1 (cover:real) ---");

        let nodes = build_mesh(nodes_count, 1.0, settle_secs, bus_capacity).await?;

        // Track entry->exit mapping for entropy
        let exit_to_entries: Arc<parking_lot::Mutex<HashMap<usize, Vec<usize>>>> =
            Arc::new(parking_lot::Mutex::new(HashMap::new()));

        let registries: Vec<CompletionRegistry> = nodes
            .iter()
            .map(|node| {
                let reg: CompletionRegistry = Arc::new(parking_lot::Mutex::new(HashMap::new()));
                spawn_completion_watcher(node.bus_subscriber.clone(), reg.clone());
                reg
            })
            .collect();

        // Spawn cover traffic if ratio > 0
        let real_rate = real_packets as f64 / duration_secs as f64;
        let cover_rate_pps = real_rate * cover_ratio;

        let mut cover_cancels: Vec<CancellationToken> = Vec::new();
        #[allow(clippy::collection_is_never_read)]
        let mut cover_dirs: Vec<tempfile::TempDir> = Vec::new();

        if cover_rate_pps > 0.0 {
            for node in &nodes {
                let mut config = NoxConfig::default();
                config.benchmark_mode = true;
                config.relayer.cover_traffic_rate = cover_rate_pps / nodes.len() as f64;
                config.relayer.drop_traffic_rate = cover_rate_pps / nodes.len() as f64;

                let cover_cancel = CancellationToken::new();
                cover_cancels.push(cover_cancel.clone());

                let cover_dir = tempdir()?;
                let cover_db = Arc::new(SledRepository::new(cover_dir.path())?);
                let cover_bus = TokioEventBus::new(bus_capacity);
                let cover_pub: Arc<dyn IEventPublisher> = Arc::new(cover_bus.clone());
                let cover_sub: Arc<dyn IEventSubscriber> = Arc::new(cover_bus.clone());

                let topo = Arc::new(TopologyManager::new(cover_db, cover_sub.clone(), None));
                let topo_clone = topo.clone();
                tokio::spawn(async move { topo_clone.run().await });
                tokio::task::yield_now().await;
                tokio::time::sleep(Duration::from_millis(50)).await;

                for (j, target) in nodes.iter().enumerate() {
                    let _ = cover_pub.publish(NoxEvent::RelayerRegistered {
                        address: format!("0x{j:040x}"),
                        sphinx_key: hex::encode(target.public_key.as_bytes()),
                        url: target.multiaddr.clone(),
                        stake: "1000".to_string(),
                        role: 3,
                        ingress_url: None,
                        metadata_url: None,
                    });
                }

                tokio::time::sleep(Duration::from_millis(200)).await;

                let metrics = MetricsService::new();
                let ts =
                    TrafficShapingService::new(config, topo, node.bus_publisher.clone(), metrics)
                        .with_cancel_token(cover_cancel.clone());

                tokio::spawn(async move { ts.run().await });
                cover_dirs.push(cover_dir);
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }

        // Inject real packets from random entry nodes
        let semaphore = Arc::new(Semaphore::new(50));
        let success_count = Arc::new(AtomicU64::new(0));
        let payload_bytes = build_bench_payload(256);
        let mut handles = Vec::new();
        let mut rng = OsRng;

        for i in 0..real_packets {
            let permit = semaphore.clone().acquire_owned().await?;
            let entry_idx = rng.gen_range(0..nodes.len());
            let exit_idx = rng.gen_range(0..nodes.len());

            let entry_pub = nodes[entry_idx].bus_publisher.clone();
            let exit_reg = registries[exit_idx].clone();
            let path = build_random_path(&nodes, entry_idx, exit_idx, hops);
            let packet_bytes = build_multi_hop_packet(&path, &payload_bytes, 0)?;
            let pkt_size = packet_bytes.len();

            let e2e_map = exit_to_entries.clone();
            let succ = success_count.clone();
            let pkt_id = format!("evc_{cover_ratio}_{i}");

            handles.push(tokio::spawn(async move {
                let (tx, rx) = oneshot::channel();
                exit_reg.lock().insert(pkt_id.clone(), tx);

                let _ = entry_pub.publish(NoxEvent::PacketReceived {
                    packet_id: pkt_id.clone(),
                    data: packet_bytes,
                    size_bytes: pkt_size,
                });

                let result = tokio::time::timeout(Duration::from_secs(30), rx).await;
                if let Ok(Ok(())) = result {
                    succ.fetch_add(1, Ordering::Relaxed);
                    e2e_map.lock().entry(exit_idx).or_default().push(entry_idx);
                } else {
                    exit_reg.lock().remove(&pkt_id);
                }
                drop(permit);
            }));

            if real_packets > 1 {
                let interval = Duration::from_secs(duration_secs) / real_packets as u32;
                tokio::time::sleep(interval.min(Duration::from_millis(50))).await;
            }
        }

        for h in handles {
            let _ = h.await;
        }

        // Cancel cover traffic
        for cancel in &cover_cancels {
            cancel.cancel();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;

        let success = success_count.load(Ordering::Relaxed);
        let delivery_rate = success as f64 / real_packets as f64;

        // Compute sender entropy from GPA perspective
        let map = exit_to_entries.lock().clone();
        let mut entropies = Vec::new();

        for entry_ids in map.values() {
            if entry_ids.is_empty() {
                continue;
            }
            let mut counts = vec![0u64; nodes_count];
            for &eid in entry_ids {
                if eid < nodes_count {
                    counts[eid] += 1;
                }
            }
            let total_obs = entry_ids.len() as f64;
            let probs: Vec<f64> = counts.iter().map(|&c| c as f64 / total_obs).collect();
            entropies.push(shannon_entropy(&probs));
        }

        let avg_entropy = if entropies.is_empty() {
            0.0
        } else {
            entropies.iter().sum::<f64>() / entropies.len() as f64
        };
        let max_entropy = (nodes_count as f64).log2();
        let normalised = if max_entropy > 0.0 {
            avg_entropy / max_entropy
        } else {
            0.0
        };
        let effective_set = 2.0_f64.powf(avg_entropy);

        info!(
            "  ratio={cover_ratio}: entropy={avg_entropy:.3} bits, normalised={normalised:.3}, \
             set={effective_set:.1}, delivery={delivery_rate:.3}"
        );

        // Re-use EntropyVsUsersPoint -- concurrent_users field stores the cover ratio * 10
        // as a proxy. Better: use the actual ratio as the index.
        results.push(EntropyVsUsersPoint {
            concurrent_users: nodes_count, // all nodes are potential senders
            shannon_entropy_bits: avg_entropy,
            max_entropy_bits: max_entropy,
            normalised_entropy: normalised,
            effective_anonymity_set: effective_set,
            delivery_rate,
        });
    }

    info!("=== ENTROPY VS COVER RATIO COMPLETE ===");

    Ok(BenchResult {
        benchmark: "entropy_vs_cover".into(),
        mode: "in_process".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "nodes": nodes_count,
            "real_packets": real_packets,
            "hops": hops,
            "duration_secs": duration_secs,
            "cover_ratios": cover_ratios,
        }),
        results: serde_json::json!({
            "points": results,
            "cover_ratios": cover_ratios,
        }),
    })
}

fn run_fec_vs_arq(
    _explicit_data_shards: usize,
    fec_ratio: f64,
    response_size: usize,
    arq_max_retries: usize,
    trials: usize,
    loss_rates: &[f64],
) -> Result<BenchResult> {
    use nox_core::protocol::fec;
    use nox_core::{
        FecInfo, Fragment, Fragmenter, Reassembler, ReassemblerConfig, SURB_PAYLOAD_SIZE,
    };

    info!(
        "FEC vs ARQ: ratio={fec_ratio}, {arq_max_retries} max retries, \
         {trials} trials, {} loss rates, {response_size} bytes",
        loss_rates.len()
    );

    let response_data: Vec<u8> = (0..response_size).map(|i| (i % 256) as u8).collect();
    let fragmenter = Fragmenter::new();
    let base_fragments = fragmenter.fragment(1, &response_data, SURB_PAYLOAD_SIZE)?;
    let d = base_fragments.len();
    let p = if d == 1 {
        1
    } else {
        (d as f64 * fec_ratio).ceil() as usize
    };

    info!("  Data shards D={d}, Parity shards P={p}");

    // Pre-compute FEC-encoded fragments
    let raw_chunks: Vec<Vec<u8>> = base_fragments.iter().map(|f| f.data.clone()).collect();
    let (padded, _) = fec::pad_to_uniform(&raw_chunks)?;
    let parity_shards = fec::encode_parity_shards(&padded, p)?;
    let fec_info = FecInfo {
        data_shard_count: d as u32,
        original_data_len: response_data.len() as u64,
    };

    let total_frags = (d + p) as u32;
    let mut fec_fragments: Vec<Fragment> = Vec::with_capacity(d + p);
    for (i, frag) in base_fragments.iter().enumerate() {
        let mut f = frag.clone();
        f.data.clone_from(&padded[i]);
        f.total_fragments = total_frags;
        f.fec = Some(fec_info.clone());
        fec_fragments.push(f);
    }
    for (pi, parity_data) in parity_shards.into_iter().enumerate() {
        fec_fragments.push(Fragment::new_with_fec(
            1,
            total_frags,
            (d + pi) as u32,
            parity_data,
            fec_info.clone(),
        )?);
    }

    // ARQ uses only data fragments (no parity)
    let arq_fragments: Vec<Fragment> = base_fragments;

    let mut rng = rand::thread_rng();
    let mut results: Vec<FecVsArqPoint> = Vec::with_capacity(loss_rates.len());

    for &loss_rate in loss_rates {
        // FEC: one-shot delivery
        let mut fec_successes = 0usize;
        for _ in 0..trials {
            let mut reassembler = Reassembler::new(ReassemblerConfig::default());
            let mut completed = false;
            for frag in &fec_fragments {
                if rng.gen::<f64>() >= loss_rate {
                    if let Ok(Some(_)) = reassembler.add_fragment(frag.clone()) {
                        completed = true;
                    }
                }
            }
            if completed {
                fec_successes += 1;
            }
        }
        let fec_delivery = fec_successes as f64 / trials as f64;

        // ARQ: stop-and-wait with retransmission
        let mut arq_successes = 0usize;
        let mut arq_total_shards_sent = 0u64;
        let mut arq_total_rounds = 0u64;

        for _ in 0..trials {
            let mut received = vec![false; d];
            let mut total_sent = 0usize;
            let mut rounds = 0usize;

            for attempt in 0..=arq_max_retries {
                rounds = attempt + 1;
                // Send all missing fragments
                for (idx, _frag) in arq_fragments.iter().enumerate() {
                    if received[idx] {
                        continue; // Already received, skip
                    }
                    total_sent += 1;
                    if rng.gen::<f64>() >= loss_rate {
                        received[idx] = true;
                    }
                }
                // Check if all received
                if received.iter().all(|&r| r) {
                    arq_successes += 1;
                    break;
                }
            }
            arq_total_shards_sent += total_sent as u64;
            arq_total_rounds += rounds as u64;
        }

        let arq_delivery = arq_successes as f64 / trials as f64;
        let arq_mean_shards = arq_total_shards_sent as f64 / trials as f64;
        let arq_mean_rounds = arq_total_rounds as f64 / trials as f64;

        info!(
            "  loss={:.0}%: FEC delivery={:.2}% ({} shards), \
             ARQ delivery={:.2}% (mean {:.1} shards, {:.1} rounds)",
            loss_rate * 100.0,
            fec_delivery * 100.0,
            d + p,
            arq_delivery * 100.0,
            arq_mean_shards,
            arq_mean_rounds,
        );

        results.push(FecVsArqPoint {
            loss_rate,
            fec_delivery_rate: fec_delivery,
            fec_bandwidth_shards: d + p,
            fec_latency_multiplier: 1.0,
            arq_delivery_rate: arq_delivery,
            arq_mean_bandwidth_shards: arq_mean_shards,
            arq_mean_round_trips: arq_mean_rounds,
            arq_max_retries,
            data_shards: d,
            parity_shards: p,
            trials,
        });
    }

    info!("=== FEC VS ARQ COMPLETE ===");

    Ok(BenchResult {
        benchmark: "fec_vs_arq".into(),
        mode: "simulation".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "data_shards": d,
            "parity_shards": p,
            "fec_ratio": fec_ratio,
            "arq_max_retries": arq_max_retries,
            "response_size": response_size,
            "trials": trials,
        }),
        results: serde_json::json!({
            "points": results,
        }),
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_combined_anonymity(
    pool_sizes: &[usize],
    mixnet_sizes: &[usize],
    packets: usize,
    hops: usize,
    mix_delay_ms: f64,
    concurrency: usize,
    settle_secs: u64,
    bus_capacity: usize,
    tag_reuse_count: usize,
) -> Result<BenchResult> {
    info!(
        "Combined anonymity: {} pool sizes × {} mixnet sizes, {packets} pkts, {hops} hops, \
         {mix_delay_ms}ms delay, tag_reuse={tag_reuse_count}",
        pool_sizes.len(),
        mixnet_sizes.len(),
    );

    let mut results: Vec<CombinedAnonymityPoint> = Vec::new();

    for &mixnet_nodes in mixnet_sizes {
        // Measure mixnet entropy empirically for this node count
        info!("--- Mixnet: {mixnet_nodes} nodes ---");
        let h_mixnet = measure_sender_entropy(
            mixnet_nodes,
            packets,
            hops,
            mix_delay_ms,
            concurrency,
            settle_secs,
            bus_capacity,
        )
        .await?;

        let h_mixnet_max = (mixnet_nodes as f64).log2();
        let mixnet_normalised = if h_mixnet_max > 0.0 {
            h_mixnet / h_mixnet_max
        } else {
            0.0
        };

        info!(
            "  Mixnet entropy: {h_mixnet:.3} bits (max={h_mixnet_max:.3}, norm={mixnet_normalised:.3})"
        );

        // For each UTXO pool size, compute the three composition scenarios.
        for &pool_size in pool_sizes {
            // UTXO entropy is analytical: log2(pool_size)
            // This represents the sender being hidden among all notes in the Merkle tree.
            // The ZK proof reveals nothing about which leaf was consumed.
            let h_utxo = (pool_size as f64).log2();

            // Scenario 1: Independent composition (post-deposit operations)
            // The adversary needs to break BOTH layers. If they are independent,
            // the combined entropy is additive:
            //   H(Sender | O_chain, O_net) = H(Sender | O_chain) + H(Sender | O_net)
            // because O_chain reveals nothing about the network path, and O_net
            // reveals nothing about which UTXO was spent.
            let h_independent = h_utxo + h_mixnet;

            // Scenario 2: Correlated composition (deposit)
            // Deposits require msg.sender -- the depositor's Ethereum address is public.
            // This means A_utxo = 1 for the deposit note (the adversary knows exactly
            // which Merkle leaf belongs to this address). Only mixnet entropy remains.
            let h_correlated = h_mixnet;

            // Scenario 3: Partial composition (transfer with recipientP_x tag)
            // The indexed recipientP_x field creates a pseudonymous tag. If the same
            // recipient receives `tag_reuse_count` transfers using the same key component,
            // the adversary can cluster these, reducing the receiver's anonymity.
            // The UTXO pool anonymity is reduced by the clustering factor:
            //   H_partial = log2(pool_size / tag_reuse_count) + H_mixnet
            // In practice, Hisoka uses fresh per-tx keys, so tag_reuse_count ≈ 1-2.
            let effective_pool = (pool_size as f64 / tag_reuse_count as f64).max(1.0);
            let h_partial = effective_pool.log2() + h_mixnet;

            let point = CombinedAnonymityPoint {
                utxo_pool_size: pool_size,
                h_utxo_bits: h_utxo,
                mixnet_nodes,
                h_mixnet_bits: h_mixnet,
                h_mixnet_max_bits: h_mixnet_max,
                mixnet_normalised,
                h_combined_independent_bits: h_independent,
                h_combined_correlated_bits: h_correlated,
                h_combined_partial_bits: h_partial,
                effective_set_independent: 2.0_f64.powf(h_independent),
                effective_set_correlated: 2.0_f64.powf(h_correlated),
            };

            info!(
                "  pool={pool_size}: H_utxo={h_utxo:.1}, H_indep={h_independent:.1}, \
                 H_corr={h_correlated:.1}, H_partial={h_partial:.1} bits"
            );

            results.push(point);
        }
    }

    info!("=== COMBINED ANONYMITY ANALYSIS COMPLETE ===");

    Ok(BenchResult {
        benchmark: "combined_anonymity".into(),
        mode: "in_process".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "utxo_pool_sizes": pool_sizes,
            "mixnet_sizes": mixnet_sizes,
            "packets": packets,
            "hops": hops,
            "mix_delay_ms": mix_delay_ms,
            "concurrency": concurrency,
            "tag_reuse_count": tag_reuse_count,
        }),
        results: serde_json::json!({
            "points": results,
        }),
    })
}

async fn run_traffic_levels(
    nodes_count: usize,
    packets: usize,
    hops: usize,
    mix_delay_ms: f64,
    settle_secs: u64,
    bus_capacity: usize,
    traffic_rates: &[f64],
) -> Result<BenchResult> {
    info!(
        "Traffic levels: {} rates, {} nodes, {} packets/step, {hops} hops, {mix_delay_ms}ms delay",
        traffic_rates.len(),
        nodes_count,
        packets,
    );

    let mut results: Vec<TrafficLevelPoint> = Vec::with_capacity(traffic_rates.len());

    for &target_pps in traffic_rates {
        info!("--- Target rate: {target_pps} pkt/s ---");

        let nodes = build_mesh(nodes_count, mix_delay_ms, settle_secs, bus_capacity).await?;

        // Track entry->exit mapping for entropy measurement
        let exit_to_entries: Arc<parking_lot::Mutex<HashMap<usize, Vec<usize>>>> =
            Arc::new(parking_lot::Mutex::new(HashMap::new()));

        let registries: Vec<CompletionRegistry> = nodes
            .iter()
            .map(|node| {
                let reg: CompletionRegistry = Arc::new(parking_lot::Mutex::new(HashMap::new()));
                spawn_completion_watcher(node.bus_subscriber.clone(), reg.clone());
                reg
            })
            .collect();

        let success_count = Arc::new(AtomicU64::new(0));
        let fail_count = Arc::new(AtomicU64::new(0));
        let latency_sum = Arc::new(AtomicU64::new(0));
        let payload_bytes = build_bench_payload(256);

        // Compute inter-packet interval for the target rate.
        // Concurrency is unlimited -- we use the interval to control the injection rate.
        let interval_us = if target_pps > 0.0 {
            (1_000_000.0 / target_pps) as u64
        } else {
            0
        };

        let mut handles = Vec::new();
        let mut rng = OsRng;
        let send_epoch = Instant::now();

        for i in 0..packets {
            // Rate-limit: wait until it's time to send this packet
            if interval_us > 0 {
                let target_time = Duration::from_micros(interval_us * i as u64);
                let elapsed = send_epoch.elapsed();
                if let Some(wait) = target_time.checked_sub(elapsed) {
                    tokio::time::sleep(wait).await;
                }
            }

            // Random entry and exit for entropy measurement
            let entry_idx = rng.gen_range(0..nodes.len());
            let exit_idx = rng.gen_range(0..nodes.len());

            let entry_pub = nodes[entry_idx].bus_publisher.clone();
            let exit_reg = registries[exit_idx].clone();
            let path = build_random_path(&nodes, entry_idx, exit_idx, hops);
            let packet_bytes = build_multi_hop_packet(&path, &payload_bytes, 0)?;
            let pkt_size = packet_bytes.len();

            let e2e_map = exit_to_entries.clone();
            let succ = success_count.clone();
            let fail = fail_count.clone();
            let lat_sum = latency_sum.clone();
            let pkt_id = format!("tl_{target_pps}_{i}");

            handles.push(tokio::spawn(async move {
                let (tx, rx) = oneshot::channel();
                exit_reg.lock().insert(pkt_id.clone(), tx);

                let inject_time = Instant::now();
                let _ = entry_pub.publish(NoxEvent::PacketReceived {
                    packet_id: pkt_id.clone(),
                    data: packet_bytes,
                    size_bytes: pkt_size,
                });

                let result = tokio::time::timeout(Duration::from_secs(30), rx).await;
                if let Ok(Ok(())) = result {
                    let latency_us = inject_time.elapsed().as_micros() as u64;
                    succ.fetch_add(1, Ordering::Relaxed);
                    lat_sum.fetch_add(latency_us, Ordering::Relaxed);
                    e2e_map.lock().entry(exit_idx).or_default().push(entry_idx);
                } else {
                    exit_reg.lock().remove(&pkt_id);
                    fail.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }

        // Wait for all in-flight packets
        for h in handles {
            let _ = h.await;
        }

        let total_duration = send_epoch.elapsed();
        let success = success_count.load(Ordering::Relaxed);
        let failed = fail_count.load(Ordering::Relaxed);
        let total_latency = latency_sum.load(Ordering::Relaxed);
        let achieved_pps = success as f64 / total_duration.as_secs_f64();
        let delivery_rate = success as f64 / packets as f64;
        let mean_latency_us = if success > 0 {
            total_latency as f64 / success as f64
        } else {
            0.0
        };

        // Compute sender entropy from GPA perspective
        let map = exit_to_entries.lock().clone();
        let mut entropies = Vec::new();

        for entry_ids in map.values() {
            if entry_ids.is_empty() {
                continue;
            }
            let mut counts = vec![0u64; nodes_count];
            for &eid in entry_ids {
                if eid < nodes_count {
                    counts[eid] += 1;
                }
            }
            let total_obs = entry_ids.len() as f64;
            let probs: Vec<f64> = counts.iter().map(|&c| c as f64 / total_obs).collect();
            entropies.push(shannon_entropy(&probs));
        }

        let avg_entropy = if entropies.is_empty() {
            0.0
        } else {
            entropies.iter().sum::<f64>() / entropies.len() as f64
        };
        let max_entropy = (nodes_count as f64).log2();
        let normalised = if max_entropy > 0.0 {
            avg_entropy / max_entropy
        } else {
            0.0
        };
        let effective_set = 2.0_f64.powf(avg_entropy);

        info!(
            "  target={target_pps} pps: achieved={achieved_pps:.1} pps, entropy={avg_entropy:.3} bits, \
             normalised={normalised:.3}, delivery={delivery_rate:.3}, mean_lat={mean_latency_us:.0}us, \
             success={success}, failed={failed}"
        );

        results.push(TrafficLevelPoint {
            traffic_pps: target_pps,
            achieved_pps,
            shannon_entropy_bits: avg_entropy,
            max_entropy_bits: max_entropy,
            normalised_entropy: normalised,
            effective_anonymity_set: effective_set,
            delivery_rate,
            packet_count: success as usize,
            mean_latency_us,
        });
    }

    info!("=== TRAFFIC LEVELS COMPLETE ===");

    Ok(BenchResult {
        benchmark: "traffic_levels".into(),
        mode: "in_process".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "nodes": nodes_count,
            "packets_per_step": packets,
            "hops": hops,
            "mix_delay_ms": mix_delay_ms,
            "traffic_rates": traffic_rates,
        }),
        results: serde_json::json!({
            "points": results,
        }),
    })
}

async fn run_cover_analysis(
    nodes_count: usize,
    real_packets: usize,
    hops: usize,
    duration_secs: u64,
    settle_secs: u64,
    bus_capacity: usize,
    cover_rates: &[f64],
) -> Result<BenchResult> {
    use nox_node::services::traffic_shaping::TrafficShapingService;
    use tokio_util::sync::CancellationToken;

    info!(
        "Cover analysis (4.3.3-5): {} rates, {} nodes, {} real pkts, {}s/step",
        cover_rates.len(),
        nodes_count,
        real_packets,
        duration_secs,
    );

    let mut results: Vec<CoverAnalysisPoint> = Vec::with_capacity(cover_rates.len());

    for &cover_rate in cover_rates {
        info!("--- Cover rate: {cover_rate} pkt/s/node ---");

        // Snapshot RSS before mesh construction
        let rss_before = read_process_rss();

        // Build mesh with cover traffic disabled
        let nodes = build_mesh(nodes_count, 1.0, settle_secs, bus_capacity).await?;

        // Per-node packet timing collectors: record timestamps of SendPacket events.
        // Active nodes (those injecting real traffic) will have real+cover packets;
        // idle nodes will have only cover packets. The GPA wants to distinguish them.
        let node_timestamps: Vec<Arc<parking_lot::Mutex<Vec<u64>>>> = (0..nodes.len())
            .map(|_| Arc::new(parking_lot::Mutex::new(Vec::with_capacity(4096))))
            .collect();

        // Per-node packet counters for lambda measurement
        let node_send_counts: Vec<Arc<AtomicU64>> = (0..nodes.len())
            .map(|_| Arc::new(AtomicU64::new(0)))
            .collect();

        // Completion registries for real packet tracking
        let registries: Vec<CompletionRegistry> = (0..nodes.len())
            .map(|_| Arc::new(parking_lot::Mutex::new(HashMap::new())))
            .collect();
        for (i, node) in nodes.iter().enumerate() {
            spawn_completion_watcher(node.bus_subscriber.clone(), registries[i].clone());
        }

        // Spawn per-node event watchers
        let cancel_token = CancellationToken::new();
        let epoch = Instant::now();
        for (i, node) in nodes.iter().enumerate() {
            let counter = node_send_counts[i].clone();
            let timestamps = node_timestamps[i].clone();
            let subscriber = node.bus_subscriber.clone();
            let cancel = cancel_token.clone();
            tokio::spawn(async move {
                let mut rx = subscriber.subscribe();
                loop {
                    tokio::select! {
                        () = cancel.cancelled() => break,
                        msg = rx.recv() => {
                            match msg {
                                Ok(NoxEvent::SendPacket { .. }) => {
                                    counter.fetch_add(1, Ordering::Relaxed);
                                    timestamps.lock().push(epoch.elapsed().as_micros() as u64);
                                }
                                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                            }
                        }
                    }
                }
            });
        }

        // Spawn cover traffic if rate > 0
        let mut cover_cancels: Vec<CancellationToken> = Vec::new();
        let mut cover_dirs: Vec<tempfile::TempDir> = Vec::new();
        if cover_rate > 0.0 {
            for node in &nodes {
                let mut config = NoxConfig::default();
                config.benchmark_mode = true;
                config.relayer.cover_traffic_rate = cover_rate;
                config.relayer.drop_traffic_rate = cover_rate;

                let cover_cancel = CancellationToken::new();
                cover_cancels.push(cover_cancel.clone());

                let cover_dir = tempdir()?;
                let cover_db = Arc::new(SledRepository::new(cover_dir.path())?);
                let cover_bus = TokioEventBus::new(bus_capacity);
                let cover_pub: Arc<dyn IEventPublisher> = Arc::new(cover_bus.clone());
                let cover_sub: Arc<dyn IEventSubscriber> = Arc::new(cover_bus.clone());

                let topo = Arc::new(TopologyManager::new(cover_db, cover_sub.clone(), None));
                let topo_clone = topo.clone();
                tokio::spawn(async move { topo_clone.run().await });
                tokio::task::yield_now().await;
                tokio::time::sleep(Duration::from_millis(50)).await;

                for (j, target) in nodes.iter().enumerate() {
                    let _ = cover_pub.publish(NoxEvent::RelayerRegistered {
                        address: format!("0x{j:040x}"),
                        sphinx_key: hex::encode(target.public_key.as_bytes()),
                        url: target.multiaddr.clone(),
                        stake: "1000".to_string(),
                        role: 3,
                        ingress_url: None,
                        metadata_url: None,
                    });
                }

                tokio::time::sleep(Duration::from_millis(200)).await;

                let metrics = MetricsService::new();
                let ts =
                    TrafficShapingService::new(config, topo, node.bus_publisher.clone(), metrics)
                        .with_cancel_token(cover_cancel.clone());

                tokio::spawn(async move { ts.run().await });
                cover_dirs.push(cover_dir);
            }

            // Let cover traffic ramp up
            tokio::time::sleep(Duration::from_secs(2)).await;
        }

        // Reset counters and timestamps after ramp-up
        for counter in &node_send_counts {
            counter.store(0, Ordering::Relaxed);
        }
        for ts in &node_timestamps {
            ts.lock().clear();
        }

        // Snapshot CPU time at measurement start
        let cpu_before = read_process_cpu_time();
        let measurement_start = Instant::now();

        // Designate active nodes: first half will inject real traffic, second half is idle.
        let active_count = (nodes_count / 2).max(1);

        // Inject real packets from active nodes only
        let semaphore = Arc::new(Semaphore::new(50));
        let real_success = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();
        let mut rng = OsRng;

        for i in 0..real_packets {
            let permit = semaphore.clone().acquire_owned().await?;
            // Only inject from active nodes (first half)
            let entry_idx = rng.gen_range(0..active_count);
            let exit_idx = (entry_idx + hops - 1) % nodes.len();

            let path = build_path(&nodes, entry_idx, hops);
            let payload_bytes = build_bench_payload(32);
            let packet_bytes = nox_crypto::build_multi_hop_packet(&path, &payload_bytes, 0)?;

            let publisher = nodes[entry_idx].bus_publisher.clone();
            let exit_reg = registries[exit_idx].clone();
            let succ = real_success.clone();

            handles.push(tokio::spawn(async move {
                let packet_id = format!("ca-{i:06}");
                let (tx, rx) = oneshot::channel();
                exit_reg.lock().insert(packet_id.clone(), tx);

                let _ = publisher.publish(NoxEvent::PacketReceived {
                    packet_id: packet_id.clone(),
                    data: packet_bytes,
                    size_bytes: 0,
                });

                match tokio::time::timeout(Duration::from_secs(30), rx).await {
                    Ok(Ok(())) => {
                        succ.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        exit_reg.lock().remove(&packet_id);
                    }
                }
                drop(permit);
            }));

            // Space out real packets over the duration
            if real_packets > 1 {
                let interval = Duration::from_secs(duration_secs) / real_packets as u32;
                tokio::time::sleep(interval.min(Duration::from_millis(50))).await;
            }
        }

        // Wait for remaining duration
        let elapsed_so_far = measurement_start.elapsed();
        let total_duration = Duration::from_secs(duration_secs);
        if let Some(remaining) = total_duration.checked_sub(elapsed_so_far) {
            tokio::time::sleep(remaining).await;
        }

        // Wait for all real packet tasks
        for h in handles {
            let _ = h.await;
        }

        let measurement_duration = measurement_start.elapsed();
        let cpu_after = read_process_cpu_time();
        let rss_after = read_process_rss();

        // Cancel cover traffic
        for cancel in &cover_cancels {
            cancel.cancel();
        }
        cancel_token.cancel();
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Collect metrics

        let real_delivered = real_success.load(Ordering::Relaxed) as usize;

        // (4.3.3) Distinguishability: compare timing distributions of active vs idle nodes.
        // Active = nodes 0..active_count, Idle = nodes active_count..nodes_count
        let active_iats: Vec<f64> = {
            let mut all_iats = Vec::new();
            for ts_lock in node_timestamps.iter().take(active_count) {
                let ts = ts_lock.lock();
                if ts.len() > 1 {
                    for w in ts.windows(2) {
                        all_iats.push((w[1] - w[0]) as f64);
                    }
                }
            }
            all_iats
        };

        let idle_iats: Vec<f64> = {
            let mut all_iats = Vec::new();
            for ts_lock in node_timestamps
                .iter()
                .skip(active_count)
                .take(nodes_count - active_count)
            {
                let ts = ts_lock.lock();
                if ts.len() > 1 {
                    for w in ts.windows(2) {
                        all_iats.push((w[1] - w[0]) as f64);
                    }
                }
            }
            all_iats
        };

        // Two-sample KS test between active and idle inter-arrival time distributions
        let (ks_d, ks_p) = two_sample_ks_test(&active_iats, &idle_iats);
        // Chi-squared: bin both distributions and test if they differ
        let (chi2, chi2_p) = two_sample_chi_squared(&active_iats, &idle_iats, 20);

        // (4.3.4) Lambda measurement: observed rate per node
        let per_node_rates: Vec<f64> = node_send_counts
            .iter()
            .map(|c| c.load(Ordering::Relaxed) as f64 / measurement_duration.as_secs_f64())
            .collect();

        let observed_mean_rate = if per_node_rates.is_empty() {
            0.0
        } else {
            per_node_rates.iter().sum::<f64>() / per_node_rates.len() as f64
        };

        let rate_stddev = if per_node_rates.len() > 1 {
            let variance: f64 = per_node_rates
                .iter()
                .map(|&r| (r - observed_mean_rate).powi(2))
                .sum::<f64>()
                / (per_node_rates.len() - 1) as f64;
            variance.sqrt()
        } else {
            0.0
        };
        let rate_cv = if observed_mean_rate > 0.0 {
            rate_stddev / observed_mean_rate
        } else {
            0.0
        };

        // Configured total lambda per node: cover_rate (loop) + cover_rate (drop) + real forwarding
        let configured_lambda = cover_rate * 2.0; // loop + drop rates are both `cover_rate`

        let lambda_ratio = if configured_lambda > 0.0 {
            observed_mean_rate / configured_lambda
        } else if observed_mean_rate > 0.0 {
            f64::INFINITY
        } else {
            1.0
        };

        // (4.3.5) Cost analysis
        let cpu_delta = cpu_after.saturating_sub(cpu_before) as f64 / 1_000_000_000.0; // ns to s
        let rss_delta = rss_after.saturating_sub(rss_before);

        let total_sends: u64 = node_send_counts
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum();
        // Estimate ~32KB per Sphinx packet
        let bandwidth_bytes = total_sends * 32_768;

        let forwards_per_real = (hops as u64).saturating_sub(1).max(1);
        let estimated_real_sends = real_delivered as u64 * forwards_per_real;
        let bandwidth_overhead = if estimated_real_sends > 0 {
            total_sends as f64 / estimated_real_sends as f64
        } else if total_sends > 0 {
            f64::INFINITY
        } else {
            1.0
        };

        info!(
            "  rate={cover_rate}: KS D={ks_d:.4} (p={ks_p:.3}), chi2={chi2:.1} (p={chi2_p:.3}), \
             lambda_obs={observed_mean_rate:.2} lambda_cfg={configured_lambda:.2} ratio={lambda_ratio:.2}, \
             cv={rate_cv:.3}, cpu={cpu_delta:.2}s, rss_delta={rss_delta} bytes, bw={bandwidth_bytes}"
        );

        results.push(CoverAnalysisPoint {
            cover_rate_pps: cover_rate,
            ks_statistic: ks_d,
            ks_p_value: ks_p,
            chi_squared_statistic: chi2,
            chi_squared_p_value: chi2_p,
            configured_lambda,
            observed_lambda: observed_mean_rate,
            lambda_ratio,
            rate_cv,
            cpu_time_secs: cpu_delta,
            rss_delta_bytes: rss_delta,
            bandwidth_bytes,
            bandwidth_overhead,
            duration_secs: measurement_duration.as_secs_f64(),
        });
    }

    info!("=== COVER ANALYSIS COMPLETE ===");

    Ok(BenchResult {
        benchmark: "cover_analysis".into(),
        mode: "in_process".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "node_count": nodes_count,
            "real_packets": real_packets,
            "hops": hops,
            "duration_secs": duration_secs,
            "cover_rates": cover_rates,
            "active_nodes": (nodes_count / 2).max(1),
            "idle_nodes": nodes_count - (nodes_count / 2).max(1),
        }),
        results: serde_json::json!({
            "points": results,
        }),
    })
}

/// Two-sample Kolmogorov-Smirnov test.
/// Returns (D statistic, approximate p-value).
fn two_sample_ks_test(sample_a: &[f64], sample_b: &[f64]) -> (f64, f64) {
    if sample_a.is_empty() || sample_b.is_empty() {
        return (0.0, 1.0);
    }

    let mut a_sorted: Vec<f64> = sample_a.to_vec();
    let mut b_sorted: Vec<f64> = sample_b.to_vec();
    a_sorted.sort_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));
    b_sorted.sort_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));

    let n_a = a_sorted.len() as f64;
    let n_b = b_sorted.len() as f64;

    // Merge both sorted arrays and compute max ECDF difference
    let mut i = 0usize;
    let mut j = 0usize;
    let mut d_max = 0.0_f64;

    while i < a_sorted.len() && j < b_sorted.len() {
        let ecdf_a = (i + 1) as f64 / n_a;
        let ecdf_b = (j + 1) as f64 / n_b;

        if a_sorted[i] <= b_sorted[j] {
            d_max = d_max.max((ecdf_a - j as f64 / n_b).abs());
            i += 1;
        } else {
            d_max = d_max.max((i as f64 / n_a - ecdf_b).abs());
            j += 1;
        }
    }

    // Handle remaining elements
    while i < a_sorted.len() {
        let ecdf_a = (i + 1) as f64 / n_a;
        d_max = d_max.max((ecdf_a - 1.0).abs());
        i += 1;
    }
    while j < b_sorted.len() {
        let ecdf_b = (j + 1) as f64 / n_b;
        d_max = d_max.max((1.0 - ecdf_b).abs());
        j += 1;
    }

    // Approximate p-value using the asymptotic formula:
    // effective n = (n_a * n_b) / (n_a + n_b)
    // P(D > d) ≈ 2 * exp(-2 * n_eff * d^2)
    let n_eff = (n_a * n_b) / (n_a + n_b);
    let p_value = (2.0 * (-2.0 * n_eff * d_max * d_max).exp()).clamp(0.0, 1.0);

    (d_max, p_value)
}

/// Two-sample chi-squared test using binned data.
/// Returns (chi2 statistic, approximate p-value).
fn two_sample_chi_squared(sample_a: &[f64], sample_b: &[f64], num_bins: usize) -> (f64, f64) {
    if sample_a.is_empty() || sample_b.is_empty() || num_bins == 0 {
        return (0.0, 1.0);
    }

    // Find global range
    let all_min = sample_a
        .iter()
        .chain(sample_b.iter())
        .copied()
        .reduce(f64::min)
        .unwrap_or(0.0);
    let all_max = sample_a
        .iter()
        .chain(sample_b.iter())
        .copied()
        .reduce(f64::max)
        .unwrap_or(1.0);
    let range = (all_max - all_min).max(1e-15);

    let bin_fn = |v: f64| -> usize {
        ((v - all_min) / range * (num_bins as f64 - 1.0))
            .round()
            .max(0.0)
            .min((num_bins - 1) as f64) as usize
    };

    let mut bins_a = vec![0u64; num_bins];
    let mut bins_b = vec![0u64; num_bins];

    for &v in sample_a {
        bins_a[bin_fn(v)] += 1;
    }
    for &v in sample_b {
        bins_b[bin_fn(v)] += 1;
    }

    let n_a = sample_a.len() as f64;
    let n_b = sample_b.len() as f64;

    // Chi-squared for two samples: sum_i (bins_a[i]/n_a - bins_b[i]/n_b)^2 / ((bins_a[i]+bins_b[i])/(n_a+n_b))
    let mut chi2 = 0.0_f64;
    for k in 0..num_bins {
        let a = bins_a[k] as f64;
        let b = bins_b[k] as f64;
        let pooled = a + b;
        if pooled > 0.0 {
            let expected_a = pooled * n_a / (n_a + n_b);
            let expected_b = pooled * n_b / (n_a + n_b);
            if expected_a > 0.0 {
                chi2 += (a - expected_a).powi(2) / expected_a;
            }
            if expected_b > 0.0 {
                chi2 += (b - expected_b).powi(2) / expected_b;
            }
        }
    }

    // Degrees of freedom = num_bins - 1
    let df = (num_bins - 1) as f64;
    let p_value = if df > 0.0 {
        let z =
            ((chi2 / df).powf(1.0 / 3.0) - (1.0 - 2.0 / (9.0 * df))) / (2.0 / (9.0 * df)).sqrt();
        normal_cdf_complement(z)
    } else {
        1.0
    };

    (chi2, p_value.clamp(0.0, 1.0))
}

/// Read current process RSS from `/proc/self/statm`. Returns bytes.
fn read_process_rss() -> u64 {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map_or(0, |pages| pages * 4096)
}

/// Read cumulative CPU time (user + sys) from `/proc/self/stat`. Returns nanoseconds.
fn read_process_cpu_time() -> u64 {
    std::fs::read_to_string("/proc/self/stat")
        .ok()
        .and_then(|s| {
            // Fields: pid (comm) state ppid ... utime stime (fields 14 and 15, 1-indexed)
            // After the closing ')' of comm, split by whitespace
            let after_comm = s.split(')').nth(1)?;
            let fields: Vec<&str> = after_comm.split_whitespace().collect();
            // utime = field index 11 (0-indexed after ')'), stime = field index 12
            let utime: u64 = fields.get(11)?.parse().ok()?;
            let stime: u64 = fields.get(12)?.parse().ok()?;
            // Convert from clock ticks to nanoseconds (100 ticks/sec on most Linux)
            let ticks_per_sec = 100_u64; // sysconf(_SC_CLK_TCK) is usually 100
            Some((utime + stime) * 1_000_000_000 / ticks_per_sec)
        })
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let bus_capacity = cli.bus_capacity;

    let result = match cli.command {
        Command::TimingCorrelation {
            nodes,
            packets,
            hops,
            mix_delay_ms,
            concurrency,
            settle_secs,
            raw_pairs,
        } => {
            let cfg = AnalyticsConfig {
                nodes,
                packets,
                hops,
                mix_delay_ms,
                concurrency,
                settle_secs,
                bus_capacity,
            };
            run_timing_correlation(&cfg, raw_pairs).await?
        }

        Command::Entropy {
            nodes,
            packets,
            hops,
            concurrency,
            settle_secs,
            delays_ms,
        } => {
            let delays: Vec<f64> = delays_ms
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            run_entropy(
                nodes,
                packets,
                hops,
                concurrency,
                settle_secs,
                bus_capacity,
                &delays,
            )
            .await?
        }

        Command::FecRecovery {
            data_shards,
            fec_ratio,
            trials,
            response_size,
            loss_rates,
        } => {
            let rates: Vec<f64> = loss_rates
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            run_fec_recovery(data_shards, fec_ratio, trials, response_size, &rates)?
        }

        Command::Unlinkability {
            nodes,
            packets,
            hops,
            concurrency,
            settle_secs,
            delays_ms,
        } => {
            let delays: Vec<f64> = delays_ms
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            run_unlinkability(
                nodes,
                packets,
                hops,
                concurrency,
                settle_secs,
                bus_capacity,
                &delays,
            )
            .await?
        }

        Command::FecRatioSweep {
            data_shards,
            ratios,
            loss_rates,
            trials,
            response_size,
            target_delivery,
        } => {
            let ratio_vec: Vec<f64> = ratios
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            let rate_vec: Vec<f64> = loss_rates
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            run_fec_ratio_sweep(
                data_shards,
                &ratio_vec,
                &rate_vec,
                trials,
                response_size,
                target_delivery,
            )?
        }

        Command::CoverTraffic {
            nodes,
            packets,
            hops,
            duration_secs,
            settle_secs,
            cover_rates,
        } => {
            let rates: Vec<f64> = cover_rates
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            run_cover_traffic(
                nodes,
                packets,
                hops,
                duration_secs,
                settle_secs,
                bus_capacity,
                &rates,
            )
            .await?
        }

        Command::AttackSim {
            nodes,
            packets,
            hops,
            mix_delay_ms,
            concurrency,
            settle_secs,
            rounds,
        } => {
            let cfg = AnalyticsConfig {
                nodes,
                packets,
                hops,
                mix_delay_ms,
                concurrency,
                settle_secs,
                bus_capacity,
            };
            run_attack_sim(&cfg, rounds).await?
        }

        Command::ReplayDetection {
            unique_tags,
            replay_attempts,
            bloom_capacity,
            bloom_fp_rate,
        } => {
            run_replay_detection(unique_tags, replay_attempts, bloom_capacity, bloom_fp_rate)
                .await?
        }

        Command::PowDos {
            difficulties,
            trials,
        } => {
            let diffs: Vec<u32> = difficulties
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            run_pow_dos(&diffs, trials)?
        }

        Command::EntropyVsUsers {
            nodes,
            packets,
            hops,
            mix_delay_ms,
            concurrency,
            settle_secs,
            user_counts,
        } => {
            let cfg = AnalyticsConfig {
                nodes,
                packets,
                hops,
                mix_delay_ms,
                concurrency,
                settle_secs,
                bus_capacity,
            };
            let counts: Vec<usize> = user_counts
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            run_entropy_vs_users(&cfg, &counts).await?
        }

        Command::EntropyVsCover {
            nodes,
            packets,
            hops,
            duration_secs,
            settle_secs,
            cover_ratios,
        } => {
            let ratios: Vec<f64> = cover_ratios
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            run_entropy_vs_cover(
                nodes,
                packets,
                hops,
                duration_secs,
                settle_secs,
                bus_capacity,
                &ratios,
            )
            .await?
        }

        Command::FecVsArq {
            data_shards,
            fec_ratio,
            response_size,
            arq_max_retries,
            trials,
            loss_rates,
        } => {
            let rates: Vec<f64> = loss_rates
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            run_fec_vs_arq(
                data_shards,
                fec_ratio,
                response_size,
                arq_max_retries,
                trials,
                &rates,
            )?
        }

        Command::CombinedAnonymity {
            pool_sizes,
            mixnet_sizes,
            packets,
            hops,
            mix_delay_ms,
            concurrency,
            settle_secs,
            tag_reuse_count,
        } => {
            let pools: Vec<usize> = pool_sizes
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            let nodes: Vec<usize> = mixnet_sizes
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            run_combined_anonymity(
                &pools,
                &nodes,
                packets,
                hops,
                mix_delay_ms,
                concurrency,
                settle_secs,
                bus_capacity,
                tag_reuse_count,
            )
            .await?
        }

        Command::TrafficLevels {
            nodes,
            packets,
            hops,
            mix_delay_ms,
            settle_secs,
            traffic_rates,
        } => {
            let rates: Vec<f64> = traffic_rates
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            run_traffic_levels(
                nodes,
                packets,
                hops,
                mix_delay_ms,
                settle_secs,
                bus_capacity,
                &rates,
            )
            .await?
        }

        Command::CoverAnalysis {
            nodes,
            packets,
            hops,
            duration_secs,
            settle_secs,
            cover_rates,
        } => {
            let rates: Vec<f64> = cover_rates
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            run_cover_analysis(
                nodes,
                packets,
                hops,
                duration_secs,
                settle_secs,
                bus_capacity,
                &rates,
            )
            .await?
        }
    };

    // JSON output to stdout
    let json = serde_json::to_string_pretty(&result).expect("JSON serialize");
    println!("{json}");

    Ok(())
}
