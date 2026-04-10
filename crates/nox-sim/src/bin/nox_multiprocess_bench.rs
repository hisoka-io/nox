//! Multi-process benchmark orchestrator.
//!
//! Spawns real `nox` processes, wires topology via admin API, injects packets
//! via HTTP ingress, and measures latency/throughput across process boundaries.
//! Subcommands: `latency`, `scale`.

#![allow(clippy::expect_used)] // Benchmark binary: panicking on serialization is acceptable.

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::{error, info, Level};

use nox_core::models::payloads::encode_payload;
use nox_core::RelayerPayload;
use nox_crypto::PathHop;
use nox_sim::bench_common::{self, BenchResult, ConcurrencyPoint, ScalePoint, ThroughputPoint};
use nox_sim::process_mesh::{
    build_padded_packet, find_nox_binary, inject_and_measure, ProcessMesh,
};

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "NOX Multi-Process Benchmark -- real TCP/P2P between N nox processes"
)]
struct Cli {
    #[command(subcommand)]
    command: BenchCommand,

    /// Path to the nox binary. Defaults to target/release/nox or target/debug/nox.
    #[arg(long)]
    nox_binary: Option<String>,

    /// Base directory for node data (configs, DBs). Defaults to `/tmp/nox_bench`.
    #[arg(long, default_value = "/tmp/nox_bench")]
    data_dir: String,

    /// Base port for P2P (node N gets base + N*10).
    #[arg(long, default_value_t = 10000)]
    base_port: u16,

    /// Seconds to wait for all nodes to become healthy.
    #[arg(long, default_value_t = 30)]
    startup_timeout: u64,

    /// Seconds to wait after topology injection for P2P mesh to stabilize.
    #[arg(long, default_value_t = 5)]
    mesh_settle_secs: u64,
}

#[derive(Subcommand, Debug)]
enum BenchCommand {
    /// Measure latency distribution across the multi-process mesh
    Latency {
        /// Number of nox processes
        #[arg(short, long, default_value_t = 10)]
        nodes: usize,

        /// Total packets to send
        #[arg(short, long, default_value_t = 500)]
        packets: usize,

        /// Poisson mix delay per hop in ms (applied via config)
        #[arg(long, default_value_t = 1.0)]
        mix_delay_ms: f64,

        /// Max concurrent in-flight packets
        #[arg(long, default_value_t = 50)]
        concurrency: usize,

        /// Warmup packets to discard from stats
        #[arg(long, default_value_t = 50)]
        warmup: usize,
    },

    /// Measure throughput at increasing send rates
    Throughput {
        /// Number of nox processes
        #[arg(short, long, default_value_t = 10)]
        nodes: usize,

        /// Duration of each rate step in seconds
        #[arg(long, default_value_t = 10)]
        duration: u64,

        /// Target packets-per-second (comma-separated)
        #[arg(long, default_value = "50,100,200,500,1000")]
        target_pps: String,

        /// Poisson mix delay per hop in ms
        #[arg(long, default_value_t = 1.0)]
        mix_delay_ms: f64,

        /// Warmup duration per rate step in seconds (discard stats during this period)
        #[arg(long, default_value_t = 2)]
        warmup_secs: u64,
    },

    /// Scaling test: run latency at multiple node counts
    Scale {
        /// Comma-separated node counts
        #[arg(long, default_value = "5,10,25,50")]
        node_counts: String,

        /// Packets per test
        #[arg(short, long, default_value_t = 200)]
        packets: usize,

        /// Poisson mix delay per hop in ms
        #[arg(long, default_value_t = 1.0)]
        mix_delay_ms: f64,

        /// Warmup packets to discard from stats (per node-count step)
        #[arg(long, default_value_t = 20)]
        warmup: usize,
    },

    /// Sweep concurrency levels at fixed target PPS to find optimal parallelism
    ConcurrencySweep {
        /// Number of nox processes
        #[arg(short, long, default_value_t = 10)]
        nodes: usize,

        /// Fixed target packets-per-second for all concurrency levels
        #[arg(long, default_value_t = 200)]
        target_pps: usize,

        /// Concurrency levels to sweep (comma-separated)
        #[arg(long, default_value = "10,25,50,100,200,500")]
        concurrency_levels: String,

        /// Duration of each concurrency step in seconds
        #[arg(long, default_value_t = 15)]
        duration: u64,

        /// Poisson mix delay per hop in ms
        #[arg(long, default_value_t = 1.0)]
        mix_delay_ms: f64,

        /// Warmup duration per step in seconds (discard stats during this period)
        #[arg(long, default_value_t = 3)]
        warmup_secs: u64,
    },
}

async fn run_latency(
    cli: &Cli,
    node_count: usize,
    packets: usize,
    mix_delay_ms: f64,
    concurrency: usize,
    warmup: usize,
) -> Result<BenchResult> {
    let nox_binary = find_nox_binary(cli.nox_binary.as_deref())?;
    info!("Using nox binary: {}", nox_binary.display());

    let data_dir = PathBuf::from(&cli.data_dir);
    let mut mesh = ProcessMesh::build(
        node_count,
        &nox_binary,
        &data_dir,
        cli.base_port,
        Duration::from_secs(cli.startup_timeout),
        Duration::from_secs(cli.mesh_settle_secs),
        mix_delay_ms,
        "http://127.0.0.1:8545",
    )
    .await?;

    let total = warmup + packets;
    info!(
        "Latency benchmark: {packets} packets ({warmup} warmup), \
         {concurrency} concurrent, {node_count} nodes"
    );

    let latencies: Arc<parking_lot::Mutex<Vec<u64>>> =
        Arc::new(parking_lot::Mutex::new(Vec::with_capacity(packets)));
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let client = mesh.http_client.clone();

    let mut handles = Vec::new();

    for i in 0..total {
        let permit = semaphore.clone().acquire_owned().await?;
        let n = mesh.node_count();

        // 3-hop path: entry -> mid -> exit
        let entry_idx = i % n;
        let mid_idx = (i + 1) % n;
        let exit_idx = (i + 2) % n;

        let entry_pk = mesh.nodes[entry_idx].sphinx_public_key;
        let entry_ingress = mesh.nodes[entry_idx].ingress_port;
        let exit_ingress = mesh.nodes[exit_idx].ingress_port;
        let mid_pk = mesh.nodes[mid_idx].sphinx_public_key;
        let exit_pk = mesh.nodes[exit_idx].sphinx_public_key;

        // Construct multiaddrs with /p2p/<PeerId> so the P2P service can resolve next hops
        let entry_addr = format!(
            "/ip4/127.0.0.1/tcp/{}/p2p/{}",
            mesh.nodes[entry_idx].p2p_port, mesh.nodes[entry_idx].peer_id
        );
        let mid_addr = format!(
            "/ip4/127.0.0.1/tcp/{}/p2p/{}",
            mesh.nodes[mid_idx].p2p_port, mesh.nodes[mid_idx].peer_id
        );
        let exit_addr = format!(
            "/ip4/127.0.0.1/tcp/{}/p2p/{}",
            mesh.nodes[exit_idx].p2p_port, mesh.nodes[exit_idx].peer_id
        );

        let lat_clone = latencies.clone();
        let is_warmup = i < warmup;
        let client_clone = client.clone();

        handles.push(tokio::spawn(async move {
            let path = vec![
                PathHop {
                    public_key: entry_pk,
                    address: entry_addr,
                },
                PathHop {
                    public_key: mid_pk,
                    address: mid_addr,
                },
                PathHop {
                    public_key: exit_pk,
                    address: exit_addr,
                },
            ];

            let payload = RelayerPayload::SubmitTransaction {
                to: [0u8; 20],
                data: vec![0xBE, 0xEF],
            };
            let payload_bytes = encode_payload(&payload).expect("encode payload");
            let packet_bytes = build_padded_packet(&path, &payload_bytes).expect("build packet");

            // Measure true E2E latency: injection -> mixnet traversal -> exit delivery
            let result = inject_and_measure(
                &client_clone,
                entry_ingress,
                exit_ingress,
                packet_bytes,
                Duration::from_secs(60),
            )
            .await;

            match result {
                Ok(elapsed) => {
                    if !is_warmup {
                        lat_clone.lock().push(elapsed.as_micros() as u64);
                    }
                }
                Err(e) => {
                    if !is_warmup {
                        error!("Packet {i} E2E delivery failed: {e}");
                    }
                }
            }

            drop(permit);
        }));
    }

    // Wait for all packets
    for handle in handles {
        let _ = handle.await;
    }

    let mut lats = latencies.lock().clone();
    let stats = bench_common::compute_latency_stats(&mut lats, packets);

    info!(
        "Results: {} delivered, p50={:.1}ms, p99={:.1}ms, loss={:.2}%",
        stats.count,
        stats.p50_us as f64 / 1000.0,
        stats.p99_us as f64 / 1000.0,
        stats.loss_rate * 100.0,
    );

    mesh.teardown().await;

    Ok(BenchResult {
        benchmark: "multiprocess_latency".into(),
        mode: "multiprocess_e2e".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "node_count": node_count,
            "packets": packets,
            "warmup": warmup,
            "concurrency": concurrency,
            "mix_delay_ms": mix_delay_ms,
            "hops": 3,
            "measurement": "e2e_delivery",
            "note": "True E2E: injection -> mixnet traversal -> exit PayloadDecrypted -> response poll"
        }),
        results: serde_json::to_value(&stats).expect("serialize stats"),
    })
}

async fn run_throughput(
    cli: &Cli,
    node_count: usize,
    duration_secs: u64,
    target_pps_str: &str,
    mix_delay_ms: f64,
    warmup_secs: u64,
) -> Result<BenchResult> {
    let nox_binary = find_nox_binary(cli.nox_binary.as_deref())?;
    let data_dir = PathBuf::from(&cli.data_dir);
    let mut mesh = ProcessMesh::build(
        node_count,
        &nox_binary,
        &data_dir,
        cli.base_port,
        Duration::from_secs(cli.startup_timeout),
        Duration::from_secs(cli.mesh_settle_secs),
        mix_delay_ms,
        "http://127.0.0.1:8545",
    )
    .await?;

    let targets: Vec<usize> = target_pps_str
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    let mut points: Vec<ThroughputPoint> = Vec::new();
    let client = mesh.http_client.clone();
    let n = mesh.node_count();

    for &target_pps in &targets {
        info!("Throughput step: {target_pps} pps for {duration_secs}s ({warmup_secs}s warmup)...");
        let interval = Duration::from_secs_f64(1.0 / target_pps as f64);
        let step_duration = Duration::from_secs(duration_secs);
        let warmup_end = Duration::from_secs(warmup_secs);
        let step_start = Instant::now();

        let success = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let fail = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let latencies: Arc<parking_lot::Mutex<Vec<u64>>> =
            Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mut pkt_idx = 0usize;
        let mut handles = Vec::new();

        while step_start.elapsed() < step_duration {
            let is_warmup = step_start.elapsed() < warmup_end;
            let entry_idx = pkt_idx % n;
            let mid_idx = (pkt_idx + 1) % n;
            let exit_idx = (pkt_idx + 2) % n;

            let entry_pk = mesh.nodes[entry_idx].sphinx_public_key;
            let entry_ingress = mesh.nodes[entry_idx].ingress_port;
            let exit_ingress = mesh.nodes[exit_idx].ingress_port;
            let mid_pk = mesh.nodes[mid_idx].sphinx_public_key;
            let exit_pk = mesh.nodes[exit_idx].sphinx_public_key;

            let entry_addr = format!(
                "/ip4/127.0.0.1/tcp/{}/p2p/{}",
                mesh.nodes[entry_idx].p2p_port, mesh.nodes[entry_idx].peer_id
            );
            let mid_addr = format!(
                "/ip4/127.0.0.1/tcp/{}/p2p/{}",
                mesh.nodes[mid_idx].p2p_port, mesh.nodes[mid_idx].peer_id
            );
            let exit_addr = format!(
                "/ip4/127.0.0.1/tcp/{}/p2p/{}",
                mesh.nodes[exit_idx].p2p_port, mesh.nodes[exit_idx].peer_id
            );

            let succ = success.clone();
            let fl = fail.clone();
            let lat = latencies.clone();
            let cl = client.clone();

            handles.push(tokio::spawn(async move {
                let path = vec![
                    PathHop {
                        public_key: entry_pk,
                        address: entry_addr,
                    },
                    PathHop {
                        public_key: mid_pk,
                        address: mid_addr,
                    },
                    PathHop {
                        public_key: exit_pk,
                        address: exit_addr,
                    },
                ];
                let payload = RelayerPayload::SubmitTransaction {
                    to: [0u8; 20],
                    data: vec![0xBE, 0xEF],
                };
                let payload_bytes = encode_payload(&payload).expect("encode payload");
                let packet_bytes =
                    build_padded_packet(&path, &payload_bytes).expect("build packet");

                // True E2E: inject -> mixnet traversal -> exit delivery -> poll confirmation
                let result = inject_and_measure(
                    &cl,
                    entry_ingress,
                    exit_ingress,
                    packet_bytes,
                    Duration::from_secs(30),
                )
                .await;

                match result {
                    Ok(elapsed) => {
                        if !is_warmup {
                            succ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            lat.lock().push(elapsed.as_micros() as u64);
                        }
                    }
                    Err(_) => {
                        if !is_warmup {
                            fl.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
            }));

            pkt_idx += 1;
            tokio::time::sleep(interval).await;
        }

        // Drain handles
        for h in handles {
            let _ = h.await;
        }

        let elapsed = step_start.elapsed().as_secs_f64();
        let sc = success.load(std::sync::atomic::Ordering::Relaxed);
        let fc = fail.load(std::sync::atomic::Ordering::Relaxed);
        let total = sc + fc;
        let mut lats = latencies.lock().clone();
        let stats = bench_common::compute_latency_stats(&mut lats, total);

        points.push(ThroughputPoint {
            target_pps,
            achieved_pps: sc as f64 / elapsed,
            success_count: sc,
            fail_count: fc,
            loss_rate: if total > 0 {
                fc as f64 / total as f64
            } else {
                0.0
            },
            latency: stats,
        });

        info!(
            "  -> achieved {:.1} pps, {sc} ok, {fc} fail, loss={:.2}%",
            sc as f64 / elapsed,
            if total > 0 {
                fc as f64 / total as f64 * 100.0
            } else {
                0.0
            },
        );
    }

    mesh.teardown().await;

    Ok(BenchResult {
        benchmark: "multiprocess_throughput".into(),
        mode: "multiprocess_e2e".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "node_count": node_count,
            "duration_secs": duration_secs,
            "target_pps": targets,
            "mix_delay_ms": mix_delay_ms,
            "hops": 3,
            "measurement": "e2e_delivery",
            "note": "True E2E: injection -> mixnet traversal -> exit PayloadDecrypted -> response poll"
        }),
        results: serde_json::json!({ "points": points }),
    })
}

async fn run_scale(
    cli: &Cli,
    node_counts_str: &str,
    packets: usize,
    mix_delay_ms: f64,
    warmup: usize,
) -> Result<BenchResult> {
    let nox_binary = find_nox_binary(cli.nox_binary.as_deref())?;
    let counts: Vec<usize> = node_counts_str
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    let mut scale_points: Vec<ScalePoint> = Vec::new();

    for &nc in &counts {
        let total = warmup + packets;
        info!("=== Scale test: {nc} nodes, {packets} packets ({warmup} warmup) ===");
        let data_dir = PathBuf::from(format!("{}/scale_{nc}", cli.data_dir));
        let mut mesh = ProcessMesh::build(
            nc,
            &nox_binary,
            &data_dir,
            cli.base_port,
            Duration::from_secs(cli.startup_timeout),
            Duration::from_secs(cli.mesh_settle_secs),
            mix_delay_ms,
            "http://127.0.0.1:8545",
        )
        .await?;

        let client = mesh.http_client.clone();
        let n = mesh.node_count();
        let latencies: Arc<parking_lot::Mutex<Vec<u64>>> =
            Arc::new(parking_lot::Mutex::new(Vec::with_capacity(packets)));
        let semaphore = Arc::new(Semaphore::new(50));

        let scale_start = Instant::now();
        let mut handles = Vec::new();
        for i in 0..total {
            let is_warmup = i < warmup;
            let permit = semaphore.clone().acquire_owned().await?;
            let entry_idx = i % n;
            let mid_idx = (i + 1) % n;
            let exit_idx = (i + 2) % n;

            let entry_pk = mesh.nodes[entry_idx].sphinx_public_key;
            let entry_ingress = mesh.nodes[entry_idx].ingress_port;
            let exit_ingress = mesh.nodes[exit_idx].ingress_port;
            let mid_pk = mesh.nodes[mid_idx].sphinx_public_key;
            let exit_pk = mesh.nodes[exit_idx].sphinx_public_key;

            let entry_addr = format!(
                "/ip4/127.0.0.1/tcp/{}/p2p/{}",
                mesh.nodes[entry_idx].p2p_port, mesh.nodes[entry_idx].peer_id
            );
            let mid_addr = format!(
                "/ip4/127.0.0.1/tcp/{}/p2p/{}",
                mesh.nodes[mid_idx].p2p_port, mesh.nodes[mid_idx].peer_id
            );
            let exit_addr = format!(
                "/ip4/127.0.0.1/tcp/{}/p2p/{}",
                mesh.nodes[exit_idx].p2p_port, mesh.nodes[exit_idx].peer_id
            );

            let lat_clone = latencies.clone();
            let cl = client.clone();

            handles.push(tokio::spawn(async move {
                let path = vec![
                    PathHop {
                        public_key: entry_pk,
                        address: entry_addr,
                    },
                    PathHop {
                        public_key: mid_pk,
                        address: mid_addr,
                    },
                    PathHop {
                        public_key: exit_pk,
                        address: exit_addr,
                    },
                ];
                let payload = RelayerPayload::SubmitTransaction {
                    to: [0u8; 20],
                    data: vec![0xBE, 0xEF],
                };
                let payload_bytes = encode_payload(&payload).expect("encode payload");
                let packet_bytes =
                    build_padded_packet(&path, &payload_bytes).expect("build packet");

                // True E2E: inject -> mixnet traversal -> exit delivery -> poll confirmation
                let result = inject_and_measure(
                    &cl,
                    entry_ingress,
                    exit_ingress,
                    packet_bytes,
                    Duration::from_secs(30),
                )
                .await;

                match result {
                    Ok(elapsed) => {
                        if !is_warmup {
                            lat_clone.lock().push(elapsed.as_micros() as u64);
                        }
                    }
                    Err(e) => {
                        if !is_warmup {
                            error!("Scale test packet {i} failed: {e}");
                        }
                    }
                }

                drop(permit);
            }));
        }

        for h in handles {
            let _ = h.await;
        }

        let scale_duration = scale_start.elapsed();
        let mut lats = latencies.lock().clone();
        let stats = bench_common::compute_latency_stats(&mut lats, total);
        let achieved_pps = stats.count as f64 / scale_duration.as_secs_f64();

        info!(
            "  {nc} nodes: {} delivered, pps={achieved_pps:.1}, p50={:.1}ms, p99={:.1}ms",
            stats.count,
            stats.p50_us as f64 / 1000.0,
            stats.p99_us as f64 / 1000.0,
        );

        scale_points.push(ScalePoint {
            node_count: nc,
            achieved_pps,
            latency: stats,
        });

        mesh.teardown().await;
    }

    Ok(BenchResult {
        benchmark: "multiprocess_scale".into(),
        mode: "multiprocess_e2e".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "node_counts": counts,
            "packets_per_test": packets,
            "mix_delay_ms": mix_delay_ms,
            "hops": 3,
            "measurement": "e2e_delivery",
            "note": "True E2E: injection -> mixnet traversal -> exit PayloadDecrypted -> response poll"
        }),
        results: serde_json::to_value(&scale_points).expect("serialize scale points"),
    })
}

async fn run_concurrency_sweep(
    cli: &Cli,
    node_count: usize,
    target_pps: usize,
    concurrency_levels_str: &str,
    duration_secs: u64,
    mix_delay_ms: f64,
    warmup_secs: u64,
) -> Result<BenchResult> {
    let nox_binary = find_nox_binary(cli.nox_binary.as_deref())?;
    let data_dir = PathBuf::from(&cli.data_dir);
    let mut mesh = ProcessMesh::build(
        node_count,
        &nox_binary,
        &data_dir,
        cli.base_port,
        Duration::from_secs(cli.startup_timeout),
        Duration::from_secs(cli.mesh_settle_secs),
        mix_delay_ms,
        "http://127.0.0.1:8545",
    )
    .await?;

    let levels: Vec<usize> = concurrency_levels_str
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    let mut points: Vec<ConcurrencyPoint> = Vec::new();
    let n = mesh.node_count();

    for &concurrency in &levels {
        info!(
            "Concurrency step: {concurrency} in-flight, {target_pps} target PPS \
             for {duration_secs}s ({warmup_secs}s warmup)..."
        );

        let interval = Duration::from_secs_f64(1.0 / target_pps as f64);
        let step_duration = Duration::from_secs(duration_secs);
        let warmup_end = Duration::from_secs(warmup_secs);
        let step_start = Instant::now();

        let success = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let fail = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let latencies: Arc<parking_lot::Mutex<Vec<u64>>> =
            Arc::new(parking_lot::Mutex::new(Vec::new()));
        let semaphore = Arc::new(Semaphore::new(concurrency));
        let client = mesh.http_client.clone();
        let mut pkt_idx = 0usize;
        let mut handles = Vec::new();

        while step_start.elapsed() < step_duration {
            // Acquire a permit -- this is the concurrency limiter
            let permit = semaphore.clone().acquire_owned().await?;
            let is_warmup = step_start.elapsed() < warmup_end;

            let entry_idx = pkt_idx % n;
            let mid_idx = (pkt_idx + 1) % n;
            let exit_idx = (pkt_idx + 2) % n;

            let entry_pk = mesh.nodes[entry_idx].sphinx_public_key;
            let entry_ingress = mesh.nodes[entry_idx].ingress_port;
            let exit_ingress = mesh.nodes[exit_idx].ingress_port;
            let mid_pk = mesh.nodes[mid_idx].sphinx_public_key;
            let exit_pk = mesh.nodes[exit_idx].sphinx_public_key;

            let entry_addr = format!(
                "/ip4/127.0.0.1/tcp/{}/p2p/{}",
                mesh.nodes[entry_idx].p2p_port, mesh.nodes[entry_idx].peer_id
            );
            let mid_addr = format!(
                "/ip4/127.0.0.1/tcp/{}/p2p/{}",
                mesh.nodes[mid_idx].p2p_port, mesh.nodes[mid_idx].peer_id
            );
            let exit_addr = format!(
                "/ip4/127.0.0.1/tcp/{}/p2p/{}",
                mesh.nodes[exit_idx].p2p_port, mesh.nodes[exit_idx].peer_id
            );

            let succ = success.clone();
            let fl = fail.clone();
            let lat = latencies.clone();
            let cl = client.clone();

            handles.push(tokio::spawn(async move {
                let path = vec![
                    PathHop {
                        public_key: entry_pk,
                        address: entry_addr,
                    },
                    PathHop {
                        public_key: mid_pk,
                        address: mid_addr,
                    },
                    PathHop {
                        public_key: exit_pk,
                        address: exit_addr,
                    },
                ];
                let payload = RelayerPayload::SubmitTransaction {
                    to: [0u8; 20],
                    data: vec![0xBE, 0xEF],
                };
                let payload_bytes = encode_payload(&payload).expect("encode payload");
                let packet_bytes =
                    build_padded_packet(&path, &payload_bytes).expect("build packet");

                // True E2E: inject -> mixnet traversal -> exit delivery -> poll confirmation
                let result = inject_and_measure(
                    &cl,
                    entry_ingress,
                    exit_ingress,
                    packet_bytes,
                    Duration::from_secs(30),
                )
                .await;

                match result {
                    Ok(elapsed) => {
                        if !is_warmup {
                            succ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            lat.lock().push(elapsed.as_micros() as u64);
                        }
                    }
                    Err(_) => {
                        if !is_warmup {
                            fl.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }

                drop(permit);
            }));

            pkt_idx += 1;
            tokio::time::sleep(interval).await;
        }

        // Drain all in-flight tasks
        for h in handles {
            let _ = h.await;
        }

        let elapsed = step_start.elapsed().as_secs_f64();
        let sc = success.load(std::sync::atomic::Ordering::Relaxed);
        let fc = fail.load(std::sync::atomic::Ordering::Relaxed);
        let total = sc + fc;
        let mut lats = latencies.lock().clone();
        let stats = bench_common::compute_latency_stats(&mut lats, total);

        points.push(ConcurrencyPoint {
            concurrency,
            target_pps,
            achieved_pps: sc as f64 / elapsed,
            success_count: sc,
            fail_count: fc,
            loss_rate: if total > 0 {
                fc as f64 / total as f64
            } else {
                0.0
            },
            latency: stats,
        });

        info!(
            "  -> concurrency={concurrency}: achieved {:.1} pps, {sc} ok, {fc} fail, \
             loss={:.2}%, p50={:.1}ms, p99={:.1}ms",
            sc as f64 / elapsed,
            if total > 0 {
                fc as f64 / total as f64 * 100.0
            } else {
                0.0
            },
            lats.get(lats.len() / 2).copied().unwrap_or(0) as f64 / 1000.0,
            lats.last().copied().unwrap_or(0) as f64 / 1000.0,
        );
    }

    mesh.teardown().await;

    Ok(BenchResult {
        benchmark: "multiprocess_concurrency_sweep".into(),
        mode: "multiprocess_e2e".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "node_count": node_count,
            "target_pps": target_pps,
            "concurrency_levels": levels,
            "duration_secs": duration_secs,
            "warmup_secs": warmup_secs,
            "mix_delay_ms": mix_delay_ms,
            "hops": 3,
            "measurement": "e2e_delivery",
            "note": "True E2E: Semaphore-bounded concurrency sweep at fixed target PPS"
        }),
        results: serde_json::json!({ "points": points }),
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");

    let cli = Cli::parse();

    let result = match &cli.command {
        BenchCommand::Latency {
            nodes,
            packets,
            mix_delay_ms,
            concurrency,
            warmup,
        } => run_latency(&cli, *nodes, *packets, *mix_delay_ms, *concurrency, *warmup).await?,
        BenchCommand::Throughput {
            nodes,
            duration,
            target_pps,
            mix_delay_ms,
            warmup_secs,
        } => {
            run_throughput(
                &cli,
                *nodes,
                *duration,
                target_pps,
                *mix_delay_ms,
                *warmup_secs,
            )
            .await?
        }
        BenchCommand::Scale {
            node_counts,
            packets,
            mix_delay_ms,
            warmup,
        } => run_scale(&cli, node_counts, *packets, *mix_delay_ms, *warmup).await?,
        BenchCommand::ConcurrencySweep {
            nodes,
            target_pps,
            concurrency_levels,
            duration,
            mix_delay_ms,
            warmup_secs,
        } => {
            run_concurrency_sweep(
                &cli,
                *nodes,
                *target_pps,
                concurrency_levels,
                *duration,
                *mix_delay_ms,
                *warmup_secs,
            )
            .await?
        }
    };

    // JSON to stdout
    println!(
        "{}",
        serde_json::to_string_pretty(&result).expect("serialize result")
    );

    Ok(())
}
