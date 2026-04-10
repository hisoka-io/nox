//! Routes real HTTP requests through a multi-process mixnet mesh and compares
//! direct vs mixnet latency for real-world targets.

#![allow(clippy::expect_used)] // Benchmark binary: panicking on serialization is acceptable.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ethers::types::Address;
use nox_client::{HttpPacketTransport, MixnetClient, MixnetClientConfig, TopologyNode};
use nox_node::services::handlers::http::SerializableHttpResponse;
use nox_sim::bench_common::{self, BenchResult};
use nox_sim::process_mesh::{find_nox_binary, ProcessMesh};
use parking_lot::RwLock;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{info, warn, Level};

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "NOX Real-World Benchmark -- HTTP requests through a real multi-process mixnet"
)]
struct Cli {
    #[command(subcommand)]
    command: BenchCommand,

    /// Path to the nox binary. Defaults to target/release/nox or target/debug/nox.
    #[arg(long)]
    nox_binary: Option<String>,

    /// Base directory for node data (configs, DBs).
    #[arg(long, default_value = "/tmp/nox_realworld_bench")]
    data_dir: String,

    /// Base port for P2P (node N gets base + N*10).
    #[arg(long, default_value_t = 12000)]
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
    /// Route real HTTP requests through the mixnet vs direct
    HttpProxy {
        /// Number of nox processes
        #[arg(short, long, default_value_t = 5)]
        nodes: usize,

        /// Poisson mix delay per hop in ms (0 = instant forwarding)
        #[arg(long, default_value_t = 0.0)]
        mix_delay_ms: f64,

        /// Number of runs per target (for statistical significance)
        #[arg(long, default_value_t = 5)]
        runs: usize,

        /// Request timeout in seconds (for both direct and mixnet).
        /// Large responses (100 MB+) need 300+ seconds through the mixnet.
        #[arg(long, default_value_t = 600)]
        timeout_secs: u64,

        /// Warmup requests to discard per target (first N requests not measured)
        #[arg(long, default_value_t = 1)]
        warmup: usize,

        /// Also measure mixnet with default (1ms) delay
        #[arg(long)]
        with_delay: bool,

        /// Custom targets as JSON array: `[{"name":"..","url":"..","method":"GET","expected_bytes":0}]`
        #[arg(long)]
        custom_targets: Option<String>,
    },
}

/// A benchmark HTTP target definition.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
struct HttpTarget {
    /// Human-readable name
    name: String,
    /// Full URL to fetch
    url: String,
    /// HTTP method
    method: String,
    /// Headers as key-value pairs
    headers: Vec<(String, String)>,
    /// Request body (empty for GET)
    body: Vec<u8>,
    /// Expected response size hint for SURB budget (0 = auto)
    expected_bytes: usize,
    /// Expected response category
    category: String,
}

/// Default benchmark targets -- curated for variety and reproducibility.
fn default_targets() -> Vec<HttpTarget> {
    vec![
        HttpTarget {
            name: "httpbin-get".into(),
            url: "https://httpbin.org/get".into(),
            method: "GET".into(),
            headers: vec![],
            body: vec![],
            expected_bytes: 2_000,
            category: "API (small JSON)".into(),
        },
        HttpTarget {
            name: "httpbin-bytes-1k".into(),
            url: "https://httpbin.org/bytes/1024".into(),
            method: "GET".into(),
            headers: vec![],
            body: vec![],
            expected_bytes: 2_000,
            category: "Binary (1KB)".into(),
        },
        HttpTarget {
            name: "httpbin-bytes-10k".into(),
            url: "https://httpbin.org/bytes/10240".into(),
            method: "GET".into(),
            headers: vec![],
            body: vec![],
            expected_bytes: 15_000,
            category: "Binary (10KB)".into(),
        },
        HttpTarget {
            name: "httpbin-bytes-100k".into(),
            url: "https://httpbin.org/bytes/102400".into(),
            method: "GET".into(),
            headers: vec![],
            body: vec![],
            expected_bytes: 110_000,
            category: "Binary (100KB)".into(),
        },
        HttpTarget {
            name: "httpbin-bytes-1m".into(),
            url: "https://httpbin.org/bytes/1048576".into(),
            method: "GET".into(),
            headers: vec![],
            body: vec![],
            expected_bytes: 1_100_000,
            category: "Binary (1MB)".into(),
        },
        HttpTarget {
            name: "coingecko-btc-price".into(),
            url: "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd"
                .into(),
            method: "GET".into(),
            headers: vec![],
            body: vec![],
            expected_bytes: 500,
            category: "API (crypto price)".into(),
        },
        HttpTarget {
            name: "cloudflare-dns-query".into(),
            url: "https://cloudflare-dns.com/dns-query?name=example.com&type=A".into(),
            method: "GET".into(),
            headers: vec![("Accept".into(), "application/dns-json".into())],
            body: vec![],
            expected_bytes: 500,
            category: "DNS-over-HTTPS".into(),
        },
        HttpTarget {
            name: "httpbin-ip".into(),
            url: "https://httpbin.org/ip".into(),
            method: "GET".into(),
            headers: vec![],
            body: vec![],
            expected_bytes: 200,
            category: "API (minimal)".into(),
        },
    ]
}

/// Result for a single HTTP target across all measurement modes.
#[derive(Serialize)]
struct TargetResult {
    target: TargetInfo,
    direct: MeasurementResult,
    mixnet_no_delay: Option<MeasurementResult>,
    mixnet_with_delay: Option<MeasurementResult>,
}

/// Target metadata (serialized into output).
#[derive(Serialize)]
struct TargetInfo {
    name: String,
    url: String,
    method: String,
    category: String,
    expected_bytes: usize,
}

/// Aggregated measurement result for one mode (direct / mixnet).
#[derive(Serialize)]
struct MeasurementResult {
    /// Individual run latencies in microseconds
    latencies_us: Vec<u64>,
    /// Number of successful runs
    success_count: usize,
    /// Number of failed runs
    fail_count: usize,
    /// Mean latency in microseconds
    mean_us: f64,
    /// Median latency in microseconds
    median_us: u64,
    /// Min latency in microseconds
    min_us: u64,
    /// Max latency in microseconds
    max_us: u64,
    /// Stddev in microseconds
    stddev_us: f64,
    /// Response body sizes in bytes (per successful run)
    response_sizes: Vec<usize>,
    /// HTTP status codes received (per successful run)
    status_codes: Vec<u16>,
    /// Overhead vs direct (only for mixnet results)
    overhead_factor: Option<f64>,
}

impl MeasurementResult {
    fn from_runs(runs: &[RunResult], direct_mean_us: Option<f64>) -> Self {
        let mut latencies: Vec<u64> = runs
            .iter()
            .filter(|r| r.success)
            .map(|r| r.latency_us)
            .collect();
        let response_sizes: Vec<usize> = runs
            .iter()
            .filter(|r| r.success)
            .map(|r| r.response_size)
            .collect();
        let status_codes: Vec<u16> = runs
            .iter()
            .filter(|r| r.success)
            .map(|r| r.status_code)
            .collect();
        let success_count = latencies.len();
        let fail_count = runs.len() - success_count;

        if latencies.is_empty() {
            return Self {
                latencies_us: vec![],
                success_count: 0,
                fail_count,
                mean_us: 0.0,
                median_us: 0,
                min_us: 0,
                max_us: 0,
                stddev_us: 0.0,
                response_sizes,
                status_codes,
                overhead_factor: None,
            };
        }

        latencies.sort_unstable();
        let sum: u64 = latencies.iter().sum();
        let n = latencies.len();
        let mean = sum as f64 / n as f64;
        let variance: f64 = latencies
            .iter()
            .map(|&v| {
                let diff = v as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / if n > 1 { (n - 1) as f64 } else { 1.0 };

        let median = latencies[n / 2];
        let min_us = latencies.first().copied().unwrap_or(0);
        let max_us = latencies.last().copied().unwrap_or(0);
        let overhead_factor = direct_mean_us.map(|d| if d > 0.0 { mean / d } else { 0.0 });

        Self {
            latencies_us: latencies,
            success_count,
            fail_count,
            mean_us: mean,
            median_us: median,
            min_us,
            max_us,
            stddev_us: variance.sqrt(),
            response_sizes,
            status_codes,
            overhead_factor,
        }
    }
}

/// A single run result.
struct RunResult {
    latency_us: u64,
    response_size: usize,
    status_code: u16,
    success: bool,
}

async fn fetch_direct(
    client: &reqwest::Client,
    target: &HttpTarget,
    timeout: Duration,
) -> Result<RunResult> {
    let start = Instant::now();

    let mut req = match target.method.as_str() {
        "GET" => client.get(&target.url),
        "POST" => client.post(&target.url).body(target.body.clone()),
        "PUT" => client.put(&target.url).body(target.body.clone()),
        "DELETE" => client.delete(&target.url),
        other => bail!("Unsupported HTTP method: {other}"),
    };

    for (key, value) in &target.headers {
        req = req.header(key, value);
    }

    let resp = tokio::time::timeout(timeout, req.send())
        .await
        .context("Direct HTTP request timed out")?
        .context("Direct HTTP request failed")?;

    let status = resp.status().as_u16();
    let body = tokio::time::timeout(Duration::from_secs(30), resp.bytes())
        .await
        .context("Reading response body timed out")?
        .context("Reading response body failed")?;

    let latency = start.elapsed();

    Ok(RunResult {
        latency_us: latency.as_micros() as u64,
        response_size: body.len(),
        status_code: status,
        success: true,
    })
}

/// Build `Vec<TopologyNode>` from `ProcessMesh` nodes.
///
/// Includes `/p2p/<PeerId>` in the address so the P2P service can resolve
/// next-hop addresses from Sphinx routing info without reverse lookups.
fn topology_from_mesh(mesh: &ProcessMesh) -> Vec<TopologyNode> {
    mesh.nodes
        .iter()
        .map(|n| {
            let mut public_key = [0u8; 32];
            public_key.copy_from_slice(n.sphinx_public_key.as_bytes());

            TopologyNode {
                id: format!("0xBenchNode{}", n.id),
                address: format!("/ip4/127.0.0.1/tcp/{}/p2p/{}", n.p2p_port, n.peer_id),
                public_key,
                layer: match n.id % 3 {
                    0 => 0, // Entry
                    1 => 1, // Mix
                    _ => 2, // Exit
                },
                eth_address: Address::zero(),
                role: 3, // Full node
            }
        })
        .collect()
}

/// A no-op event publisher -- required by `MixnetClient::new` but unused
/// when HTTP transport is configured.
struct NoopPublisher;

impl nox_core::IEventPublisher for NoopPublisher {
    fn publish(
        &self,
        _event: nox_core::NoxEvent,
    ) -> Result<usize, nox_core::traits::interfaces::EventBusError> {
        Ok(0)
    }
}

/// Create a `MixnetClient` wired to the process mesh via HTTP transport.
fn create_mixnet_client(
    mesh: &ProcessMesh,
    timeout: Duration,
) -> (Arc<MixnetClient>, mpsc::Sender<(String, Vec<u8>)>) {
    let topology = topology_from_mesh(mesh);
    let topology = Arc::new(RwLock::new(topology));

    let bus = Arc::new(NoopPublisher);
    let (response_tx, response_rx) = mpsc::channel(1024);

    // Entry node is node 0
    let entry_url = format!("http://127.0.0.1:{}", mesh.nodes[0].ingress_port);

    let config = MixnetClientConfig {
        timeout,
        pow_difficulty: 0,
        surbs_per_request: 10,
        entry_node_pubkey: Some(*mesh.nodes[0].sphinx_public_key.as_bytes()),
        default_fec_ratio: 0.3,
        // Fast polling for benchmarks -- 500ms default adds up to 250ms avg latency
        http_poll_interval_ms: 25,
    };

    let transport = Arc::new(HttpPacketTransport::with_client(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(35))
            .build()
            .expect("build reqwest client"),
    ));

    let client =
        MixnetClient::new(topology, bus, response_rx, config).with_transport(transport, entry_url);

    (Arc::new(client), response_tx)
}

/// Fetch a target via the mixnet's HTTP proxy.
async fn fetch_via_mixnet(
    client: &MixnetClient,
    target: &HttpTarget,
    timeout: Duration,
) -> Result<RunResult> {
    let start = Instant::now();

    let response_bytes = tokio::time::timeout(
        timeout,
        client.send_http_request(
            &target.url,
            &target.method,
            target.headers.clone(),
            target.body.clone(),
            target.expected_bytes,
        ),
    )
    .await
    .context("Mixnet HTTP request timed out")?
    .map_err(|e| anyhow::anyhow!("Mixnet HTTP request failed: {e}"))?;

    let latency = start.elapsed();

    // Deserialize the response
    let http_resp: SerializableHttpResponse = bincode::deserialize(&response_bytes)
        .context("Failed to deserialize SerializableHttpResponse from mixnet")?;

    Ok(RunResult {
        latency_us: latency.as_micros() as u64,
        response_size: http_resp.body.len(),
        status_code: http_resp.status,
        success: true,
    })
}

/// Parameters for `run_http_proxy`, bundled to avoid too-many-arguments.
struct HttpProxyParams<'a> {
    cli: &'a Cli,
    node_count: usize,
    mix_delay_ms: f64,
    runs: usize,
    timeout_secs: u64,
    warmup: usize,
    with_delay: bool,
    custom_targets: Option<&'a String>,
}

async fn run_http_proxy(params: HttpProxyParams<'_>) -> Result<BenchResult> {
    let HttpProxyParams {
        cli,
        node_count,
        mix_delay_ms,
        runs,
        timeout_secs,
        warmup,
        with_delay,
        custom_targets,
    } = params;
    let nox_binary = find_nox_binary(cli.nox_binary.as_deref())?;
    info!("Using nox binary: {}", nox_binary.display());

    let targets = if let Some(json) = &custom_targets {
        serde_json::from_str::<Vec<HttpTarget>>(json)
            .context("Failed to parse custom targets JSON")?
    } else {
        default_targets()
    };

    let timeout = Duration::from_secs(timeout_secs);
    let total_runs = warmup + runs;

    info!(
        "HTTP Proxy benchmark: {} targets, {runs} runs ({warmup} warmup), {node_count} nodes",
        targets.len()
    );

    // Phase 1: Direct measurements (no mixnet needed)
    info!("=== Phase 1: Direct HTTP measurements ===");
    let direct_client = reqwest::Client::builder().timeout(timeout).build()?;

    let mut target_results: Vec<TargetResult> = Vec::new();

    for target in &targets {
        info!("  Direct: {} ({})", target.name, target.url);
        let mut direct_runs = Vec::new();

        for i in 0..total_runs {
            match fetch_direct(&direct_client, target, timeout).await {
                Ok(result) => {
                    if i >= warmup {
                        info!(
                            "    run {}/{}: {}ms, {} bytes, HTTP {}",
                            i - warmup + 1,
                            runs,
                            result.latency_us / 1000,
                            result.response_size,
                            result.status_code
                        );
                        direct_runs.push(result);
                    }
                }
                Err(e) => {
                    if i >= warmup {
                        warn!("    run {}/{}: FAILED -- {e}", i - warmup + 1, runs);
                        direct_runs.push(RunResult {
                            latency_us: 0,
                            response_size: 0,
                            status_code: 0,
                            success: false,
                        });
                    }
                }
            }
            // Brief delay between runs to avoid rate limiting
            if i < total_runs - 1 {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }

        let direct_result = MeasurementResult::from_runs(&direct_runs, None);
        info!(
            "  Direct {}: mean={:.1}ms, median={:.1}ms, {}/{} ok",
            target.name,
            direct_result.mean_us / 1000.0,
            direct_result.median_us as f64 / 1000.0,
            direct_result.success_count,
            runs,
        );

        target_results.push(TargetResult {
            target: TargetInfo {
                name: target.name.clone(),
                url: target.url.clone(),
                method: target.method.clone(),
                category: target.category.clone(),
                expected_bytes: target.expected_bytes,
            },
            direct: direct_result,
            mixnet_no_delay: None,
            mixnet_with_delay: None,
        });
    }

    // Phase 2: Mixnet measurements (no delay)
    info!(
        "=== Phase 2: Mixnet HTTP measurements (mix_delay={}ms) ===",
        mix_delay_ms
    );

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

    let (mixnet_client, _response_tx) = create_mixnet_client(&mesh, timeout);

    // Start the response loop in the background
    let response_client = Arc::clone(&mixnet_client);
    let response_handle = tokio::spawn(async move {
        response_client.run_response_loop().await;
    });

    for (idx, target) in targets.iter().enumerate() {
        info!("  Mixnet: {} ({})", target.name, target.url);
        let mut mixnet_runs = Vec::new();

        for i in 0..total_runs {
            match fetch_via_mixnet(&mixnet_client, target, timeout).await {
                Ok(result) => {
                    if i >= warmup {
                        info!(
                            "    run {}/{}: {}ms, {} bytes, HTTP {}",
                            i - warmup + 1,
                            runs,
                            result.latency_us / 1000,
                            result.response_size,
                            result.status_code
                        );
                        mixnet_runs.push(result);
                    }
                }
                Err(e) => {
                    if i >= warmup {
                        warn!("    run {}/{}: FAILED -- {e}", i - warmup + 1, runs);
                        mixnet_runs.push(RunResult {
                            latency_us: 0,
                            response_size: 0,
                            status_code: 0,
                            success: false,
                        });
                    }
                }
            }
            // Brief delay between runs
            if i < total_runs - 1 {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }

        let direct_mean = target_results[idx].direct.mean_us;
        let mixnet_result = MeasurementResult::from_runs(
            &mixnet_runs,
            if direct_mean > 0.0 {
                Some(direct_mean)
            } else {
                None
            },
        );
        info!(
            "  Mixnet {}: mean={:.1}ms, median={:.1}ms, overhead={:.1}x, {}/{} ok",
            target.name,
            mixnet_result.mean_us / 1000.0,
            mixnet_result.median_us as f64 / 1000.0,
            mixnet_result.overhead_factor.unwrap_or(0.0),
            mixnet_result.success_count,
            runs,
        );

        target_results[idx].mixnet_no_delay = Some(mixnet_result);
    }

    // Tear down no-delay mesh
    response_handle.abort();
    mesh.teardown().await;

    // Phase 3 (optional): Mixnet with 1ms delay
    if with_delay {
        let delay_ms = 1.0;
        info!(
            "=== Phase 3: Mixnet HTTP measurements (mix_delay={}ms) ===",
            delay_ms
        );

        let data_dir_delay = PathBuf::from(format!("{}_delay", cli.data_dir));
        let mut mesh_delay = ProcessMesh::build(
            node_count,
            &nox_binary,
            &data_dir_delay,
            cli.base_port,
            Duration::from_secs(cli.startup_timeout),
            Duration::from_secs(cli.mesh_settle_secs),
            delay_ms,
            "http://127.0.0.1:8545",
        )
        .await?;

        let (mixnet_client_delay, _response_tx_delay) = create_mixnet_client(&mesh_delay, timeout);

        let response_client_delay = Arc::clone(&mixnet_client_delay);
        let response_handle_delay = tokio::spawn(async move {
            response_client_delay.run_response_loop().await;
        });

        for (idx, target) in targets.iter().enumerate() {
            info!("  Mixnet (delay): {} ({})", target.name, target.url);
            let mut delay_runs = Vec::new();

            for i in 0..total_runs {
                match fetch_via_mixnet(&mixnet_client_delay, target, timeout).await {
                    Ok(result) => {
                        if i >= warmup {
                            info!(
                                "    run {}/{}: {}ms, {} bytes, HTTP {}",
                                i - warmup + 1,
                                runs,
                                result.latency_us / 1000,
                                result.response_size,
                                result.status_code
                            );
                            delay_runs.push(result);
                        }
                    }
                    Err(e) => {
                        if i >= warmup {
                            warn!("    run {}/{}: FAILED -- {e}", i - warmup + 1, runs);
                            delay_runs.push(RunResult {
                                latency_us: 0,
                                response_size: 0,
                                status_code: 0,
                                success: false,
                            });
                        }
                    }
                }
                if i < total_runs - 1 {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }

            let direct_mean = target_results[idx].direct.mean_us;
            let delay_result = MeasurementResult::from_runs(
                &delay_runs,
                if direct_mean > 0.0 {
                    Some(direct_mean)
                } else {
                    None
                },
            );
            info!(
                "  Mixnet (delay) {}: mean={:.1}ms, median={:.1}ms, overhead={:.1}x, {}/{} ok",
                target.name,
                delay_result.mean_us / 1000.0,
                delay_result.median_us as f64 / 1000.0,
                delay_result.overhead_factor.unwrap_or(0.0),
                delay_result.success_count,
                runs,
            );

            target_results[idx].mixnet_with_delay = Some(delay_result);
        }

        response_handle_delay.abort();
        mesh_delay.teardown().await;
    }

    // Build summary
    info!("=== Summary ===");
    for tr in &target_results {
        let direct_ms = tr.direct.mean_us / 1000.0;
        let mixnet_ms = tr
            .mixnet_no_delay
            .as_ref()
            .map_or(0.0, |m| m.mean_us / 1000.0);
        let overhead = tr
            .mixnet_no_delay
            .as_ref()
            .and_then(|m| m.overhead_factor)
            .unwrap_or(0.0);
        info!(
            "  {:<25} direct={:>7.1}ms  mixnet={:>7.1}ms  overhead={:.1}x",
            tr.target.name, direct_ms, mixnet_ms, overhead,
        );
    }

    Ok(BenchResult {
        benchmark: "realworld_http_proxy".into(),
        mode: "multiprocess_http".into(),
        hardware: bench_common::detect_hardware(),
        timestamp: bench_common::now_iso8601(),
        git_commit: bench_common::git_commit(),
        params: serde_json::json!({
            "node_count": node_count,
            "mix_delay_ms": mix_delay_ms,
            "runs": runs,
            "warmup": warmup,
            "timeout_secs": timeout_secs,
            "with_delay": with_delay,
            "target_count": targets.len(),
            "targets": targets.iter().map(|t| &t.name).collect::<Vec<_>>(),
        }),
        results: serde_json::to_value(&target_results).expect("serialize target results"),
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
        BenchCommand::HttpProxy {
            nodes,
            mix_delay_ms,
            runs,
            timeout_secs,
            warmup,
            with_delay,
            custom_targets,
        } => {
            run_http_proxy(HttpProxyParams {
                cli: &cli,
                node_count: *nodes,
                mix_delay_ms: *mix_delay_ms,
                runs: *runs,
                timeout_secs: *timeout_secs,
                warmup: *warmup,
                with_delay: *with_delay,
                custom_targets: custom_targets.as_ref(),
            })
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
