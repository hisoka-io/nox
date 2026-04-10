//! Shared types and statistics for NOX benchmark binaries.

use serde::Serialize;

/// Top-level JSON envelope emitted by every benchmark subcommand.
#[derive(Serialize)]
pub struct BenchResult {
    pub benchmark: String,
    pub mode: String,
    pub hardware: HardwareSpec,
    pub timestamp: String,
    pub git_commit: String,
    pub params: serde_json::Value,
    pub results: serde_json::Value,
}

/// Machine metadata captured at benchmark start.
#[derive(Serialize)]
pub struct HardwareSpec {
    pub cpu_model: String,
    pub physical_cores: usize,
    pub logical_threads: usize,
    pub ram_gb: f64,
    pub os: String,
    pub rust_version: String,
    pub cpu_governor: String,
}

pub fn detect_hardware() -> HardwareSpec {
    let cpu_model = read_proc_field("/proc/cpuinfo", "model name");
    let physical_cores = detect_physical_cores().unwrap_or(1);

    let logical_threads = std::thread::available_parallelism()
        .map(std::num::NonZero::get)
        .unwrap_or(1);

    let ram_gb = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines().find(|l| l.starts_with("MemTotal")).and_then(|l| {
                l.split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse::<f64>().ok())
            })
        })
        .map_or(0.0, |kb| kb / 1_048_576.0);

    let os = std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|s| {
            s.lines().find(|l| l.starts_with("PRETTY_NAME")).map(|l| {
                l.split('=')
                    .nth(1)
                    .unwrap_or("Linux")
                    .trim_matches('"')
                    .to_string()
            })
        })
        .unwrap_or_else(|| "Linux".into());

    let rust_version = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map_or_else(String::new, |s| s.trim().to_string());

    let cpu_governor =
        std::fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
            .map_or_else(|_| "unknown".into(), |s| s.trim().to_string());

    HardwareSpec {
        cpu_model,
        physical_cores,
        logical_threads,
        ram_gb,
        os,
        rust_version,
        cpu_governor,
    }
}

fn read_proc_field(path: &str, field_prefix: &str) -> String {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with(field_prefix))
                .map(|l| l.split(':').nth(1).unwrap_or("unknown").trim().to_string())
        })
        .unwrap_or_else(|| "unknown".into())
}

fn detect_physical_cores() -> Option<usize> {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    let mut cores = std::collections::HashSet::new();
    let mut current_physical: Option<String> = None;

    for line in cpuinfo.lines() {
        if line.starts_with("physical id") {
            current_physical = line.split(':').nth(1).map(|s| s.trim().to_string());
        } else if line.starts_with("core id") {
            if let (Some(phys), Some(core)) = (
                &current_physical,
                line.split(':').nth(1).map(|s| s.trim().to_string()),
            ) {
                cores.insert(format!("{phys}:{core}"));
            }
        }
    }

    if cores.is_empty() {
        None
    } else {
        Some(cores.len())
    }
}

#[must_use]
pub fn git_commit() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map_or_else(|| "unknown".into(), |s| s.trim().to_string())
}

#[must_use]
pub fn now_iso8601() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Latency distribution summary with percentiles and optional loss info.
#[derive(Serialize)]
pub struct LatencyStats {
    pub count: usize,
    pub min_us: u64,
    pub max_us: u64,
    pub mean_us: f64,
    pub p50_us: u64,
    pub p90_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub p999_us: u64,
    pub stddev_us: f64,
    pub loss_count: usize,
    pub loss_rate: f64,
}

/// Compute latency statistics from microsecond samples.
/// Uses Bessel-corrected variance (n-1) and NIST linear-interpolation percentiles.
pub fn compute_latency_stats(latencies_us: &mut [u64], total_sent: usize) -> LatencyStats {
    let loss_count = total_sent.saturating_sub(latencies_us.len());
    let loss_rate = if total_sent > 0 {
        loss_count as f64 / total_sent as f64
    } else {
        0.0
    };

    if latencies_us.is_empty() {
        return LatencyStats {
            count: 0,
            min_us: 0,
            max_us: 0,
            mean_us: 0.0,
            p50_us: 0,
            p90_us: 0,
            p95_us: 0,
            p99_us: 0,
            p999_us: 0,
            stddev_us: 0.0,
            loss_count,
            loss_rate,
        };
    }

    latencies_us.sort_unstable();
    let n = latencies_us.len();
    let sum: u64 = latencies_us.iter().sum();
    let mean = sum as f64 / n as f64;

    let variance: f64 = latencies_us
        .iter()
        .map(|&v| {
            let diff = v as f64 - mean;
            diff * diff
        })
        .sum::<f64>()
        / if n > 1 { (n - 1) as f64 } else { 1.0 };

    LatencyStats {
        count: n,
        min_us: latencies_us[0],
        max_us: latencies_us[n - 1],
        mean_us: mean,
        p50_us: percentile_interpolated(latencies_us, 50.0),
        p90_us: percentile_interpolated(latencies_us, 90.0),
        p95_us: percentile_interpolated(latencies_us, 95.0),
        p99_us: percentile_interpolated(latencies_us, 99.0),
        p999_us: percentile_interpolated(latencies_us, 99.9),
        stddev_us: variance.sqrt(),
        loss_count,
        loss_rate,
    }
}

/// Linear-interpolation percentile on a **sorted** slice.
fn percentile_interpolated(sorted: &[u64], p: f64) -> u64 {
    let n = sorted.len();
    if n == 0 {
        return 0;
    }
    if n == 1 {
        return sorted[0];
    }
    let rank = (p / 100.0) * (n - 1) as f64;
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;
    let frac = rank - lower as f64;

    let lo = sorted[lower.min(n - 1)] as f64;
    let hi = sorted[upper.min(n - 1)] as f64;
    (lo + frac * (hi - lo)).round() as u64
}

/// One data point from a throughput sweep.
#[derive(Serialize)]
pub struct ThroughputPoint {
    pub target_pps: usize,
    pub achieved_pps: f64,
    pub success_count: usize,
    pub fail_count: usize,
    pub loss_rate: f64,
    pub latency: LatencyStats,
}

/// One data point from a scaling sweep.
#[derive(Serialize)]
pub struct ScalePoint {
    pub node_count: usize,
    pub achieved_pps: f64,
    pub latency: LatencyStats,
}

/// One data point from a concurrency sweep.
#[derive(Serialize)]
pub struct ConcurrencyPoint {
    pub concurrency: usize,
    pub target_pps: usize,
    pub achieved_pps: f64,
    pub success_count: usize,
    pub fail_count: usize,
    pub loss_rate: f64,
    pub latency: LatencyStats,
}

/// Per-operation timing statistics (nanoseconds).
#[cfg(feature = "hop-metrics")]
#[derive(Serialize)]
pub struct OpStats {
    pub count: usize,
    pub min_ns: u64,
    pub max_ns: u64,
    pub mean_ns: f64,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
}

/// Aggregated per-hop breakdown.
#[cfg(feature = "hop-metrics")]
#[derive(Serialize)]
pub struct HopBreakdown {
    pub ecdh: OpStats,
    pub key_derive: OpStats,
    pub mac_verify: OpStats,
    pub routing_decrypt: OpStats,
    pub body_decrypt: OpStats,
    pub blinding: OpStats,
    pub total_sphinx: OpStats,
}

/// Compute per-operation nanosecond statistics.
#[cfg(feature = "hop-metrics")]
pub fn compute_op_stats(values: &mut [u64]) -> OpStats {
    if values.is_empty() {
        return OpStats {
            count: 0,
            min_ns: 0,
            max_ns: 0,
            mean_ns: 0.0,
            p50_ns: 0,
            p95_ns: 0,
            p99_ns: 0,
        };
    }
    values.sort_unstable();
    let n = values.len();
    let sum: u64 = values.iter().sum();
    let mean = sum as f64 / n as f64;

    OpStats {
        count: n,
        min_ns: values[0],
        max_ns: values[n - 1],
        mean_ns: mean,
        p50_ns: percentile_interpolated(values, 50.0),
        p95_ns: percentile_interpolated(values, 95.0),
        p99_ns: percentile_interpolated(values, 99.0),
    }
}

/// One data point on the entropy-vs-delay curve.
#[derive(Serialize)]
pub struct EntropyPoint {
    pub mix_delay_ms: f64,
    pub shannon_entropy_bits: f64,
    pub max_entropy_bits: f64,
    /// `H / H_max` (1.0 = perfect anonymity).
    pub normalised_entropy: f64,
    /// `2^H`.
    pub effective_anonymity_set: f64,
    /// `-log2(max(p_i))`. Worst-case metric.
    pub min_entropy_bits: f64,
    pub packet_count: usize,
    pub sender_count: usize,
}

/// Timing correlation analysis result.
#[derive(Serialize)]
pub struct CorrelationResult {
    /// Near 0 = good mixing, near 1 = timing leaks.
    pub pearson_r: f64,
    pub pearson_p_value: f64,
    pub spearman_rho: f64,
    pub mutual_information_bits: f64,
    pub sample_count: usize,
    pub mix_delay_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_pairs: Option<Vec<(u64, u64)>>,
}

/// Statistical unlinkability test result.
#[derive(Serialize)]
pub struct UnlinkabilityResult {
    pub mix_delay_ms: f64,
    pub traffic_pps: f64,
    /// Lower = more uniform = better mixing.
    pub ks_statistic: f64,
    /// p > 0.05 = cannot reject uniform hypothesis.
    pub ks_p_value: f64,
    pub chi_squared_statistic: f64,
    pub chi_squared_p_value: f64,
    pub sample_count: usize,
}

/// FEC recovery curve data point.
#[derive(Serialize)]
pub struct FecRecoveryPoint {
    pub loss_rate: f64,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub delivery_rate: f64,
    pub trials: usize,
    pub mean_fragments_received: f64,
}

/// FEC ratio sweep data point.
#[derive(Serialize)]
pub struct FecRatioPoint {
    pub fec_ratio: f64,
    pub loss_rate: f64,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub delivery_rate: f64,
    /// (D + P) / D.
    pub bandwidth_overhead: f64,
    pub trials: usize,
}

/// Optimal FEC ratio for a given loss rate to achieve target delivery.
#[derive(Serialize)]
pub struct FecOptimalRatio {
    pub loss_rate: f64,
    pub target_delivery: f64,
    pub min_ratio: Option<f64>,
    pub min_parity_shards: Option<usize>,
}

/// Cover traffic analysis data point.
#[derive(Serialize)]
pub struct CoverTrafficPoint {
    pub cover_rate_pps: f64,
    pub real_rate_pps: f64,
    pub total_packets: usize,
    pub real_packets: usize,
    pub cover_packets: usize,
    /// total / real. 1.0 = no cover.
    pub bandwidth_overhead: f64,
    pub traffic_entropy_bits: f64,
    /// entropy / log2(N). 1.0 = perfect indistinguishability.
    pub normalised_entropy: f64,
    pub duration_secs: f64,
}

/// Attack simulation result.
#[derive(Serialize)]
pub struct AttackResult {
    pub attack_type: String,
    pub params: serde_json::Value,
    pub entropy_under_attack: f64,
    pub baseline_entropy: f64,
    /// 1 - (attack / baseline). 0 = no impact, 1 = full deanon.
    pub entropy_reduction: f64,
    pub success_probability: f64,
    pub rounds: usize,
}

/// Replay detection benchmark result.
#[derive(Serialize)]
pub struct ReplayDetectionResult {
    pub implementation: String,
    pub unique_tags: usize,
    pub replay_attempts: usize,
    pub false_negatives: usize,
    pub false_positives: usize,
    pub false_positive_rate: f64,
    pub false_negative_rate: f64,
    pub insert_throughput_ops: f64,
    pub check_throughput_ops: f64,
    pub capacity: usize,
    pub configured_fp_rate: f64,
}

/// `PoW` `DoS` mitigation benchmark result.
#[derive(Serialize)]
pub struct PowDosResult {
    pub difficulty: u32,
    pub algorithm: String,
    pub mean_solve_us: f64,
    pub p50_solve_us: f64,
    pub p99_solve_us: f64,
    pub mean_verify_ns: f64,
    pub solve_throughput: f64,
    pub verify_throughput: f64,
    /// `solve_time / verify_time`.
    pub asymmetry_ratio: f64,
    pub trials: usize,
}

/// Entropy vs concurrent users data point.
#[derive(Serialize)]
pub struct EntropyVsUsersPoint {
    pub concurrent_users: usize,
    pub shannon_entropy_bits: f64,
    pub max_entropy_bits: f64,
    pub normalised_entropy: f64,
    pub effective_anonymity_set: f64,
    pub delivery_rate: f64,
}

/// Anonymity at varying traffic levels.
#[derive(Serialize)]
pub struct TrafficLevelPoint {
    pub traffic_pps: f64,
    pub achieved_pps: f64,
    pub shannon_entropy_bits: f64,
    pub max_entropy_bits: f64,
    pub normalised_entropy: f64,
    pub effective_anonymity_set: f64,
    pub delivery_rate: f64,
    pub packet_count: usize,
    pub mean_latency_us: f64,
}

/// Cover traffic comprehensive analysis data point.
#[derive(Serialize)]
pub struct CoverAnalysisPoint {
    pub cover_rate_pps: f64,

    pub ks_statistic: f64,
    pub ks_p_value: f64,
    pub chi_squared_statistic: f64,
    pub chi_squared_p_value: f64,

    pub configured_lambda: f64,
    pub observed_lambda: f64,
    /// `observed / configured` (should be ~1.0).
    pub lambda_ratio: f64,
    /// Coefficient of variation (stddev / mean).
    pub rate_cv: f64,

    pub cpu_time_secs: f64,
    pub rss_delta_bytes: u64,
    pub bandwidth_bytes: u64,
    pub bandwidth_overhead: f64,
    pub duration_secs: f64,
}

/// Combined mixnet x UTXO anonymity data point.
/// Models composition of mixnet-layer (sender-IP) and UTXO-layer (sender-note)
/// privacy under independent, correlated, and partial scenarios.
#[derive(Serialize)]
pub struct CombinedAnonymityPoint {
    pub utxo_pool_size: usize,
    pub h_utxo_bits: f64,
    pub mixnet_nodes: usize,
    pub h_mixnet_bits: f64,
    pub h_mixnet_max_bits: f64,
    pub mixnet_normalised: f64,
    /// `H_utxo + H_mixnet` (post-deposit operations).
    pub h_combined_independent_bits: f64,
    /// `H_mixnet` only (deposits reveal identity).
    pub h_combined_correlated_bits: f64,
    /// Adjusted for `recipientP_x` tag linkage.
    pub h_combined_partial_bits: f64,
    pub effective_set_independent: f64,
    pub effective_set_correlated: f64,
}

/// Gas cost profile for a single circuit type.
#[derive(Serialize)]
pub struct GasProfilePoint {
    pub circuit: String,
    pub gas_used: u64,
    pub gas_limit: u64,
    pub proof_gen_ms: u64,
    pub public_inputs_count: usize,
    pub merkle_inserts: u32,
    pub nullifiers_spent: u32,
    pub relayer_paid: bool,
    pub runs: usize,
}

/// Full `DeFi` pipeline timing breakdown for one operation.
#[derive(Serialize)]
pub struct DefiPipelinePoint {
    pub operation: String,
    pub transport: String,
    pub proof_gen_ms: u64,
    pub sphinx_build_ms: u64,
    pub mixnet_transit_ms: u64,
    pub surb_response_ms: u64,
    pub chain_exec_ms: u64,
    pub total_e2e_ms: u64,
    pub gas_used: u64,
}

/// Economic analysis at a specific gas/ETH price pair.
#[derive(Serialize)]
pub struct EconomicsPoint {
    pub circuit: String,
    pub eth_price_usd: f64,
    pub gas_price_gwei: f64,
    pub gas_used: u64,
    pub cost_usd: f64,
    pub fee_revenue_usd: f64,
    pub margin_percent: f64,
    pub is_profitable: bool,
}

/// Break-even and operational economics summary.
#[derive(Serialize)]
pub struct BreakEvenAnalysis {
    pub vps_cost_usd: f64,
    pub eth_price_usd: f64,
    pub gas_price_gwei: f64,
    pub avg_profit_per_tx_usd: f64,
    pub txs_per_day_break_even: f64,
    pub revenue_per_1k_txs_usd: f64,
    pub monthly_revenue_100_txs_day_usd: f64,
    pub monthly_revenue_1k_txs_day_usd: f64,
}

/// Privacy premium: private vs public operation cost.
#[derive(Serialize)]
pub struct PrivacyPremiumPoint {
    pub operation: String,
    pub private_gas: u64,
    pub public_gas: u64,
    pub premium_ratio: f64,
    pub private_cost_usd: f64,
    pub public_cost_usd: f64,
    pub premium_usd: f64,
}

/// Operational metric for a single measurement.
#[derive(Serialize)]
pub struct OperationalPoint {
    pub metric: String,
    pub value: f64,
    pub unit: String,
    pub context: String,
}

/// FEC vs ARQ comparison data point.
#[derive(Serialize)]
pub struct FecVsArqPoint {
    pub loss_rate: f64,
    pub fec_delivery_rate: f64,
    pub fec_bandwidth_shards: usize,
    pub fec_latency_multiplier: f64,
    pub arq_delivery_rate: f64,
    pub arq_mean_bandwidth_shards: f64,
    pub arq_mean_round_trips: f64,
    pub arq_max_retries: usize,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub trials: usize,
}
