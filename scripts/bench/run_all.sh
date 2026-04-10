#!/usr/bin/env bash
# ---
# run_all.sh -- runs the benchmark suite
# ---
#
# Runs the full benchmark suite and stores results in
# scripts/bench/data/ as JSON. Generates all charts via gen_charts.py.
#
# Usage:
#   ./scripts/bench/run_all.sh                  # Run Tier 1 + Tier 2
#   ./scripts/bench/run_all.sh --tier1          # Criterion micro-benchmarks only
#   ./scripts/bench/run_all.sh --tier2          # Integration benchmarks only
#   ./scripts/bench/run_all.sh --tier3          # Real-world HTTP proxy benchmarks (requires network)
#   ./scripts/bench/run_all.sh --tier5          # Economics & gas profiling (requires Anvil/chain)
#   ./scripts/bench/run_all.sh --charts-only    # Regenerate charts from existing data
#   ./scripts/bench/run_all.sh --skip-build     # Skip cargo build steps
#   ./scripts/bench/run_all.sh --runs 3         # Multi-run aggregation (3 runs per bench)
#   ./scripts/bench/run_all.sh --release        # Build in release mode (slower build, faster bench)
#
# Output:
#   - JSON data:  scripts/bench/data/*.json
#   - Charts:     scripts/bench/charts/*.{png,svg}
#   - Criterion:  target/criterion/report/index.html
#
# Prerequisites:
#   - cargo, rustc (nightly recommended for criterion)
#   - python3 with matplotlib, numpy
#   - For multi-process: nox binary built (cargo build -p nox)
#   - For Tier 3: network access (real HTTP requests to external APIs)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NOX_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DATA_DIR="$SCRIPT_DIR/data"
CHART_DIR="$SCRIPT_DIR/charts"

# Colors for stderr
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()  { echo -e "${GREEN}[run_all]${NC} $*" >&2; }
warn() { echo -e "${YELLOW}[run_all]${NC} $*" >&2; }
err()  { echo -e "${RED}[run_all]${NC} $*" >&2; exit 1; }
hdr()  { echo -e "\n${CYAN}${BOLD}--- $* ---${NC}" >&2; }

# Defaults
RUN_TIER1=false
RUN_TIER2=false
RUN_TIER3=false
RUN_TIER4=false
RUN_TIER5=false
CHARTS_ONLY=false
SKIP_BUILD=false
RELEASE_MODE=false
NUM_RUNS=1

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --tier1)       RUN_TIER1=true; shift ;;
        --tier2)       RUN_TIER2=true; shift ;;
        --tier3)       RUN_TIER3=true; shift ;;
        --tier4)       RUN_TIER4=true; shift ;;
        --tier5)       RUN_TIER5=true; shift ;;
        --charts-only) CHARTS_ONLY=true; shift ;;
        --skip-build)  SKIP_BUILD=true; shift ;;
        --release)     RELEASE_MODE=true; shift ;;
        --runs)        NUM_RUNS="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--tier1] [--tier2] [--tier3] [--tier4] [--tier5] [--charts-only] [--skip-build] [--release] [--runs N]"
            exit 0
            ;;
        *) err "Unknown argument: $1" ;;
    esac
done

# If no tier specified, run tiers 1+2 (tier 3/4 are opt-in)
if ! $RUN_TIER1 && ! $RUN_TIER2 && ! $RUN_TIER3 && ! $RUN_TIER4 && ! $RUN_TIER5 && ! $CHARTS_ONLY; then
    RUN_TIER1=true
    RUN_TIER2=true
fi

# Build profile
# Note: cargo maps the "dev" profile to target/debug/, not target/dev/
if $RELEASE_MODE; then
    CARGO_PROFILE="--release"
    PROFILE_NAME="release"
else
    CARGO_PROFILE=""
    PROFILE_NAME="debug"
fi

RUNS_FLAG=""
if [ "$NUM_RUNS" -gt 1 ]; then
    RUNS_FLAG="--runs $NUM_RUNS"
fi

mkdir -p "$DATA_DIR" "$CHART_DIR"

# Record system info
hdr "System Information"
log "CPU:     $(grep 'model name' /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs || echo 'unknown')"
log "RAM:     $(awk '/MemTotal/ {printf "%.1f GB", $2/1048576}' /proc/meminfo 2>/dev/null || echo 'unknown')"
log "Kernel:  $(uname -r)"
log "Rust:    $(rustc --version 2>/dev/null || echo 'not found')"
log "Git:     $(cd "$NOX_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
log "Profile: $PROFILE_NAME"
log "Runs:    $NUM_RUNS"
log "Data:    $DATA_DIR"
log "Charts:  $CHART_DIR"

# Track timing
BENCH_START=$(date +%s)
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

run_bench() {
    local name="$1"
    shift
    local start_ts
    start_ts=$(date +%s)
    log "Running: $name"
    if "$@"; then
        local elapsed=$(( $(date +%s) - start_ts ))
        log "  ${GREEN}PASS${NC} ($name, ${elapsed}s)"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        local elapsed=$(( $(date +%s) - start_ts ))
        warn "  ${RED}FAIL${NC} ($name, ${elapsed}s) -- continuing..."
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

skip_bench() {
    warn "  SKIP: $1"
    SKIP_COUNT=$((SKIP_COUNT + 1))
}

# ---
# Build
# ---

if ! $CHARTS_ONLY && ! $SKIP_BUILD; then
    hdr "Building"

    if $RUN_TIER2; then
        log "Building nox_bench (features: dev-node)..."
        (cd "$NOX_ROOT" && cargo build $CARGO_PROFILE -p nox-sim --bin nox_bench --features dev-node 2>&1 | tail -5) >&2

        log "Building nox_bench (features: dev-node,hop-metrics)..."
        (cd "$NOX_ROOT" && cargo build $CARGO_PROFILE -p nox-sim --bin nox_bench --features "dev-node,hop-metrics" 2>&1 | tail -5) >&2

        log "Building nox_multiprocess_bench..."
        (cd "$NOX_ROOT" && cargo build $CARGO_PROFILE -p nox-sim --bin nox_multiprocess_bench --features dev-node 2>&1 | tail -5) >&2

        log "Building nox binary (for multi-process)..."
        (cd "$NOX_ROOT" && cargo build --release -p nox 2>&1 | tail -5) >&2
    fi

    log "Build complete."
fi

NOX_BENCH="$NOX_ROOT/target/$PROFILE_NAME/nox_bench"
NOX_BENCH_HOP="$NOX_ROOT/target/$PROFILE_NAME/nox_bench"
MP_BENCH="$NOX_ROOT/target/$PROFILE_NAME/nox_multiprocess_bench"
NOX_BIN="$NOX_ROOT/target/release/nox"

# ---
# Tier 1: Criterion Micro-Benchmarks
# ---

if $RUN_TIER1 && ! $CHARTS_ONLY; then
    hdr "Tier 1: Criterion Micro-Benchmarks"

    log "Running sphinx_bench (nox-crypto)..."
    run_bench "sphinx_bench" \
        cargo bench --bench sphinx_bench -p nox-crypto

    log "Running surb_bench (nox-crypto)..."
    run_bench "surb_bench" \
        cargo bench --bench surb_bench -p nox-crypto

    log "Running pow_bench (nox-crypto)..."
    run_bench "pow_bench" \
        cargo bench --bench pow_bench -p nox-crypto

    log "Running crypto_bench (darkpool-crypto)..."
    run_bench "crypto_bench" \
        cargo bench --bench crypto_bench -p darkpool-crypto

    log "Running protocol_bench (nox-core)..."
    run_bench "protocol_bench" \
        cargo bench --bench protocol_bench -p nox-core

    log "Criterion reports: target/criterion/report/index.html"
fi

# ---
# Tier 2: Integration Benchmarks (nox_bench -- in-process)
# ---

if $RUN_TIER2 && ! $CHARTS_ONLY; then
    hdr "Tier 2: In-Process Integration Benchmarks"

    # --- Latency CDF (with mix delay) ---
    log "Latency CDF (1ms delay, 5K packets, 5 nodes)..."
    run_bench "latency_cdf" bash -c \
        "\"$NOX_BENCH\" $RUNS_FLAG latency --nodes 5 --packets 5000 --hops 3 \
         --mix-delay-ms 1.0 --concurrency 50 --warmup 50 --raw-latencies \
         > \"$DATA_DIR/latency_cdf.json\""

    # --- Latency CDF (no delay) ---
    log "Latency CDF (0ms delay, 5K packets, 5 nodes)..."
    run_bench "latency_cdf_nodelay" bash -c \
        "\"$NOX_BENCH\" $RUNS_FLAG latency --nodes 5 --packets 5000 --hops 3 \
         --mix-delay-ms 0.0 --concurrency 50 --warmup 50 --raw-latencies \
         > \"$DATA_DIR/latency_cdf_nodelay.json\""

    # --- Throughput sweep (in-process) ---
    log "Throughput sweep (5 nodes, 10s per step)..."
    run_bench "throughput_sweep" bash -c \
        "\"$NOX_BENCH\" $RUNS_FLAG throughput --nodes 5 --duration 10 \
         --target-pps 100,500,1000,2000,5000 --hops 3 \
         > \"$DATA_DIR/throughput_sweep.json\""

    # --- SURB RTT ---
    log "SURB RTT (5 nodes, 500 round-trips)..."
    run_bench "surb_rtt" bash -c \
        "\"$NOX_BENCH\" $RUNS_FLAG surb-rtt --nodes 5 --packets 500 --hops 3 \
         --mix-delay-ms 1.0 --concurrency 25 --raw-latencies \
         > \"$DATA_DIR/surb_rtt.json\""

    # --- SURB RTT FEC comparison ---
    log "SURB RTT FEC comparison (5 nodes, 100 round-trips, 10KB response)..."
    run_bench "surb_rtt_fec" bash -c \
        "\"$NOX_BENCH\" $RUNS_FLAG surb-rtt-fec --nodes 5 --packets 100 --hops 3 \
         --mix-delay-ms 1.0 --concurrency 10 --response-size 10240 \
         --fec-ratio 0.3 --raw-latencies \
         > \"$DATA_DIR/surb_rtt_fec.json\""

    # --- Per-hop breakdown (requires hop-metrics feature) ---
    log "Per-hop breakdown (5 nodes, 500 packets, hop-metrics)..."
    run_bench "per_hop" bash -c \
        "cargo run -p nox-sim --bin nox_bench --features 'dev-node,hop-metrics' \
         $CARGO_PROFILE -- $RUNS_FLAG per-hop --nodes 5 --packets 500 --hops 3 \
         > \"$DATA_DIR/per_hop_breakdown.json\""

    # --- Latency vs delay sweep ---
    log "Latency vs delay sweep (0, 1, 5, 10, 50, 100ms)..."
    DELAY_RESULTS="[]"
    for DELAY in 0 1 5 10 50 100; do
        log "  delay=${DELAY}ms..."
        RESULT=$("$NOX_BENCH" $RUNS_FLAG latency --nodes 5 --packets 2000 --hops 3 \
            --mix-delay-ms "$DELAY" --concurrency 50 --warmup 50 2>/dev/null || echo '{}')
        if [ "$RESULT" != "{}" ]; then
            DELAY_RESULTS=$(echo "$DELAY_RESULTS" | python3 -c "
import sys, json
arr = json.load(sys.stdin)
arr.append(json.loads('''$RESULT'''))
json.dump(arr, sys.stdout)
" 2>/dev/null || echo "$DELAY_RESULTS")
        fi
    done
    echo "$DELAY_RESULTS" | python3 -c "
import sys, json
data = json.load(sys.stdin)
json.dump(data, sys.stdout, indent=2)
" > "$DATA_DIR/latency_vs_delay.json" 2>/dev/null && \
        log "  Saved latency_vs_delay.json (${#DELAY_RESULTS} entries)" || \
        warn "  Failed to save latency_vs_delay.json"
    PASS_COUNT=$((PASS_COUNT + 1))

    # ---
    # Tier 2: Multi-Process Benchmarks
    # ---

    hdr "Tier 2: Multi-Process Benchmarks"

    if [ -f "$NOX_BIN" ]; then
        # --- MP Throughput sweep ---
        log "MP throughput sweep (10 nodes, 10s per step)..."
        run_bench "mp_throughput" bash -c \
            "\"$MP_BENCH\" --nox-binary \"$NOX_BIN\" throughput \
             --nodes 10 --duration 10 --target-pps 50,100,200,500,1000 \
             > \"$DATA_DIR/mp_throughput_sweep.json\""

        # --- MP Scaling ---
        log "MP scaling (5,10,25,50 nodes, 200 packets each)..."
        run_bench "mp_scaling" bash -c \
            "\"$MP_BENCH\" --nox-binary \"$NOX_BIN\" scale \
             --node-counts 5,10,25,50 --packets 200 \
             > \"$DATA_DIR/scaling.json\""

        # --- MP Latency ---
        log "MP latency (10 nodes, 500 packets)..."
        run_bench "mp_latency" bash -c \
            "\"$MP_BENCH\" --nox-binary \"$NOX_BIN\" latency \
             --nodes 10 --packets 500 \
             > \"$DATA_DIR/mp_latency.json\""

        # --- MP Concurrency Sweep ---
        log "MP concurrency sweep (10 nodes, 200 target PPS, 15s per step)..."
        run_bench "mp_concurrency_sweep" bash -c \
            "\"$MP_BENCH\" --nox-binary \"$NOX_BIN\" concurrency-sweep \
             --nodes 10 --target-pps 200 \
             --concurrency-levels 10,25,50,100,200,500 \
             --duration 15 --warmup-secs 3 \
             > \"$DATA_DIR/concurrency_sweep.json\""
    else
        skip_bench "Multi-process benchmarks (nox binary not found at $NOX_BIN -- build with cargo build --release -p nox)"
    fi
fi

# ---
# Tier 3: Real-World HTTP Proxy Benchmarks
# ---

if $RUN_TIER3 && ! $CHARTS_ONLY; then
    hdr "Tier 3: Real-World HTTP Proxy Benchmarks"

    if ! $SKIP_BUILD; then
        log "Building nox_realworld_bench..."
        (cd "$NOX_ROOT" && cargo build $CARGO_PROFILE -p nox-sim --bin nox_realworld_bench --features dev-node 2>&1 | tail -5) >&2

        log "Building nox binary (release, for multi-process mesh)..."
        (cd "$NOX_ROOT" && cargo build --release -p nox 2>&1 | tail -5) >&2
    fi

    RW_BENCH="$NOX_ROOT/target/$PROFILE_NAME/nox_realworld_bench"

    if [ -f "$RW_BENCH" ] && [ -f "$NOX_BIN" ]; then
        # --- HTTP proxy: Direct vs Mixnet (no delay) vs Mixnet (1ms delay) ---
        log "HTTP proxy benchmark (5 nodes, 5 runs, 7 targets)..."
        run_bench "http_proxy" bash -c \
            "\"$RW_BENCH\" --nox-binary \"$NOX_BIN\" http-proxy \
             --nodes 5 --runs 5 --warmup 1 --timeout-secs 60 --with-delay \
             > \"$DATA_DIR/http_proxy.json\""
    else
        [ ! -f "$RW_BENCH" ] && skip_bench "HTTP proxy (nox_realworld_bench not found at $RW_BENCH)"
        [ ! -f "$NOX_BIN" ] && skip_bench "HTTP proxy (nox binary not found at $NOX_BIN)"
    fi
fi

# ---
# Tier 4: Privacy & Anonymity Analytics
# ---

if $RUN_TIER4 && ! $CHARTS_ONLY; then
    hdr "Tier 4: Privacy & Anonymity Analytics"

    if ! $SKIP_BUILD; then
        log "Building nox_privacy_analytics..."
        (cd "$NOX_ROOT" && cargo build $CARGO_PROFILE -p nox-sim --bin nox_privacy_analytics --features dev-node 2>&1 | tail -5) >&2
    fi

    PRIV_BENCH="$NOX_ROOT/target/$PROFILE_NAME/nox_privacy_analytics"

    if [ -f "$PRIV_BENCH" ]; then
        # --- Timing Correlation (4.2.1-4.2.2) ---
        log "Timing correlation (10 nodes, 2000 packets, 1ms delay)..."
        run_bench "timing_correlation" bash -c \
            "\"$PRIV_BENCH\" timing-correlation \
             --nodes 10 --packets 2000 --hops 3 --mix-delay-ms 1.0 \
             --concurrency 50 --raw-pairs \
             > \"$DATA_DIR/timing_correlation.json\""

        # --- Entropy vs Delay (4.1.1-4.1.3) ---
        log "Entropy vs delay sweep (10 nodes, 1000 packets/step, 9 delays)..."
        run_bench "entropy" bash -c \
            "\"$PRIV_BENCH\" entropy \
             --nodes 10 --packets 1000 --hops 3 --concurrency 50 \
             --delays-ms 0,0.5,1,2,5,10,20,50,100 \
             > \"$DATA_DIR/entropy.json\""

        # --- FEC Recovery (4.5.1-4.5.3) ---
        log "FEC recovery curve (D=10, ratio=0.3, 1000 trials/rate, 9 loss rates)..."
        run_bench "fec_recovery" bash -c \
            "\"$PRIV_BENCH\" fec-recovery \
             --data-shards 10 --fec-ratio 0.3 --trials 1000 \
             --response-size 307200 \
             --loss-rates 0.0,0.05,0.1,0.15,0.2,0.25,0.3,0.4,0.5 \
             > \"$DATA_DIR/fec_recovery.json\""

        # --- Unlinkability (4.2.3-4.2.4) ---
        log "Unlinkability test (10 nodes, 2000 packets/step, 5 delays)..."
        run_bench "unlinkability" bash -c \
            "\"$PRIV_BENCH\" unlinkability \
             --nodes 10 --packets 2000 --hops 3 --concurrency 50 \
             --delays-ms 0.5,1,5,10,50 \
             > \"$DATA_DIR/unlinkability.json\""

        # --- Attack Simulation (4.4.1-4.4.3) ---
        log "Attack simulations (15 nodes, 1000 packets/round, 10 rounds)..."
        run_bench "attack_sim" bash -c \
            "\"$PRIV_BENCH\" attack-sim \
             --nodes 15 --packets 1000 --hops 3 --mix-delay-ms 1.0 \
             --concurrency 50 --rounds 10 \
             > \"$DATA_DIR/attack_sim.json\""

        # --- FEC Ratio Sweep (4.5.4) ---
        log "FEC ratio sweep (D=10, ratios 0.1-2.0, 1000 trials/rate)..."
        run_bench "fec_ratio_sweep" bash -c \
            "\"$PRIV_BENCH\" fec-ratio-sweep \
             --data-shards 10 --trials 1000 --response-size 307200 \
             --loss-rate 0.1 --fec-ratios 0.1,0.2,0.3,0.5,0.7,1.0,1.5,2.0 \
             > \"$DATA_DIR/fec_ratio_sweep.json\""

        # --- FEC vs ARQ (4.5.5) ---
        log "FEC vs ARQ comparison..."
        run_bench "fec_vs_arq" bash -c \
            "\"$PRIV_BENCH\" fec-vs-arq \
             --data-shards 10 --fec-ratio 0.3 --trials 1000 \
             --response-size 307200 \
             --loss-rates 0.0,0.05,0.1,0.15,0.2,0.25,0.3 \
             > \"$DATA_DIR/fec_vs_arq.json\""

        # --- Cover Traffic Analysis (4.3.1-4.3.2) ---
        log "Cover traffic analysis (10 nodes, 2000 packets)..."
        run_bench "cover_traffic" bash -c \
            "\"$PRIV_BENCH\" cover-traffic \
             --nodes 10 --packets 2000 --hops 3 --mix-delay-ms 1.0 \
             --concurrency 50 \
             > \"$DATA_DIR/cover_traffic.json\""

        # --- Cover Analysis (extended) ---
        log "Cover analysis (varying cover rates)..."
        run_bench "cover_analysis" bash -c \
            "\"$PRIV_BENCH\" cover-analysis \
             --nodes 10 --packets 1000 --hops 3 --mix-delay-ms 1.0 \
             --concurrency 50 \
             > \"$DATA_DIR/cover_analysis.json\""

        # --- Replay Detection Benchmark ---
        log "Replay detection (bloom filter accuracy)..."
        run_bench "replay_detection" bash -c \
            "\"$PRIV_BENCH\" replay-detection \
             --capacity 1000000 --fp-rate 0.001 \
             --test-insertions 100000 \
             > \"$DATA_DIR/replay_detection.json\""

        # --- PoW DoS Mitigation ---
        log "PoW DoS mitigation analysis..."
        run_bench "pow_dos" bash -c \
            "\"$PRIV_BENCH\" pow-dos \
             --difficulties 0,1,2,3,4,5,6,8,10,12 \
             --samples 1000 \
             > \"$DATA_DIR/pow_dos.json\""

        # --- Entropy vs Users ---
        log "Entropy vs user count (10-1000 users)..."
        run_bench "entropy_vs_users" bash -c \
            "\"$PRIV_BENCH\" entropy-vs-users \
             --nodes 10 --hops 3 --mix-delay-ms 1.0 \
             --user-counts 10,25,50,100,250,500,1000 \
             --packets-per-user 20 \
             > \"$DATA_DIR/entropy_vs_users.json\""

        # --- Entropy vs Cover Traffic ---
        log "Entropy vs cover traffic rate..."
        run_bench "entropy_vs_cover" bash -c \
            "\"$PRIV_BENCH\" entropy-vs-cover \
             --nodes 10 --packets 1000 --hops 3 --mix-delay-ms 1.0 \
             --cover-ratios 0.0,0.1,0.25,0.5,1.0,2.0 \
             > \"$DATA_DIR/entropy_vs_cover.json\""

        # --- Traffic Levels ---
        log "Traffic level scenarios..."
        run_bench "traffic_levels" bash -c \
            "\"$PRIV_BENCH\" traffic-levels \
             --nodes 10 --hops 3 --mix-delay-ms 1.0 \
             --levels low,medium,high,burst \
             > \"$DATA_DIR/traffic_levels.json\""

        # --- Combined Anonymity Summary ---
        log "Combined anonymity metrics..."
        run_bench "combined_anonymity" bash -c \
            "\"$PRIV_BENCH\" combined-anonymity \
             --nodes 10 --packets 2000 --hops 3 --mix-delay-ms 1.0 \
             --concurrency 50 \
             > \"$DATA_DIR/combined_anonymity.json\""
    else
        skip_bench "Privacy analytics (nox_privacy_analytics not found at $PRIV_BENCH)"
    fi
fi

# ---
# Tier 5: Economics & Gas Profiling
# ---

if $RUN_TIER5 && ! $CHARTS_ONLY; then
    hdr "Tier 5: Economics & Gas Profiling"

    if ! $SKIP_BUILD; then
        log "Building nox_economics..."
        (cd "$NOX_ROOT" && cargo build $CARGO_PROFILE -p nox-sim --bin nox_economics --features dev-node 2>&1 | tail -5) >&2
    fi

    ECON_BENCH="$NOX_ROOT/target/$PROFILE_NAME/nox_economics"

    if [ -f "$ECON_BENCH" ]; then
        # --- Gas Profile (per-circuit gas consumption) ---
        log "Gas profile (7 circuit types)..."
        run_bench "gas_profile" bash -c \
            "\"$ECON_BENCH\" gas-profile \
             > \"$DATA_DIR/gas_profile.json\""

        # --- DeFi Pipeline E2E Timing ---
        log "DeFi pipeline (proof gen → Sphinx → mixnet → chain exec)..."
        run_bench "defi_pipeline" bash -c \
            "\"$ECON_BENCH\" defi-pipeline \
             > \"$DATA_DIR/defi_pipeline.json\""

        # --- Economics (break-even analysis) ---
        log "Economics analysis (break-even, profitability)..."
        run_bench "economics" bash -c \
            "\"$ECON_BENCH\" economics \
             > \"$DATA_DIR/economics.json\""

        # --- Operational Costs ---
        log "Operational cost breakdown..."
        run_bench "operational" bash -c \
            "\"$ECON_BENCH\" operational \
             > \"$DATA_DIR/operational.json\""
    else
        skip_bench "Economics (nox_economics not found at $ECON_BENCH)"
    fi
fi

# ---
# Chart Generation
# ---

hdr "Chart Generation"

if command -v python3 &>/dev/null; then
    # Check for matplotlib
    if python3 -c "import matplotlib" 2>/dev/null; then
        log "Generating charts from $DATA_DIR..."
        run_bench "gen_charts" \
            python3 "$SCRIPT_DIR/gen_charts.py" --all \
                --data-dir "$DATA_DIR" --out-dir "$CHART_DIR"
    else
        skip_bench "Charts (python3 matplotlib not installed -- pip install matplotlib numpy)"
    fi
else
    skip_bench "Charts (python3 not found)"
fi

# ---
# Summary
# ---

TOTAL_ELAPSED=$(( $(date +%s) - BENCH_START ))
TOTAL_MIN=$((TOTAL_ELAPSED / 60))
TOTAL_SEC=$((TOTAL_ELAPSED % 60))

hdr "Summary"
log "Total time:  ${TOTAL_MIN}m ${TOTAL_SEC}s"
log "Passed:      $PASS_COUNT"
log "Failed:      $FAIL_COUNT"
log "Skipped:     $SKIP_COUNT"
log ""
log "Data:        $DATA_DIR/"
log "Charts:      $CHART_DIR/"
log "Criterion:   $NOX_ROOT/target/criterion/report/index.html"
log ""

if [ "$FAIL_COUNT" -gt 0 ]; then
    warn "${FAIL_COUNT} benchmark(s) failed. Check output above for details."
    exit 1
fi

log "${GREEN}All benchmarks complete.${NC}"
