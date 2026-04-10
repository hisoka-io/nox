#!/usr/bin/env bash
# Multi-process benchmark runner
#
# Builds the nox binary (release) and the bench driver, then runs
# the specified benchmark subcommand.
#
# Usage:
#   ./scripts/bench/run_multiprocess.sh latency --nodes 10 --packets 500
#   ./scripts/bench/run_multiprocess.sh scale --node-counts 5,10,25,50
#   ./scripts/bench/run_multiprocess.sh throughput --nodes 10 --target-pps 100,500,1000
#
# Results (JSON) go to stdout. Pipe to a file for archival:
#   ./scripts/bench/run_multiprocess.sh latency --nodes 25 > results/latency_25.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NOX_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
WORKSPACE_ROOT="$(cd "$NOX_ROOT/../.." && pwd)"

# Colors for stderr
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[bench]${NC} $*" >&2; }
warn() { echo -e "${YELLOW}[bench]${NC} $*" >&2; }
err() { echo -e "${RED}[bench]${NC} $*" >&2; exit 1; }

# Build nox binary (release for accurate numbers)
log "Building nox binary (release)..."
(cd "$WORKSPACE_ROOT" && cargo build --release -p nox 2>&1 | tail -3) >&2

NOX_BIN="$WORKSPACE_ROOT/target/release/nox"
if [ ! -f "$NOX_BIN" ]; then
    err "nox binary not found at $NOX_BIN"
fi

log "nox binary: $NOX_BIN ($(du -h "$NOX_BIN" | cut -f1))"

# Build bench driver
log "Building nox_multiprocess_bench..."
(cd "$WORKSPACE_ROOT" && cargo build --release -p nox-sim --bin nox_multiprocess_bench --features dev-node 2>&1 | tail -3) >&2

BENCH_BIN="$WORKSPACE_ROOT/target/release/nox_multiprocess_bench"
if [ ! -f "$BENCH_BIN" ]; then
    err "nox_multiprocess_bench binary not found at $BENCH_BIN"
fi

# Record system info
log "Hardware: $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)"
log "RAM: $(awk '/MemTotal/ {printf "%.1f GB", $2/1048576}' /proc/meminfo)"
log "Kernel: $(uname -r)"
log "Rust: $(rustc --version)"
log "Git: $(cd "$NOX_ROOT" && git rev-parse --short HEAD)"
log ""

# Run benchmark -- pass all arguments through
log "Running: nox_multiprocess_bench $*"
log "---"

exec "$BENCH_BIN" --nox-binary "$NOX_BIN" "$@"
