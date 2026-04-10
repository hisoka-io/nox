#!/usr/bin/env bash
# Profile-Guided Optimization (PGO) build for NOX.
#
# Two-pass compilation:
#   1. Instrumented build - runs benchmarks to generate profiling data
#   2. Optimized build - uses profiling data for better codegen decisions
#
# Requirements:
#   - Rust nightly (for -Cprofile-generate / -Cprofile-use)
#   - llvm-profdata (ships with rustup's llvm-tools component)
#
# Usage:
#   ./scripts/pgo_build.sh            # full PGO build
#   ./scripts/pgo_build.sh --release  # same (default)
#   ./scripts/pgo_build.sh --bench    # use bench profile instead of release

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PGO_DIR="$ROOT_DIR/target/pgo"
PROFILE_DIR="$PGO_DIR/profiles"
MERGED_PROF="$PGO_DIR/merged.profdata"
PROFILE="${1:---release}"

# Resolve the cargo profile flag
case "$PROFILE" in
  --bench)
    CARGO_PROFILE="--profile bench"
    ;;
  --release|*)
    CARGO_PROFILE="--release"
    ;;
esac

echo "=== NOX PGO Build ==="
echo "Profile:     $PROFILE"
echo "PGO dir:     $PGO_DIR"
echo ""

# ---------------------------------------------------------------------------
# Step 0: Check toolchain prerequisites
# ---------------------------------------------------------------------------
if ! rustup component list --installed 2>/dev/null | grep -q llvm-tools; then
  echo "Installing llvm-tools component..."
  rustup component add llvm-tools
fi

LLVM_PROFDATA="$(rustup run stable sh -c 'ls "$(rustc --print sysroot)"/lib/rustlib/*/bin/llvm-profdata 2>/dev/null | head -1' || true)"
if [[ -z "$LLVM_PROFDATA" ]]; then
  echo "ERROR: llvm-profdata not found. Install with: rustup component add llvm-tools"
  exit 1
fi
echo "llvm-profdata: $LLVM_PROFDATA"

# ---------------------------------------------------------------------------
# Step 1: Instrumented build (profile-generate)
# ---------------------------------------------------------------------------
echo ""
echo "=== Pass 1: Instrumented build ==="
rm -rf "$PROFILE_DIR"
mkdir -p "$PROFILE_DIR"

RUSTFLAGS="-Cprofile-generate=$PROFILE_DIR" \
  cargo build $CARGO_PROFILE --workspace --features dev-node

# ---------------------------------------------------------------------------
# Step 2: Run workloads to generate profiling data
# ---------------------------------------------------------------------------
echo ""
echo "=== Pass 1: Generating profile data via benchmarks ==="

# Run crypto benchmarks (exercises Poseidon, AES, BJJ, ECDH, Sphinx hot paths)
RUSTFLAGS="-Cprofile-generate=$PROFILE_DIR" \
  cargo bench --bench crypto_bench -- --sample-size 20 2>/dev/null || true

RUSTFLAGS="-Cprofile-generate=$PROFILE_DIR" \
  cargo bench --bench sphinx_bench -- --sample-size 20 2>/dev/null || true

RUSTFLAGS="-Cprofile-generate=$PROFILE_DIR" \
  cargo bench --bench surb_bench -- --sample-size 20 2>/dev/null || true

# Run unit tests (broader code coverage)
RUSTFLAGS="-Cprofile-generate=$PROFILE_DIR" \
  cargo test --workspace -- --test-threads=4 2>/dev/null || true

echo "Profile data collected: $(find "$PROFILE_DIR" -name '*.profraw' | wc -l) raw profiles"

# ---------------------------------------------------------------------------
# Step 3: Merge profiles
# ---------------------------------------------------------------------------
echo ""
echo "=== Merging profiles ==="
"$LLVM_PROFDATA" merge -o "$MERGED_PROF" "$PROFILE_DIR"
echo "Merged profile: $(du -h "$MERGED_PROF" | cut -f1)"

# ---------------------------------------------------------------------------
# Step 4: Optimized build (profile-use)
# ---------------------------------------------------------------------------
echo ""
echo "=== Pass 2: Optimized build ==="
RUSTFLAGS="-Cprofile-use=$MERGED_PROF -Cllvm-args=-pgo-warn-missing-function" \
  cargo build $CARGO_PROFILE --workspace --features dev-node

echo ""
echo "=== PGO build complete ==="
echo "Binary: target/$(echo $CARGO_PROFILE | sed 's/--//' | sed 's/profile //')/nox"
echo ""
echo "To verify improvement, run benchmarks against the PGO binary."
