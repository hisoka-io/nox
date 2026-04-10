#!/usr/bin/env bash
# scripts/bootstrap-artifacts.sh
#
# Clones darkpool-v2, compiles contracts and circuits, and copies the
# resulting artifacts into this repo. Idempotent -- re-running refreshes all.
#
# Usage:
#   ./scripts/bootstrap-artifacts.sh                     # default branch
#   ./scripts/bootstrap-artifacts.sh --branch main       # specific branch
#   ./scripts/bootstrap-artifacts.sh --skip-circuits     # only contracts

set -euo pipefail

# --- Configuration ---
DARKPOOL_REPO="https://github.com/hisoka-io/darkpool-v2.git"
DEFAULT_BRANCH="release/campaign"
CLONE_DIR="${TMPDIR:-/tmp}/darkpool-v2-artifacts"

# Resolve repo root (script lives in scripts/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Output directories
ARTIFACTS_DIR="$REPO_ROOT/artifacts"
CONTRACTS_OUT="$ARTIFACTS_DIR/contracts"
CIRCUITS_OUT="$ARTIFACTS_DIR/circuits"

# Also populate legacy paths that existing code references
LEGACY_ABI_CONTRACTS="$REPO_ROOT/abi/contracts"
LEGACY_CIRCUITS="$REPO_ROOT/circuits"

# --- Parse arguments ---
BRANCH="$DEFAULT_BRANCH"
COMMIT=""
SKIP_CIRCUITS=false
SKIP_CONTRACTS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --branch)   BRANCH="$2"; shift 2 ;;
        --commit)   COMMIT="$2"; shift 2 ;;
        --skip-circuits)   SKIP_CIRCUITS=true; shift ;;
        --skip-contracts)  SKIP_CONTRACTS=true; shift ;;
        --help|-h)
            echo "Usage: $0 [--branch <branch>] [--commit <sha>] [--skip-circuits] [--skip-contracts]"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# --- Helpers ---
info()  { echo "  [bootstrap] $*"; }
error() { echo "  [bootstrap] ERROR: $*" >&2; exit 1; }

check_tool() {
    command -v "$1" >/dev/null 2>&1 || error "$1 is required but not found. Install it first."
}

# --- Preflight checks ---
info "Checking required tools..."
check_tool git

if [[ "$SKIP_CONTRACTS" == false ]]; then
    check_tool node
    check_tool npx
fi

if [[ "$SKIP_CIRCUITS" == false ]]; then
    check_tool nargo
fi

# --- Clone / update repo ---
if [[ -d "$CLONE_DIR/.git" ]]; then
    info "Updating existing clone at $CLONE_DIR..."
    cd "$CLONE_DIR"
    git fetch --all --prune
else
    info "Cloning darkpool-v2 into $CLONE_DIR..."
    rm -rf "$CLONE_DIR"
    git clone --depth 50 "$DARKPOOL_REPO" "$CLONE_DIR"
    cd "$CLONE_DIR"
fi

if [[ -n "$COMMIT" ]]; then
    info "Checking out commit $COMMIT..."
    git checkout "$COMMIT"
elif [[ -n "$BRANCH" ]]; then
    info "Checking out branch $BRANCH..."
    git checkout "$BRANCH" 2>/dev/null || git checkout "origin/$BRANCH"
    git pull origin "$BRANCH" 2>/dev/null || true
fi

ACTUAL_COMMIT=$(git rev-parse --short HEAD)
info "Using darkpool-v2 at commit $ACTUAL_COMMIT"

# --- Compile contracts ---
if [[ "$SKIP_CONTRACTS" == false ]]; then
    info "Installing dependencies for evm-contracts..."
    cd "$CLONE_DIR/packages/evm-contracts"

    # Install node_modules if needed
    if [[ ! -d "node_modules" ]]; then
        npm install --legacy-peer-deps 2>&1 | tail -3
    fi

    info "Compiling Solidity contracts (Hardhat)..."
    npx hardhat compile 2>&1 | tail -5

    # Copy full Hardhat artifacts (with bytecode)
    info "Copying contract artifacts..."
    mkdir -p "$CONTRACTS_OUT" "$LEGACY_ABI_CONTRACTS"

    # Copy the contracts/ subtree (skip debug files)
    cd artifacts
    find contracts -name '*.json' -not -name '*.dbg.json' | while read -r f; do
        dir=$(dirname "$CONTRACTS_OUT/$f")
        mkdir -p "$dir"
        cp "$f" "$CONTRACTS_OUT/$f"

        # Also populate legacy abi/contracts/ path
        legacy_dir=$(dirname "$LEGACY_ABI_CONTRACTS/../contracts/$f")
        mkdir -p "$legacy_dir"
        cp "$f" "$LEGACY_ABI_CONTRACTS/../contracts/$f"
    done
    cd "$CLONE_DIR"

    CONTRACT_COUNT=$(find "$CONTRACTS_OUT" -name '*.json' | wc -l)
    info "Copied $CONTRACT_COUNT contract artifacts"
else
    info "Skipping contract compilation (--skip-contracts)"
fi

# --- Compile circuits ---
if [[ "$SKIP_CIRCUITS" == false ]]; then
    info "Compiling Noir circuits..."
    cd "$CLONE_DIR/packages/circuits"

    nargo compile 2>&1 | tail -10

    # Copy compiled circuit JSON files
    info "Copying circuit artifacts..."
    mkdir -p "$CIRCUITS_OUT" "$LEGACY_CIRCUITS"

    for circuit_json in target/*/*.json; do
        name=$(basename "$circuit_json")
        cp "$circuit_json" "$CIRCUITS_OUT/$name"
        cp "$circuit_json" "$LEGACY_CIRCUITS/$name"
    done

    CIRCUIT_COUNT=$(find "$CIRCUITS_OUT" -name '*.json' | wc -l)
    info "Copied $CIRCUIT_COUNT circuit artifacts"
else
    info "Skipping circuit compilation (--skip-circuits)"
fi

# --- Write metadata ---
cat > "$ARTIFACTS_DIR/.metadata.json" << EOF
{
  "source_repo": "$DARKPOOL_REPO",
  "branch": "$BRANCH",
  "commit": "$ACTUAL_COMMIT",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "skip_contracts": $SKIP_CONTRACTS,
  "skip_circuits": $SKIP_CIRCUITS
}
EOF

# --- Summary ---
info ""
info "Bootstrap complete!"
info "  Source:    darkpool-v2 @ $ACTUAL_COMMIT ($BRANCH)"
info "  Artifacts: $ARTIFACTS_DIR/"
if [[ "$SKIP_CONTRACTS" == false ]]; then
    info "  Contracts: $CONTRACT_COUNT files in artifacts/contracts/"
fi
if [[ "$SKIP_CIRCUITS" == false ]]; then
    info "  Circuits:  $CIRCUIT_COUNT files in artifacts/circuits/"
fi
info ""
info "You can now run integration tests:"
info "  cargo test --workspace"
info "  cargo test --test master_e2e -- --ignored --nocapture"
