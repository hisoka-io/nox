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
# Source: hisoka-io/darkpool-v2 @ release/campaign. The branch is org-retired but
# its CONTENT is intact (gas_payment circuit + GasPaymentVerifier.sol are both
# present). The repo is PRIVATE, so CI must supply credentials -- an unauthenticated
# `git clone` is what killed the nightly slow-tests run.
#
# Do NOT repoint this at the successor repo (hisoka-io/darkpool, "Howl") as-is:
# Howl ships no gas_payment circuit and no GasPaymentVerifier.sol, both of which
# native_prover_parity and NativeProver require. Rehoming gas_payment is part of
# HOWL-16, not NOX-10.
#
# Override with --repo/--branch or the DARKPOOL_REPO/DARKPOOL_BRANCH env vars.
DARKPOOL_REPO="${DARKPOOL_REPO:-https://github.com/hisoka-io/darkpool-v2.git}"
DEFAULT_BRANCH="${DARKPOOL_BRANCH:-release/campaign}"
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
        --repo)     DARKPOOL_REPO="$2"; shift 2 ;;
        --branch)   BRANCH="$2"; shift 2 ;;
        --commit)   COMMIT="$2"; shift 2 ;;
        --skip-circuits)   SKIP_CIRCUITS=true; shift ;;
        --skip-contracts)  SKIP_CONTRACTS=true; shift ;;
        --help|-h)
            echo "Usage: $0 [--repo <url>] [--branch <branch>] [--commit <sha>] [--skip-circuits] [--skip-contracts]"
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

# Fail fast with an actionable message instead of an opaque `git clone` error.
# The source repo is private, so CI needs credentials in the environment.
#
# GIT_TERMINAL_PROMPT=0 is load-bearing: without it, git blocks forever on an
# interactive credential prompt when auth is missing, which in CI reads as a
# hung job rather than a failed one.
export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=echo

info "Verifying access to $DARKPOOL_REPO ..."
REMOTE_HEADS=""
if ! REMOTE_HEADS=$(git ls-remote --heads "$DARKPOOL_REPO" 2>/dev/null); then
    error "Cannot reach $DARKPOOL_REPO (unreachable, private without credentials, renamed, or deleted).
    In CI, supply credentials -- e.g. set repo secret DARKPOOL_REPO_TOKEN and run:
      git config --global url.\"https://x-access-token:\$TOKEN@github.com/\".insteadOf \"https://github.com/\"
    Locally, override the source: --repo <url> --branch <branch>."
fi

if [[ -z "$COMMIT" ]] && ! grep -q "refs/heads/$BRANCH\$" <<< "$REMOTE_HEADS"; then
    error "Branch '$BRANCH' does not exist on $DARKPOOL_REPO.
    Available: $(sed 's#.*refs/heads/##' <<< "$REMOTE_HEADS" | paste -sd, -)
    Override with --branch <branch>."
fi

if [[ "$SKIP_CONTRACTS" == false ]]; then
    check_tool node
    check_tool npx
    check_tool pnpm
fi

if [[ "$SKIP_CIRCUITS" == false ]]; then
    check_tool nargo
fi

# --- Clone / update repo ---
# `git clone --depth N` fetches ONLY the remote default branch, so a later
# `git checkout release/campaign` fails with "pathspec did not match". Fetch the
# requested ref explicitly and check out FETCH_HEAD instead.
if [[ ! -d "$CLONE_DIR/.git" ]]; then
    info "Initializing clone at $CLONE_DIR..."
    rm -rf "$CLONE_DIR"
    mkdir -p "$CLONE_DIR"
    git -C "$CLONE_DIR" init -q
    git -C "$CLONE_DIR" remote add origin "$DARKPOOL_REPO"
fi

cd "$CLONE_DIR"
git remote set-url origin "$DARKPOOL_REPO"

if [[ -n "$COMMIT" ]]; then
    info "Fetching commit $COMMIT..."
    git fetch --depth 50 origin "$COMMIT" \
        || error "Commit $COMMIT not found on $DARKPOOL_REPO."
else
    info "Fetching branch $BRANCH..."
    git fetch --depth 50 origin "refs/heads/$BRANCH" \
        || error "Failed to fetch branch '$BRANCH' from $DARKPOOL_REPO."
fi

git checkout -q --detach FETCH_HEAD \
    || error "Failed to check out the fetched ref."

ACTUAL_COMMIT=$(git rev-parse --short HEAD)
info "Using darkpool-v2 at commit $ACTUAL_COMMIT"

# --- Compile contracts ---
if [[ "$SKIP_CONTRACTS" == false ]]; then
    # darkpool-v2 is a pnpm workspace: its package.json files use the
    # "workspace:^" protocol, which npm cannot resolve (EUNSUPPORTEDPROTOCOL).
    # Install from the workspace root with pnpm, not npm from the package dir.
    info "Installing workspace dependencies (pnpm)..."
    cd "$CLONE_DIR"

    if [[ ! -d "node_modules" ]]; then
        pnpm install --frozen-lockfile 2>&1 | tail -3
    fi

    cd "$CLONE_DIR/packages/evm-contracts"

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
mkdir -p "$ARTIFACTS_DIR"
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
