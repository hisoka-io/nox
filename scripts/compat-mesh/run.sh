#!/usr/bin/env bash
# Runs a published client release against a local mesh that mixes two nox
# builds, for example the current tree and the previous release.
#
# Usage:
#   LEGACY_BIN=/path/to/previous/nox scripts/compat-mesh/run.sh <scenario>...
#
# Scenarios (7 nodes: 0-3 relays, 4-6 exits):
#   legacy        every node runs LEGACY_BIN
#   current       every node runs the current build
#   exits-first   exits run the current build, relays LEGACY_BIN
#   relays-first  relays run the current build, exits LEGACY_BIN
#   mixed         even nodes run the current build, odd nodes LEGACY_BIN
#
# Env:
#   NOX_BIN       current nox binary (default target/release/nox)
#   MESH_BIN      nox_mesh_server binary (default target/release/nox_mesh_server)
#   LEGACY_BIN    previous nox binary (required unless only "current" runs)
#   CLIENT_VERSION  client release to test (default 0.2.0)
#   BASE_PORT, ANVIL_PORT, HTTP_PORT  local ports (defaults 24000, 18545, 18080)
# Client workload knobs are passed through to client.mjs.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$ROOT/scripts/compat-mesh"
NOX_BIN="${NOX_BIN:-$ROOT/target/release/nox}"
MESH_BIN="${MESH_BIN:-$ROOT/target/release/nox_mesh_server}"
CLIENT_VERSION="${CLIENT_VERSION:-0.2.0}"
BASE_PORT="${BASE_PORT:-24000}"
ANVIL_PORT="${ANVIL_PORT:-18545}"
export HTTP_PORT="${HTTP_PORT:-18080}"
WORK="${WORK:-$(mktemp -d /tmp/nox-compat-mesh.XXXXXX)}"
NODES=7
ROLES="1,1,1,1,2,2,3"

[ $# -gt 0 ] || { sed -n '2,20p' "$0"; exit 2; }

if [ ! -d "$WORK/client/node_modules/@hisoka-io/nox-client" ]; then
    mkdir -p "$WORK/client"
    (cd "$WORK/client" && npm init -y >/dev/null && \
        npm install --silent --no-audit --no-fund "@hisoka-io/nox-client@$CLIENT_VERSION" >/dev/null)
fi
cp "$HERE/client.mjs" "$WORK/client/client.mjs"
INSTALLED="$(node -p "require('$WORK/client/node_modules/@hisoka-io/nox-client/package.json').version")"
[ "$INSTALLED" = "$CLIENT_VERSION" ] || { echo "client $INSTALLED installed, expected $CLIENT_VERSION" >&2; exit 1; }

ANVIL_PID=""
MESH_PID=""
cleanup() {
    [ -n "$MESH_PID" ] && kill -INT "$MESH_PID" 2>/dev/null && wait "$MESH_PID" 2>/dev/null || true
    [ -n "$ANVIL_PID" ] && kill "$ANVIL_PID" 2>/dev/null && wait "$ANVIL_PID" 2>/dev/null || true
    MESH_PID=""
    ANVIL_PID=""
}
trap cleanup EXIT

legacy_nodes() {
    case "$1" in
        legacy) echo "0,1,2,3,4,5,6" ;;
        current) echo "" ;;
        exits-first) echo "0,1,2,3" ;;
        relays-first) echo "4,5,6" ;;
        mixed) echo "1,3,5" ;;
        *) echo "unknown scenario: $1" >&2; exit 2 ;;
    esac
}

status=0
for scenario in "$@"; do
    legacy="$(legacy_nodes "$scenario")"
    data="$WORK/$scenario"
    rm -rf "$data"
    mkdir -p "$data"

    anvil --port "$ANVIL_PORT" --silent >"$data/anvil.log" 2>&1 &
    ANVIL_PID=$!

    args=(--nodes "$NODES" --roles "$ROLES" --data-dir "$data/mesh" --base-port "$BASE_PORT"
          --anvil-port "$ANVIL_PORT" --mix-delay-ms 0 --nox-binary "$NOX_BIN")
    if [ -n "$legacy" ]; then
        [ -n "${LEGACY_BIN:-}" ] || { echo "LEGACY_BIN is required for $scenario" >&2; exit 2; }
        args+=(--legacy-binary "$LEGACY_BIN" --legacy-nodes "$legacy")
    fi
    NOX_KEEP_LOGS=1 "$MESH_BIN" "${args[@]}" >"$data/mesh_stdout.log" 2>"$data/mesh_server.log" &
    MESH_PID=$!

    for _ in $(seq 1 120); do
        [ -f "$data/mesh/mesh_info.json" ] && break
        kill -0 "$MESH_PID" 2>/dev/null || { echo "mesh server exited, see $data/mesh_server.log" >&2; exit 1; }
        sleep 1
    done
    [ -f "$data/mesh/mesh_info.json" ] || { echo "mesh not ready, see $data/mesh_server.log" >&2; exit 1; }

    echo "=== $scenario (previous build on nodes: ${legacy:-none})"
    if MESH_INFO="$data/mesh/mesh_info.json" node "$WORK/client/client.mjs" | tee "$data/client.log"; then
        result=PASS
    else
        result=FAIL
        status=1
    fi

    # Handles dropped for an unknown previous hop would break replies.
    dropped=0
    for i in $(seq 0 $((NODES - 1))); do
        port=$((BASE_PORT + i * 10 + 1))
        n="$(curl -sf "http://127.0.0.1:$port/metrics" | awk '/^nox_wire_handle_dropped_total\{reason="unknown_layer"\}/ {s+=$2} END {print s+0}')"
        dropped=$((dropped + n))
    done
    echo "=== $scenario: client $result, handles dropped for unknown previous hop: $dropped"
    [ "$dropped" -eq 0 ] || status=1

    cleanup
    sleep 2
done

echo "logs: $WORK"
exit $status
