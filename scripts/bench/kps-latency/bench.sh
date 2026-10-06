#!/usr/bin/env bash
# nox-kps latency bench: headless Chromium dials a local nox-kps through a UDP
# relay that adds delay, loss and an optional bottleneck; a mock upstream
# stands in for the node. Runs in a private network namespace (no root
# needed), so nothing on the host network is touched and runs can overlap.
#
# Usage: scripts/bench/kps-latency/bench.sh [options]
#   --kps PATH        nox-kps binary (default: target/release/nox-kps)
#   --task T          download | upload | dial (default: download)
#   --reply M         json | binary | binary1 mock claim reply (default: binary)
#   --delay MS        one-way delay each direction (default: 137, i.e. 274 ms RTT)
#   --loss P          random loss per packet and direction (default: 0)
#   --rate MBIT       server-to-client bottleneck rate, 0 = none (default: 0)
#   --queue KB        bottleneck queue (default: 64)
#   --calls N         calls per connection (default: 20)
#   --gap MS          pause between calls (default: 500)
#   --bytes N         upload body size (default: 32768, one Sphinx packet)
#   --chunk N         write the request in chunks of N bytes, 0 = one write (default: 0)
#   --runs R          connections, one after another (default: 1)
#   --seed N          loss RNG seed (default: random)
#   --out PREFIX      result files PREFIX-<run>.json (default: ./kps-bench)
# KPS_BENCH_KEEP=1 keeps the work directory (kps, relay and mock logs).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"

if [[ -z "${KPS_BENCH_IN_NS:-}" ]]; then
  for tool in unshare ip python3 node; do
    command -v "$tool" >/dev/null || { echo "bench.sh: $tool is required" >&2; exit 1; }
  done
  if [[ ! -f "$here/dist/bench.js" ]]; then
    echo "bench.sh: run 'npm ci && npm run build' in $here first" >&2
    exit 1
  fi
  export KPS_BENCH_IN_NS=1
  exec unshare -rn bash -c \
    'ip link set lo up && ip link add d0 type dummy && ip addr add 10.9.0.1/24 dev d0 && ip link set d0 up && exec "$0" "$@"' \
    "$0" "$@"
fi

kps="$root/target/release/nox-kps" task=download reply=binary delay=137 loss=0 rate=0 queue=64
calls=20 gap=500 bytes=32768 chunk=0 runs=1 seed="" out="$PWD/kps-bench"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --kps) kps="$2" ;;
    --task) task="$2" ;;
    --reply) reply="$2" ;;
    --delay) delay="$2" ;;
    --loss) loss="$2" ;;
    --rate) rate="$2" ;;
    --queue) queue="$2" ;;
    --calls) calls="$2" ;;
    --gap) gap="$2" ;;
    --bytes) bytes="$2" ;;
    --chunk) chunk="$2" ;;
    --runs) runs="$2" ;;
    --seed) seed="$2" ;;
    --out) out="$2" ;;
    *) echo "bench.sh: unknown option $1" >&2; exit 2 ;;
  esac
  shift 2
done
kps="$(realpath "$kps")"
[[ "$out" = /* ]] || out="$PWD/$out"

work="$(mktemp -d)"
pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [[ -n "${KPS_BENCH_KEEP:-}" ]]; then echo "logs kept in $work" >&2; else rm -rf "$work"; fi
}
trap cleanup EXIT

kps_port=15905 relay_port=15907 upstream_port=15902
cat >"$work/kps.toml" <<EOF
listen = "0.0.0.0:$kps_port"
advertise = ["10.9.0.1"]
allow_private_advertise = true
key_file = "$work/kps.key"
upstream_ingress = "127.0.0.1:$upstream_port"
upstream_topology = "127.0.0.1:$upstream_port"
keccak_dir = ""
admin_listen = "127.0.0.1:15906"
log_level = "warn"
EOF
certhash="$("$kps" -c "$work/kps.toml" init | sed -n 's/^certhash: //p')"
echo "expected_certhash = \"$certhash\"" >>"$work/kps.toml"
addr="10.9.0.1:$relay_port:$certhash"

python3 "$here/mock_upstream.py" --port "$upstream_port" --reply "$reply" >"$work/mock.log" 2>&1 &
pids+=($!)
relay_args=(--listen "$relay_port" --target "$kps_port" --delay "$delay" --loss "$loss" --rate-mbit "$rate" --queue-kb "$queue")
[[ -n "$seed" ]] && relay_args+=(--seed "$seed")
python3 "$here/relay.py" "${relay_args[@]}" >"$work/relay.log" 2>&1 &
pids+=($!)
"$kps" -c "$work/kps.toml" run >"$work/kps.log" 2>&1 &
pids+=($!)
sleep 1.5

for ((i = 1; i <= runs; i++)); do
  node "$here/run.mjs" "$out-$i.json" "$task" "$addr" "$calls" "$gap" "$bytes" "$chunk" ||
    echo "bench.sh: run $i failed" >&2
done
results=()
for ((i = 1; i <= runs; i++)); do
  [[ -f "$out-$i.json" ]] && results+=("$(basename "$out")=$out-$i.json")
done
python3 "$here/summarize.py" "${results[@]}"
tail -n 2 "$work/relay.log"
