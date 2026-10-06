# nox-kps latency bench

Measures what a browser sees when it talks to nox-kps over a long, lossy
path: headless Chromium dials a local nox-kps over WebRTC through a UDP relay
that adds delay, random loss and an optional bottleneck link, and a mock
upstream stands in for the node. Every run happens in a private network
namespace (`unshare -rn`, no root needed), so it touches nothing on the host
network and several runs can go in parallel.

```text
Chromium ──UDP── relay.py (delay, loss, bottleneck) ──UDP── nox-kps ──HTTP── mock_upstream.py
10.9.0.1:15907                                     :15905               127.0.0.1:15902
```

## Setup (once)

```bash
cd scripts/bench/kps-latency
npm ci                 # playwright, @kpstreams/webrtc-client, esbuild
npm run browsers       # Chromium for playwright
npm run build          # entry.ts -> dist/bench.js
cargo build --release -p nox-kps
```

Needs `unshare` and `ip` (util-linux, iproute2), Python 3 and Node 20+.

## Run

```bash
# 20 reply downloads at India-like RTT (137 ms each way), the default
scripts/bench/kps-latency/bench.sh --out /tmp/kps-a

# A/B two builds under 1.5% loss each way, 12 connections each
bench.sh --kps ./nox-kps-before --loss 0.015 --runs 12 --out /tmp/before
bench.sh --kps ./nox-kps-after  --loss 0.015 --runs 12 --out /tmp/after
python3 summarize.py 'before=/tmp/before-*.json' 'after=/tmp/after-*.json'
```

Options (also listed at the top of `bench.sh`):

| Option | Default | Meaning |
|---|---|---|
| `--kps PATH` | `target/release/nox-kps` | nox-kps binary under test |
| `--task` | `download` | `download` (claims answered with the mock reply), `upload` (32 KB `POST /api/v1/packets`), `dial` |
| `--reply` | `binary` | `binary` (data + parity, 64.8 KB), `binary1` (one reply, 32.4 KB), `json` (v1, about 230 KB) |
| `--delay MS` | `137` | One-way delay each direction |
| `--loss P` | `0` | Random loss per packet and direction |
| `--rate MBIT` / `--queue KB` | `0` / `64` | Server-to-client bottleneck: rate limit with a drop-tail queue |
| `--calls N` / `--gap MS` | `20` / `500` | Calls per connection, pause between calls |
| `--bytes N` / `--chunk N` | `32768` / `0` | Upload size; write the request in chunks of N bytes |
| `--runs R` | `1` | Connections, one after another |
| `--seed N` | random | Loss RNG seed |
| `--out PREFIX` | `./kps-bench` | Writes `PREFIX-<run>.json` |

`KPS_BENCH_KEEP=1` keeps the work directory with the nox-kps, relay and mock
logs; `RUST_LOG` and `KPS_DEBUG` pass through to nox-kps.

## Output

Each result file holds every call's `ttfb` and `done` times (ms from the
first write). `summarize.py` prints, per label, the first call after the
dial ("cold") and the rest ("warm"): p50, p90, mean, max, and how many calls
or dials failed. The relay log line at the end says how many packets each
direction lost or dropped at the bottleneck.

Things to keep in mind when reading numbers:

- Runs under loss vary a lot; use `--runs 12` or more and compare pooled
  numbers.
- The relay is Python. At the default rates it adds well under a
  millisecond, but heavy parallel load on the host shows up as jitter.
- The mock answers at once. The bench measures the browser link and nox-kps,
  not the mixnet.
