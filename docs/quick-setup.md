# Quick setup

## Prerequisites

- **Rust 1.95.0** toolchain (edition 2021)
- **pkg-config + libssl-dev** (Ubuntu: `sudo apt install pkg-config libssl-dev`)

Optional (for full simulation):

- **Foundry** Anvil for local Ethereum (`curl -L https://foundry.paradigm.xyz | bash && foundryup`)
- **solc 0.8.30** for the committed payment-evidence fixture

## Build

```bash
git clone https://github.com/hisoka-io/nox.git
cd nox
cargo build --workspace --release
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

## Run a node

To join the public testnet on Arbitrum Sepolia, use the operator kit,
[hisoka-io/run-nox](https://github.com/hisoka-io/run-nox). It pins the release image and the deployment manifest,
ships relay and exit templates with the deployed contract addresses, verifies them on chain before startup, and
documents registration.

To run a source build against such a config:

```bash
# Keys plus the public values for registration (build output goes to stderr)
cargo run --release --bin nox -- keygen > .env
set -a; . ./.env; set +a
# Prints the role, chain, registry and public identity derived from config + env
cargo run --release --bin nox -- --config config.toml check-config
cargo run --release --bin nox -- --config config.toml
```

Environment variables override the TOML file. They use the `NOX__` prefix (two underscores), and `__` separates
nested fields, for example `NOX__CHAIN_ID=421614` or `NOX__NETWORK__MAX_CONNECTIONS=2000`. Variables with a
single underscore (`NOX_CHAIN_ID`) are ignored. See [configuration](configuration.md#environment-variables).

## Testing

```bash
cargo test --workspace                                    # full suite
cargo test --workspace --lib                              # unit tests only
cargo test -p nox-crypto                                  # specific crate
cargo bench                                               # criterion micro-benchmarks
```

Integration tests:

```bash
cargo test --test payment_trace_safety --features dev-node -- --nocapture
cargo test --test transaction_outbox -- --nocapture
cargo test --test http_e2e -- --nocapture
cargo test -p nox-core --test fec
```

## Crate map

| Crate | Purpose |
|---|---|
| [`nox-crypto`](../crates/nox-crypto/) | Sphinx packets, SURBs, proof of work |
| [`nox-core`](../crates/nox-core/) | Shared protocol types, events, fragmentation, FEC |
| [`nox-client`](../crates/nox-client/) | Route selection, topology sync, SURB budget |
| [`nox-node`](../crates/nox-node/) | Relay/exit node: services, P2P, blockchain, telemetry |
| [`nox-oracle`](../crates/nox-oracle/) | Price oracle: CoinGecko, Binance, aggregate median |
| [`nox-test-infra`](../crates/nox-test-infra/) | Protocol-neutral test harnesses |
| [`nox-sim`](../crates/nox-sim/) | Simulation and benchmark binaries |
