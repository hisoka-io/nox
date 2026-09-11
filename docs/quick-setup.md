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

```bash
cargo run --release -- --config config.toml
```

Or with environment variables:

```bash
NOX_ETH_RPC_URL=https://mainnet.infura.io/v3/YOUR_KEY \
NOX_ROUTING_PRIVATE_KEY=<hex> \
NOX_ETH_WALLET_PRIVATE_KEY=<hex> \
NOX_CHAIN_ID=1 \
NOX_NODE_ROLE=exit \
cargo run --release
```

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
cargo test --test fec_e2e
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
