# Quick setup

## Prerequisites

- **Rust** stable toolchain (edition 2021)
- **pkg-config + libssl-dev** (Ubuntu: `sudo apt install pkg-config libssl-dev`)

Optional (for full simulation):

- **Foundry** Anvil for local Ethereum (`curl -L https://foundry.paradigm.xyz | bash && foundryup`)
- **Node.js** Required for bb.js WASM prover subprocess

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
cargo test --workspace                                    # full suite (845+ tests)
cargo test --workspace --lib                              # unit tests only
cargo test -p nox-crypto                                  # specific crate
cargo bench                                               # 47 criterion micro-benchmarks
```

Integration tests (require Anvil + Node.js + [bootstrapped artifacts](../scripts/bootstrap-artifacts.sh)):

```bash
cargo test --test master_e2e -- --ignored --nocapture
cargo test --test http_e2e -- --ignored --nocapture
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
| [`nox-prover`](../crates/nox-prover/) | ZK proof generation via bb.js subprocess |
| [`darkpool-crypto`](../crates/darkpool-crypto/) | BabyJubJub, Poseidon2, AES-128-CBC, ECDH, KDF |
| [`darkpool-client`](../crates/darkpool-client/) | Privacy wallet SDK: deposit, withdraw, transfer, scan |
| [`nox-test-infra`](../crates/nox-test-infra/) | Contract deployment and test harnesses |
| [`nox-sim`](../crates/nox-sim/) | Simulation and benchmark binaries |
