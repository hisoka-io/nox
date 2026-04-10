# Contributing

## Setup

```bash
# Ubuntu/Debian
sudo apt install pkg-config libssl-dev

# Optional: Foundry for E2E tests
curl -L https://foundry.paradigm.xyz | bash && foundryup

# Build
git clone https://github.com/hisoka-io/nox.git
cd nox
cargo build --workspace
```

Integration tests need artifacts from `darkpool-v2`:

```bash
./scripts/bootstrap-artifacts.sh              # clone, compile, copy
./scripts/bootstrap-artifacts.sh --commit abc # pin a specific commit
```

## Before submitting a PR

```bash
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

## Code standards

CI enforces:

- Zero clippy warnings
- No `.unwrap()` in runtime paths - use `Result<T, E>` with `thiserror`
- No `TODO` / `FIXME` / `HACK` comments

Error messages should include enough context to debug:

```rust
// Bad
return Err(anyhow!("request failed"));

// Good
return Err(anyhow!(
    "Mixnet timeout (hop 2, elapsed: {}ms, peer: {})",
    elapsed.as_millis(),
    peer_id
));
```

### Security

- Constant-time comparison (`subtle::ConstantTimeEq`) for secrets
- Never log private keys or plaintext - trace IDs and public commitments only
- Key material must implement `Zeroize + ZeroizeOnDrop`

### Broadcast channels

Don't use `while let Ok()` - it silently drops the task on overflow:

```rust
loop {
    match rx.recv().await {
        Ok(event) => handle(event),
        Err(RecvError::Lagged(n)) => {
            tracing::warn!(missed = n, "event bus overflow");
        }
        Err(RecvError::Closed) => break,
    }
}
```

## Where to put new code

| Adding...            | Location                                 |
|----------------------|------------------------------------------|
| Service handler      | `crates/nox-node/src/services/handlers/` |
| Event type           | `crates/nox-core/src/events.rs`          |
| Crypto primitive     | `crates/darkpool-crypto/src/`            |
| Sphinx feature       | `crates/nox-crypto/src/sphinx/`          |
| Client operation     | `crates/darkpool-client/src/`            |
| Metric               | `crates/nox-node/src/telemetry/metrics.rs` |
| Integration test     | `tests/`                                 |
| Benchmark            | `benches/` or `crates/<crate>/benches/`  |

## Testing

```bash
cargo test --workspace                                    # all 575 tests
cargo test --workspace --lib                              # unit tests only
cargo test -p nox-crypto                                  # single crate
cargo test --test master_e2e -- --ignored                 # E2E (needs Anvil + Node.js)
cargo bench                                               # criterion micro-benchmarks
```

Unit tests go in the same file (`#[cfg(test)] mod tests`). Integration tests go in `tests/`. Use `#[ignore]` for tests that need external infra.

## Security

Found a vulnerability? Don't open a public issue - see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree your contributions will be licensed under [Apache 2.0](LICENSE).
