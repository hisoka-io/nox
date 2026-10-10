.PHONY: check test test-integration test-http test-fec test-anvil test-heavy clippy clean

# Standard CI suite (runs on every push)
check:
	cargo check --workspace --features dev-node

test:
	cargo test --workspace --features dev-node

# Every root integration suite in tests/ (needs anvil 1.3.2 and solc 0.8.30), as CI runs it
test-integration:
	cargo nextest run -p nox-mixnet --features dev-node --no-fail-fast

# HTTP ingress pipeline tests (ephemeral ports, no external deps, ~30s)
test-http:
	cargo test --test http_e2e

# Reed-Solomon FEC integration tests (no external deps)
test-fec:
	cargo test -p nox-core --test fec

# Anvil-dependent paid execution tests
test-anvil:
	cargo test --test transaction_plan -- --nocapture
	cargo test --test transaction_outbox -- --nocapture
	cargo test --test payment_trace_safety --features dev-node -- --nocapture

# Long exit storage horizons that CI runs nightly (a few minutes)
test-heavy:
	cargo test -p nox-node --test exit_storage_bounds -- --ignored --nocapture

# Lint (deny all warnings)
clippy:
	cargo clippy --workspace --features dev-node -- -D warnings

# Remove build artifacts
clean:
	cargo clean
