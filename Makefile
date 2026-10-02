.PHONY: check test test-integration test-http test-fec test-anvil test-heavy test-large clippy clean

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

# Reed-Solomon FEC integration tests (no external deps, ~1s)
test-fec:
	cargo test --test fec_e2e

# Anvil-dependent paid execution tests
test-anvil:
	cargo test --test transaction_plan -- --nocapture
	cargo test --test transaction_outbox -- --nocapture
	cargo test --test payment_trace_safety --features dev-node -- --nocapture
	cargo test --test anvil_trace_debug -- --ignored --nocapture

# Large payload FEC tests (~30s for 1-10MB, ~2min for 300MB) - no external deps
test-large:
	cargo test --test large_payload -- --ignored --nocapture

# Large-payload stress suite
test-heavy:
	cargo test --test large_payload -- --ignored --nocapture

# Lint (deny all warnings)
clippy:
	cargo clippy --workspace --features dev-node -- -D warnings

# Remove build artifacts
clean:
	cargo clean
