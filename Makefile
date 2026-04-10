.PHONY: check test test-http test-fec test-anvil test-heavy test-large clippy clean

# Standard CI suite (runs on every push)
check:
	cargo check --workspace --features dev-node

test:
	cargo test --workspace --features dev-node

# HTTP ingress pipeline tests (ephemeral ports, no external deps, ~30s)
test-http:
	cargo test --test http_e2e

# Reed-Solomon FEC integration tests (no external deps, ~1s)
test-fec:
	cargo test --test fec_e2e

# Anvil-dependent tests (~60s) - requires: anvil on PATH, bootstrap-artifacts.sh run
test-anvil:
	cargo test --test economics_e2e --features dev-node -- --ignored --nocapture
	cargo test --test anvil_trace_debug -- --ignored --nocapture

# Large payload FEC tests (~30s for 1-10MB, ~2min for 300MB) - no external deps
test-large:
	cargo test --test large_payload -- --ignored --nocapture

# Full heavy suite (~5-10 min) - requires: anvil + node on PATH, bootstrap-artifacts.sh run
test-heavy:
	cargo test --test master_e2e --features dev-node -- --ignored --nocapture
	cargo test --test native_prover_parity -- --ignored --nocapture

# Lint (deny all warnings)
clippy:
	cargo clippy --workspace --features dev-node -- -D warnings

# Remove build artifacts
clean:
	cargo clean
