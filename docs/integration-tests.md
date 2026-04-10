# Integration tests

Tests excluded from `cargo test --workspace` because they need external processes or take a while.

## Quick reference

```bash
make test-http     # HTTP ingress pipeline       (~30s, no deps)
make test-fec      # Reed-Solomon FEC            (~1s,  no deps)
make test-anvil    # economics_e2e + anvil_trace (~60s, needs anvil)
make test-heavy    # master_e2e + prover parity  (~5 min, needs anvil + node)
```

## Prerequisites

**Anvil** (for `test-anvil` and `test-heavy`):
```bash
curl -L https://foundry.paradigm.xyz | bash && foundryup
export PATH="$HOME/.foundry/bin:$PATH"
```

**Node.js v18+** (for `test-heavy` only):
```bash
node --version
```

**Contract + circuit artifacts** (for `test-anvil` and `test-heavy`):
```bash
./scripts/bootstrap-artifacts.sh              # clone, compile, copy
./scripts/bootstrap-artifacts.sh --commit abc # pin a specific commit
```

Downloads circuit SRS (~200MB, cached), compiles Noir circuits, and copies Hardhat artifacts to `./artifacts/`.

## CI

`cargo test --workspace` (including `http_e2e` and `fec_e2e`) runs on every push. The heavier tests (`economics_e2e`, `master_e2e`, `native_prover_parity`) run via `.github/workflows/slow-tests.yml` on manual trigger.
