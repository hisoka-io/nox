# Integration tests

Tests excluded from `cargo test --workspace` because they need external processes or take a while.

## Quick reference

```bash
make test-http     # HTTP ingress pipeline
make test-fec      # Reed-Solomon FEC
make test-anvil    # paid execution and durable outbox
make test-heavy    # large-payload stress cases
```

## Prerequisites

**Anvil and solc 0.8.30** (for `test-anvil`):
```bash
curl -L https://foundry.paradigm.xyz | bash && foundryup
export PATH="$HOME/.foundry/bin:$PATH"
```

The committed payment-evidence fixture compiles its protocol-neutral contracts locally. It does not clone or
interpret an application protocol.

## CI

`cargo test --workspace` plus focused payment, outbox, HTTP, and FEC gates run on every push. Large-payload and
trace diagnostics run through `.github/workflows/slow-tests.yml`.
