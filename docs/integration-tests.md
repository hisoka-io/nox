# Integration tests

The root crate (`nox-mixnet`) owns every file in `tests/`. Some of them start Anvil or compile contracts with
solc, so they need the prerequisites below.

## Quick reference

```bash
make test-integration  # every tests/*.rs suite (needs Anvil and solc), a minute or two
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

On every push and pull request, `.github/workflows/ci.yml` runs:

- **Test**: `cargo nextest run` over the subcrates, plus the HTTP, FEC, transaction plan and outbox suites;
- **Integration Tests**: `cargo nextest run -p nox-mixnet --features dev-node`, which compiles and runs every
  `tests/*.rs` file with Anvil 1.3.2 and solc 0.8.30 installed;
- **Payment Trace Safety**: the committed payment evidence suite.

Tests marked `#[ignore]` are skipped there. The large-payload stress cases and the Anvil trace diagnostics run
nightly through `.github/workflows/slow-tests.yml`. A new slow or environment-dependent test should be
`#[ignore = "<reason>"]` and added to that workflow rather than left out of CI.
