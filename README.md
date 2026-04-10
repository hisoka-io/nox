<p align="center">
  <img src="docs/assets/banner-dark.svg" alt="NOX" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/hisoka-io/nox/actions/workflows/ci.yml"><img src="https://github.com/hisoka-io/nox/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-stable-orange.svg" alt="Rust" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License" /></a>
  <a href="#testing"><img src="https://img.shields.io/badge/tests-845%20passed-brightgreen.svg" alt="Tests" /></a>
</p>

<br />

Sphinx mix network for private DeFi on Ethereum. Transactions are onion-encrypted through a 3-layer relay network with Poisson mixing delays. Responses return anonymously via SURBs. No one, not even relay operators, can link a transaction to its sender.

**[Live Mixnet Map](https://map.hisoka.io)** · **[Nox Explorer](https://shield.hisoka.io)**

## Why

DeFi transactions leak metadata. ZK proofs hide _what_ you did, but your IP address, timing, and RPC provider still reveal _who_ you are. Tor doesn't mix, so it's vulnerable to timing analysis. VPNs are single points of trust.

## DeFi metadata protection

| Factor | Tor | Nym | VPN | NOX |
|---|:---:|:---:|:---:|:---:|
| IP hidden from RPC | 🟡 | ✅ | 🟡 | ✅ |
| Timing decorrelation | ❌ | ✅ | ❌ | ✅ |
| Gas fingerprint resistance | ❌ | ❌ | ❌ | ✅ |
| Mempool shielding | ❌ | ❌ | ❌ | ✅ |
| Sender/receiver unlinkability | ❌ | ✅ | ❌ | ✅ |
| Anonymous responses | ❌ | ✅ | ❌ | ✅ |
| Native TX execution | ❌ | ❌ | ❌ | ✅ |

Sphinx packets go in, executed transactions come out. The relayer gets paid via ZK proof and never learns who sent it.

## Key features

- 3-layer onion encryption so no single node sees the full path
- Random delays at each hop to break timing correlation
- Anonymous reply packets (SURBs) so responses don't reveal the sender
- Error correction on responses so lost packets don't require retransmission
- ZK gas payment so relayers get paid without learning who paid them
- Proof of work anti-spam to rate limit without identity

## Quick start

```bash
git clone https://github.com/hisoka-io/nox.git
cd nox
cargo build --workspace --release
cargo test --workspace
cargo run --release -- --config config.toml
```

Full setup guide, prerequisites, environment variables, and testing in [docs/quick-setup.md](docs/quick-setup.md).

## Docs

- [Quick setup](docs/quick-setup.md)
- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)
- [Changelog](CHANGELOG.md)

## Resources
- [The Loopix Anonymity System](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/piotrowska) (USENIX Security 2017)
- [Sphinx: A Compact and Provably Secure Mix Format](https://www.cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf) (IEEE S&P 2009)

## License

[Apache 2.0](LICENSE)
