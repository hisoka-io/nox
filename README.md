<p align="center">
  <img src="docs/assets/banner-dark.svg" alt="NOX" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/hisoka-io/nox/actions/workflows/ci.yml"><img src="https://github.com/hisoka-io/nox/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.95.0-orange.svg" alt="Rust 1.95.0" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License" /></a>
</p>

<br />

Sphinx mix network for private DeFi on Ethereum. Transactions are onion-encrypted through a 3-layer relay network with Poisson mixing delays. Responses return anonymously via SURBs. No one, not even relay operators, can link a transaction to its sender.

**[Live Mixnet Map](https://map.hisoka.io)** · **[Nox Explorer](https://demo.nox.hisoka.io)** · **[anon-rpc demo](https://demo.nox.hisoka.io/anon-rpc)**

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

Sphinx packets go in, opaque actions come out. Paid execution is protocol-neutral and bound to a selected exit.

## Key features

- 3-layer onion encryption so no single node sees the full path
- Random delays at each hop to break timing correlation
- Anonymous reply packets (SURBs) so responses don't reveal the sender
- Error correction on responses so lost packets don't require retransmission
- Fixed-point paid execution with durable transaction recovery
- Proof of work anti-spam to rate limit without identity
- End-to-end TLS tunnels (`tunnel_v1`): the client runs TLS with its RPC provider and the exit relays the encrypted records
- KPS entry (`nox-kps`) so browsers reach a node directly over WebRTC and QUIC

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
- [End-to-end TLS tunnels](docs/tunnel.md)
- [KPS entry (nox-kps)](crates/nox-kps/README.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)
- [Changelog](CHANGELOG.md)

## Ecosystem

- [run-nox](https://github.com/hisoka-io/run-nox): operator kit for running a relay or exit on the public testnet
- [`@hisoka-io/nox-client`](https://www.npmjs.com/package/@hisoka-io/nox-client): TypeScript client SDK ([source](https://github.com/hisoka-io/nox-sdk))
- [`@hisoka-io/anon-rpc-worker`](https://www.npmjs.com/package/@hisoka-io/anon-rpc-worker): Nox transport for [anon-rpc](https://github.com/ethereum/anon-rpc) wallets, with end-to-end TLS to the RPC provider
- Worker specifier on Ethereum Sepolia: [`0x35133267A8F7EC35046a83DCA0f4Ca8A6e1b7A9A`](https://sepolia.etherscan.io/address/0x35133267A8F7EC35046a83DCA0f4Ca8A6e1b7A9A), one stable address that follows the current worker release
- [Live mixnet map](https://map.hisoka.io) and [demo](https://demo.nox.hisoka.io) ([anon-rpc demo](https://demo.nox.hisoka.io/anon-rpc))

## Resources
- [The Loopix Anonymity System](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/piotrowska) (USENIX Security 2017)
- [Sphinx: A Compact and Provably Secure Mix Format](https://www.cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf) (IEEE S&P 2009)

## License

[Apache 2.0](LICENSE)
