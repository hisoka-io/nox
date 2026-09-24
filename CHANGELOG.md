# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

- Replaced the embedded Howl wallet, prover, `gas_payment`, and RelayerMulticall stack with protocol-neutral
  paid quote and EntryPoint execution types.
- Added fixed-point profitability, committed settlement evidence, durable signed transaction recovery, and
  bounded quote reservations.
- Removed the retired DarkPool crypto/client/prover crates and divergent deployment kit.
- Persisted observer cursor, peers and sessions are now scoped to `(chain_id, registry)`; pointing an existing
  data volume at another registry (or starting on an unscoped pre-release volume) drops them and replays from
  `chain_start_block`. Seed snapshots must also match the registry's on-chain `topologyFingerprint()`.
- The node-local topology fingerprint is recomputed from the served node set, so replayed or duplicate
  registry events no longer drift it away from the chain.
- Added `nox check-config` to validate a config (file + `NOX__*` env) and print its public identity.

## [0.1.0] - 2026-04-10

Initial release. 11-crate workspace implementing a Loopix-model Sphinx mixnet for private DeFi on Ethereum.

- Sphinx onion routing (X25519, ChaCha20, HMAC-SHA256, 32 KB fixed packets)
- SURB anonymous responses with Reed-Solomon FEC
- 4-stage relay pipeline (ingest → workers → mix → egress)
- Loopix cover traffic (server-side loop + drop)
- P2P via libp2p (TCP/Noise/Yamux, GossipSub, rate limiting)
- ZK gas payment integration, profitability engine, price oracle
- Privacy client SDK (deposit, withdraw, transfer)
- 575 tests, 47 benchmarks, 61 Prometheus metrics

Known limitations documented in [SECURITY.md](SECURITY.md).
