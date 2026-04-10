# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
