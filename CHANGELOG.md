# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

- Replay tags are derived from the per-hop shared secret and checked in the workers after header
  verification. The replay filter is persisted every `relayer.bloom_persist_interval_secs` (default 60)
  and on graceful shutdown.
- The ingress response buffer is restricted to SURB replies. Responses are claimed by 32-hex-character
  SURB ID on `/api/v1/responses/claim`, `/api/v1/ws` and `/api/v1/responses/stream`. The legacy batch
  endpoint `GET /api/v1/responses/pending` is retired (410 Gone) in favour of `/claim`.
- `PacketTransport::recv_responses_batch` takes the SURB IDs to claim, and `HttpPacketTransport` uses
  `/api/v1/responses/claim`.
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
- `chain_start_block` is now scanned inclusively. The observer previously started at the block after it, so
  registrations mined in the registry's deployment block were never seen.
- `/topology` no longer makes an RPC call per request. Its `block_number` is now the block the chain observer
  has applied, held 16 blocks behind the scanned head but never before the latest registry log. That block
  matches the served node set, and client RPCs that trail the node's RPC can serve it. The endpoint no longer
  returns 503 when the RPC is down.
- Hardened exit requests to user-supplied RPC, broadcast and HTTP URLs. RPC error text returned to clients no
  longer includes upstream transport details.
- `/events` no longer streams `packet_processed`. Packet counts and latency remain available as aggregates on
  `/metrics` and `/metrics/json`.
- Added an `[ingress]` config section: a per-client-IP rate limit on the HTTP ingress (default 100 req/s, burst
  400) and an optional CORS origin allowlist for the ingress and API ports (default: any origin).
- Exit nodes reject the legacy `SubmitTransaction` payload and request; paid execution uses
  `PaidTransactionV2`. A request with reply SURBs receives a `SUBMISSION` rejection.
- Removed the unused AEAD encapsulation from `nox_crypto::SphinxPacket`; the type is now a fixed-size buffer.
  Packet sizes are unchanged.

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
