# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow the git tags
(`v<version>`). The release process is in [docs/releasing.md](docs/releasing.md).

## [Unreleased]

- Every crate and binary now reports the workspace version (`0.4.0-rc.2`) instead of `0.1.0`. This shows in
  `nox --version`, the `x-nox-version` response header and the `nox_build_info` metric.
- Bumped anyhow and rand past their unsoundness advisories, and multihash to 0.19.5, which drops the yanked
  `core2` dependency.
- Dropped libp2p's unused `dns` feature. The P2P transport never resolved DNS multiaddrs (peers are dialed by
  `/ip4` address from the registry), so behaviour is unchanged and `hickory-proto` leaves the build.
- Release images are built only after the full CI suite passes on the tagged commit, and only for tags whose
  version matches the crates and has a changelog section. Each tag gets a GitHub release with these notes and
  the image digest.
- Replay tags are derived from the per-hop shared secret and checked in the workers after header
  verification. The replay filter is persisted every `relayer.bloom_persist_interval_secs` (default 60)
  and on graceful shutdown.
- The ingress response buffer is restricted to SURB replies. Responses are claimed by 32-hex-character
  SURB ID on `/api/v1/responses/claim`, `/api/v1/ws` and `/api/v1/responses/stream`. The legacy batch
  endpoint `GET /api/v1/responses/pending` is retired (410 Gone) in favour of `/claim`.
- `PacketTransport::recv_responses_batch` takes the SURB IDs to claim, and `HttpPacketTransport` uses
  `/api/v1/responses/claim`.
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
- P2P admission follows the registry: peers are matched to registered nodes by the libp2p identity in their
  P2P URL. `network.peer_admission` (`enforce` by default, `monitor`, `off`) refuses non-members once the node
  set is verified on-chain and `network.peer_admission_grace_secs` has passed, and closes links to peers that
  left the registry. Once enforcement is live, banned or over-limit
  addresses are refused before the handshake; member addresses are exempt.
- Registry profile events (ingress/metadata URL, stake, freeze, slash, key, role, URL) re-read the node's full
  profile. Frozen nodes stay in the served membership but are not routed through. A periodic reconcile
  (`topology_reconcile_interval_secs`, default 300) repairs updates lost on the event bus.
- The topology manager is the only writer of persisted peers, and layers are derived from address and role
  on load, so `/topology` no longer serves stale layers after a restart.
- `/topology` serves schema 2 with per-member liveness from the node's P2P links when the observer has a
  chain position.
- Loop cover returns to the sending node; `nox_cover_loop_{sent,returned,lost}_total` and
  `nox_cover_loop_rtt_seconds` report per-path delivery.
- Exit payloads are dispatched through four bounded per-type lanes (`[exit_workers]`: paid, quote, proxy,
  control). Dropped payloads and bus lag are counted per lane and subscriber.
- A transaction sent from the exit wallet outside the node no longer pauses paid submission: the node
  re-reads the chain nonce before signing, classifies "nonce too low" and "replacement transaction
  underpriced", retires an outbox record whose nonce was mined by another transaction and releases its quote.
- Paid quotes are refused while submission is paused. Quote admission checks reservation limits earlier, and
  expired reservations are released on demand.
- New metrics: `nox_paid_outcomes_total{kind,result,code}`, `nox_eth_submission_blocked`,
  `nox_eth_wallet_balance_gwei`, `nox_eth_wallet_balance_low`, `nox_quote_outstanding`,
  `nox_quote_pending_sponsored_gas`, `nox_quote_rolling_loss_gwei`, `nox_storage_degraded`,
  `nox_exit_payloads_dropped_total`, `nox_exit_lane_inflight`, `nox_event_bus_subscriber_lagged_total`.
  Paid v2 submissions now count in `nox_eth_transactions_submitted_total{type="paid_v2"}`, and
  `nox_health_status` reports 1 (degraded) while storage writes fail or paid submission is paused.
- Price server: one HTTP client with a descriptive User-Agent and a 10 s timeout, providers polled
  concurrently, Binance via `api.binance.us`, CryptoCompare only with `PRICE_CRYPTOCOMPARE_API_KEY`, and a
  price is published only when `PRICE_MIN_SOURCES` (default 2) providers agree.

## [0.4.0-rc.1] - 2026-09-25

Image: `ghcr.io/hisoka-io/nox:0.4.0-rc.1`.

### Upgrade notes

- The container now runs as the unprivileged user `nox` with UID:GID `10001:10001` (it ran as root before).
  Writable volumes (`/var/lib/nox` and any log or state mounts) must be owned by `10001:10001` before the new
  image starts, for example
  `docker run --rm --user 0:0 --entrypoint /bin/chown <image> -R 10001:10001 <mount>`. Config files only need to
  be readable.
- Persisted chain state is scoped to `(chain_id, registry)`. Pointing a data volume at another registry, or
  starting on an unscoped volume from an earlier release, drops the cursor, peers and sessions and replays the
  registry from `chain_start_block`.
- Seed topology snapshots are rejected unless they match the registry's on-chain `topologyFingerprint()`.

### Changes

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
- Bumped rustls to 0.23.45 (RUSTSEC-2026-0285).
- The builder image moved to Rust 1.95.0.

## [0.2.5] - 2026-08-01

Image: `ghcr.io/hisoka-io/nox:0.2.5`.

- The chain observer scans registry logs in bounded block ranges, so a node that was offline for a long time
  catches up instead of failing on an oversized `eth_getLogs` request.
- Storage failures that persist across retries mark the node's sled store as degraded and log once at ERROR,
  instead of failing silently.
- The fallback profitability path now records `cumulative_revenue_usd` and `cumulative_cost_usd` in micro-USD,
  like the primary path. It under-reported by 10,000x before.
- The root crate is published as `nox-mixnet` (the `nox` name is taken on crates.io). The binary is still `nox`.
- The Docker image carries OCI source and license labels.

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
