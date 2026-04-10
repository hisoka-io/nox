# Architecture

NOX is a 3-layer stratified mix network implementing the [Loopix](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/piotrowska) anonymity model. Clients encrypt messages as Sphinx packets, each node peels one layer and applies a random delay, and exit nodes execute the request on Ethereum. Responses return via SURBs with Reed-Solomon FEC.

## Sphinx packet format

All packets are fixed-size **32 KB**.

```
|<-------------- 32,768 bytes (PACKET_SIZE) ----------------->|
|<- Header: 1024B ->|<- Nonce: 12B ->|<- Ciphertext+Tag: 31,732B ->|
```

The outer packet uses ChaCha20-Poly1305 AEAD. Inside is the Sphinx header and onion-encrypted body.

### Header (472 bytes)

```
|<- Ephemeral Key: 32B ->|<- Routing Info: 400B ->|<- MAC: 32B ->|<- PoW Nonce: 8B ->|
```

- **Routing info**: 128 bytes per hop (hop type, next-hop MAC, next-hop address). 400 bytes = max **3 hops**.
- **MAC**: HMAC-SHA256, constant-time verified via `subtle` crate.
- **PoW nonce**: Blake3 hashcash solution.

### Per-hop operations

1. X25519 ECDH with relay's static key
2. Derive keys via 4x SHA-256: routing key, MAC key, body key, blinding scalar
3. Verify MAC (constant-time)
4. Decrypt routing info and body (ChaCha20)
5. Blind ephemeral key for next hop (Curve25519 scalar mul)

ECDH + key blinding account for ~95% of per-hop cost. Symmetric ops are negligible.

### Replay protection

Blake3 tag over `(ephemeral_key, mac, nonce)`. Checked against a rotational Bloom filter (10M capacity, 0.1% FP, 1-hour window). Tags are per-hop because key blinding changes the ephemeral key.

### Padding

ISO/IEC 7816-4 with constant-time unpadding via `subtle`.

---

## Relay pipeline

4-stage concurrent pipeline in `nox-node/src/services/relayer/`:

```
PacketReceived
     |
     v
 IngestStage ──> WorkerStage (x N) ──> MixStage ──> EgressStage
 replay check     Sphinx peel           DelayQueue    SendPacket
 PoW verify       route/exit classify   Poisson       or ExitPayload
```

- **Ingest**: Parse header, check replay bloom, verify PoW. Drops on full queue (backpressure).
- **Workers**: N parallel instances on a MPMC channel. ECDH + MAC + decrypt + key blind.
- **Mix**: Poisson delay queue (`tokio_util::time::DelayQueue`). λ = 1/avg_delay_ms.
- **Egress**: Publishes `SendPacket` (forward) or `PayloadDecrypted` (exit) to the event bus.

---

## SURB responses

The client pre-computes a return path as a SURB. The exit node wraps its response in the SURB without learning who the client is.

### Lifecycle

1. **Client creates SURB**: Ephemeral X25519 scalar, shared secrets with each hop, routing layers built backwards, PoW solved. Returns `(Surb, SurbRecovery)`.
2. **Client attaches SURBs to request**: Multiple SURBs for fragmented responses + FEC parity.
3. **Exit encapsulates**: Pad, encrypt with SURB's payload key, build Sphinx packet from pre-computed header.
4. **Response traverses mixnet**: Indistinguishable from forward traffic.
5. **Client decrypts**: Peel each layer with stored keys, decrypt final payload, remove padding.

---

## Forward error correction

Reed-Solomon FEC on SURB responses handles packet loss without retransmission round-trips. In a mixnet, each ARQ retry adds a full round-trip through Poisson delays. FEC trades bandwidth for latency.

**Encoding**: Fragment response into D data shards (30 KB each), generate P parity shards (P = ceil(D * fec_ratio), default 0.3). Any D-of-(D+P) shards suffice for recovery.

**Limits**: 255 max shards (GF(2^8)), 200 max fragments, ~6.4 MB max message.

---

## Traffic shaping

Loopix cover traffic via two Poisson streams:

- **Loop**: Self-routed packets through all 3 layers. Health monitoring + traffic pattern cover.
- **Drop**: Random-path packets, silently discarded at exit. Volume hiding.

**Gap**: Client-side cover traffic is not implemented. Server-side cover protects inter-node links, but client activity is observable. See [SECURITY.md](../SECURITY.md).

---

## Exit service

Dispatches decrypted payloads by type: Ethereum TX execution, HTTP proxy (SSRF-protected), anonymous RPC, echo, or fragmented message reassembly. Anonymous requests include SURBs for response delivery.

Reassembly is bounded: 10 MB buffer, 50 concurrent messages, 200 fragments max, 120s stale timeout.

---

## P2P networking

libp2p stack: TCP + Noise + Yamux + Ed25519 identity + CBOR serialization.

Protocols: `/nox/packet/1` (Sphinx relay + handshake + topology), identify, ping, GossipSub (fee updates).

DoS protection: token-bucket rate limiting (3 tiers: Unknown/Trusted/Penalized), max 1000 connections, /24 subnet filtering, graduated IP bans, session tickets for fast reconnection.

---

## Topology

3 layers: Entry (0), Mix (1), Exit (2). Layer assignment is deterministic from `SHA256(address)`. Nodes discovered via HTTP seed bootstrap, on-chain `NoxRegistry` events, or P2P sync. XOR fingerprint over all registered nodes matches on-chain for consistency verification.

---

## Economic model

Clients pay exit nodes via `gas_payment` ZK proof: "I own a note with sufficient balance and I'm transferring X to relayer Y" - without revealing the note or sender. Exit nodes verify the proof, simulate the TX (`eth_simulateV1`), check profitability (revenue/cost >= 1 + margin), then submit.

Price oracle (`nox-oracle`) aggregates from Binance and CoinGecko.

---

## Observability

61 Prometheus metrics at `/metrics`. Additional endpoints: `/topology` (JSON), `/events` (SSE stream), `/admin/config` (redacted).

---

## Threat model

See [SECURITY.md](../SECURITY.md) for the full threat model including five P0 gaps. In summary:

**Protected against**: IP identification, content analysis, replay, packet flooding, sender-receiver linkability, key compromise (current packets), header tagging, MEV/front-running, relay payment linkability.

**Partial**: Inter-node traffic analysis (server cover only), timing correlation (depends on traffic volume), Sybil attacks (staking but no handshake verification).

**Not protected**: Client activity observation (no client cover), past traffic decryption (no key rotation), body tagging (no SPRP cipher).
