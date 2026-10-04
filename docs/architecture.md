# Architecture

NOX is a 3-layer stratified mix network implementing the [Loopix](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/piotrowska) anonymity model. Clients encrypt messages as Sphinx packets, each node peels one layer and applies a random delay, and exit nodes execute the request on Ethereum. Responses return via SURBs with Reed-Solomon FEC.

## Sphinx packet format

All packets are fixed-size **32 KB**.

```
|<-------------- 32,768 bytes (PACKET_SIZE) ----------------->|
|<- Sphinx header: 472B ->|<- Onion-encrypted body: 32,296B ->|
```

There is no outer encryption layer: the Sphinx header and body fill the packet. Application payloads are capped at `MAX_PAYLOAD_SIZE` (31,716 bytes), a budget that is part of the wire format.

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

Blake3 tag derived from the per-hop ECDH shared secret, checked after the header MAC verifies and before the body is decrypted. Checked against a rotational Bloom filter (`bloom_capacity`, 0.1% FP, `replay_window`). Tags are per-hop because key blinding changes the ephemeral key. The filter is written to `bloom.bin` on rotation, every `bloom_persist_interval_secs` while it changes, and on graceful shutdown.

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
 parse header     ECDH + MAC verify     DelayQueue    SendPacket
                  replay check          Poisson       or ExitPayload
                  Sphinx peel
```

- **Ingest**: Parse header. Drops on full queue (backpressure). `PoW` is verified at HTTP ingress.
- **Workers**: N parallel instances on a MPMC channel. ECDH + MAC, replay check, then decrypt + key blind.
- **Mix**: Poisson delay queue (`tokio_util::time::DelayQueue`). λ = 1/avg_delay_ms.
- **Egress**: Publishes `SendPacket` (forward) or `PayloadDecrypted` (exit) to the event bus.

### Packet identifiers

Each `SphinxPacket` carries an `id` string. A node uses its own random local ID internally and picks the
`id` it sends to the next hop when the packet leaves (`relayer.wire_ids = "per_hop"`, the default):

- Forward and cover packets get a fresh random ID (32 lowercase hex characters) at every hop.
- A reply built by an exit from a client's SURB is sent as `reply-0-{surb_id_hex}`. The entry node needs
  this handle to file the reply for its client.
- A node relaying a packet passes the reply handle on only when the packet came from an exit-capable
  registry member (role Exit or Full), which is where replies come from. In every other case, including a
  previous hop that is not a known member, the packet leaves with a fresh ID and
  `nox_wire_handle_dropped_total{reason}` counts the dropped handle.
- Inbound IDs from earlier versions (`{label}-{counter}-{surb_id_hex}`) are read as the same handle.

`relayer.wire_ids = "passthrough"` keeps IDs unchanged from hop to hop. It exists for benchmark harnesses
that follow one packet across nodes and is only accepted with `benchmark_mode = true`.

---

## SURB responses

The client pre-computes a return path as a SURB. The exit node wraps its response in the SURB without learning who the client is.

### Lifecycle

1. **Client creates SURB**: Ephemeral X25519 scalar, shared secrets with each hop, routing layers built backwards, PoW solved. Returns `(Surb, SurbRecovery)`.
2. **Client attaches SURBs to request**: Multiple SURBs for fragmented responses + FEC parity.
3. **Exit encapsulates**: Pad, encrypt with SURB's payload key, build Sphinx packet from pre-computed header.
4. **Response traverses mixnet**: Indistinguishable from forward traffic.
5. **Entry buffers the reply**: The last hop of the return path is the client's entry node. It buffers the still-encrypted reply under `reply-0-{surb_id_hex}`, using the reply handle the packet arrived with. Packets without a handle are never buffered.
6. **Client claims and decrypts**: The client claims its replies by exact SURB ID (`POST /api/v1/responses/claim`, `GET /api/v1/ws` or `GET /api/v1/responses/stream`; each SURB ID is 32 hex characters), peels each layer with stored keys, decrypts the final payload and removes padding.

### Format 2 replies

`Surb::new_v2` builds a SURB whose replies need no handle on the wire:

- Every hop's routing info carries a format 2 flag, covered by the header MAC (relay hops: the last byte of
  the hop's 128-byte segment; final hop: byte 1). Relay addresses in a format 2 SURB are limited to 93 bytes.
- The entry derives a 16-byte *delivery ID* from its shared secret with the SURB
  (`blake3::derive_key("nox surb v2 delivery id", ss)`). The client computes the same value; it is
  `SurbRecovery.id`.
- `Surb.id` is the constant `SURB_V2_MARKER`. An exit that sees it seals the reply with a 16-byte tag
  (`message || tag || 0x80 || 0...`, keyed from the SURB payload keys) and sends no reply handle.
  `SurbRecovery::decrypt` checks the tag when `version = 2`.

Node behaviour with `relayer.surb_formats = "both"` (default):

- A relay that sees the flag sends the packet on with a fresh identifier, whatever identifier it arrived with.
- An entry that sees the flag on the final hop files the reply under its delivery ID only, and only when the
  packet came over P2P from an admitted peer. Packets submitted over HTTP are never filed.
- Delivery-keyed replies live in their own store: at most 1,000 entries and 64 MiB, and no single previous-hop
  peer may hold more than 25% of either. They never push handle-keyed replies out.
- Claim, WebSocket and SSE return each reply as `reply-0-{the ID it was claimed with}`.
- The node lists `surb_v2` in `capabilities` in `/metrics/json` (and `paid_v2` on exits with paid execution).

`relayer.surb_formats = "v1"` turns format 2 off: flags are ignored and a format 2 SURB is answered like any
other SURB.

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

Registry admission: a peer is a member when its libp2p identity appears as `/p2p/<peer id>` in a registered node's
P2P URL; Noise authenticates that identity. In `enforce` mode (default) the node refuses connections and packets from
non-members once a registry reconcile has confirmed its node set against `topologyFingerprint()` and
`relayerCount()`, and closes links to peers that left the registry after `peer_admission_grace_secs`. IP bans and subnet
caps are refused from the same point; member addresses are exempt from both.

---

## Topology

3 layers: Entry (0), Mix (1), Exit (2). Primary layer assignment is derived from the first byte of
`SHA256(lowercase 0x address text)` and the on-chain role. Production topology schema 2 carries the complete,
canonically ordered Registry membership at one block plus a separate liveness record for every member. Clients verify
the full fingerprint, count, profiles, roles, and derived layers against that block before using fresh online liveness
to select routes. The client default liveness window is three minutes; future or older observations are ineligible.
Frozen members remain in the authenticated membership set but are not route eligible. Once the chain observer
has a position, node `/topology` endpoints also serve schema 2, with liveness from the node's own P2P links (itself
online; a member online if it answered within `topology_liveness_window_secs`). Without a position they serve schema 1.

The node keeps its view current by re-reading a member's full registry profile after every profile event (URL,
ingress, metadata, key, role, stake, freeze) and by a periodic reconcile that re-reads all members and compares the
node set with the chain. Loop cover travels through one node in each of the other two layers and back to the sender;
`nox_cover_loop_{sent,returned,lost}_total{first_hop,second_hop}` expose nodes that drop traffic.

### KPS entry

`nox-kps` (`crates/nox-kps`) gives browsers and native clients a direct path to a node's ingress over
[KPS](https://github.com/ethereum/kps): WebRTC and QUIC on one UDP port (15005), with the node authenticated by the
certificate hash in its address (`<ip>:15005:<certhash>`, published through the registry `metadataUrl`). Each KPS
stream carries one HTTP/1.1 exchange under the `nox-kps-http/1` profile ([PROTOCOL.md](../crates/nox-kps/PROTOCOL.md)).
nox-kps forwards packets, claims, topology and health to the node's loopback ingress with the client's source
address in `X-Real-IP`, so the node's per-IP limits apply, and serves `/metadata.json` and hash-addressed worker
bundles itself. It ships in the node image and runs as its own process and container (uid 10002).

---

## Economic model

Clients submit application-opaque EntryPoint calldata bound to a selected exit and execution ID. Exit nodes validate the request before simulation, accept only the EntryPoint settlement event for their own address, value only the exit fee, authorize the maximum transaction plan with fixed-point prices, persist signed bytes, and then submit.

Price oracle (`nox-oracle`) aggregates from Binance and CoinGecko.

---

## Observability

61 Prometheus metrics at `/metrics` (JSON summary at `/metrics/json`). Additional endpoints: `/topology` (JSON), `/events` (SSE stream of node, peer and topology events), `/admin/config` (redacted). `/events` carries no per-packet events: packet counts and latency are published only as aggregates.

The HTTP ingress applies a per-client-IP token bucket and an optional CORS origin allowlist (`[ingress]` in `config.example.toml`).

---

## Threat model

See [SECURITY.md](../SECURITY.md) for the full threat model including five P0 gaps. In summary:

**Protected against**: IP identification, content analysis, replay, packet flooding, sender-receiver linkability, key compromise (current packets), header tagging, MEV/front-running, relay payment linkability.

**Partial**: Inter-node traffic analysis (server cover only), timing correlation (depends on traffic volume), Sybil attacks (staking; P2P peers must be registered).

**Not protected**: Client activity observation (no client cover), past traffic decryption (no key rotation), body tagging (no SPRP cipher).
