# Vendored dependency sources

Two crates of the WebRTC stack that nox-kps uses are built from the sources in
this directory through the workspace `[patch.crates-io]` table. Each one was
first committed verbatim, and the nox changes sit on top of it in separate
commits, so `git log -p vendor/` shows exactly what differs from upstream.
`NOX_VENDOR_BASE` in each directory names the upstream source.

Only nox-kps (the browser-facing entry sidecar) links these crates. The node
binaries do not use them.

## webrtc-sctp 0.13.0

Base: the kps fork at `a73a0a8f9e4f76f3b89ba1155562ec836bcf3f3b`, which is the
same rev kps `libs/rust/v0.2.2` patches in (`scripts/check-kps-patches.sh`
checks this). It already carries the read-shutdown drain and zero-window fixes.

Sender and receiver tuning for browser links with 250-300 ms round trips.
Every KPS exchange is one request and one reply, so most of a call's time is
the first flight of each; the changes aim at getting a 32-65 KB reply out in
one flight, and at recovering from a single lost packet without falling back
to a slow window.

| Setting | Upstream | Here | Where |
|---|---|---|---|
| Initial congestion window | min(4·MTU, max(2·MTU, 4,380 B)) = 4,380 B | 56 MTU = 68,768 B: one or two encrypted replies (32,402 / 64,797 B claim batch) with framing leave in one flight | `association_internal.rs` `INITIAL_CWND_MTUS` |
| Pacing | none, a window leaves at line rate | token bucket: 10 packets back to back after an idle period, the rest at 1.25 × the delivery rate measured from ack trains (20 Mbit/s before the first measurement); after a congestion loss the rate drops to just under the measured one | `pacing.rs`, write loop in `mod.rs` |
| Window after one loss | fast retransmit: max(cwnd/2, 4 MTU); T3-rtx: 1 MTU | at least the initial window when at most 2 chunks are lost in the window (random loss); RFC 4960 §7.2.3 otherwise, and on repeated T3-rtx expiries | `LOSS_CWND_FLOOR_MTUS`, `LOSS_FLOOR_MAX_LOSSES` |
| Tail loss | waits for T3-rtx (1 s at least) | after 2 × SRTT (+200 ms for a lone chunk) without progress, the earliest 4 unacked chunks are resent, cwnd untouched (after RFC 8985 TLP) | `TLP_*`, `tlp_timeout` |
| Receiver SACKs | every second packet (200 ms delayed-ack timer) | every packet for the first 64 KiB of each burst from the peer, so a browser in slow start (one MTU per SACK) opens its window twice as fast | `IMMEDIATE_SACK_BURST_*` |
| RTO.Initial | 3 s | 1 s (RFC 6298) | `timer/rtx_timer.rs` |

RTO.Min keeps RFC 4960's 1 s. In a test with 1.5% random loss each way on an
emulated 274 ms path, the 1 s floor gave the best reply times; a 300 ms floor
(SRTT + max(4·RTTVAR, 250 ms)) triggered more retransmission timeouts.

The numbers behind each setting come from `scripts/bench/kps-latency`
(headless Chromium, 274 ms RTT, with and without 1.5% loss and a 20 Mbit/s
bottleneck with a 32 KiB queue).

Chunk parsing: `Packet::unmarshal` hands each chunk the rest of the packet, so
every parser reads only up to its own chunk length.

| Chunk | Change | Where |
|---|---|---|
| FORWARD-TSN | stream entries end at the chunk length | `chunk/chunk_forward_tsn.rs` |
| INIT, INIT ACK | optional parameters end at the chunk length | `chunk/chunk_init.rs` |
| SHUTDOWN | size checked against the chunk length | `chunk/chunk_shutdown.rs` |
| ABORT, ERROR | error causes end at the chunk length | `chunk/chunk_abort.rs`, `chunk/chunk_error.rs` |

## webrtc-ice 0.14.0

Base: crates.io `webrtc-ice` 0.14.0, the version webrtc 0.14 resolves.

The kps server runs an ICE-lite agent with a single host candidate. Upstream,
that agent selects a candidate pair only when the browser sends a check with
`USE-CANDIDATE`, and DTLS waits for that selection. Browsers send their DTLS
ClientHello as soon as their first check succeeds but nominate on a later
check, 1 to 2.6 s afterwards, so every browser dial waited that long.

Here a lite agent selects the pair on the first authenticated check from the
peer (`agent_selector.rs`, controlled `handle_binding_request`). The check is
authenticated with the ICE password, which kps derives from the server
certhash, so only a client that knows the published address gets this far. A
later `USE-CANDIDATE` for another pair still switches to that pair.
