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

Sender tuning added for browser links with 250-300 ms round trips:

| Setting | Upstream | Here | Where |
|---|---|---|---|
| Initial congestion window | min(4·MTU, max(2·MTU, 4380 B)) = 4,380 B | min(10·MTU, max(2·MTU, 14,600 B)) = 12,280 B (RFC 6928 IW10) | `association_internal.rs` `initial_cwnd` |
| RTO.Initial | 3 s | 1 s (RFC 6298) | `timer/rtx_timer.rs` |

RTO.Min keeps RFC 4960's 1 s. In a test with 1.5% random loss each way on an
emulated 274 ms path, the 1 s floor gave the best reply times; a 300 ms floor
(SRTT + max(4·RTTVAR, 250 ms)) triggered more retransmission timeouts. A
retransmission timeout resets the window to one MTU and halves `ssthresh`, as
RFC 4960 §7.2.3 requires.

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
