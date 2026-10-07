# End-to-end TLS tunnels

With a tunnel, the client runs TLS itself and the exit relays TLS records between the client and one
upstream host. Requests, responses and the sender's identity stay end-to-end encrypted between the
client and its RPC provider. Exits relay TLS ciphertext and see the provider's host name, timing and
sizes.

`ServiceRequest::TunnelV1` (bincode tag 8) carries one exchange. Exits that accept it list `tunnel_v1`
in the `capabilities` array of `/metrics/json`; clients send it only to those exits. Every other request
type works as before.

## What the exit sees

| Visible to the exit | End-to-end encrypted |
|---|---|
| Destination host name (TLS server name, the exit's own DNS lookup, the IP address) and port | URL path and query, including API keys |
| When a tunnel opens and closes | Request and response headers |
| Number, size and timing of TLS records in each direction | JSON-RPC method and parameters |
| The TLS client fingerprint, shared by every client of one version | Signed transactions |
| | Response content |
| | The sender |

The exit can neither read nor change the content. A client detects a cut-short response from HTTP
framing or the TLS `close_notify`, never from the exit's end-of-stream marker alone.

## Wire format

Payloads use the usual encoding: version byte `1`, then bincode with fixed-width little-endian integers.

```rust
ServiceRequest::TunnelV1(TunnelRequestV1 {
    tunnel_id: [u8; 16],       // client-random, one per tunnel
    seq: u32,                  // 0 opens; +1 for each new write or close; a copy repeats it
    open: Option<TunnelOpenV1>,// { host: String, port: u16 }, present exactly on seq 0
    ack_offset: u64,           // contiguous downstream bytes the client holds
    data: Vec<u8>,             // TLS records to write upstream
    close: bool,               // half-close upstream after writing data
    hold_ms: u32,              // how long the exit may hold this exchange's SURBs
})

TunnelReplyV1::Data { seq, offset: u64, data, fin: Option<TunnelFinV1> }   // tag 0
TunnelReplyV1::Rejected { seq, code: TunnelRejectCodeV1, retryable, detail } // tag 1
TunnelFinV1 = Eof | NeedSurbs | Expired
```

Each reply goes in its own SURB as the body of a one-fragment `ServiceResponse`. A data part carries at
most 30,656 bytes. Pinned byte vectors for both types are in `crates/nox-core/src/models/payloads.rs`.

### Exchanges

- Seq 0 opens the tunnel and carries the TLS `ClientHello`. Each later seq carries the next client
  records; a copy of a seq (for more SURBs, or after a loss) is never written upstream twice.
- Downstream bytes are numbered from 0 for the life of the tunnel. The exit keeps them from the
  client's `ack_offset` on, up to `max_window_bytes`, and pauses reading the upstream when that window
  or the exit-wide budget is full.
- The exit sends parts while it holds more than one SURB. The last SURB carries `Eof` when the upstream
  has closed and every byte has gone out, or `NeedSurbs` when more bytes wait. A copy with fresh SURBs
  resends from its `ack_offset`.
- When `hold_ms` (clamped to `min_hold_ms`..`max_hold_ms`) passes with SURBs left, the exit sends one
  empty part with `Expired` and releases the rest.
- A request with `close` and no SURBs ends the tunnel.
- Closed tunnel IDs are answered with `Expired` until `session_max_secs` after the open, so a replayed
  open never reaches the upstream twice.

## Checks at the exit

On open, before any connection:

- the port is in `tunnel.allowed_ports` (default `[443]`);
- the host is a DNS name (ASCII, internationalized names as punycode, no IP literal, no trailing dot)
  and passes `http.allowed_domains`;
- the first bytes are one complete TLS `ClientHello` whose server name equals the host, whose ALPN list
  is exactly `http/1.1`, and which offers no early data and no pre-shared key.

Then the exit resolves the host, checks every address with the same SSRF rules as the HTTP proxy, and
connects only to those addresses. For the rest of the tunnel every client byte must follow TLS record
framing (content types 20-23, record versions 0x0301 or 0x0303, lengths up to 16,640).

Rejections carry a `TunnelRejectCodeV1`: `Malformed`, `Disabled`, `PortNotAllowed`, `HostNotAllowed`,
`NotTls`, `DestinationBlocked`, `DnsFailed`, `ConnectFailed`, `SessionLimit`, `RateLimited`,
`UnknownSession`, `OutOfOrder`, `ByteLimit`, `UpstreamClosed`, `Expired`. `DnsFailed`, `ConnectFailed`,
`SessionLimit` and `RateLimited` are marked retryable.

## Operating an exit

- Turn tunnels on with `[tunnel] enabled = true` ([configuration.md](configuration.md#tunnel-exit-node)).
- Each open tunnel holds one TCP socket. Keep `max_sessions` well below the process file-descriptor
  limit, with headroom for P2P and HTTP connections.
- Buffered downstream data is bounded by `max_total_buffered_bytes` across all tunnels (128 MiB by
  default). Downstream bandwidth per exchange is bounded by the SURBs the client supplies, as on the HTTP
  proxy path.
- `http.allowed_domains` applies to the TLS server name. Hosts behind a shared CDN front are reached as
  the CDN routes them.
- Opens are rate-limited exit-wide (`opens_per_sec`, `opens_burst`). When `max_sessions` is reached the
  longest-idle tunnel with nothing in flight is closed to make room; clients move to another tunnel exit
  on `SessionLimit` or `RateLimited`.

### Metrics

Prometheus (`/metrics`):

| Metric | Labels |
|---|---|
| `nox_tunnel_sessions_active` | |
| `nox_tunnel_opens_total` | `result`: `opened` or a reject code |
| `nox_tunnel_exchanges_total` | `kind`: `write`, `copy`, `rejected`, `dropped` |
| `nox_tunnel_parts_total` | |
| `nox_tunnel_bytes_total` | `direction`: `up`, `down` |
| `nox_tunnel_closes_total` | `reason`: `eof`, `client`, `idle`, `lifetime`, `evicted`, `byte_limit`, `not_tls`, `upstream` |

`/metrics/json` adds `tunnelSessionsActive`, `tunnelOpened`, `tunnelOpenRejected` and `tunnelClosed`.
No metric or log line above `debug` names a host, address or tunnel; debug lines name a tunnel by the
first 4 bytes of its ID and never include relayed bytes.
