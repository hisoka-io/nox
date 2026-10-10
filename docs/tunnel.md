# End-to-end TLS tunnels

With a tunnel, the client runs TLS itself and the exit relays TLS records between the client and one
upstream host. Requests and responses stay end-to-end encrypted between the client and its RPC
provider, and the mixnet keeps the sender's identity hidden from both the exit and the provider. Exits
relay TLS ciphertext and see the provider's host name, timing and sizes.

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

Content stays confidential and tamper-evident end to end. The client confirms a response is complete
from HTTP framing or the TLS `close_notify`; the exit's end-of-stream marker is a transport hint.

The exit sees when each tunnel opens, so at low traffic the timing of one client's sequential tunnels
can link its calls; more traffic through each exit widens the crowd they hide in. The TLS key exchange
is classical X25519; a post-quantum hybrid key exchange, which keeps recorded tunnels confidential
against future quantum computers, is the next milestone.

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
  records. The exit writes each seq upstream exactly once; a copy (for more SURBs, or after a loss)
  only brings fresh SURBs and an updated `ack_offset`.
- Downstream bytes are numbered from 0 for the life of the tunnel. The exit keeps them from the
  client's `ack_offset` on, up to `max_window_bytes`, and pauses reading the upstream when that window
  or the exit-wide budget is full.
- The exit sends parts while it holds more than one SURB. The last SURB carries `Eof` when the upstream
  has closed and every byte has gone out, or `NeedSurbs` when more bytes wait. A copy with fresh SURBs
  resends from its `ack_offset`.
- When `hold_ms` (clamped to `min_hold_ms`..`max_hold_ms`) passes with SURBs left, the exit sends one
  empty part with `Expired` and releases the rest.
- A request with `close` and no SURBs ends the tunnel (any seq after 0).
- The exit takes a seq's data once the upstream has read the previous seq's data. Data on a new seq
  after the upstream closed, or while the previous write is still unread, ends the tunnel with
  `UpstreamClosed` and is never written.
- Closed tunnel IDs are answered with `Expired` until `session_max_secs` after the open, so each tunnel
  ID opens at most one upstream connection.

## Checks at the exit

On open, before any connection:

- the port is in `tunnel.allowed_ports` (default `[443]`);
- the host is a DNS name (ASCII, internationalized names as punycode, no trailing dot) and passes
  `http.allowed_domains`. IP literals are refused, including names whose last label is a number
  (`134744072`, `8.8.2056`, `0x08080808`), which system resolvers read as IPv4 addresses;
- the first bytes are one complete TLS `ClientHello` whose server name equals the host, whose ALPN list
  is exactly `http/1.1`, and which offers no early data, no pre-shared key and no TLS 1.2 session
  ticket.

Then the exit resolves the host, checks every address with the same SSRF rules as the HTTP proxy, and
connects only to those addresses, with one `connect_timeout_ms` deadline for both steps. Rejection
details name the rule, never a resolved address. For the rest of the tunnel every client byte must follow TLS record
framing (content types 20-23, record versions 0x0301 or 0x0303, lengths up to 16,640).

Rejections carry a `TunnelRejectCodeV1`: `Malformed`, `Disabled`, `PortNotAllowed`, `HostNotAllowed`,
`NotTls`, `DestinationBlocked`, `DnsFailed`, `ConnectFailed`, `SessionLimit`, `RateLimited`,
`UnknownSession`, `OutOfOrder`, `ByteLimit`, `UpstreamClosed`, `Expired`. `DnsFailed`, `ConnectFailed`,
`SessionLimit` and `RateLimited` are marked retryable.

## Operating an exit

- Turn tunnels on with `[tunnel] enabled = true` ([configuration.md](configuration.md#tunnel-exit-node)).
- Each open tunnel holds one TCP socket. Keep `max_sessions` well below the process file-descriptor
  limit, with headroom for P2P and HTTP connections. A container started with Docker's usual soft limit of
  1,024 open files suits `max_sessions = 512`; for the default 4,096, raise the limit first (compose
  `ulimits: nofile`).
- Downstream data waiting for acknowledgement is kept within `max_total_buffered_bytes` across all
  tunnels (128 MiB by default). When that is reached, the longest-idle tunnels holding bytes close to
  make room, and each tunnel with an exchange in flight keeps reading up to its fair share (the limit
  divided by the open tunnels, at least one part). Downstream bandwidth per exchange is bounded by the
  SURBs the client supplies, as on the HTTP proxy path.
- Upstream data waiting to be written is at most one client write (`max_write_bytes`) per tunnel.
- Once the upstream closes, a tunnel closes after `closed_linger_ms` without a client request.
- `http.allowed_domains` applies to the TLS server name. Hosts behind a shared CDN front are reached as
  the CDN routes them.
- Opens are rate-limited exit-wide (`opens_per_sec`, `opens_burst`). When `max_sessions` is reached the
  longest-idle tunnel with nothing in flight is closed to make room, or else the tunnel whose upstream
  has been silent longest, past `stall_evict_ms`; clients move to another tunnel exit on `SessionLimit`
  or `RateLimited`.

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
Metrics and log lines above `debug` carry counts only. Debug lines name a tunnel by the first 4 bytes
of its ID and leave relayed bytes out.
