# nox-kps-http/1

The wire profile nox-kps serves on every KPS stream. It builds on the KPS-HTTP/1
profile of [tor-js](https://github.com/ethereum/tor-js/blob/main/PROTOCOL.md) and
on the `kps:` resolver profile of
[anon-rpc SPEC §4.2](https://github.com/ethereum/anon-rpc/blob/main/SPEC.md), with
one tightening: request bodies are delimited by `Content-Length`.

## 1. Transport

- A client dials `<ip>:<port>:<certhash>` with KPS (WebRTC for browsers, QUIC for
  native clients; both on the same UDP port). The certhash pins the server's
  certificate, so the address authenticates the node.
- One HTTP/1.1 exchange per KPS stream. Connections are reused; streams are not.
- KPS datagrams are not used; received datagrams are ignored.

## 2. Requests

```
METHOD SP origin-form SP HTTP/1.1 CRLF
Host: <certhash>            (required; never a trust input)
Content-Type: ...           (routes with a body)
Content-Length: <n>         (required when there is a body; must equal the body length)
CRLF
<body>
```

Then the client closes its write side (`closeWrite()`).

- Header block (request line included): at most 16 KiB, else `431`.
- Complete header block within 10 s of opening the stream, else the stream is reset.
- The whole exchange completes within 30 s, else the stream is reset.
- Refused with `400`: `Transfer-Encoding`, more than one distinct `Content-Length`,
  `Upgrade`, `Expect`, a missing `Host`, an absolute-form target. `obs-fold` is
  refused by the parser.
- HTTP versions other than 1.1: `505`.
- A body shorter than its `Content-Length` abandons the exchange: the stream is
  reset without a response.
- A second request written on the same stream is never read.

## 3. Responses

- Status line, headers, body. nox-kps always sends `Content-Length` (except on
  `204` and `304`, which carry neither body nor length) and then finishes the
  stream, so the body is also delimited by end of stream.
- Never `Transfer-Encoding`, never `3xx`.
- Errors carry a short `text/plain; charset=utf-8` diagnostic that clients must
  not parse.

## 4. Routes

The allowlist is fixed in the binary. Unknown path `404`; known path with
another method `405` with `Allow`; unknown method `501`.

| Method | Path | Request rules | Served by |
|---|---|---|---|
| POST | `/api/v1/packets` | `Content-Type: application/octet-stream`; body exactly 32,768 bytes (shorter `400`, longer `413`) | node ingress |
| POST | `/api/v1/responses/claim` | `Content-Type: application/json`; at most 64 KiB (`413`); `{"surb_ids":[...]}` with at most 128 IDs of exactly 32 hex characters (`400`; the operator's value is `limits.claimMaxSurbIds` in §5) | node ingress |
| GET | `/topology` | no body | node topology API; one response is shared by all clients for 1 s |
| GET | `/health` | no body | nox-kps: `200 {"status":"ok"}` when the node ingress answers its health check, else `503 {"status":"degraded","upstream":"ingress-unreachable"}` |
| GET, HEAD | `/metadata.json` | no body | nox-kps (§5) |
| GET, HEAD | `/keccak/<hh>/<62 hex>` | no body; lowercase hex only | nox-kps bundle store (§6) |

A wrong media type is `415`; a body without `Content-Length` is `411`; a body on
a `GET` route is `400`. Query strings are ignored and never forwarded.

Per client IP (IPv6: per /64), token buckets limit packets (20/s, burst 100),
claims (30/s, burst 200), topology (2/s, burst 10) and bundles (1/s, burst 5).
Over the limit: `429` with `Retry-After: 1`. When too many upstream requests
are in flight, or 8 bundle downloads are already in progress: `503` with
`Retry-After: 1`.

Upstream failures: `502` (connection refused or reset, response over the
relay cap) and `504` (no answer in time). Other node statuses pass through.

Claim sizing. The node removes every reply it returns from its buffer, and
writes each reply's bytes as a JSON array of decimal numbers: one full reply
(31,716 bytes) is at most 126,928 bytes of JSON. nox-kps refuses to start
unless `claimMaxSurbIds` full replies fit in `claimResponseMaxBytes`
(128 × 126,928 + 2 = 16,246,786 ≤ 16,777,216 with the defaults), so every
claim it accepts can be relayed whole. Clients split larger claims into
chunks of at most `claimMaxSurbIds` IDs.

What reaches the node: the route's fixed method and path, `Host`,
`Content-Type`, `Content-Length`, the body, and one `X-Real-IP` carrying the
KPS source address of the client (any client-supplied forwarding header is
dropped). What returns to the client: status, body, `Content-Type`,
`Cache-Control`, `Retry-After`.

## 5. `/metadata.json`

```json
{
  "protocol": "nox-kps-http/1",
  "software": "nox-kps",
  "version": "0.1.0",
  "node": "0x862d6b1105bde9d64dc5182fe3cd9d09f6f37463",
  "addresses": ["3.239.73.249:15005:uEiB..."],
  "capabilities": ["metadata", "health", "packets", "claim", "topology", "worker-bundles"],
  "limits": { "packetBytes": 32768, "claimRequestMaxBytes": 65536, "claimMaxSurbIds": 128, "claimResponseMaxBytes": 16777216 },
  "demo": false
}
```

Keys appear in this order. `node` is `null` when not configured;
`worker-bundles` is listed only when the bundle store is enabled.

## 6. `kps:` worker bundles

`GET /keccak/<hh>/<rest>` returns the bytes whose keccak-256 is `<hh><rest>`
(2 + 62 lowercase hex characters), with `Content-Type: text/javascript`,
`Cache-Control: public, max-age=31536000, immutable` and `Content-Length`.
Anything else is `404`. Files are hashed when loaded and held in memory; a file
whose bytes do not match its name is never served. The resolver string a
specifier publishes is `kps:<ip>:<port>:<certhash>/keccak/<hh>/<62 hex>`.
Identity content coding is always served; a gzip copy is available behind
`limits.bundle_gzip` for clients that list `gzip`.
