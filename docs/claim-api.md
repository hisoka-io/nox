# Reply claims: protocol v2

`POST /api/v1/responses/claim` is how a client collects the replies its SURBs
brought back to an entry node. Version 2 adds four optional request fields:

- a compact reply encoding (binary or base64 instead of a JSON number array);
- retain-until-ack, so a transfer that is cut off can be claimed again;
- explicit acks;
- long-polling, so a claim waits at the entry for the reply instead of
  polling every 200 ms.

Every v2 field is optional and every v1 request is answered exactly as before.
The same API is served on the node's ingress port and through nox-kps
(`kps:<ip>:<port>:<certhash>/api/v1/responses/claim`).

## Request

`Content-Type: application/json`

```json
{
  "surb_ids": ["<32 hex>", "..."],
  "encoding": "binary",
  "retain": true,
  "ack": ["<32 hex>", "..."],
  "wait_ms": 15000
}
```

| Field | Type | Default | Meaning |
|---|---|---|---|
| `surb_ids` | array of 32-hex strings | required | Reply IDs to claim (SURB IDs for format 1, delivery IDs for format 2). Only exact matches are returned. |
| `encoding` | string | `"json"` | `"json"`, `"base64"` or `"binary"`. Unknown values fall back to `"json"`. Overrides `Accept`. |
| `retain` | bool | `false` | `false`: each returned reply is deleted (v1). `true`: each returned reply stays at the entry until acked, or until the claim grace (20 s by default) has passed since it was first returned. |
| `ack` | array of 32-hex strings | `[]` | Replies the client has. They are deleted **before** the claim runs, so an ID in both lists is deleted and not returned. Acking an ID whose reply has not been claimed yet deletes it too (for example a parity reply that is no longer needed). |
| `wait_ms` | integer | `0` | Long-poll: hold the request until at least one of `surb_ids` has a reply, or this many milliseconds have passed. Honoured only together with `retain: true`. Capped by the entry (see `x-nox-claim-wait-max-ms`). |

Entries skip fields they do not know, so newer clients can add fields and
older entries keep answering.

Instead of `encoding`, a client can send `Accept: application/vnd.nox.claim-batch`
to select the binary encoding. A body `encoding` field always wins.

### Limits (through nox-kps)

- Body at most `claimRequestMaxBytes` (64 KiB), else `413`.
- At most `claimMaxSurbIds` (128) IDs in `surb_ids` and at most as many in
  `ack`, each exactly 32 hex characters, else `400`.
- `encoding` at most 32 characters; `retain` a bool; `wait_ms` a non-negative
  integer, else `400`.
- `wait_ms` is capped to `claimWaitMaxMs` (20,000 by default). When all
  long-poll slots are busy (`limits.max_concurrent_claim_waits`, 128 by
  default) the claim is relayed with `wait_ms: 0` and answers at once.
  Long-polls do not use the general in-flight upstream slots.
- Claims are rate-limited per IP at 30/s, burst 200 (unchanged).

## Response

Every claim response carries:

| Header | Value |
|---|---|
| `x-nox-claim-version` | `2` |
| `x-nox-claim-wait-max-ms` | Longest `wait_ms` honoured (through nox-kps: the lower of the node's and the relay's limit) |

An entry without these headers is a v1 entry; see Compatibility.

Status codes: `200` with replies, `204` when none of the IDs has a reply yet
(after the wait, if one was granted), `400` for a malformed ID or field.

### `encoding: "json"` (default, v1)

`Content-Type: application/json`

```json
[{"id": "reply-0-<32 hex>", "data": [12, 255, 0, ...]}]
```

### `encoding: "base64"`

`Content-Type: application/json`

```json
[{"id": "reply-0-<32 hex>", "data_b64": "DP8A...", "reclaimed": false}]
```

`data_b64` is standard base64 (RFC 4648 §4) with `=` padding.

### `encoding: "binary"`

`Content-Type: application/vnd.nox.claim-batch`

All integers are big-endian.

```text
offset  size  field
0       1     version = 0x01
1       2     item count N
then N items:
        1     flags (bit 0 = reclaimed; other bits 0, ignore them)
        2     id length L
        L     id (ASCII, e.g. "reply-0-<32 hex>")
        4     data length D
        D     data (one encrypted reply, at most 31,716 bytes)
```

The body ends after the last item. A reader should reject a version byte it
does not know and should check that every length stays inside the body.

Size for the usual two-reply answer (data plus parity, 32,296 bytes each):
64,689 bytes binary, about 86 KB base64, about 230.7 KB JSON.

`reclaimed` (binary flag bit 0, base64 field) is set when a retaining claim had
already returned this reply: the earlier transfer was lost or is still in
flight. JSON v1 items do not carry it.

## Retain and ack: client flow

```text
claim  {surb_ids:[a,b], encoding:"binary", retain:true, wait_ms:15000}
  <- 200 [a]                  (a stays at the entry for the claim grace)
claim  {surb_ids:[b], ack:[a], encoding:"binary", retain:true, wait_ms:15000}
  <- 204 after up to 15 s     (a is deleted first; b never came)
```

If a claim is cut off (stream reset, timeout, connection lost), claim the same
IDs again within the grace and the entry answers with the same replies,
flagged `reclaimed`. Ack every reply once it has been decoded; unacked
replies are dropped when the grace ends.

Clients should not re-claim replies they already hold: acking them is what
frees the entry's memory.

## Long-poll: client flow

Keep one long-poll claim open per entry for all IDs that are waiting, with
`retain: true` and `wait_ms` at most `x-nox-claim-wait-max-ms` (through
nox-kps also at most `limits.claimWaitMaxMs` from `/metadata.json`). When it
answers (`200` or `204`), ack what arrived and open the next one. When a new
request adds IDs while a long-poll is open, either open a second claim for the
new IDs or let the current one finish; both are fine. nox-kps allows 32
streams per connection.

## Compatibility

| Client | Entry | Result |
|---|---|---|
| v1 (`{"surb_ids":[...]}` only) | v2 | Exactly v1: JSON number arrays, delete on claim, immediate answer. Unknown response headers are ignored. |
| v2 | v1 node (rc.6 and earlier) | The v1 node ignores the extra fields: it answers immediately with v1 JSON and deletes on claim. The client recognises this by `Content-Type: application/json` without `data_b64`, or by the missing `x-nox-claim-version`, and falls back to v1 parsing and its own polling. |
| v2 | v1 nox-kps (rc.6) in front of a v2 node | rc.6 nox-kps relays the body unchanged and relays `Content-Type`, `Cache-Control` and `Retry-After` back. Encoding, retain and ack work. Its claim timeout is 10 s, so long-polls go through nox-kps releases that list the `claim-v2` capability with `limits.claimWaitMaxMs > 0` in `/metadata.json`. |

How a v2 client decides what to send:

1. Through nox-kps: read `/metadata.json` once per entry. `claim-v2` in
   `capabilities` means this relay forwards long-polls; use
   `limits.claimWaitMaxMs` as the cap. Without it, send `encoding` and
   `retain` (harmless on older entries) but not `wait_ms`.
2. Direct HTTP: send the v2 fields; check `x-nox-claim-version` on the
   first answer and use `x-nox-claim-wait-max-ms` as the cap. The ingress
   CORS policy lists both headers in `Access-Control-Expose-Headers`, so
   browser clients can read them.
3. Always parse by `Content-Type`: `application/vnd.nox.claim-batch` is the
   binary batch; `application/json` items have either `data` (number array)
   or `data_b64`.

## Streams

`GET /api/v1/responses/stream?surb_ids=a,b&encoding=base64` (SSE) and the
`/api/v1/ws` WebSocket (a `subscribe` message with `"encoding":"base64"`)
send `{"id","data_b64","reclaimed"}` items instead of number arrays. Both
keep the v1 delete-on-delivery behaviour and are served on the node's ingress
port. nox-kps answers each exchange with one length-delimited response, so
over KPS the long-poll claim is the push channel: it returns as soon as a
reply lands.

## Node settings

`[ingress]` in the node config:

| Key | Default | Meaning |
|---|---|---|
| `claim_retain_grace_ms` | `20000` | How long a retained reply stays re-claimable after its first claim (1 to 300,000). |
| `claim_wait_max_ms` | `20000` | Longest long-poll honoured (0 to 60,000; 0 turns long-polling off). |
| `claim_wait_max_concurrent` | `256` | Claims that may long-poll at once; beyond it a claim answers at once. |

nox-kps `[limits]`: `claim_wait_max_ms` (default 20,000, at most 60,000),
`max_concurrent_claim_waits` (default 128).

Metrics: `nox_ingress_claim_events_total{event=...}` on the node with
`reclaimed`, `acked`, `wait`, `wait_busy`, `wait_timeout`, and one count per
encoding (`json`, `base64`, `binary`, counting replies sent);
`nox_kps_claim_waits_total{result=granted|busy|off}` on nox-kps.

## Privacy notes

- A reply is only ever returned for its exact 16-byte random ID, which only
  the client that built the SURB knows. Retain, re-claim and ack all use that
  same ID; nothing else can address a reply.
- Retaining keeps a reply at most `claim_retain_grace_ms` after its first
  claim, and never past the 5-minute TTL that unclaimed replies already have.
  Retained replies count against the same entry and byte caps, and are
  evicted before unclaimed replies.
- A re-claim tells the entry nothing new: the entry already sees every claim
  for an ID, and a client that lost a transfer would claim the same IDs again
  under v1 too (and get `204`).
- Logs and metrics carry counts only, never IDs.
