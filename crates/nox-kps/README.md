# nox-kps

The KPS entry sidecar for [Nox](https://github.com/hisoka-io/nox) mixnet nodes.

nox-kps lets browsers and native clients reach a Nox node directly over
[KPS](https://github.com/ethereum/kps) (Key Pinned Streams): WebRTC for
browsers and QUIC for native clients, both on one UDP port, with the node
authenticated by the certificate hash in its address. No domain name, no
certificate authority and no gateway sit in the path. This is how the Nox
anon-rpc worker talks to the mixnet from inside a wallet.

Each KPS stream carries one HTTP/1.1 exchange (the `nox-kps-http/1` profile in
[PROTOCOL.md](PROTOCOL.md)). nox-kps forwards a fixed allowlist of routes to
the node's loopback ingress and serves the rest itself:

| Route | Purpose |
|---|---|
| `POST /api/v1/packets` | submit one 32 KiB Sphinx packet |
| `POST /api/v1/responses/claim` | claim SURB replies by ID |
| `GET /topology` | the node's view of the network |
| `GET /health` | entry health (probes the node) |
| `GET /metadata.json` | capability document |
| `GET /keccak/<hh>/<62 hex>` | hash-addressed worker bundles (the anon-rpc `kps:` resolver) |

The node binary does not change. nox-kps runs next to it in the same compose
project, with host networking, as uid 10002.

## Ports

| Port | Protocol | Exposure | Use |
|---|---|---|---|
| 15005 | UDP | public | KPS (WebRTC + QUIC) |
| 15006 | TCP | loopback | `/metrics` (Prometheus) and `/healthz` |
| 15002, 15003 | TCP | loopback | the node's ingress and topology API (upstreams) |

Open UDP 15005 in the cloud security group and in the host firewall. nox-kps
makes no outbound internet connections.

The `lo` interface should carry only `127.0.0.1/8` and `::1`: the kps listener
gathers its WebRTC candidates from `lo*` interfaces, and an extra address there
breaks browser dials. `nox-kps check-config` and the startup log name any
such address.

## Install on a node

1. Load the image (until a registry image is published):

   ```sh
   docker load < nox-kps.tar
   export NOX_KPS_IMAGE=nox-kps@sha256:<digest>
   ```

2. Copy [`deploy/docker-compose.kps.yml`](deploy/docker-compose.kps.yml) next to the
   node's `docker-compose.yml`, and [`deploy/nox-kps.example.toml`](deploy/nox-kps.example.toml)
   to `nox-kps.toml`. Set `advertise` to the node's public IP and `node_address`
   to its registry address.

3. Validate the configuration:

   ```sh
   docker compose -f docker-compose.yml -f docker-compose.kps.yml run --rm nox-kps-admin nox-kps check-config
   ```

4. Create the identity once. This prints the certhash, the KPS address and the
   `metadataUrl` string to publish:

   ```sh
   docker compose -f docker-compose.yml -f docker-compose.kps.yml run --rm nox-kps-admin nox-kps init
   ```

   The key lives in the `nox-kps-identity` volume. Back it up with the node's
   other secrets: the certhash is part of the node's published address, and
   `nox-kps run` only ever loads this key. Copy the printed
   `expected_certhash = "..."` line into `nox-kps.toml`: `run` serves only the
   identity it names, so a swapped or wrongly restored volume is caught before
   any client connects.

5. Set the node's client-IP header so its per-IP limits apply to KPS clients
   (nginx already sends the same header), then restart the node:

   ```toml
   [ingress]
   client_ip_header = "x-real-ip"
   ```

6. Start nox-kps and check it:

   ```sh
   docker compose -f docker-compose.yml -f docker-compose.kps.yml up -d nox-kps
   docker exec nox-kps nox-kps healthcheck --kps   # dials the listener over QUIC end to end
   docker exec nox-kps nox-kps address
   ```

7. Publish the address on chain with the node's `updateMetadataUrl`, using the
   `metadataUrl` value printed by `init` or `address`
   (`kps:<ip>:15005:<certhash>/metadata.json`).

## Worker bundles

```sh
docker compose -f docker-compose.yml -f docker-compose.kps.yml run --rm \
  -v "$PWD/anon-rpc-worker.js:/in/anon-rpc-worker.js:ro" \
  nox-kps-admin nox-kps bundle add /in/anon-rpc-worker.js
```

`bundle add` stores the file under its keccak-256 name, read-only, and prints
the `kps:` resolver strings. The running service picks it up within
`limits.bundle_rescan_secs`. `bundle list` shows what is served and
`bundle verify` re-hashes every file.

## Configuration

TOML at `/etc/nox-kps/config.toml`, with `NOX_KPS__<KEY>` environment overrides
(`NOX_KPS__LIMITS__MAX_CONNECTIONS=256`; lists are comma-separated). Unknown
keys are refused, and every invalid value is reported with its field name.
[`deploy/nox-kps.example.toml`](deploy/nox-kps.example.toml) lists every key
with its default.

Limits worth knowing: 256 connections (16 per client IP), 32 concurrent streams
per connection, 120 s idle timeout, 1 h connection lifetime, 10 s to send a
request head, 30 s per exchange, 8 bundle downloads at once, and per-IP
request rates that match the node's nginx limits. A connection whose
exchanges time out twice in a row is closed so the client redials.

## Observability

- `curl -s 127.0.0.1:15006/metrics`: connections, streams by route and status,
  profile refusals, rate limiting, upstream errors, bytes, request durations,
  bundle hits, build info.
- `curl -s 127.0.0.1:15006/healthz`: liveness (also used by `nox-kps healthcheck`).
- Logs are JSON lines. At `info` they carry startup facts and a counter summary
  every 60 s. Client addresses, request bodies and SURB IDs are not logged at
  `info` or above.

## Rollback

`docker compose -f docker-compose.yml -f docker-compose.kps.yml stop nox-kps`
stops KPS service; the node and its HTTPS ingress keep running unchanged.
Keep the identity volume: starting nox-kps again restores the same address.

## Development

```sh
cargo test                      # unit + integration tests (QUIC and WebRTC over loopback)
cargo clippy --all-targets -- -D warnings
cargo deny check
cargo test --release --test soak -- --ignored --nocapture   # soak, see tests/soak.rs
```

The `kps` crate needs the `[patch.crates-io]` block in the workspace
`Cargo.toml`; `scripts/check-kps-patches.sh` confirms it matches the pinned
kps release.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
