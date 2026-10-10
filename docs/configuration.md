# Configuration

Config loads in order: struct defaults → TOML file → environment variables. Later values win.

```bash
cargo run --release -- --config config.toml
```

## Top-level fields

| Field | Type | Default | Description |
|---|---|---|---|
| `eth_rpc_url` | `String` | `"http://127.0.0.1:8545"` | Ethereum JSON-RPC endpoint |
| `oracle_url` | `String` | `"http://127.0.0.1:3000"` | Price oracle HTTP URL |
| `chain_id` | `u64` | `0` | Ethereum chain ID (non-zero in production) |
| `node_role` | `"relay"` / `"exit"` / `"full"` | `"full"` | Node operating mode |
| `p2p_port` | `u16` | `9000` | libp2p listening port |
| `p2p_listen_addr` | `String` | `"0.0.0.0"` | P2P bind address |
| `db_path` | `String` | `"./data/nox_db"` | Sled database directory |
| `metrics_port` | `u16` | `9090` | Prometheus metrics port |
| `ingress_port` | `u16` | `0` (disabled) | HTTP packet injection port |
| `topology_api_port` | `u16` | `0` (disabled) | Public topology API port |
| `min_pow_difficulty` | `u32` | `3` | PoW difficulty for incoming packets (0-63) |
| `min_profit_margin_percent` | `u64` | `10` | TX profitability threshold (%) |
| `min_gas_balance` | `String` | `"10000000000000000"` | Min ETH balance in wei (0.01 ETH) |
| `native_asset_price_id` | `String` | empty | Oracle asset ID for the chain gas token |
| `native_asset_decimals` | `u8` | `18` | Chain gas-token decimals |
| `chain_data_fee_mode` | enum | `rpc_gas_estimate_includes_data_fee` | Treat RPC gas estimate as total chain gas |
| `gas_limit_buffer_bps` | `u32` | `2000` | Gas-limit reservation buffer |
| `initial_fee_buffer_bps` | `u32` | `2000` | Initial gas-price buffer |
| `replacement_step_bps` | `u32` | `2000` | Capped replacement increase |
| `quote_ttl_secs` | `u64` | `0` | Signed quote lifetime; required for Exit/Full |
| `quote_network_fee_bps` | `u32` | `0` | Network reward share of exit fee |
| `quote_maximum_transaction_gas` | `u64` | `0` | Operator ceiling for caller gas reservations |
| `quote_max_outstanding` | `u32` | `0` | Durable outstanding quote capacity |
| `quote_max_pending_sponsored_gas` | `u64` | `0` | Aggregate sponsored-gas reservation limit |
| `quote_rolling_loss_limit_native` | `String` | `"0"` | Rolling unreimbursed gas-loss ceiling |
| `quote_rolling_loss_window_secs` | `u64` | `0` | Rolling loss window |
| `benchmark_mode` | `bool` | `false` | Skip production validations |
| `bootstrap_topology_urls` | `Vec<String>` | `[]` | Seed node URLs |

### Contract addresses

| Field | Required for |
|---|---|
| `registry_contract_address` | All roles (production) |
| `nox_entry_point_address` | Exit/Full |
| `nox_reward_pool_address` | Exit/Full |

### Sensitive fields

Excluded from logs and serialization, zeroized on drop:

| Field | Type | Required for |
|---|---|---|
| `routing_private_key` | X25519 hex | All roles (production) |
| `p2p_private_key` | Ed25519 hex | Optional (auto-generated if empty) |
| `eth_wallet_private_key` | Secp256k1 hex | Exit/Full |

### `[[payment_adapters]]` and `[[tokens]]`

Exit and Full nodes require an explicit adapter allowlist and token metadata. Each adapter declares its address,
allowed fee assets, and maximum payment gas. Every allowed fee asset must have exactly one `[[tokens]]` entry
with a nonzero address, symbol, decimals, and oracle price ID. Production nodes do not inherit mainnet token
addresses. Measure each enabled adapter's complete transaction under production-equivalent conditions, apply the
configured gas buffer, and set quote and aggregate pending-gas ceilings above that measured bound.

## Nested configuration

### Registry reconciliation

| Field | Default | Description |
|---|---|---|
| `topology_reconcile_interval_secs` | `300` | How often every member is re-read from the registry and the node set is checked against `topologyFingerprint()` and `relayerCount()`. 0 disables it, which also keeps P2P admission permissive |
| `chain_cursor_persist_interval_secs` | `60` | Minimum time between writes of the chain observer's scan cursor; the cursor is also written on graceful shutdown. After a crash the observer re-scans up to this much history, and registry events are safe to replay. 0 writes it after every scanned range |

### `[network]`

| Field | Default | Description |
|---|---|---|
| `max_connections` | `1000` | Max total connections |
| `max_connections_per_peer` | `2` | Max per peer |
| `ping_interval_secs` | `15` | Heartbeat interval |
| `session_ttl_secs` | `86400` | Session ticket lifetime |
| `peer_admission` | `"enforce"` | `enforce`, `monitor` or `off`. Enforce refuses peers outside the registry, and banned or over-limit addresses, once membership is verified on-chain and the grace period has passed |
| `peer_admission_grace_secs` | `120` | Delay after startup before enforcement, and how long a link to a peer that left the registry is kept |
| `topology_liveness_window_secs` | `60` | A member is reported online in `/topology` if it answered on P2P within this window |
| `tcp_nodelay` | `true` | Sets `TCP_NODELAY` on P2P connections, so each Sphinx packet is sent at once instead of waiting on Nagle's algorithm and the peer's delayed ACK |
| `max_concurrent_streams` | `256` | Inbound packet streams served at once per connection. libp2p drops streams above this without telling the sender; nodes before v0.4.0-rc.9 send a whole reply at once, so this absorbs one reply burst from them |
| `max_packets_in_flight_per_peer` | `48` | Packet requests kept open to one peer. Later packets wait in order until earlier ones are answered, so a many-fragment reply never exceeds the next hop's stream limit (100 on rc.8 and earlier) |
| `max_queued_packets_per_peer` | `512` | Packets held per peer while the in-flight limit is reached (16 MiB of Sphinx packets); more are dropped and counted in `nox_p2p_outbound_dropped{reason="queue_full"}` |

### `[network.rate_limit]`

Three reputation tiers: Unknown, Trusted, Penalized.

| Field | Default | Description |
|---|---|---|
| `burst_unknown` / `rate_unknown` | 50 / 100 | Unknown peers |
| `burst_trusted` / `rate_trusted` | 100 / 200 | Trusted peers |
| `burst_penalized` / `rate_penalized` | 10 / 25 | Penalized peers |
| `violations_before_disconnect` | `5` | Strikes before disconnect |
| `trust_promotion_time_secs` | `3600` | Time to promote to trusted |

### `[network.connection_filter]`

| Field | Default | Description |
|---|---|---|
| `max_per_subnet` | `50` | Max connections per /24 subnet |

### `[relayer]`

| Field | Default | Description |
|---|---|---|
| `queue_size` | `10000` | Pipeline channel capacity |
| `worker_count` | `num_cpus` | Sphinx peeling workers |
| `replay_window` | `3600` | Replay filter rotation window (seconds) |
| `bloom_capacity` | `100000` | Replay filter capacity per window |
| `bloom_persist_interval_secs` | `60` | How often the replay filter is written to disk while it changes (also written on rotation and graceful shutdown; `0` = only those) |
| `mix_delay_ms` | `500.0` | Average Poisson delay (ms) |
| `cover_traffic_rate` | `0.05` | Loop cover packets/sec |
| `drop_traffic_rate` | `0.05` | Drop cover packets/sec |
| `cover_loop_timeout_secs` | `60` | A loop cover packet not back within this time counts as lost |
| `wire_ids` | `"per_hop"` | Packet identifiers sent to the next hop: `"per_hop"` (fresh at every hop, replies keep only their `reply-0-{surb_id}` handle) or `"passthrough"` (unchanged across hops, benchmark harnesses only; requires `benchmark_mode = true`). Env: `NOX__RELAYER__WIRE_IDS` |
| `surb_formats` | `"both"` | SURB reply formats handled: `"both"` (format 1 and format 2, advertises `surb_v2`) or `"v1"` (format 2 off; flags ignored, format 2 SURBs answered in format 1). Env: `NOX__RELAYER__SURB_FORMATS` |

### `[relayer.fragmentation]`

| Field | Default | Description |
|---|---|---|
| `max_pending_bytes` | `10485760` | Max reassembly buffer (10 MB) |
| `max_concurrent_messages` | `50` | Simultaneous reassemblies |
| `timeout_seconds` | `300` | Incomplete message timeout |

### `[http]` (exit node)

| Field | Default | Description |
|---|---|---|
| `allowed_domains` | `null` (open) | Domain allowlist |
| `allow_private_ips` | `false` | **Never enable in production** |
| `request_timeout_secs` | `10` | Proxy timeout |
| `max_response_bytes` | `1048576` | Max response (1 MB) |
| `pool_idle_timeout_secs` | `600` | How long an idle upstream connection stays pooled |
| `http2_keep_alive_interval_secs` | `30` | HTTP/2 PING interval on upstream connections, also while idle (0 = off) |
| `warm_interval_secs` | `60` | How often recently used upstream origins get a `HEAD /` to keep their connection warm (0 = off) |
| `warm_recent_secs` | `600` | An origin counts as recently used this long after its last request |
| `max_cached_hosts` | `256` | Upstream origins that keep a pinned client (least recently used out first) |

Each upstream origin gets a client pinned to the addresses its host resolves
to. Every address must pass the SSRF check; the client is reused while the
host keeps resolving to addresses it was pinned to.

### `[ingress]`

| Field | Default | Description |
|---|---|---|
| `rate_limit_per_sec` / `rate_limit_burst` | 100 / 400 | Token bucket per client IP on `ingress_port` (0 turns the limit off) |
| `client_ip_header` | `""` | Header naming the client IP for loopback connections (nox-kps sends `x-real-ip`) |
| `cors_allowed_origins` | `[]` | Browser origins allowed by CORS; empty allows any |
| `claim_retain_grace_ms` | `20000` | How long a reply returned by a retaining claim stays re-claimable after its first claim (claim protocol v2, [claim-api.md](claim-api.md)) |
| `claim_wait_max_ms` | `20000` | Longest claim long-poll honoured; 0 answers claims at once |
| `claim_wait_max_concurrent` | `256` | Claims that may long-poll at once |

### `[exit_workers]` (exit node)

Decoded exit payloads go to one of four lanes, each with its own bounded queue and
concurrency limit. A full lane drops new payloads and counts them in
`nox_exit_payloads_dropped_total{lane,reason}`; the other lanes keep running.

| Field | Default | Lane |
|---|---|---|
| `paid_concurrency` | `4` | Paid transaction submissions |
| `quote_concurrency` | `8` | Paid quote requests |
| `proxy_concurrency` | `32` | HTTP, RPC and signed-transaction broadcast |
| `control_concurrency` | `16` | Echo and cover traffic |
| `queue_capacity` | `256` | Payloads waiting per lane |

### `[exit_replenishment]` (exit node)

A large response that runs out of SURBs waits at the exit until the client sends more
(`ReplenishSurbs`), and SURBs that arrive first are kept for it. Both stores are filled by
anonymous clients, so each is capped; at a cap the oldest entry is dropped.

| Field | Default | Description |
|---|---|---|
| `max_pending_responses` | `100` | Partial responses waiting for SURBs |
| `max_pending_bytes` | `134217728` | Undelivered response bytes across them (128 MiB) |
| `max_surb_requests` | `100` | Requests with early SURBs kept |
| `max_surbs_per_request` | `512` | SURBs kept per request |
| `entry_ttl_secs` | `300` | Seconds an unused entry is kept |

### `[storage]`

A maintenance pass runs at startup and then every `maintenance_interval_secs`. It slims and
deletes records whose work is complete, updates `nox_storage_records{tree,kind}`,
`nox_storage_blob_files` and `nox_storage_blob_bytes`, and flushes the database. Records the
node may still act on are kept: transactions until they are mined or failed, quotes that are
outstanding, inflight or submitted, `nonce:local` and the quote counters. Removed records are
counted in `nox_storage_retention_total{record,action}`.

| Field | Default | Description |
|---|---|---|
| `maintenance_interval_secs` | `600` | Seconds between passes |
| `prune_terminal_records` | `true` | Delete terminal records after their retention; `false` keeps them (slimmed) |
| `slim_terminal_transactions_after_secs` | `0` | Age at which a mined or failed transaction drops its signed bytes (hash kept) |
| `terminal_transaction_retention_secs` | `604800` | Age at which a mined or failed transaction record is deleted (7 days) |
| `expired_quote_retention_secs` | `600` | Seconds after `valid_until` before an unused expired quote is deleted |
| `terminal_quote_retention_secs` | `604800` | Seconds after `valid_until` before a confirmed, reverted or rejected quote is deleted |
| `maintenance_batch_limit` | `2000` | Most transaction records one pass changes. Quotes have their own budget: twice the most quotes the cap admits per interval (`2 * quote_max_outstanding * ceil(maintenance_interval_secs / quote_ttl_secs)`, 10240 for the example exit), and at least this value |
| `compact_on_start_blob_bytes` | `268435456` | Compact at startup when sled blob files exceed this (256 MiB); `0` = never |

sled 0.34 forgets blob files that were pending deletion whenever the node stops, so blob
files can accumulate across restarts while the live data stays small. Compaction copies every
record into a fresh database, checks a digest of the copy, swaps it in and removes the old
files. It runs at startup above `compact_on_start_blob_bytes`, or offline with the node
stopped:

```bash
nox db stats   --config /etc/nox/config.toml      # size, blob files, records per kind
nox db compact --config /etc/nox/config.toml      # add --keep-backup to keep the old files
```

`--db-path <dir>` overrides the config. If a compaction is interrupted during the swap, the
node refuses to open the database until `nox db compact` is run again to finish it.

## Node roles

| Role | Wallet | Chain execution | Exit service |
|---|---|---|---|
| `relay` | No | No | No |
| `exit` | Yes | Yes | Yes |
| `full` | Yes | Yes | Yes |

## Environment variables

Environment variables override the TOML file. The prefix is `NOX__` (two underscores), and `__` also separates
nested fields. A variable with a single underscore, such as `NOX_CHAIN_ID`, is ignored.

```bash
# Secrets (`nox keygen` prints these lines)
NOX__ROUTING_PRIVATE_KEY=<32-byte hex>
NOX__P2P_PRIVATE_KEY=<32-byte hex>
NOX__ETH_WALLET_PRIVATE_KEY=<32-byte hex>      # exit and full nodes

# Flat fields (public testnet values; see hisoka-io/run-nox for the full deployment)
NOX__ETH_RPC_URL=https://arbitrum-sepolia-rpc.publicnode.com
NOX__CHAIN_ID=421614
NOX__NODE_ROLE=relay
NOX__P2P_PORT=15000
NOX__METRICS_PORT=15001                        # must be p2p_port + 1 on the public network

# Nested fields
NOX__NETWORK__MAX_CONNECTIONS=2000
NOX__NETWORK__RATE_LIMIT__RATE_UNKNOWN=150
NOX__RELAYER__QUEUE_SIZE=20000
NOX__RELAYER__MIX_DELAY_MS=250.0
NOX__HTTP__ALLOW_PRIVATE_IPS=false
```

List fields such as `bootstrap_topology_urls`, `tokens` and `payment_adapters` cannot be set from the environment;
set them in the TOML file. Run `nox --config config.toml check-config` to see the role, chain, registry and public
identity that result from the file and the environment together.

### Non-config environment variables

| Variable | Default | Description |
|---|---|---|
| `RUST_LOG` | `info` | Tracing filter (e.g., `debug`, `nox_node=trace`) |
| `PRICE_SERVER_PORT` | `3000` | Oracle HTTP server port |
| `PRICE_SERVER_BIND` | `127.0.0.1` | Oracle bind address. Keep it on loopback: only the local exit reads it |
| `PRICE_MIN_SOURCES` | `2` | Providers that must agree on an asset before its price is published. Below this, the last price ages out and exits refuse quotes instead of trusting one feed |
| `PRICE_HTTP_TIMEOUT_SECS` | `10` | Total timeout for one upstream price request |
| `PRICE_BINANCE_BASE_URL` | `https://api.binance.us/api/v3` | Binance-compatible ticker API (`api.binance.com` refuses US hosts) |
| `PRICE_COINGECKO_API_KEY` | unset | Optional CoinGecko demo key. The keyless API works without it |
| `PRICE_CRYPTOCOMPARE_API_KEY` | unset | CryptoCompare is used only when this key is set |
| `PRICE_KRAKEN_BASE_URL`, `PRICE_COINGECKO_BASE_URL`, `PRICE_CRYPTOCOMPARE_BASE_URL` | public endpoints | Upstream overrides, for mirrors and tests |

## Examples

See [docs/examples/](examples/) for complete configs: [relay](examples/relay.toml), [exit](examples/exit.toml), [dev](examples/dev.toml), and [full](examples/full.toml).
