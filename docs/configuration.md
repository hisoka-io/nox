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
