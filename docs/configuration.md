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
| `benchmark_mode` | `bool` | `false` | Skip production validations |
| `bootstrap_topology_urls` | `Vec<String>` | `[]` | Seed node URLs |

### Contract addresses

| Field | Required for |
|---|---|
| `registry_contract_address` | All roles (production) |
| `relayer_multicall_address` | Exit/Full |
| `nox_reward_pool_address` | Exit/Full |

### Sensitive fields

Excluded from logs and serialization, zeroized on drop:

| Field | Type | Required for |
|---|---|---|
| `routing_private_key` | X25519 hex | All roles (production) |
| `p2p_private_key` | Ed25519 hex | Optional (auto-generated if empty) |
| `eth_wallet_private_key` | Secp256k1 hex | Exit/Full |

## Nested configuration

### `[network]`

| Field | Default | Description |
|---|---|---|
| `max_connections` | `1000` | Max total connections |
| `max_connections_per_peer` | `2` | Max per peer |
| `ping_interval_secs` | `15` | Heartbeat interval |
| `session_ttl_secs` | `86400` | Session ticket lifetime |

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
| `mix_delay_ms` | `500.0` | Average Poisson delay (ms) |
| `cover_traffic_rate` | `0.05` | Loop cover packets/sec |
| `drop_traffic_rate` | `0.05` | Drop cover packets/sec |

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

## Node roles

| Role | Wallet | Chain execution | Exit service |
|---|---|---|---|
| `relay` | No | No | No |
| `exit` | Yes | Yes | Yes |
| `full` | Yes | Yes | Yes |

## Environment variables

All config fields can be set via `NOX_` prefix. Nested fields use `__` as separator:

```bash
# Flat fields
NOX_ETH_RPC_URL=https://mainnet.infura.io/v3/KEY
NOX_CHAIN_ID=1
NOX_P2P_PORT=9000
NOX_NODE_ROLE=exit
NOX_ROUTING_PRIVATE_KEY=<32-byte hex>
NOX_ETH_WALLET_PRIVATE_KEY=<32-byte hex>
NOX_REGISTRY_CONTRACT_ADDRESS=0x...
NOX_RELAYER_MULTICALL_ADDRESS=0x...
NOX_NOX_REWARD_POOL_ADDRESS=0x...
NOX_INGRESS_PORT=8080
NOX_METRICS_PORT=9090
NOX_BENCHMARK_MODE=true

# Nested fields
NOX_NETWORK__MAX_CONNECTIONS=2000
NOX_NETWORK__RATE_LIMIT__RATE_UNKNOWN=150
NOX_RELAYER__QUEUE_SIZE=20000
NOX_RELAYER__WORKER_COUNT=8
NOX_RELAYER__MIX_DELAY_MS=250.0
NOX_RELAYER__COVER_TRAFFIC_RATE=0.1
NOX_RELAYER__FRAGMENTATION__TIMEOUT_SECONDS=600
NOX_HTTP__ALLOW_PRIVATE_IPS=false
NOX_HTTP__MAX_RESPONSE_BYTES=2097152

# Bootstrap topology
NOX_BOOTSTRAP_TOPOLOGY_URLS='["http://seed1:8080/topology","http://seed2:8080/topology"]'
```

### Non-config environment variables

| Variable | Default | Description |
|---|---|---|
| `RUST_LOG` | `info` | Tracing filter (e.g., `debug`, `nox_node=trace`) |
| `PRICE_SERVER_PORT` | `3000` | Oracle HTTP server port |
| `PRICE_SERVER_BIND` | `127.0.0.1` | Oracle bind address |

## Examples

See [docs/examples/](examples/) for complete configs: [relay](examples/relay.toml), [exit](examples/exit.toml), [dev](examples/dev.toml), and [full](examples/full.toml).
