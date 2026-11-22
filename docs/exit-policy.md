# Exit policy

An exit is the last hop of a Nox route. It turns a client's request into a connection to the public internet or
to Ethereum, so the services a client calls see the exit's address. This page states what a Nox exit relays,
what it refuses, the limits it applies and how to report abuse. It describes the node at `v0.4.0-rc.13` with the
exit template in [run-nox](https://github.com/hisoka-io/run-nox) (`configs/exit.toml`). The 10 testnet nodes,
including the three exits, are run by the Hisoka team today; operator onboarding is open with a public kit, and
outside exits follow this policy.

## What an exit relays

| Request type | What the exit does |
|---|---|
| HTTP and HTTPS | Makes the request itself to any public host. The template sets no domain allowlist, so the open web is reachable. Responses come back to the client over SURBs |
| JSON-RPC | Forwards read-only Ethereum JSON-RPC calls to the exit's own RPC provider, or any method to an RPC URL the client names |
| Signed transaction broadcast | Submits a transaction the client signed, to the exit's provider or to an RPC URL the client names |
| Paid execution | Quotes, then submits a paid call through `NoxEntryPoint`, paid from shielded notes (see [claim-api.md](claim-api.md)) |
| End-to-end TLS tunnels | Relays TLS records between the client and one host on TCP port 443; the client runs TLS itself (see [tunnel.md](tunnel.md)) |

## What an exit refuses

- **Private and special-use destinations.** With `allow_private_ips = false` (the template value, kept on every
  public exit), the exit refuses any destination that is not a public internet address. This keeps clients away
  from the exit's own host, its cloud network and other local services.
- **Hosts that resolve partly to refused addresses.** The exit resolves the host name, checks every address it
  returns, and refuses the request if any one fails. It then connects only to the addresses it checked (a pinned
  connection), so the request stays on the addresses that passed.
- **Redirects to other hosts.** The HTTP proxy and client-named RPC URLs return a redirect to the client instead
  of following it, so every host the exit contacts passes the same checks.
- **Other schemes and ports.** HTTP requests use `http` or `https`. Tunnels connect to the ports in
  `tunnel.allowed_ports` (`[443]` in the template), and reach hosts by DNS name only.
- **Write methods on the exit's own RPC.** Calls to the exit's provider are limited to a read-only method list;
  `eth_getLogs` ranges are bounded to 2,000 blocks.
- **Domains outside an allowlist, when one is set.** An operator may set `[http] allowed_domains`; tunnels apply
  it to the TLS server name. The Hisoka exits leave it unset.

## Limits

| Limit | Template value | Why |
|---|---|---|
| HTTP request timeout | 120 s (`[http] request_timeout_secs`) | Slow upstreams do not hold exit workers |
| HTTP response size | 128 MiB (`[http] max_response_bytes`) | Bounds memory and SURB use per request |
| JSON-RPC calls | 100 per second per exit, 15 s per call | Shares the exit's provider fairly |
| Open tunnels | 512 per exit (`[tunnel] max_sessions`) | One socket each; the node checks this against its open-file limit at start |
| Tunnel opens | 50 per second, bursts of 200 (node defaults) | Bounds connection churn upstream |
| Requests per destination host | 20 per second, bursts of 200, HTTP, tunnel opens and client-named RPC URLs together (`[exit_limits]`, node defaults) | Bounds what one host receives from an exit and keeps capacity for other hosts |
| Tunnel lifetime | 600 s and 64 MiB per tunnel (node defaults) | Long transfers use fresh tunnels and fresh routes |
| Work in flight | per class: paid 4, quotes 8, HTTP/RPC/broadcast 32, tunnels 64 (node defaults) | Each class keeps moving when another is busy |
| Packet admission | proof of work on every packet (`min_pow_difficulty = 3`) and per-peer packet rates (`[network.rate_limit]`) | Floods cost the sender |
| Paid quotes | outstanding quotes, pending sponsored gas and a rolling loss limit (`quote_*` keys) | Caps what an exit can spend on paid execution |
| Paid quotes per payment credential | 12 per minute, bursts of 12 (`[exit_limits]`, node defaults) | Repeated quotes for one payment are answered before any RPC, price or signing work |

Requests past a limit get an error reply (`RateLimited` and `SessionLimit` tunnel errors are marked retryable), and
the client tries again or picks another exit.

## What an exit sees

- **HTTP and HTTPS requests:** the exit makes the request, so it reads the URL, headers and body, and the
  response. Use a tunnel when the content should stay between the client and the service.
- **Tunnels:** the host name, port, timing and sizes; the content stays end-to-end encrypted.
- **The previous hop as the source:** each request arrives through the mixnet, so the exit sees the mix node
  before it, and the client's address stays with the entry node.

Per-request details (hosts, URLs, RPC methods, packet and request IDs, transaction hashes) are logged at debug
level only; the default `info` level keeps them out of the node's logs.

## Why

Nox is general-purpose: wallets and dapps reach RPC providers, block explorers, price APIs and other HTTPS
services through it, and a domain allowlist would break that use and single out the hosts it lists. The exit
policy therefore stays open on destinations and strict on reachability: public addresses only, checked after DNS,
pinned for the connection, with bounded cost per request. The anon-rpc worker sends wallet traffic through TLS
tunnels by default, so the exit relays ciphertext for that traffic.

## Abuse contact

Report abuse that comes from a Nox exit address to [security@hisoka.io](mailto:security@hisoka.io). Include the
exit address, the time (UTC) and the destination. Because requests arrive through the mixnet, an exit operator can
act on destinations and rates, not on senders. For security vulnerabilities, follow [SECURITY.md](../SECURITY.md).

## For exit operators

- Keep `allow_private_ips = false`.
- Keep the `[http]` and `[tunnel]` blocks from the template, or tighten them (an `allowed_domains` list, fewer
  tunnel sessions); preflight checks the rest of the configuration against the release record.
- Watch the HTTP proxy results (`result="ssrf_blocked"` among them), `nox_tunnel_opens_total{result}` and
  `nox_tunnel_closes_total{reason}` on `/metrics`.
