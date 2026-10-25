# Security Policy

## Reporting Vulnerabilities

Found a vulnerability? Don't open a public issue. Email us instead:

**Email:** [security@hisoka.io](mailto:security@hisoka.io)

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

### Response Timeline

| Action                 | Timeline                                                 |
| ---------------------- | -------------------------------------------------------- |
| Acknowledgment         | Within 48 hours                                          |
| Initial assessment     | Within 7 days                                            |
| Fix development        | Depends on severity (critical: 72 hours, high: 2 weeks)  |
| Coordinated disclosure | After fix is released, or 90 days, whichever comes first |

We will credit reporters in the advisory unless they prefer to remain anonymous.

## Scope

### In Scope

- All Rust code in this repository
- Cryptographic implementations (Sphinx, SURB, PoW, X25519, ChaCha20)
- Network protocols (P2P, HTTP ingress, packet format)
- Configuration handling (key material, validation, zeroization)
- Economic model (fixed-point paid execution, quote limits, and durable submission)

### Out of Scope

- Third-party dependencies (report upstream to the respective maintainer)
- The Ethereum smart contracts (separate repository: `hisoka-io/darkpool`)
- Infrastructure and deployment issues
- Social engineering attacks

## Supported Versions

| Version        | Supported   |
| -------------- | ----------- |
| Latest `main`  | Yes         |
| Older releases | Best effort |

## Temporary Dependency Exceptions

`cargo deny` remains blocking. Exceptions and accepted yanked warnings require a named owner, a removal deadline,
documented reachability, and an enforced control.

| Advisory | Reachability | Compensating control | Migration owner | Deadline |
| --- | --- | --- | --- | --- |
| `RUSTSEC-2025-0141` | Bincode v1 encodes the versioned mixnet wire; in nox-kps, `kps -> webrtc -> webrtc-dtls` (de)serialises local DTLS session state | Payload size/version limits and strict inner decoding are enforced; outer Sphinx padding has a dedicated zero-only decoder; nox-kps hands bincode no network input; wire bytes are pinned by golden vectors shared with the TypeScript SDK. The advisory covers every bincode release, so a drop-in upgrade does not clear it: the exit is a versioned wire format agreed with the SDK | protocol-wire, nox-kps | 2027-03-31 |
| `RUSTSEC-2025-0057` | `sled 0.34 -> fxhash` in the node's local store | sled hashes only its internal page ids, log offsets and tree names with it, never stored keys | storage | 2026-12-31 |
| `RUSTSEC-2024-0384` | libp2p runtime timing (`instant`) | Protocol expiry and money arithmetic use explicit chain or standard monotonic time, not this crate | networking | 2026-12-31 |
| `RUSTSEC-2024-0436` | `libp2p -> netlink-packet-utils -> paste` proc macro | Build-time expansion only; no runtime input reaches the macro | networking | 2026-12-31 |
| Yanked `keccak 0.1.5` | `sha3` worker-bundle hashing in nox-kps | Cargo lock checksum is pinned; nox-kps tests bundle names against known Keccak-256 digests | nox-kps | 2026-12-31 |
| Yanked `spin 0.9.8` | `reed-solomon-erasure 6` synchronization | Fragment/shard counts and memory are bounded; FEC property, corruption, and recovery suites cover the path | protocol-wire | 2026-12-31 |

Chain access runs on Alloy. Owners update libp2p and Reed-Solomon dependencies, replace sled as the node's local
store, and move the v1 bincode wire to a versioned replacement before the recorded deadlines.
`scripts/check-rustsec-exceptions.sh` blocks expired advisory exceptions and warns 30 days ahead; a weekly
scheduled run reports new advisories and upcoming deadlines without waiting for a push. Expired yanked-package entries fail review and must not be extended
without a new security assessment.
