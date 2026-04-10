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
- Cryptographic implementations (Sphinx, SURB, PoW, ECDH, Poseidon2, AES)
- Network protocols (P2P, HTTP ingress, packet format)
- Configuration handling (key material, validation, zeroization)
- Economic model (profitability calculation, gas payment verification)

### Out of Scope

- Third-party dependencies (report upstream to the respective maintainer)
- The Ethereum smart contracts (separate repository: `hisoka-io/darkpool-v2`)
- Infrastructure and deployment issues
- Social engineering attacks

## Supported Versions

| Version        | Supported   |
| -------------- | ----------- |
| Latest `main`  | Yes         |
| Older releases | Best effort |