//! nox-kps: the KPS entry sidecar for Nox mixnet nodes.
//!
//! It terminates [KPS](https://github.com/ethereum/kps) (Key Pinned Streams:
//! WebRTC for browsers and QUIC for native clients on one UDP port, pinned by
//! certificate hash) and serves each stream as one HTTP/1.1 exchange under
//! the `nox-kps-http/1` profile:
//!
//! - a fixed allowlist of Nox routes (packet submit, response claim, topology)
//!   is proxied to the node's loopback ingress and topology ports, with the
//!   client's KPS source address in the client-IP header the node keys its
//!   rate limits on;
//! - `GET /health` and `GET /metadata.json` are answered locally;
//! - `GET /keccak/<hh>/<62 hex>` serves hash-addressed anon-rpc worker bundles
//!   (the `kps:` resolver profile of anon-rpc SPEC §4.2).
//!
//! Prometheus metrics and `/healthz` are served on a loopback TCP port.

pub mod app;
pub mod bundles;
pub mod config;
pub mod error;
pub mod exchange;
pub mod healthcheck;
pub mod identity;
pub mod limits;
pub mod metrics;
pub mod proxy;
pub mod routes;
pub mod server;
pub mod telemetry;

pub use config::{RawConfig, Settings};
pub use server::{start, RunningServer};

/// The `kps` library release this build links (`Cargo.toml`: tag
/// `libs/rust/v0.2.2`). Reported in `nox_kps_build_info`.
pub const KPS_VERSION: &str = "0.2.2";

/// Wire profile name served in `/metadata.json` (see PROTOCOL.md).
pub const PROTOCOL: &str = "nox-kps-http/1";

#[cfg(test)]
mod tests {
    #[test]
    fn kps_version_matches_the_lockfile() {
        let lock = include_str!("../../../Cargo.lock");
        let needle = format!("name = \"kps\"\nversion = \"{}\"", super::KPS_VERSION);
        assert!(
            lock.contains(&needle),
            "Cargo.lock pins another kps version"
        );
        assert!(lock.contains("tag=libs%2Frust%2Fv0.2.2"));
    }
}
