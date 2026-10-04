//! nox-kps: the KPS entry sidecar for Nox mixnet nodes.
//!
//! It terminates [KPS](https://github.com/ethereum/kps) (Key Pinned Streams:
//! WebRTC for browsers and QUIC for native clients on one UDP port, pinned by
//! certificate hash) and serves each stream as one HTTP/1.1 exchange:
//!
//! - allowlisted Nox routes (packet submit, response claim, topology, health)
//!   are proxied to the node's loopback ingress and topology ports, with the
//!   client's KPS source address in the client-IP header the node rate-limits
//!   on;
//! - `GET /keccak/<hh>/<62 hex>` serves hash-addressed anon-rpc worker bundles
//!   (the `kps:` resolver profile of anon-rpc SPEC §4.2);
//! - `GET /metadata.json` describes the endpoint.
//!
//! Prometheus metrics and `/health` are served on a loopback TCP port.

pub mod app;
pub mod bundles;
pub mod config;
pub mod error;
pub mod exchange;
pub mod identity;
pub mod limits;
pub mod metrics;
pub mod proxy;
pub mod server;
pub mod telemetry;

pub use config::{RawConfig, Settings};
pub use server::{start, RunningServer};
