//! NOX production relay/exit node -- packet ingestion, Poisson mixing, P2P
//! forwarding, on-chain execution, and Prometheus telemetry.

pub mod blockchain;
pub mod config;
pub mod infra;
pub mod ingress;
pub mod network;
pub mod node;
pub mod price;
pub mod services;
pub mod telemetry;

pub use config::{NodeRole, NoxConfig};
pub use infra::event_bus::TokioEventBus;
pub use infra::storage::SledRepository;
pub use node::NoxNode;
