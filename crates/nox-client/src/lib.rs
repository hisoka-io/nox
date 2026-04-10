//! Client-side interface for the NOX mix network: route construction, Sphinx packet
//! creation, SURB budget management, and topology discovery.

pub mod cover_traffic;
pub mod http_transport;
pub mod mixnet_client;
pub mod surb_budget;
pub mod topology_node;
pub mod topology_sync;

pub use cover_traffic::CoverTrafficController;
pub use http_transport::HttpPacketTransport;
pub use mixnet_client::{BroadcastOptions, MixnetClient, MixnetClientConfig, MixnetClientError};
pub use surb_budget::{
    AdaptiveSurbBudget, SurbBudget, DEFAULT_MEDIUM_SURBS, DEFAULT_RPC_SURBS,
    ESTIMATED_SURB_SERIALIZED_SIZE, MAX_SURBS, USABLE_RESPONSE_PER_SURB,
};
pub use topology_node::TopologyNode;
pub use topology_sync::{
    TopologySyncClient, TopologySyncConfig, TopologySyncError, DEFAULT_SEED_URLS,
};
