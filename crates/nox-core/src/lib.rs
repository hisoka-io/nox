//! Shared protocol types, traits, and domain models for the NOX mixnet.

pub mod events;
pub mod models;
pub mod protocol;
pub mod traits;
pub mod utils;

pub use events::NoxEvent;
pub use models::chain::{PendingTransaction, TxStatus};
pub use models::handshake::{
    Capabilities, Handshake, PeerInfo, MIN_SUPPORTED_VERSION, PROTOCOL_VERSION,
};
pub use models::note::Note;
pub use models::payloads::{RelayerPayload, RpcResponse, ServiceRequest};
pub use models::topology::{RelayerNode, TopologySnapshot};
pub use protocol::fec::{FecError, FecInfo};
pub use protocol::fragmentation::{
    Fragment, FragmentationError, Fragmenter, Reassembler, ReassemblerConfig, SURB_PAYLOAD_SIZE,
};
pub use protocol::kdf::HisokaKdf;
pub use protocol::serialization::{
    deserialize_fr, deserialize_scalar, serialize_fr, serialize_scalar,
};
pub use traits::interfaces::*;
pub use traits::service::{ServiceError, ServiceHandler};
pub use traits::transport::PacketTransport;
pub use utils::{compute_topology_fingerprint, token_to_f64, wei_to_eth_f64, xor_into_fingerprint};
