//! Shared protocol types, traits, and domain models for the NOX mixnet.

pub mod events;
pub mod models;
pub mod protocol;
pub mod traits;
pub mod utils;

pub use events::NoxEvent;
pub use models::chain::{
    DecodedTransaction, ExecutionId, LegacyPendingTransaction, LegacyTxStatus, PendingTransaction,
    PendingTransactionV2, QuoteStatusV2, StoredQuoteV2, StoredTransactionV2, TxStatus, TxStatusV2,
};
pub use models::handshake::{
    Capabilities, Handshake, PeerInfo, MIN_SUPPORTED_VERSION, PROTOCOL_VERSION,
};
pub use models::payloads::{
    ExecutionQuoteV1, PaidQuoteOutcomeV2, PaidQuoteRequestV2, PaidTransactionOutcomeV2,
    PaidTransactionRejectionCodeV2, PaidTransactionRequestV2, RelayerPayload, RpcResponse,
    ServiceRequest,
};
pub use models::topology::{
    primary_layer_for_role, RelayerNode, TopologyLiveness, TopologyLivenessStatus, TopologySnapshot,
};
pub use protocol::fec::{FecError, FecInfo};
pub use protocol::fragmentation::{
    Fragment, FragmentationError, Fragmenter, Reassembler, ReassemblerConfig, SURB_PAYLOAD_SIZE,
};
pub use traits::interfaces::*;
pub use traits::service::{ServiceError, ServiceHandler};
pub use traits::transport::PacketTransport;
pub use utils::{compute_topology_fingerprint, token_to_f64, wei_to_eth_f64, xor_into_fingerprint};
