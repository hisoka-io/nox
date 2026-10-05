use serde::{Deserialize, Serialize};

use crate::{ExecutionQuoteV1, PaidQuoteRequestV2};

pub type ExecutionId = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TxStatusV2 {
    Prepared,
    Submitted,
    ReplacementPrepared,
    Replaced,
    Mined,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LegacyTxStatus {
    Pending,
    Mined,
    Failed,
    Replaced,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingTransactionV2 {
    pub execution_id: ExecutionId,
    pub to: String,
    pub data_hash: [u8; 32],
    pub nonce: u64,
    pub gas_limit: String,
    pub gas_price: String,
    pub maximum_fee_per_gas: String,
    /// Stored as a `0x` hex string; records with a JSON number array still decode.
    /// Empty once a terminal record has been slimmed.
    #[serde(with = "crate::models::stored_bytes")]
    pub raw_signed_tx: Vec<u8>,
    pub tx_hash: String,
    pub prior_transaction_hashes: Vec<String>,
    pub replacement_attempts: u32,
    pub first_sent_at: u64,
    pub last_update_at: u64,
    pub status: TxStatusV2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyPendingTransaction {
    pub id: String,
    pub to: String,
    /// Stored as a `0x` hex string; records with a JSON number array still decode.
    /// Empty once a terminal record has been slimmed.
    #[serde(with = "crate::models::stored_bytes")]
    pub data: Vec<u8>,
    pub nonce: u64,
    pub gas_limit: String,
    pub gas_price: String,
    pub tx_hash: String,
    pub first_sent_at: u64,
    pub last_update_at: u64,
    pub status: LegacyTxStatus,
}

pub type PendingTransaction = LegacyPendingTransaction;
pub type TxStatus = LegacyTxStatus;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredTransactionV2 {
    pub schema: u8,
    pub transaction: PendingTransactionV2,
}

#[derive(Debug, Clone)]
pub enum DecodedTransaction {
    V2(PendingTransactionV2),
    Legacy(LegacyPendingTransaction),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum QuoteStatusV2 {
    Outstanding,
    Inflight,
    Submitted,
    Confirmed,
    Reverted,
    Expired,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StoredQuoteV2 {
    pub schema: u8,
    pub request: PaidQuoteRequestV2,
    pub quote: ExecutionQuoteV1,
    pub execution_id: ExecutionId,
    pub exit_signature: Vec<u8>,
    pub pending_sponsored_gas: u64,
    pub rolling_loss_window_secs: u64,
    pub status: QuoteStatusV2,
}
