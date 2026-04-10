use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TxStatus {
    Pending,
    Mined,
    Failed,
    Replaced,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTransaction {
    pub id: String,
    pub to: String,
    pub data: Vec<u8>,
    pub nonce: u64,
    pub gas_limit: String,
    pub gas_price: String,
    pub tx_hash: String,
    pub first_sent_at: u64,
    pub last_update_at: u64,
    pub status: TxStatus,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx_status_serialization_roundtrip() {
        for status in [
            TxStatus::Pending,
            TxStatus::Mined,
            TxStatus::Failed,
            TxStatus::Replaced,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let decoded: TxStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, decoded);
        }
    }

    #[test]
    fn test_pending_transaction_json_roundtrip() {
        let tx = PendingTransaction {
            id: "packet-abc123".to_string(),
            to: "0xdeadbeef00000000000000000000000000000001".to_string(),
            data: vec![1, 2, 3, 4],
            nonce: 42,
            gas_limit: "21000".to_string(),
            gas_price: "1000000000".to_string(),
            tx_hash: "0xabc".to_string(),
            first_sent_at: 1_700_000_000,
            last_update_at: 1_700_000_100,
            status: TxStatus::Pending,
        };

        let json = serde_json::to_string(&tx).unwrap();
        let decoded: PendingTransaction = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.id, tx.id);
        assert_eq!(decoded.nonce, tx.nonce);
        assert_eq!(decoded.status, tx.status);
        assert_eq!(decoded.data, tx.data);
    }

    #[test]
    fn test_tx_status_all_variants_distinct() {
        let statuses = [
            TxStatus::Pending,
            TxStatus::Mined,
            TxStatus::Failed,
            TxStatus::Replaced,
        ];
        // Each variant is different from all others
        for i in 0..statuses.len() {
            for j in 0..statuses.len() {
                if i != j {
                    assert_ne!(statuses[i], statuses[j]);
                }
            }
        }
    }
}
