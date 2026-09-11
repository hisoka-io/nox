use nox_core::{
    DecodedTransaction, ExecutionId, LegacyPendingTransaction, LegacyTxStatus, PendingTransaction,
    PendingTransactionV2, StoredTransactionV2, TxStatus, TxStatusV2,
};

#[test]
fn root_exports_keep_legacy_and_v2_statuses_distinct() {
    let execution_id: ExecutionId = [7; 32];
    let legacy: PendingTransaction = LegacyPendingTransaction {
        id: "legacy".to_string(),
        to: "0x0000000000000000000000000000000000000001".to_string(),
        data: vec![1],
        nonce: 1,
        gas_limit: "21000".to_string(),
        gas_price: "1".to_string(),
        tx_hash: format!("0x{}", "00".repeat(32)),
        first_sent_at: 1,
        last_update_at: 1,
        status: TxStatus::Pending,
    };
    let v2 = PendingTransactionV2 {
        execution_id,
        to: legacy.to.clone(),
        data_hash: [8; 32],
        nonce: 2,
        gas_limit: "22000".to_string(),
        gas_price: "2".to_string(),
        maximum_fee_per_gas: "3".to_string(),
        raw_signed_tx: vec![2],
        tx_hash: format!("0x{}", "11".repeat(32)),
        prior_transaction_hashes: Vec::new(),
        replacement_attempts: 0,
        first_sent_at: 2,
        last_update_at: 2,
        status: TxStatusV2::Prepared,
    };
    let stored = StoredTransactionV2 {
        schema: 2,
        transaction: v2.clone(),
    };
    let decoded = DecodedTransaction::V2(v2);

    assert_eq!(legacy.status, LegacyTxStatus::Pending);
    assert_eq!(stored.schema, 2);
    assert!(matches!(decoded, DecodedTransaction::V2(_)));
}
