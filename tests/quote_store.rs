use ethers::types::U256;
use nox_core::{
    ExecutionQuoteV1, IStorageRepository, PaidQuoteRequestV2, QuoteStatusV2, StoredQuoteV2,
};
use nox_node::infra::storage::{QuoteStoreError, SledRepository};

fn word(value: u64) -> [u8; 32] {
    let mut encoded = [0_u8; 32];
    U256::from(value).to_big_endian(&mut encoded);
    encoded
}

fn quote(id: u8, valid_until_unix: u64) -> StoredQuoteV2 {
    let request = PaidQuoteRequestV2 {
        chain_id: 421_614,
        entry_point: [1; 20],
        client_intent_id: [2; 32],
        payment_adapter: [3; 20],
        payment_id: [id; 32],
        fee_asset: [5; 20],
        payment_gas_limit: 500_000,
        action_target: [6; 20],
        action_calldata_hash: [7; 32],
        action_gas_limit: 700_000,
        tracked_assets_hash: [8; 32],
        maximum_transaction_gas: 1_500_000,
        return_data_limit: 256,
        valid_until_unix,
    };
    StoredQuoteV2 {
        schema: 1,
        request,
        quote: ExecutionQuoteV1 {
            quote_version: 1,
            chain_id: word(421_614),
            entry_point: [1; 20],
            exit_address: [9; 20],
            client_intent_id: [2; 32],
            payment_adapter: [3; 20],
            payment_id: [id; 32],
            fee_asset: [5; 20],
            exit_fee: word(77),
            network_fee: word(8),
            payment_gas_limit: word(500_000),
            action_target: [6; 20],
            action_calldata_hash: [7; 32],
            action_gas_limit: word(700_000),
            tracked_assets_hash: [8; 32],
            maximum_transaction_gas: word(1_450_000),
            maximum_fee_per_gas: word(123),
            return_data_limit: word(256),
            valid_after_unix: 100,
            valid_until_unix,
            quote_nonce: word(u64::from(id)),
        },
        execution_id: [id; 32],
        exit_signature: vec![10; 65],
        pending_sponsored_gas: 1_450_000,
        rolling_loss_window_secs: 3_600,
        status: QuoteStatusV2::Outstanding,
    }
}

async fn counter(repository: &SledRepository, key: &[u8]) -> u64 {
    let bytes = repository.get(key).await.unwrap().unwrap();
    u64::from_le_bytes(bytes.try_into().unwrap())
}

#[tokio::test]
async fn terminal_release_is_symmetric_and_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let repository = SledRepository::new(directory.path()).unwrap();
    let first = quote(1, 1_000);
    repository
        .create_quote_durably(&first, 1, 1_450_000, U256::from(100), 3_600, 100)
        .await
        .unwrap();
    repository
        .take_quote_durably(first.execution_id, 101)
        .await
        .unwrap();
    repository
        .mark_quote_submitted_durably(first.execution_id)
        .await
        .unwrap();
    assert!(repository
        .finalize_quote_durably(
            first.execution_id,
            QuoteStatusV2::Confirmed,
            U256::zero(),
            102
        )
        .await
        .unwrap());
    assert!(!repository
        .finalize_quote_durably(
            first.execution_id,
            QuoteStatusV2::Confirmed,
            U256::zero(),
            102
        )
        .await
        .unwrap());
    assert_eq!(counter(&repository, b"quote:outstanding").await, 0);
    assert_eq!(counter(&repository, b"quote:pending-gas").await, 0);

    repository
        .create_quote_durably(&quote(2, 1_000), 1, 1_450_000, U256::from(100), 3_600, 103)
        .await
        .unwrap();
}

#[tokio::test]
async fn expired_quotes_release_capacity_and_inflight_quotes_survive_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let repository = SledRepository::new(directory.path()).unwrap();
    let expired = quote(3, 100);
    repository
        .create_quote_durably(&expired, 1, 1_450_000, U256::from(100), 3_600, 90)
        .await
        .unwrap();
    assert_eq!(
        repository.prune_expired_quotes_durably(100).await.unwrap(),
        1
    );

    let inflight = quote(4, 1_000);
    repository
        .create_quote_durably(&inflight, 1, 1_450_000, U256::from(100), 3_600, 101)
        .await
        .unwrap();
    repository
        .take_quote_durably(inflight.execution_id, 102)
        .await
        .unwrap();
    drop(repository);

    let reopened = SledRepository::new(directory.path()).unwrap();
    assert_eq!(
        reopened
            .load_quote(inflight.execution_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        QuoteStatusV2::Inflight,
    );
    assert!(reopened
        .create_quote_durably(&quote(5, 1_000), 1, 2_900_000, U256::from(100), 3_600, 103)
        .await
        .is_err());
}

#[tokio::test]
async fn reverted_receipt_trips_rolling_loss_at_exact_boundary() {
    let directory = tempfile::tempdir().unwrap();
    let repository = SledRepository::new(directory.path()).unwrap();
    let first = quote(6, 1_000);
    repository
        .create_quote_durably(&first, 2, 2_900_000, U256::from(100), 3_600, 100)
        .await
        .unwrap();
    repository
        .take_quote_durably(first.execution_id, 101)
        .await
        .unwrap();
    assert!(repository
        .finalize_quote_durably(
            first.execution_id,
            QuoteStatusV2::Reverted,
            U256::from(100),
            102
        )
        .await
        .unwrap());
    assert!(repository
        .create_quote_durably(&quote(7, 1_000), 2, 2_900_000, U256::from(100), 3_600, 103)
        .await
        .is_err());
}

#[tokio::test]
async fn quote_conflicts_and_expiry_are_typed() {
    let directory = tempfile::tempdir().unwrap();
    let repository = SledRepository::new(directory.path()).unwrap();
    let reserved = quote(8, 1_000);
    repository
        .create_quote_durably(&reserved, 2, 2_900_000, U256::from(100), 3_600, 100)
        .await
        .unwrap();

    assert!(matches!(
        repository
            .create_quote_durably(&reserved, 2, 2_900_000, U256::from(100), 3_600, 100)
            .await,
        Err(QuoteStoreError::DuplicateIdentity)
    ));
    assert!(matches!(
        repository
            .take_quote_durably(reserved.execution_id, 1_000)
            .await,
        Err(QuoteStoreError::Expired)
    ));
    assert!(matches!(
        repository.take_quote_durably([0xff; 32], 101).await,
        Err(QuoteStoreError::Unknown)
    ));
}
