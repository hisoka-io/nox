use ethers::types::{Address, Block, Bytes, TransactionReceipt, H256, U256};
use ethers::utils::Anvil;
use nox_core::DecodedTransaction;
use nox_core::{
    ExecutionId, ExecutionQuoteV1, LegacyPendingTransaction, LegacyTxStatus, PaidQuoteRequestV2,
    PendingTransactionV2, QuoteStatusV2, StoredQuoteV2, TxStatusV2,
};
use nox_node::blockchain::{
    executor::ChainExecutor,
    transaction_plan::TransactionPlan,
    tx_manager::{SubmitError, TransactionManager},
};
use nox_node::infra::storage::{decode_stored_transaction, CreateOutboxResult, SledRepository};
use nox_node::telemetry::metrics::MetricsService;
use nox_node::NoxConfig;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{body_string_contains, method};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

#[derive(Clone)]
struct JsonRpcResult(serde_json::Value);

impl Respond for JsonRpcResult {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let request_json: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": request_json["id"].clone(),
            "result": self.0
        }))
    }
}

#[derive(Clone)]
struct JsonRpcError(&'static str);

impl Respond for JsonRpcError {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let request_json: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": request_json["id"].clone(),
            "error": { "code": -32000, "message": self.0 }
        }))
    }
}

#[derive(Clone)]
struct RawTransactionHashResponder;

impl Respond for RawTransactionHashResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let request_json: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        let encoded = request_json["params"][0].as_str().unwrap();
        let raw = hex::decode(encoded.strip_prefix("0x").unwrap()).unwrap();
        let hash = ethers::types::H256::from(ethers::utils::keccak256(raw));
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": request_json["id"].clone(),
            "result": format!("{hash:?}")
        }))
    }
}

#[derive(Clone)]
struct ReplacementAmbiguityResponder(Arc<AtomicUsize>);

impl Respond for ReplacementAmbiguityResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let request_json: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        let send_index = self.0.fetch_add(1, Ordering::SeqCst);
        if send_index == 1 {
            return ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": request_json["id"].clone(),
                "error": { "code": -32000, "message": "timeout after acceptance" }
            }));
        }
        let encoded = request_json["params"][0].as_str().unwrap();
        let raw = hex::decode(encoded.strip_prefix("0x").unwrap()).unwrap();
        let hash = ethers::types::H256::from(ethers::utils::keccak256(raw));
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": request_json["id"].clone(),
            "result": format!("{hash:?}")
        }))
    }
}

fn record(execution_id: ExecutionId) -> PendingTransactionV2 {
    PendingTransactionV2 {
        execution_id,
        to: "0x0000000000000000000000000000000000000001".to_string(),
        data_hash: [2; 32],
        nonce: 4,
        gas_limit: "21000".to_string(),
        gas_price: "10".to_string(),
        maximum_fee_per_gas: "20".to_string(),
        raw_signed_tx: vec![1, 2, 3],
        tx_hash: format!("0x{}", "11".repeat(32)),
        prior_transaction_hashes: Vec::new(),
        replacement_attempts: 0,
        first_sent_at: 1,
        last_update_at: 1,
        status: TxStatusV2::Prepared,
    }
}

fn quote_record(execution_id: ExecutionId) -> StoredQuoteV2 {
    StoredQuoteV2 {
        schema: 1,
        request: PaidQuoteRequestV2 {
            chain_id: 31_337,
            entry_point: [1; 20],
            client_intent_id: [2; 32],
            payment_adapter: [3; 20],
            payment_id: execution_id,
            fee_asset: [4; 20],
            payment_gas_limit: 21_000,
            action_target: [5; 20],
            action_calldata_hash: [6; 32],
            action_gas_limit: 21_000,
            tracked_assets_hash: [7; 32],
            maximum_transaction_gas: 100_000,
            return_data_limit: 0,
            valid_until_unix: u64::MAX,
        },
        quote: ExecutionQuoteV1 {
            quote_version: 1,
            chain_id: [0; 32],
            entry_point: [1; 20],
            exit_address: [2; 20],
            client_intent_id: [2; 32],
            payment_adapter: [3; 20],
            payment_id: execution_id,
            fee_asset: [4; 20],
            exit_fee: [0; 32],
            network_fee: [0; 32],
            payment_gas_limit: [0; 32],
            action_target: [5; 20],
            action_calldata_hash: [6; 32],
            action_gas_limit: [0; 32],
            tracked_assets_hash: [7; 32],
            maximum_transaction_gas: [0; 32],
            maximum_fee_per_gas: [0; 32],
            return_data_limit: [0; 32],
            valid_after_unix: 0,
            valid_until_unix: u64::MAX,
            quote_nonce: [0; 32],
        },
        execution_id,
        exit_signature: vec![0; 65],
        pending_sponsored_gas: 100_000,
        rolling_loss_window_secs: 3_600,
        status: QuoteStatusV2::Outstanding,
    }
}

async fn quote_counter(repository: &SledRepository, key: &[u8]) -> u64 {
    let encoded = nox_core::IStorageRepository::get(repository, key)
        .await
        .unwrap()
        .unwrap();
    u64::from_le_bytes(encoded.try_into().unwrap())
}

async fn anvil_executor() -> (ethers::utils::AnvilInstance, Arc<ChainExecutor>) {
    let anvil = Anvil::new().spawn();
    let mut config = NoxConfig::default();
    config.eth_rpc_url = anvil.endpoint();
    config.chain_id = anvil.chain_id();
    config.eth_wallet_private_key = hex::encode(anvil.keys()[0].to_bytes());
    let executor = Arc::new(ChainExecutor::new(&config).await.unwrap());
    (anvil, executor)
}

async fn wait_for_receipt(executor: &ChainExecutor, hash: H256) -> TransactionReceipt {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(receipt) = executor.get_transaction_receipt(hash).await.unwrap() {
                return receipt;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("transaction receipt timeout")
}

async fn signed_record(executor: &ChainExecutor, status: TxStatusV2) -> PendingTransactionV2 {
    let target = Address::from_low_u64_be(71);
    let calldata = Bytes::new();
    let raw = executor
        .sign_legacy_transaction(
            target,
            calldata.clone(),
            U256::zero(),
            U256::from(21_000),
            U256::from(2_000_000_000_u64),
        )
        .await
        .unwrap();
    PendingTransactionV2 {
        execution_id: [7; 32],
        to: format!("{target:?}"),
        data_hash: ethers::utils::keccak256(&calldata),
        nonce: 0,
        gas_limit: "21000".to_string(),
        gas_price: "2000000000".to_string(),
        maximum_fee_per_gas: "3000000000".to_string(),
        raw_signed_tx: raw.to_vec(),
        tx_hash: format!(
            "{:?}",
            ethers::types::H256::from(ethers::utils::keccak256(&raw))
        ),
        prior_transaction_hashes: if status == TxStatusV2::ReplacementPrepared {
            vec![format!("0x{}", "33".repeat(32))]
        } else {
            Vec::new()
        },
        replacement_attempts: u32::from(status == TxStatusV2::ReplacementPrepared),
        first_sent_at: 1,
        last_update_at: 1,
        status,
    }
}

#[tokio::test]
async fn concurrent_execution_creation_has_one_durable_identity() {
    let directory = tempfile::tempdir().unwrap();
    let repository = Arc::new(SledRepository::new(directory.path()).unwrap());
    let execution_id = [9; 32];
    let first_record = record(execution_id);
    let second_record = first_record.clone();
    let (first, second) = tokio::join!(
        repository.create_outbox_durably(execution_id, &first_record, 5),
        repository.create_outbox_durably(execution_id, &second_record, 5),
    );
    let outcomes = [first.unwrap(), second.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, CreateOutboxResult::Created))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, CreateOutboxResult::Existing(_)))
            .count(),
        1
    );

    drop(repository);
    let reopened = SledRepository::new(directory.path()).unwrap();
    let stored = nox_core::IStorageRepository::scan(&reopened, b"tx:")
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
    assert!(matches!(
        decode_stored_transaction(&stored[0].1).unwrap(),
        DecodedTransaction::V2(_)
    ));
}

#[test]
fn unknown_schema_and_malformed_legacy_records_fail_closed() {
    assert!(decode_stored_transaction(br#"{"schema":3,"transaction":{}}"#).is_err());
    assert!(decode_stored_transaction(br#"{"id":"partial"}"#).is_err());
}

#[tokio::test]
#[ignore = "private crash probe launched by durable_crash_points_preserve_outbox"]
async fn outbox_crash_probe() {
    let Ok(database_path) = std::env::var("NOX_OUTBOX_CRASH_DB") else {
        return;
    };
    let point = std::env::var("NOX_OUTBOX_CRASH_POINT").unwrap();
    let server = MockServer::start().await;
    let mut config = NoxConfig::default();
    config.eth_rpc_url = server.uri();
    config.chain_id = 31_337;
    config.eth_wallet_private_key =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string();
    let executor = ChainExecutor::new(&config).await.unwrap();
    let target = Address::from_low_u64_be(44);
    let gas_price = if point.starts_with("replacement") {
        12
    } else {
        10
    };
    let raw = executor
        .sign_legacy_transaction(
            target,
            Bytes::from(vec![4, 5, 6]),
            U256::zero(),
            U256::from(50_000),
            U256::from(gas_price),
        )
        .await
        .unwrap();
    let hash = ethers::types::H256::from(ethers::utils::keccak256(&raw));
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": format!("{hash:?}")
        })))
        .mount(&server)
        .await;
    let mut crash_record = PendingTransactionV2 {
        execution_id: [6; 32],
        to: format!("{target:?}"),
        data_hash: ethers::utils::keccak256([4, 5, 6]),
        nonce: 0,
        gas_limit: "50000".to_string(),
        gas_price: gas_price.to_string(),
        maximum_fee_per_gas: "20".to_string(),
        raw_signed_tx: raw.to_vec(),
        tx_hash: format!("{hash:?}"),
        prior_transaction_hashes: Vec::new(),
        replacement_attempts: 0,
        first_sent_at: 1,
        last_update_at: 1,
        status: TxStatusV2::Prepared,
    };
    if point.starts_with("replacement") {
        crash_record.status = TxStatusV2::ReplacementPrepared;
        crash_record.prior_transaction_hashes = vec![format!("0x{}", "22".repeat(32))];
        crash_record.replacement_attempts = 1;
    }
    let repository = SledRepository::new(database_path).unwrap();
    repository
        .create_outbox_durably(crash_record.execution_id, &crash_record, 1)
        .await
        .unwrap();
    if point.ends_with("post_send") {
        assert_eq!(
            executor
                .broadcast_raw_signed_tx(&crash_record.raw_signed_tx)
                .await
                .unwrap(),
            hash
        );
    }
    std::process::abort();
}

#[test]
fn durable_crash_points_preserve_outbox() {
    for point in [
        "initial_pre_send",
        "initial_post_send",
        "replacement_pre_send",
        "replacement_post_send",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .arg("outbox_crash_probe")
            .arg("--ignored")
            .arg("--exact")
            .arg("--nocapture")
            .env("NOX_OUTBOX_CRASH_DB", directory.path())
            .env("NOX_OUTBOX_CRASH_POINT", point)
            .status()
            .unwrap();
        assert!(!status.success(), "crash probe must abort at {point}");
        let repository = SledRepository::new(directory.path()).unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let records = runtime
            .block_on(nox_core::IStorageRepository::scan(&repository, b"tx:"))
            .unwrap();
        assert_eq!(records.len(), 1, "durable record missing at {point}");
        let DecodedTransaction::V2(transaction) = decode_stored_transaction(&records[0].1).unwrap()
        else {
            panic!("crash record must use schema 2");
        };
        assert_eq!(transaction.nonce, 0);
        assert_eq!(
            transaction.tx_hash,
            format!(
                "{:?}",
                ethers::types::H256::from(ethers::utils::keccak256(&transaction.raw_signed_tx))
            )
        );
        let nonce_floor = runtime
            .block_on(nox_core::IStorageRepository::get(
                &repository,
                b"nonce:local",
            ))
            .unwrap()
            .unwrap();
        assert_eq!(u64::from_le_bytes(nonce_floor.try_into().unwrap()), 1);
    }
}

#[tokio::test]
async fn concurrent_manager_submissions_allocate_one_nonce_and_broadcast() {
    let (_anvil, executor) = anvil_executor().await;
    let directory = tempfile::tempdir().unwrap();
    let repository = Arc::new(SledRepository::new(directory.path()).unwrap());
    let manager = Arc::new(
        TransactionManager::new(
            executor.clone(),
            repository.clone(),
            MetricsService::new(),
            nox_node::config::DEFAULT_REPLACEMENT_STEP_BPS,
        )
        .await
        .unwrap(),
    );
    let plan = TransactionPlan {
        gas_limit: U256::from(21_000),
        initial_fee_per_gas: U256::from(2_000_000_000_u64),
        maximum_fee_per_gas: U256::from(3_000_000_000_u64),
        chain_data_fee_native: U256::zero(),
    };
    let execution_id = [3; 32];
    let target = Address::from_low_u64_be(17);
    let first = manager.submit_planned(execution_id, target, Bytes::new(), plan.clone());
    let second = manager.submit_planned(execution_id, target, Bytes::new(), plan);
    let (first, second) = tokio::join!(first, second);
    let outcomes = [first, second];
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Err(SubmitError::Duplicate { .. })))
            .count(),
        1
    );
    assert_eq!(executor.get_nonce().await.unwrap(), U256::one());
    assert_eq!(
        nox_core::IStorageRepository::scan(repository.as_ref(), b"tx:")
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn prepared_states_rebroadcast_the_stored_transaction_identity() {
    for prepared_status in [TxStatusV2::Prepared, TxStatusV2::ReplacementPrepared] {
        let (_anvil, executor) = anvil_executor().await;
        let directory = tempfile::tempdir().unwrap();
        let repository = Arc::new(SledRepository::new(directory.path()).unwrap());
        let prepared = signed_record(executor.as_ref(), prepared_status.clone()).await;
        repository
            .create_outbox_durably(prepared.execution_id, &prepared, 1)
            .await
            .unwrap();

        let _manager = TransactionManager::new(
            executor,
            repository.clone(),
            MetricsService::new(),
            nox_node::config::DEFAULT_REPLACEMENT_STEP_BPS,
        )
        .await
        .unwrap();
        let records = nox_core::IStorageRepository::scan(repository.as_ref(), b"tx:")
            .await
            .unwrap();
        let DecodedTransaction::V2(recovered) = decode_stored_transaction(&records[0].1).unwrap()
        else {
            panic!("recovered record must use schema 2");
        };
        let expected_status = if prepared_status == TxStatusV2::Prepared {
            TxStatusV2::Submitted
        } else {
            TxStatusV2::Replaced
        };
        assert_eq!(recovered.status, expected_status);
        assert_eq!(recovered.raw_signed_tx, prepared.raw_signed_tx);
        assert_eq!(recovered.tx_hash, prepared.tx_hash);
    }
}

#[tokio::test]
async fn legacy_record_sets_nonce_floor_and_remains_monitor_only() {
    let (_anvil, executor) = anvil_executor().await;
    let directory = tempfile::tempdir().unwrap();
    let repository = Arc::new(SledRepository::new(directory.path()).unwrap());
    let legacy = serde_json::json!({
        "id": "legacy-baseline",
        "to": "0x0000000000000000000000000000000000000001",
        "data": [1, 2],
        "nonce": 4,
        "gas_limit": "21000",
        "gas_price": "1",
        "tx_hash": format!("0x{}", "44".repeat(32)),
        "first_sent_at": 1,
        "last_update_at": 1,
        "status": "Pending"
    });
    nox_core::IStorageRepository::put(
        repository.as_ref(),
        b"tx:4",
        &serde_json::to_vec(&legacy).unwrap(),
    )
    .await
    .unwrap();
    let manager = TransactionManager::new(
        executor,
        repository.clone(),
        MetricsService::new(),
        nox_node::config::DEFAULT_REPLACEMENT_STEP_BPS,
    )
    .await
    .unwrap();
    let submission = manager
        .submit_planned(
            [8; 32],
            Address::from_low_u64_be(88),
            Bytes::new(),
            TransactionPlan {
                gas_limit: U256::from(21_000),
                initial_fee_per_gas: U256::from(2_000_000_000_u64),
                maximum_fee_per_gas: U256::from(3_000_000_000_u64),
                chain_data_fee_native: U256::zero(),
            },
        )
        .await;
    assert!(!matches!(submission, Err(SubmitError::Duplicate { .. })));
    let records = nox_core::IStorageRepository::scan(repository.as_ref(), b"tx:")
        .await
        .unwrap();
    assert_eq!(records.len(), 2);
    assert!(records.iter().any(|(_, bytes)| matches!(
        decode_stored_transaction(bytes).unwrap(),
        DecodedTransaction::Legacy(_)
    )));
    assert!(records.iter().any(|(_, bytes)| matches!(
        decode_stored_transaction(bytes).unwrap(),
        DecodedTransaction::V2(PendingTransactionV2 { nonce: 5, .. })
    )));
}

#[tokio::test]
async fn corrupt_v2_record_aborts_manager_startup() {
    let (_anvil, executor) = anvil_executor().await;
    let directory = tempfile::tempdir().unwrap();
    let repository = Arc::new(SledRepository::new(directory.path()).unwrap());
    nox_core::IStorageRepository::put(
        repository.as_ref(),
        b"tx:0",
        br#"{"schema":2,"transaction":{"execution_id":[]}}"#,
    )
    .await
    .unwrap();
    assert!(TransactionManager::new(
        executor,
        repository,
        MetricsService::new(),
        nox_node::config::DEFAULT_REPLACEMENT_STEP_BPS,
    )
    .await
    .is_err());
}

/// The interval `TransactionManager::run_monitor` sleeps between passes.
const MONITOR_INTERVAL: Duration = Duration::from_secs(12);

/// Runs the next monitor pass now instead of an interval later: moves the
/// clock past the interval, then waits for the pass to end. The monitor sets
/// the quote gauges as the last step of a pass, which is the signal used here.
async fn run_monitor_pass(metrics: &MetricsService) {
    const PASS_RUNNING: i64 = -1;
    metrics.quote_outstanding.set(PASS_RUNNING);
    // The monitor task has to be waiting on its interval before the clock moves.
    tokio::task::yield_now().await;
    tokio::time::pause();
    tokio::time::advance(MONITOR_INTERVAL).await;
    tokio::time::resume();
    tokio::time::timeout(Duration::from_secs(30), async {
        while metrics.quote_outstanding.get() == PASS_RUNNING {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the monitor pass did not finish");
}

async fn replacement_case(maximum_fee_per_gas: U256) -> PendingTransactionV2 {
    let anvil = Anvil::new().arg("--no-mining").spawn();
    let mut config = NoxConfig::default();
    config.eth_rpc_url = anvil.endpoint();
    config.chain_id = anvil.chain_id();
    config.eth_wallet_private_key = hex::encode(anvil.keys()[0].to_bytes());
    let executor = Arc::new(ChainExecutor::new(&config).await.unwrap());
    let directory = tempfile::tempdir().unwrap();
    let repository = Arc::new(SledRepository::new(directory.path()).unwrap());
    let manager = TransactionManager::new(
        executor.clone(),
        repository.clone(),
        MetricsService::new(),
        nox_node::config::DEFAULT_REPLACEMENT_STEP_BPS,
    )
    .await
    .unwrap();
    manager
        .submit_planned(
            [5; 32],
            Address::from_low_u64_be(99),
            Bytes::new(),
            TransactionPlan {
                gas_limit: U256::from(21_000),
                initial_fee_per_gas: U256::from(2_000_000_000_u64),
                maximum_fee_per_gas,
                chain_data_fee_native: U256::zero(),
            },
        )
        .await
        .unwrap();
    let records = nox_core::IStorageRepository::scan(repository.as_ref(), b"tx:")
        .await
        .unwrap();
    let DecodedTransaction::V2(mut submitted) = decode_stored_transaction(&records[0].1).unwrap()
    else {
        panic!("submitted record must use schema 2");
    };
    submitted.last_update_at = 0;
    repository.persist_v2_durably(&submitted).await.unwrap();
    drop(manager);

    let cancellation = CancellationToken::new();
    let metrics = MetricsService::new();
    let manager = Arc::new(
        TransactionManager::new(
            executor,
            repository.clone(),
            metrics.clone(),
            nox_node::config::DEFAULT_REPLACEMENT_STEP_BPS,
        )
        .await
        .unwrap()
        .with_cancel_token(cancellation.clone()),
    );
    let monitor = tokio::spawn({
        let manager = manager.clone();
        async move { manager.run_monitor().await }
    });
    run_monitor_pass(&metrics).await;
    cancellation.cancel();
    monitor.await.unwrap();
    let records = nox_core::IStorageRepository::scan(repository.as_ref(), b"tx:")
        .await
        .unwrap();
    let DecodedTransaction::V2(monitored) = decode_stored_transaction(&records[0].1).unwrap()
    else {
        panic!("monitored record must use schema 2");
    };
    monitored
}

#[tokio::test]
async fn replacement_policy_applies_exact_step_and_never_exceeds_ceiling() {
    let capped = replacement_case(U256::from(2_000_000_000_u64)).await;
    let stepped = replacement_case(U256::from(3_000_000_000_u64)).await;
    assert_eq!(capped.replacement_attempts, 0);
    assert_eq!(capped.gas_price, "2000000000");
    assert!(capped.prior_transaction_hashes.is_empty());
    assert_eq!(stepped.replacement_attempts, 1);
    assert_eq!(stepped.gas_price, "2400000000");
    assert_eq!(stepped.prior_transaction_hashes.len(), 1);
    assert_eq!(stepped.status, TxStatusV2::Replaced);
}

#[tokio::test]
async fn capped_mined_transaction_reconciles_before_replacement() {
    let (_anvil, executor) = anvil_executor().await;
    let directory = tempfile::tempdir().unwrap();
    let repository = Arc::new(SledRepository::new(directory.path()).unwrap());
    let manager = TransactionManager::new(
        executor.clone(),
        repository.clone(),
        MetricsService::new(),
        nox_node::config::DEFAULT_REPLACEMENT_STEP_BPS,
    )
    .await
    .unwrap();
    manager
        .submit_planned(
            [1; 32],
            Address::from_low_u64_be(29),
            Bytes::new(),
            TransactionPlan {
                gas_limit: U256::from(21_000),
                initial_fee_per_gas: U256::from(2_000_000_000_u64),
                maximum_fee_per_gas: U256::from(2_000_000_000_u64),
                chain_data_fee_native: U256::zero(),
            },
        )
        .await
        .unwrap();
    let records = nox_core::IStorageRepository::scan(repository.as_ref(), b"tx:")
        .await
        .unwrap();
    let DecodedTransaction::V2(mut submitted) = decode_stored_transaction(&records[0].1).unwrap()
    else {
        panic!("submitted record must use schema 2");
    };
    submitted.last_update_at = 0;
    repository.persist_v2_durably(&submitted).await.unwrap();
    drop(manager);

    let cancellation = CancellationToken::new();
    let metrics = MetricsService::new();
    let manager = Arc::new(
        TransactionManager::new(
            executor,
            repository.clone(),
            metrics.clone(),
            nox_node::config::DEFAULT_REPLACEMENT_STEP_BPS,
        )
        .await
        .unwrap()
        .with_cancel_token(cancellation.clone()),
    );
    let monitor = tokio::spawn({
        let manager = manager.clone();
        async move { manager.run_monitor().await }
    });
    run_monitor_pass(&metrics).await;
    cancellation.cancel();
    monitor.await.unwrap();
    let records = nox_core::IStorageRepository::scan(repository.as_ref(), b"tx:")
        .await
        .unwrap();
    let DecodedTransaction::V2(reconciled) = decode_stored_transaction(&records[0].1).unwrap()
    else {
        panic!("reconciled record must use schema 2");
    };
    assert_eq!(reconciled.status, TxStatusV2::Mined);
    assert_eq!(reconciled.replacement_attempts, 0);
    assert!(reconciled.prior_transaction_hashes.is_empty());
}

async fn broadcast_error_case(
    message: &'static str,
) -> (
    Result<nox_node::blockchain::tx_manager::SubmittedTransaction, SubmitError>,
    PendingTransactionV2,
    usize,
) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_string_contains("eth_getTransactionCount"))
        .respond_with(JsonRpcResult(serde_json::json!("0x0")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("eth_sendRawTransaction"))
        .respond_with(JsonRpcError(message))
        .mount(&server)
        .await;
    let mut config = NoxConfig::default();
    config.eth_rpc_url = server.uri();
    config.chain_id = 31_337;
    config.eth_wallet_private_key =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string();
    let executor = Arc::new(ChainExecutor::new(&config).await.unwrap());
    let directory = tempfile::tempdir().unwrap();
    let repository = Arc::new(SledRepository::new(directory.path()).unwrap());
    let manager = TransactionManager::new(
        executor,
        repository.clone(),
        MetricsService::new(),
        nox_node::config::DEFAULT_REPLACEMENT_STEP_BPS,
    )
    .await
    .unwrap();
    let outcome = manager
        .submit_planned(
            [4; 32],
            Address::from_low_u64_be(12),
            Bytes::new(),
            TransactionPlan {
                gas_limit: U256::from(21_000),
                initial_fee_per_gas: U256::from(2_000_000_000_u64),
                maximum_fee_per_gas: U256::from(3_000_000_000_u64),
                chain_data_fee_native: U256::zero(),
            },
        )
        .await;
    let records = nox_core::IStorageRepository::scan(repository.as_ref(), b"tx:")
        .await
        .unwrap();
    let DecodedTransaction::V2(stored) = decode_stored_transaction(&records[0].1).unwrap() else {
        panic!("broadcast record must use schema 2");
    };
    let send_count = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| String::from_utf8_lossy(&request.body).contains("eth_sendRawTransaction"))
        .count();
    (outcome, stored, send_count)
}

#[tokio::test]
async fn broadcast_classification_preserves_one_prepared_identity() {
    let (already_known, known_record, known_sends) = broadcast_error_case("already known").await;
    assert!(already_known.is_ok());
    assert_eq!(known_record.status, TxStatusV2::Submitted);
    assert_eq!(known_sends, 1);

    for message in ["timeout after acceptance", "nonce too low"] {
        let (outcome, stored, sends) = broadcast_error_case(message).await;
        assert!(matches!(
            outcome,
            Err(SubmitError::AmbiguousBroadcast { .. })
        ));
        assert_eq!(stored.status, TxStatusV2::Prepared);
        assert_eq!(stored.nonce, 0);
        assert_eq!(sends, 1);
    }
}

#[tokio::test]
async fn live_monitor_rebroadcasts_ambiguous_prepared_bytes_without_restart() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_string_contains("eth_getTransactionCount"))
        .respond_with(JsonRpcResult(serde_json::json!("0x0")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("eth_sendRawTransaction"))
        .respond_with(JsonRpcError("timeout after acceptance"))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("eth_sendRawTransaction"))
        .respond_with(RawTransactionHashResponder)
        .with_priority(5)
        .mount(&server)
        .await;
    let mut config = NoxConfig::default();
    config.eth_rpc_url = server.uri();
    config.chain_id = 31_337;
    config.eth_wallet_private_key =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string();
    let executor = Arc::new(ChainExecutor::new(&config).await.unwrap());
    let directory = tempfile::tempdir().unwrap();
    let repository = Arc::new(SledRepository::new(directory.path()).unwrap());
    let quote = quote_record([2; 32]);
    repository
        .create_quote_durably(&quote, 1, 100_000, U256::from(1), 3_600, 1)
        .await
        .unwrap();
    repository
        .take_quote_durably(quote.execution_id, 2)
        .await
        .unwrap();
    let cancellation = CancellationToken::new();
    let metrics = MetricsService::new();
    let manager = Arc::new(
        TransactionManager::new(
            executor,
            repository.clone(),
            metrics.clone(),
            nox_node::config::DEFAULT_REPLACEMENT_STEP_BPS,
        )
        .await
        .unwrap()
        .with_cancel_token(cancellation.clone()),
    );
    let outcome = manager
        .submit_planned(
            [2; 32],
            Address::from_low_u64_be(23),
            Bytes::new(),
            TransactionPlan {
                gas_limit: U256::from(21_000),
                initial_fee_per_gas: U256::from(2_000_000_000_u64),
                maximum_fee_per_gas: U256::from(3_000_000_000_u64),
                chain_data_fee_native: U256::zero(),
            },
        )
        .await;
    assert!(matches!(
        outcome,
        Err(SubmitError::AmbiguousBroadcast { .. })
    ));
    let before = nox_core::IStorageRepository::scan(repository.as_ref(), b"tx:")
        .await
        .unwrap();
    let DecodedTransaction::V2(prepared) = decode_stored_transaction(&before[0].1).unwrap() else {
        panic!("ambiguous record must use schema 2");
    };
    assert_eq!(prepared.status, TxStatusV2::Prepared);

    let monitor = tokio::spawn({
        let manager = manager.clone();
        async move { manager.run_monitor().await }
    });
    run_monitor_pass(&metrics).await;
    cancellation.cancel();
    monitor.await.unwrap();
    let after = nox_core::IStorageRepository::scan(repository.as_ref(), b"tx:")
        .await
        .unwrap();
    let DecodedTransaction::V2(recovered) = decode_stored_transaction(&after[0].1).unwrap() else {
        panic!("recovered record must use schema 2");
    };
    assert_eq!(recovered.status, TxStatusV2::Submitted);
    assert_eq!(recovered.raw_signed_tx, prepared.raw_signed_tx);
    assert_eq!(recovered.tx_hash, prepared.tx_hash);
    assert_eq!(
        repository
            .load_quote(quote.execution_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        QuoteStatusV2::Inflight,
    );
    assert_eq!(quote_counter(&repository, b"quote:outstanding").await, 1);
    assert_eq!(
        quote_counter(&repository, b"quote:pending-gas").await,
        100_000
    );
    let sends = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| String::from_utf8_lossy(&request.body).contains("eth_sendRawTransaction"))
        .count();
    assert_eq!(sends, 2);
}

#[tokio::test]
async fn live_monitor_rebroadcasts_ambiguous_replacement_bytes_without_restart() {
    let server = MockServer::start().await;
    let mut latest_block = Block::<H256>::default();
    latest_block.timestamp = U256::from(1);
    Mock::given(method("POST"))
        .and(body_string_contains("eth_getBlockByNumber"))
        .respond_with(JsonRpcResult(serde_json::to_value(latest_block).unwrap()))
        .mount(&server)
        .await;
    for (rpc_method, value) in [
        ("eth_getTransactionCount", serde_json::json!("0x0")),
        ("eth_getTransactionReceipt", serde_json::Value::Null),
        ("eth_gasPrice", serde_json::json!("0x64")),
    ] {
        Mock::given(method("POST"))
            .and(body_string_contains(rpc_method))
            .respond_with(JsonRpcResult(value))
            .mount(&server)
            .await;
    }
    let send_count = Arc::new(AtomicUsize::new(0));
    Mock::given(method("POST"))
        .and(body_string_contains("eth_sendRawTransaction"))
        .respond_with(ReplacementAmbiguityResponder(send_count.clone()))
        .mount(&server)
        .await;
    let mut config = NoxConfig::default();
    config.eth_rpc_url = server.uri();
    config.chain_id = 31_337;
    config.eth_wallet_private_key =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string();
    let executor = Arc::new(ChainExecutor::new(&config).await.unwrap());
    let directory = tempfile::tempdir().unwrap();
    let repository = Arc::new(SledRepository::new(directory.path()).unwrap());
    let manager = TransactionManager::new(
        executor.clone(),
        repository.clone(),
        MetricsService::new(),
        nox_node::config::DEFAULT_REPLACEMENT_STEP_BPS,
    )
    .await
    .unwrap();
    manager
        .submit_planned(
            [12; 32],
            Address::from_low_u64_be(24),
            Bytes::new(),
            TransactionPlan {
                gas_limit: U256::from(21_000),
                initial_fee_per_gas: U256::from(100),
                maximum_fee_per_gas: U256::from(200),
                chain_data_fee_native: U256::zero(),
            },
        )
        .await
        .unwrap();
    let records = nox_core::IStorageRepository::scan(repository.as_ref(), b"tx:")
        .await
        .unwrap();
    let DecodedTransaction::V2(mut submitted) = decode_stored_transaction(&records[0].1).unwrap()
    else {
        panic!("submitted record must use schema 2");
    };
    submitted.last_update_at = 0;
    repository.persist_v2_durably(&submitted).await.unwrap();
    drop(manager);

    let cancellation = CancellationToken::new();
    let metrics = MetricsService::new();
    let manager = Arc::new(
        TransactionManager::new(
            executor,
            repository.clone(),
            metrics.clone(),
            nox_node::config::DEFAULT_REPLACEMENT_STEP_BPS,
        )
        .await
        .unwrap()
        .with_cancel_token(cancellation.clone()),
    );
    let monitor = tokio::spawn({
        let manager = manager.clone();
        async move { manager.run_monitor().await }
    });
    run_monitor_pass(&metrics).await;
    run_monitor_pass(&metrics).await;
    cancellation.cancel();
    monitor.await.unwrap();
    let records = nox_core::IStorageRepository::scan(repository.as_ref(), b"tx:")
        .await
        .unwrap();
    let DecodedTransaction::V2(recovered) = decode_stored_transaction(&records[0].1).unwrap()
    else {
        panic!("replacement record must use schema 2");
    };
    assert_eq!(recovered.status, TxStatusV2::Replaced);
    assert_eq!(recovered.replacement_attempts, 1);
    assert_eq!(recovered.prior_transaction_hashes.len(), 1);
    assert_eq!(send_count.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn legacy_pending_receipt_becomes_terminal_without_raw_broadcast() {
    use ethers::middleware::SignerMiddleware;
    use ethers::providers::{Http, Middleware, Provider};
    use ethers::signers::{LocalWallet, Signer};
    use ethers::types::TransactionRequest;

    let anvil = Anvil::new().spawn();
    let provider = Provider::<Http>::try_from(anvil.endpoint()).unwrap();
    let wallet = LocalWallet::from(anvil.keys()[0].clone()).with_chain_id(anvil.chain_id());
    let client = SignerMiddleware::new(provider, wallet);
    let receipt = client
        .send_transaction(
            TransactionRequest::new()
                .to(Address::from_low_u64_be(91))
                .value(U256::one()),
            None,
        )
        .await
        .unwrap()
        .await
        .unwrap()
        .unwrap();

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_string_contains("eth_getTransactionCount"))
        .respond_with(JsonRpcResult(serde_json::json!("0x1")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("eth_getTransactionReceipt"))
        .respond_with(JsonRpcResult(serde_json::to_value(&receipt).unwrap()))
        .mount(&server)
        .await;
    let mut config = NoxConfig::default();
    config.eth_rpc_url = server.uri();
    config.chain_id = anvil.chain_id();
    config.eth_wallet_private_key = hex::encode(anvil.keys()[0].to_bytes());
    let executor = Arc::new(ChainExecutor::new(&config).await.unwrap());
    let directory = tempfile::tempdir().unwrap();
    let repository = Arc::new(SledRepository::new(directory.path()).unwrap());
    let legacy = LegacyPendingTransaction {
        id: "legacy-mined".to_string(),
        to: format!("{:?}", Address::from_low_u64_be(91)),
        data: Vec::new(),
        nonce: 0,
        gas_limit: "21000".to_string(),
        gas_price: "1".to_string(),
        tx_hash: format!("{:?}", receipt.transaction_hash),
        first_sent_at: 1,
        last_update_at: 0,
        status: LegacyTxStatus::Pending,
    };
    nox_core::IStorageRepository::put(
        repository.as_ref(),
        b"tx:0",
        &serde_json::to_vec(&legacy).unwrap(),
    )
    .await
    .unwrap();
    let metrics = MetricsService::new();
    let cancellation = CancellationToken::new();
    let manager = Arc::new(
        TransactionManager::new(
            executor,
            repository.clone(),
            metrics.clone(),
            nox_node::config::DEFAULT_REPLACEMENT_STEP_BPS,
        )
        .await
        .unwrap()
        .with_cancel_token(cancellation.clone()),
    );
    let monitor = tokio::spawn({
        let manager = manager.clone();
        async move { manager.run_monitor().await }
    });
    run_monitor_pass(&metrics).await;
    cancellation.cancel();
    monitor.await.unwrap();

    let stored = nox_core::IStorageRepository::scan(repository.as_ref(), b"tx:")
        .await
        .unwrap();
    let DecodedTransaction::Legacy(terminal) = decode_stored_transaction(&stored[0].1).unwrap()
    else {
        panic!("legacy record must retain its schema");
    };
    assert_eq!(terminal.status, LegacyTxStatus::Mined);
    assert_eq!(metrics.eth_tx_pending.get(), 0);
    let raw_sends = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| String::from_utf8_lossy(&request.body).contains("eth_sendRawTransaction"))
        .count();
    assert_eq!(raw_sends, 0);
}

#[tokio::test]
async fn prepared_nonce_too_low_receipt_is_terminal_and_pruned() {
    let (anvil, source_executor) = anvil_executor().await;
    let prepared = signed_record(source_executor.as_ref(), TxStatusV2::Prepared).await;
    let transaction_hash = source_executor
        .broadcast_raw_signed_tx(&prepared.raw_signed_tx)
        .await
        .unwrap();
    let receipt = wait_for_receipt(source_executor.as_ref(), transaction_hash).await;

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_string_contains("eth_getTransactionCount"))
        .respond_with(JsonRpcResult(serde_json::json!("0x1")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("eth_sendRawTransaction"))
        .respond_with(JsonRpcError("nonce too low"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("eth_getTransactionReceipt"))
        .respond_with(JsonRpcResult(serde_json::to_value(&receipt).unwrap()))
        .mount(&server)
        .await;
    let mut config = NoxConfig::default();
    config.eth_rpc_url = server.uri();
    config.chain_id = anvil.chain_id();
    config.eth_wallet_private_key = hex::encode(anvil.keys()[0].to_bytes());
    let recovery_executor = Arc::new(ChainExecutor::new(&config).await.unwrap());
    let directory = tempfile::tempdir().unwrap();
    let repository = Arc::new(SledRepository::new(directory.path()).unwrap());
    let quote = quote_record(prepared.execution_id);
    repository
        .create_quote_durably(&quote, 1, 100_000, U256::from(1), 3_600, 1)
        .await
        .unwrap();
    repository
        .take_quote_durably(quote.execution_id, 2)
        .await
        .unwrap();
    repository
        .mark_quote_submitted_durably(quote.execution_id)
        .await
        .unwrap();
    repository
        .create_outbox_durably(prepared.execution_id, &prepared, 1)
        .await
        .unwrap();
    let metrics = MetricsService::new();
    let _manager = TransactionManager::new(
        recovery_executor,
        repository.clone(),
        metrics.clone(),
        nox_node::config::DEFAULT_REPLACEMENT_STEP_BPS,
    )
    .await
    .unwrap();

    let records = nox_core::IStorageRepository::scan(repository.as_ref(), b"tx:")
        .await
        .unwrap();
    let DecodedTransaction::V2(terminal) = decode_stored_transaction(&records[0].1).unwrap() else {
        panic!("terminal recovered record must use schema 2");
    };
    assert_eq!(terminal.status, TxStatusV2::Mined);
    assert_eq!(metrics.eth_tx_pending.get(), 0);
    assert_eq!(
        repository
            .load_quote(quote.execution_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        QuoteStatusV2::Confirmed,
    );
    assert_eq!(quote_counter(&repository, b"quote:outstanding").await, 0);
    assert_eq!(quote_counter(&repository, b"quote:pending-gas").await, 0);
}

fn small_plan() -> TransactionPlan {
    TransactionPlan {
        gas_limit: U256::from(21_000),
        initial_fee_per_gas: U256::from(2_000_000_000_u64),
        maximum_fee_per_gas: U256::from(3_000_000_000_u64),
        chain_data_fee_native: U256::zero(),
    }
}

/// Signs and mines a transaction from the exit wallet outside the transaction manager, the
/// way an operator claim with the exit key does.
async fn external_wallet_transaction(executor: &ChainExecutor, nonce: u64) {
    let raw = executor
        .sign_legacy_transaction(
            Address::from_low_u64_be(99),
            Bytes::new(),
            U256::from(nonce),
            U256::from(21_000),
            U256::from(2_000_000_000_u64),
        )
        .await
        .unwrap();
    let hash = executor.broadcast_raw_signed_tx(&raw).await.unwrap();
    wait_for_receipt(executor, hash).await;
}

async fn stored_v2(repository: &SledRepository, nonce: u64) -> PendingTransactionV2 {
    let key = format!("tx:{nonce}");
    let bytes = nox_core::IStorageRepository::get(repository, key.as_bytes())
        .await
        .unwrap()
        .unwrap();
    let DecodedTransaction::V2(record) = decode_stored_transaction(&bytes).unwrap() else {
        panic!("record must use schema 2");
    };
    record
}

#[tokio::test]
async fn external_wallet_transaction_does_not_wedge_next_submission() {
    let (_anvil, executor) = anvil_executor().await;
    let directory = tempfile::tempdir().unwrap();
    let repository = Arc::new(SledRepository::new(directory.path()).unwrap());
    let metrics = MetricsService::new();
    let manager = TransactionManager::new(
        executor.clone(),
        repository.clone(),
        metrics.clone(),
        nox_node::config::DEFAULT_REPLACEMENT_STEP_BPS,
    )
    .await
    .unwrap();

    external_wallet_transaction(executor.as_ref(), 0).await;

    let submitted = manager
        .submit_planned(
            [5; 32],
            Address::from_low_u64_be(0x1234),
            Bytes::new(),
            small_plan(),
        )
        .await
        .unwrap();
    let receipt = wait_for_receipt(executor.as_ref(), submitted.transaction_hash).await;
    assert_eq!(receipt.status, Some(1_u64.into()));
    assert_eq!(
        stored_v2(&repository, 1).await.status,
        TxStatusV2::Submitted
    );
    assert!(!manager.is_submission_blocked());
    assert_eq!(metrics.eth_submission_blocked.get(), 0);
}

#[tokio::test]
async fn prepared_transaction_superseded_by_external_nonce_is_retired() {
    let (_anvil, executor) = anvil_executor().await;
    let prepared = signed_record(executor.as_ref(), TxStatusV2::Prepared).await;
    external_wallet_transaction(executor.as_ref(), prepared.nonce).await;

    let directory = tempfile::tempdir().unwrap();
    let repository = Arc::new(SledRepository::new(directory.path()).unwrap());
    let quote = quote_record(prepared.execution_id);
    repository
        .create_quote_durably(&quote, 1, 100_000, U256::from(1), 3_600, 1)
        .await
        .unwrap();
    repository
        .take_quote_durably(quote.execution_id, 2)
        .await
        .unwrap();
    repository
        .create_outbox_durably(prepared.execution_id, &prepared, 1)
        .await
        .unwrap();

    let metrics = MetricsService::new();
    let manager = TransactionManager::new(
        executor.clone(),
        repository.clone(),
        metrics.clone(),
        nox_node::config::DEFAULT_REPLACEMENT_STEP_BPS,
    )
    .await
    .unwrap();

    assert_eq!(stored_v2(&repository, 0).await.status, TxStatusV2::Failed);
    assert_eq!(
        repository
            .load_quote(quote.execution_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        QuoteStatusV2::Rejected,
    );
    assert_eq!(quote_counter(&repository, b"quote:outstanding").await, 0);
    assert_eq!(quote_counter(&repository, b"quote:pending-gas").await, 0);
    assert!(!manager.is_submission_blocked());
    assert_eq!(metrics.eth_tx_pending.get(), 0);
    assert_eq!(
        metrics
            .eth_tx_outcomes_total
            .get_or_create(&vec![
                ("type".to_string(), "paid_v2".to_string()),
                ("result".to_string(), "superseded".to_string()),
            ])
            .get(),
        1
    );

    let submitted = manager
        .submit_planned(
            [6; 32],
            Address::from_low_u64_be(0x1234),
            Bytes::new(),
            small_plan(),
        )
        .await
        .unwrap();
    wait_for_receipt(executor.as_ref(), submitted.transaction_hash).await;
    assert_eq!(stored_v2(&repository, 1).await.execution_id, [6; 32]);
}

#[tokio::test]
async fn nonce_consumed_at_broadcast_releases_quote_and_unblocks() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_string_contains("eth_getTransactionCount"))
        .and(body_string_contains("\"pending\""))
        .respond_with(JsonRpcResult(serde_json::json!("0x0")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("eth_getTransactionCount"))
        .and(body_string_contains("\"latest\""))
        .respond_with(JsonRpcResult(serde_json::json!("0x1")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("eth_sendRawTransaction"))
        .respond_with(JsonRpcError("nonce too low: next nonce 1, tx nonce 0"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("eth_getTransactionReceipt"))
        .respond_with(JsonRpcResult(serde_json::Value::Null))
        .mount(&server)
        .await;
    let mut config = NoxConfig::default();
    config.eth_rpc_url = server.uri();
    config.chain_id = 31_337;
    config.eth_wallet_private_key =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string();
    let executor = Arc::new(ChainExecutor::new(&config).await.unwrap());
    let directory = tempfile::tempdir().unwrap();
    let repository = Arc::new(SledRepository::new(directory.path()).unwrap());
    let execution_id = [4; 32];
    let quote = quote_record(execution_id);
    repository
        .create_quote_durably(&quote, 1, 100_000, U256::from(1), 3_600, 1)
        .await
        .unwrap();
    repository
        .take_quote_durably(execution_id, 2)
        .await
        .unwrap();
    let metrics = MetricsService::new();
    let manager = TransactionManager::new(
        executor,
        repository.clone(),
        metrics.clone(),
        nox_node::config::DEFAULT_REPLACEMENT_STEP_BPS,
    )
    .await
    .unwrap();

    let outcome = manager
        .submit_planned(
            execution_id,
            Address::from_low_u64_be(12),
            Bytes::new(),
            small_plan(),
        )
        .await;

    assert!(
        matches!(outcome, Err(SubmitError::NonceConsumed { nonce: 0 })),
        "unexpected outcome: {outcome:?}"
    );
    assert_eq!(stored_v2(&repository, 0).await.status, TxStatusV2::Failed);
    assert_eq!(
        repository
            .load_quote(execution_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        QuoteStatusV2::Rejected,
    );
    assert_eq!(quote_counter(&repository, b"quote:outstanding").await, 0);
    assert!(!manager.is_submission_blocked());
    assert_eq!(metrics.eth_submission_blocked.get(), 0);
}
