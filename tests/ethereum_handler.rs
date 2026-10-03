//! EthereumHandler tests in mock mode (requires `dev-node` feature).

#![cfg(feature = "dev-node")]

use ethers::prelude::*;
use nox_core::models::payloads::RelayerPayload;
use nox_core::traits::service::{ServiceError, ServiceHandler};
use nox_core::{
    PaidQuoteOutcomeV2, PaidQuoteRequestV2, PaidTransactionOutcomeV2, PaidTransactionRequestV2,
    QuoteStatusV2,
};
use nox_node::blockchain::executor::ChainExecutor;
use nox_node::blockchain::tx_manager::TransactionManager;
use nox_node::price::client::PriceClient;
use nox_node::services::handlers::ethereum::EthereumHandler;
use nox_node::telemetry::metrics::MetricsService;
use nox_node::{NoxConfig, SledRepository};
use std::str::FromStr;
use std::sync::Arc;
use tempfile::tempdir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_PRIVATE_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const TEST_POOL_ADDRESS: &str = "0x1234567890123456789012345678901234567890";

async fn make_mock_chain_executor() -> Arc<ChainExecutor> {
    let mut config = NoxConfig::default();
    config.benchmark_mode = true;
    config.chain_id = 31337;
    config.eth_wallet_private_key = TEST_PRIVATE_KEY.to_string();
    Arc::new(
        ChainExecutor::new(&config)
            .await
            .expect("ChainExecutor::new in mock mode"),
    )
}

async fn make_tx_manager(executor: Arc<ChainExecutor>) -> Arc<TransactionManager> {
    let dir = tempdir().expect("tempdir");
    let storage = Arc::new(SledRepository::new(dir.path()).expect("SledRepository"));
    let metrics = MetricsService::new();
    Arc::new(
        TransactionManager::new(
            executor,
            storage,
            metrics,
            nox_node::config::DEFAULT_REPLACEMENT_STEP_BPS,
        )
        .await
        .expect("TransactionManager::new in mock mode"),
    )
}

async fn make_handler(price_server_uri: &str) -> EthereumHandler {
    let executor = make_mock_chain_executor().await;
    let tx_mgr = make_tx_manager(executor.clone()).await;
    let metrics = MetricsService::new();
    let price_client =
        Arc::new(PriceClient::new(price_server_uri, Default::default()).expect("price client"));
    let pool_address = Address::from_str(TEST_POOL_ADDRESS).expect("valid pool address");
    EthereumHandler::new(
        executor,
        tx_mgr,
        metrics,
        10, // 10% min profit margin
        price_client,
        pool_address,
        128 * 1024, // 128 KB max broadcast tx size
    )
}

async fn mock_price_server() -> MockServer {
    let server = MockServer::start().await;
    let observed_at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    Mock::given(method("GET"))
        .and(path("/prices"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({
                "ethereum": { "price_e8": "300000000000", "observed_at_unix": observed_at_unix, "asset_id": "ethereum", "source": "test" },
                "usd-coin": { "price_e8": "100000000", "observed_at_unix": observed_at_unix, "asset_id": "usd-coin", "source": "test" }
            }),
        ))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn test_mock_paid_tx_requires_committed_payment_evidence() {
    let mock_server = mock_price_server().await;
    let handler = make_handler(&mock_server.uri()).await;

    let to: Address = "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"
        .parse()
        .expect("valid address");
    let data = Bytes::from(vec![0xca, 0xfe]);

    let result = handler
        .handle_paid_transaction("test-packet-001", to, data)
        .await;

    assert!(matches!(
        result,
        Err(nox_node::services::handlers::ethereum::PaidRejection::Simulation { .. })
    ));
}

#[tokio::test]
async fn test_ethereum_handler_rejects_legacy_submit_tx_payload() {
    let mock_server = mock_price_server().await;
    let handler = make_handler(&mock_server.uri()).await;

    let to = [0u8; 20]; // zero address -- mock doesn't care about destination
    let payload = RelayerPayload::SubmitTransaction {
        to,
        data: vec![0x01, 0x02, 0x03],
    };

    let result = handler.handle("test-packet-002", &payload).await;
    match result {
        Err(ServiceError::ProcessingFailed(detail)) => {
            assert!(detail.starts_with("SUBMISSION:"), "{detail}");
            assert!(detail.contains("PaidTransactionV2"), "{detail}");
        }
        other => panic!("legacy SubmitTransaction must be rejected, got {other:?}"),
    }
}

#[tokio::test]
async fn test_ethereum_handler_service_handler_ignores_other_payloads() {
    let mock_server = mock_price_server().await;
    let handler = make_handler(&mock_server.uri()).await;

    let payload = RelayerPayload::Dummy {
        padding: b"hello".to_vec(),
    };
    let result = handler.handle("test-packet-003", &payload).await;
    assert!(
        result.is_ok(),
        "non-SubmitTransaction payload returned Err: {result:?}"
    );
}

#[tokio::test]
async fn test_ethereum_handler_broadcast_empty_tx_rejected() {
    let mock_server = mock_price_server().await;
    let handler = make_handler(&mock_server.uri()).await;

    let result = handler
        .handle_broadcast("test-packet-004", vec![], None, None)
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("Empty"),
        "expected 'Empty' in error: {err}"
    );
}

#[tokio::test]
async fn test_ethereum_handler_broadcast_oversized_tx_rejected() {
    let mock_server = mock_price_server().await;
    let handler = make_handler(&mock_server.uri()).await;

    let oversized = vec![0xffu8; 128 * 1024 + 1];
    let result = handler
        .handle_broadcast("test-packet-005", oversized, None, None)
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("too large"),
        "expected 'too large' in error: {err}"
    );
}

#[tokio::test]
async fn test_ethereum_handler_broadcast_custom_method_without_url_rejected() {
    let mock_server = mock_price_server().await;
    let handler = make_handler(&mock_server.uri()).await;

    let result = handler
        .handle_broadcast(
            "test-packet-006",
            vec![0x01, 0x02],
            None,                                   // no rpc_url
            Some("admin_importRawKey".to_string()), // custom method
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("rpc_url"),
        "expected 'rpc_url' in error: {err}"
    );
}

#[tokio::test]
async fn test_ethereum_handler_broadcast_default_path_succeeds() {
    let mock_server = mock_price_server().await;
    let handler = make_handler(&mock_server.uri()).await;

    let raw_tx = vec![0x02u8; 256];
    let result = handler
        .handle_broadcast("test-packet-007", raw_tx, None, None)
        .await;

    assert!(result.is_ok(), "broadcast failed in mock mode: {result:?}");
    let resp = result.unwrap();
    assert_eq!(resp.len(), 32);
}

#[tokio::test]
async fn test_ethereum_handler_broadcast_custom_url_loopback_blocked() {
    let price_server = mock_price_server().await;
    let rpc_server = MockServer::start().await; // binds 127.0.0.1:N

    let handler = make_handler(&price_server.uri()).await;
    let raw_tx = vec![0x01u8; 100];

    let result = handler
        .handle_broadcast(
            "test-packet-008",
            raw_tx,
            Some(rpc_server.uri()),
            Some("eth_sendRawTransaction".to_string()),
        )
        .await;

    assert!(result.is_err(), "loopback URL not blocked by SSRF guard");
    let err = result.unwrap_err();
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("blocked") || msg.contains("ssrf"),
        "expected 'blocked' or 'ssrf' in error: {err}"
    );
}

#[tokio::test]
async fn test_ethereum_handler_from_config_invalid_address() {
    let price_server = mock_price_server().await;
    let executor = make_mock_chain_executor().await;
    let tx_mgr = make_tx_manager(executor.clone()).await;
    let metrics = MetricsService::new();
    let price_client =
        Arc::new(PriceClient::new(&price_server.uri(), Default::default()).expect("price client"));

    let result = EthereumHandler::from_config(
        executor,
        tx_mgr,
        metrics,
        10,
        price_client,
        "not_a_valid_address",
        128 * 1024,
        "ethereum",
        18,
        nox_node::config::DEFAULT_GAS_LIMIT_BUFFER_BPS,
        nox_node::config::DEFAULT_INITIAL_FEE_BUFFER_BPS,
        "0x0000000000000000000000000000000000000000",
    );

    match result {
        Err(ServiceError::ProcessingFailed(_)) => {} // expected
        Err(other) => panic!("Expected ProcessingFailed, got Err({other})"),
        Ok(_) => panic!("from_config with invalid address should return Err, got Ok"),
    }
}

#[tokio::test]
async fn paid_quote_is_signed_reserved_and_duplicate_payment_rejected() {
    let price_server = mock_price_server().await;
    let entry_point = Address::from_low_u64_be(11);
    let adapter = Address::from_low_u64_be(12);
    let fee_asset = Address::from_low_u64_be(13);
    let pool = Address::from_low_u64_be(14);
    let mut config = NoxConfig::default();
    config.benchmark_mode = true;
    config.chain_id = 31_337;
    config.eth_wallet_private_key = TEST_PRIVATE_KEY.to_string();
    config.nox_entry_point_address = format!("{entry_point:?}");
    config.nox_reward_pool_address = format!("{pool:?}");
    config.quote_ttl_secs = 30;
    config.quote_network_fee_bps = 500;
    config.quote_maximum_transaction_gas = 2_000_000;
    config.quote_max_outstanding = 4;
    config.quote_max_pending_sponsored_gas = 8_000_000;
    config.quote_rolling_loss_limit_native = "100000000000000000".to_string();
    config.quote_rolling_loss_window_secs = 3_600;
    config.payment_adapters = vec![nox_node::config::PaymentAdapterConfig {
        address: format!("{adapter:?}"),
        fee_assets: vec![format!("{fee_asset:?}")],
        maximum_payment_gas: 600_000,
    }];
    let executor = Arc::new(ChainExecutor::new(&config).await.unwrap());
    let directory = tempdir().unwrap();
    let storage = Arc::new(SledRepository::new(directory.path()).unwrap());
    let manager = Arc::new(
        TransactionManager::new(
            executor.clone(),
            storage.clone(),
            MetricsService::new(),
            nox_node::config::DEFAULT_REPLACEMENT_STEP_BPS,
        )
        .await
        .unwrap(),
    );
    let prices =
        Arc::new(PriceClient::new(&price_server.uri(), Default::default()).expect("price client"));
    let mut handler = EthereumHandler::from_config(
        executor.clone(),
        manager,
        MetricsService::new(),
        10,
        prices,
        &config.nox_reward_pool_address,
        128 * 1024,
        "ethereum",
        18,
        nox_node::config::DEFAULT_GAS_LIMIT_BUFFER_BPS,
        nox_node::config::DEFAULT_INITIAL_FEE_BUFFER_BPS,
        &config.nox_entry_point_address,
    )
    .unwrap()
    .with_quote_policy(&config)
    .unwrap();
    handler.register_token(fee_asset, "USDC", 6, "usd-coin");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let request = PaidQuoteRequestV2 {
        chain_id: config.chain_id,
        entry_point: entry_point.0,
        client_intent_id: [2; 32],
        payment_adapter: adapter.0,
        payment_id: [4; 32],
        fee_asset: fee_asset.0,
        payment_gas_limit: 500_000,
        action_target: Address::from_low_u64_be(15).0,
        action_calldata_hash: [7; 32],
        action_gas_limit: 700_000,
        tracked_assets_hash: [8; 32],
        maximum_transaction_gas: 1_600_000,
        return_data_limit: 256,
        valid_until_unix: now + 60,
    };

    let issued = handler.handle_paid_quote_v2(request.clone()).await;
    let PaidQuoteOutcomeV2::Issued {
        quote,
        execution_id,
        exit_signature,
    } = issued
    else {
        panic!("expected issued quote, got {issued:?}");
    };
    assert_eq!(
        U256::from_big_endian(&quote.maximum_transaction_gas),
        U256::from(1_600_000)
    );
    let exit_fee = U256::from_big_endian(&quote.exit_fee);
    let network_fee = U256::from_big_endian(&quote.network_fee);
    assert_eq!(network_fee, (exit_fee * 500 + 9_999) / 10_000);
    let signature = Signature::try_from(exit_signature.as_slice()).unwrap();
    assert_eq!(
        signature.recover(H256::from(execution_id)).unwrap(),
        executor.address()
    );
    assert_eq!(
        storage
            .load_quote(execution_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        QuoteStatusV2::Outstanding,
    );

    let duplicate = handler.handle_paid_quote_v2(request).await;
    assert!(matches!(
        duplicate,
        PaidQuoteOutcomeV2::Rejected {
            code: nox_core::PaidTransactionRejectionCodeV2::DuplicateExecution,
            ..
        }
    ));

    let mut expired = storage.load_quote(execution_id).await.unwrap().unwrap();
    expired.execution_id = [9; 32];
    expired.request.payment_id = [9; 32];
    expired.request.valid_until_unix = now;
    expired.quote.payment_id = [9; 32];
    expired.quote.valid_until_unix = now;
    storage
        .create_quote_durably(&expired, 2, 3_200_000, U256::from(1), 3_600, now - 1)
        .await
        .unwrap();
    let expired_outcome = handler
        .handle_paid_transaction_v2(PaidTransactionRequestV2 {
            chain_id: config.chain_id,
            entry_point: entry_point.0,
            calldata: vec![1],
            execution_id: expired.execution_id,
            valid_until_unix: now,
        })
        .await;
    assert!(matches!(
        expired_outcome,
        PaidTransactionOutcomeV2::Rejected {
            code: nox_core::PaidTransactionRejectionCodeV2::ExpiredQuote,
            ..
        }
    ));
    assert_eq!(
        storage
            .load_quote(expired.execution_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        QuoteStatusV2::Expired,
    );

    storage.take_quote_durably(execution_id, now).await.unwrap();
    let duplicate_submission = handler
        .handle_paid_transaction_v2(PaidTransactionRequestV2 {
            chain_id: config.chain_id,
            entry_point: entry_point.0,
            calldata: vec![1],
            execution_id,
            valid_until_unix: quote.valid_until_unix,
        })
        .await;
    assert!(matches!(
        duplicate_submission,
        PaidTransactionOutcomeV2::Rejected {
            code: nox_core::PaidTransactionRejectionCodeV2::DuplicateExecution,
            ..
        }
    ));
}
