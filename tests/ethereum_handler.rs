//! EthereumHandler tests in mock mode (requires `dev-node` feature).

#![cfg(feature = "dev-node")]

use ethers::prelude::*;
use nox_core::models::payloads::RelayerPayload;
use nox_core::traits::service::{ServiceError, ServiceHandler};
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
        TransactionManager::new(executor, storage, metrics)
            .await
            .expect("TransactionManager::new in mock mode"),
    )
}

async fn make_handler(price_server_uri: &str) -> EthereumHandler {
    let executor = make_mock_chain_executor().await;
    let tx_mgr = make_tx_manager(executor.clone()).await;
    let metrics = MetricsService::new();
    let price_client = Arc::new(PriceClient::new(price_server_uri));
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
    Mock::given(method("GET"))
        .and(path("/prices"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({ "ethereum": { "price": 3000.0 }, "usd-coin": { "price": 1.0 } }),
        ))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn test_ethereum_handler_paid_tx_success() {
    let mock_server = mock_price_server().await;
    let handler = make_handler(&mock_server.uri()).await;

    let to: Address = "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"
        .parse()
        .expect("valid address");
    let data = Bytes::from(vec![0xca, 0xfe]);

    let result = handler
        .handle_paid_transaction("test-packet-001", to, data)
        .await;

    assert!(
        result.is_ok(),
        "paid tx failed in mock+dev-node: {result:?}"
    );
    let tx_hash = result.unwrap();
    assert_ne!(tx_hash, H256::zero());
}

#[tokio::test]
async fn test_ethereum_handler_service_handler_submit_tx_payload() {
    let mock_server = mock_price_server().await;
    let handler = make_handler(&mock_server.uri()).await;

    let to = [0u8; 20]; // zero address -- mock doesn't care about destination
    let payload = RelayerPayload::SubmitTransaction {
        to,
        data: vec![0x01, 0x02, 0x03],
    };

    let result = handler.handle("test-packet-002", &payload).await;
    assert!(result.is_ok(), "SubmitTransaction returned Err: {result:?}");
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
    let price_client = Arc::new(PriceClient::new(&price_server.uri()));

    let result = EthereumHandler::from_config(
        executor,
        tx_mgr,
        metrics,
        10,
        price_client,
        "not_a_valid_address",
        128 * 1024,
    );

    match result {
        Err(ServiceError::ProcessingFailed(_)) => {} // expected
        Err(other) => panic!("Expected ProcessingFailed, got Err({other})"),
        Ok(_) => panic!("from_config with invalid address should return Err, got Ok"),
    }
}
