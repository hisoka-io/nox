//! ChainExecutor tests in mock/benchmark mode (requires `dev-node` feature).

#![cfg(feature = "dev-node")]

use ethers::prelude::*;
use nox_node::blockchain::executor::ChainExecutor;
use nox_node::NoxConfig;

async fn make_mock_executor() -> ChainExecutor {
    let mut config = NoxConfig::default();
    config.benchmark_mode = true;
    config.chain_id = 31337;
    config.eth_wallet_private_key =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string();

    ChainExecutor::new(&config)
        .await
        .expect("ChainExecutor::new should succeed in mock mode")
}

#[tokio::test]
async fn test_chain_executor_constructs_in_mock_mode() {
    let _executor = make_mock_executor().await;
}

#[tokio::test]
async fn test_chain_executor_address_is_deterministic() {
    let executor = make_mock_executor().await;
    let addr1 = executor.address();
    let addr2 = executor.address();
    assert_eq!(addr1, addr2);
    let expected: Address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        .parse()
        .expect("valid address literal");
    assert_eq!(addr1, expected);
}

#[tokio::test]
async fn test_chain_executor_check_gas_health_mock_ok() {
    let executor = make_mock_executor().await;
    let result = executor.check_gas_health().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_chain_executor_get_gas_price_mock() {
    let executor = make_mock_executor().await;
    let gas_price = executor
        .get_gas_price()
        .await
        .expect("get_gas_price should succeed in mock mode");
    assert_eq!(gas_price, U256::from(10_000_000_000u64));
}

#[tokio::test]
async fn test_chain_executor_get_nonce_mock() {
    let executor = make_mock_executor().await;
    let nonce = executor
        .get_nonce()
        .await
        .expect("get_nonce should succeed in mock mode");
    assert_eq!(nonce, U256::zero());
}

#[tokio::test]
async fn test_chain_executor_simulate_transaction_mock() {
    let executor = make_mock_executor().await;
    let to: Address = "0x1234567890123456789012345678901234567890"
        .parse()
        .expect("valid address");
    let gas = executor
        .simulate_transaction(to, Bytes::from(vec![0xde, 0xad]))
        .await
        .expect("simulate_transaction should succeed in mock mode");
    assert_eq!(gas, 100_000);
}

#[tokio::test]
async fn test_chain_executor_simulate_with_logs_mock() {
    let executor = make_mock_executor().await;
    let to: Address = "0x1234567890123456789012345678901234567890"
        .parse()
        .expect("valid address");
    let (gas, logs) = executor
        .simulate_transaction_with_logs(to, Bytes::from(vec![0xbe, 0xef]))
        .await
        .expect("simulate_transaction_with_logs should succeed in mock mode");
    assert_eq!(gas, 100_000);
    assert!(logs.is_empty());
}

#[tokio::test]
async fn test_chain_executor_estimate_gas_mock() {
    let executor = make_mock_executor().await;
    let to: Address = "0x1234567890123456789012345678901234567890"
        .parse()
        .expect("valid address");
    let gas = executor
        .estimate_gas(to, Bytes::from(vec![0x01]))
        .await
        .expect("estimate_gas should succeed in mock mode");
    assert_eq!(gas, 100_000);
}

#[tokio::test]
async fn test_chain_executor_submit_transaction_mock() {
    let executor = make_mock_executor().await;
    let to: Address = "0x1234567890123456789012345678901234567890"
        .parse()
        .expect("valid address");
    let hash = executor
        .submit_transaction(to, Bytes::from(vec![0x42]), U256::from(200_000u64))
        .await
        .expect("submit_transaction should succeed in mock mode");
    assert_ne!(hash, H256::zero());
}

#[tokio::test]
async fn test_chain_executor_submit_returns_different_hashes() {
    let executor = make_mock_executor().await;
    let to: Address = "0x1234567890123456789012345678901234567890"
        .parse()
        .expect("valid address");
    let h1 = executor
        .submit_transaction(to, Bytes::from(vec![0x01]), U256::from(100_000u64))
        .await
        .expect("first submit");
    let h2 = executor
        .submit_transaction(to, Bytes::from(vec![0x02]), U256::from(100_000u64))
        .await
        .expect("second submit");
    assert_ne!(h1, h2);
}

#[tokio::test]
async fn test_chain_executor_send_raw_mock() {
    let executor = make_mock_executor().await;
    let tx = TransactionRequest::new()
        .to("0x1234567890123456789012345678901234567890"
            .parse::<Address>()
            .expect("valid address"))
        .data(vec![0xff]);
    let hash = executor
        .send_raw(tx)
        .await
        .expect("send_raw should succeed in mock mode");
    assert_ne!(hash, H256::zero());
}

#[tokio::test]
async fn test_chain_executor_broadcast_raw_signed_tx_mock() {
    let executor = make_mock_executor().await;
    let fake_raw_tx = vec![0x02, 0x01, 0x00];
    let hash = executor
        .broadcast_raw_signed_tx(&fake_raw_tx)
        .await
        .expect("broadcast_raw_signed_tx should succeed in mock mode");
    assert_ne!(hash, H256::zero());
}

#[tokio::test]
async fn test_chain_executor_get_receipt_mock() {
    let executor = make_mock_executor().await;
    let _ = executor.get_transaction_receipt(H256::zero()).await;
}
