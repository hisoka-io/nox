//! Economics E2E: profitability calculator + master economics tests.

use ethers::prelude::*;
use ethers::types::{Address, H256, U256};
use ethers::utils::Anvil;
use nox_core::{IEventPublisher, IEventSubscriber, NoxEvent, RelayerPayload, ServiceHandler};
use nox_node::blockchain::executor::ChainExecutor;
use nox_node::blockchain::tx_manager::TransactionManager;
use nox_node::price::client::{PriceClient, PriceClientError, PriceSource};
use nox_node::services::exit::ExitService;
use nox_node::services::handlers::ethereum::EthereumHandler;
use nox_node::services::profitability::ProfitabilityCalculator;
use nox_node::telemetry::metrics::MetricsService;
use nox_node::{NoxConfig, SledRepository, TokioEventBus};

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tracing::{info, Level};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Create a RewardsDeposited log from the correct pool address.
fn create_rewards_log(pool_address: Address, asset: Address, amount: U256) -> ethers::types::Log {
    let topic0 = H256::from(ethers::utils::keccak256(
        "RewardsDeposited(address,address,uint256)",
    ));

    let mut topic1_bytes = [0u8; 32];
    topic1_bytes[12..].copy_from_slice(asset.as_bytes());
    let topic1 = H256::from(topic1_bytes);

    let topic2 = H256::zero();

    let mut data = vec![0u8; 32];
    amount.to_big_endian(&mut data);

    ethers::types::Log {
        address: pool_address,
        topics: vec![topic0, topic1, topic2],
        data: ethers::types::Bytes::from(data),
        ..Default::default()
    }
}

async fn mock_price_server(body: &str) -> MockServer {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/prices"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::from_str::<serde_json::Value>(body).unwrap()),
        )
        .mount(&mock_server)
        .await;
    mock_server
}

#[tokio::test]
async fn test_economics_integration_unprofitable() {
    let mock_server =
        mock_price_server(r#"{ "ethereum": { "price": 2000.0 }, "usd-coin": { "price": 1.0 } }"#)
            .await;

    let price_client = Arc::new(PriceClient::new(&mock_server.uri()));
    let pool_address = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
    let calc = ProfitabilityCalculator::new(10, price_client, pool_address);

    let weth_address = Address::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();

    // Cost: $10.00, Revenue: $5.00
    let amount = U256::from(2_500_000_000_000_000u64);
    let log = create_rewards_log(pool_address, weth_address, amount);

    let profitable = calc
        .is_profitable(100_000, U256::from(50_000_000_000u64), &[log])
        .await;

    assert!(!profitable, "Should be unprofitable ($5 rev < $10 cost)");
}

#[tokio::test]
async fn test_economics_integration_profitable() {
    let mock_server =
        mock_price_server(r#"{ "ethereum": { "price": 2000.0 }, "usd-coin": { "price": 1.0 } }"#)
            .await;

    let price_client = Arc::new(PriceClient::new(&mock_server.uri()));
    let pool_address = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
    let calc = ProfitabilityCalculator::new(10, price_client, pool_address);

    let weth_address = Address::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();

    // Cost: $10.00, Revenue: $12.00
    let amount = U256::from(6_000_000_000_000_000u64);
    let log = create_rewards_log(pool_address, weth_address, amount);

    let profitable = calc
        .is_profitable(100_000, U256::from(50_000_000_000u64), &[log])
        .await;

    assert!(profitable, "Should be profitable ($12 rev > $10 cost)");
}

#[tokio::test]
async fn test_rejects_event_from_wrong_pool() {
    let mock_server =
        mock_price_server(r#"{ "ethereum": { "price": 2000.0 }, "usd-coin": { "price": 1.0 } }"#)
            .await;

    let price_client = Arc::new(PriceClient::new(&mock_server.uri()));
    let real_pool = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
    let fake_pool = Address::from_str("0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF").unwrap();

    let calc = ProfitabilityCalculator::new(0, price_client, real_pool);

    let weth_address = Address::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
    let amount = U256::from(1_000_000_000_000_000_000u64);
    let fake_log = create_rewards_log(fake_pool, weth_address, amount);

    let profitable = calc
        .is_profitable(100_000, U256::from(50_000_000_000u64), &[fake_log])
        .await;

    assert!(
        !profitable,
        "Should reject RewardsDeposited from wrong pool address"
    );
}

#[tokio::test]
async fn test_usdc_6_decimal_handling() {
    let mock_server =
        mock_price_server(r#"{ "ethereum": { "price": 3000.0 }, "usd-coin": { "price": 1.0 } }"#)
            .await;

    let price_client = Arc::new(PriceClient::new(&mock_server.uri()));
    let pool_address = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
    let calc = ProfitabilityCalculator::new(0, price_client, pool_address);

    let usdc_address = Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();

    let amount = U256::from(100_000_000u64); // 100 USDC (6 decimals)
    let log = create_rewards_log(pool_address, usdc_address, amount);

    let result = calc
        .analyze(50_000, U256::from(20_000_000_000u64), &[log])
        .await;

    assert!(
        result.revenue_usd > 90.0 && result.revenue_usd < 110.0,
        "USDC revenue should be ~$100, got ${:.6}",
        result.revenue_usd
    );
    assert!(result.is_profitable);
}

abigen!(
    MockERC20,
    r#"[
        function mint(address to, uint256 amount) external
        function approve(address spender, uint256 amount) external returns (bool)
        function balanceOf(address account) external view returns (uint256)
        function transfer(address to, uint256 amount) external returns (bool)
        function decimals() external view returns (uint8)
    ]"#
);

abigen!(
    RelayerMulticallContract,
    r#"[
        struct RelayerCall { address target; bytes data; uint256 value; bool requireSuccess; }
        function multicall(RelayerCall[] calldata calls) external payable
        event CallExecuted(uint256 indexed index, bool success, bytes returnData)
        event CallFailed(uint256 indexed index, bytes returnData)
    ]"#
);

abigen!(
    NoxRewardPoolContract,
    r#"[
        function depositRewards(address asset, uint256 amount) external
        function setAssetStatus(address asset, bool status) external
        function totalCollected(address asset) external view returns (uint256)
        event RewardsDeposited(address indexed asset, address indexed from, uint256 amount)
    ]"#
);

struct RealWorldPriceClient {
    eth_price: f64,
    usdc_price: f64,
}

#[async_trait::async_trait]
impl PriceSource for RealWorldPriceClient {
    async fn get_price(&self, asset: &str) -> Result<f64, PriceClientError> {
        match asset {
            "ethereum" => Ok(self.eth_price),
            "usd-coin" => Ok(self.usdc_price),
            _ => Err(PriceClientError::AssetNotFound),
        }
    }
}

struct TestInfrastructure {
    anvil: ethers::utils::AnvilInstance,
    client: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
    weth_address: Address,
    usdc_address: Address,
    reward_pool_address: Address,
    relayer_multicall_address: Address,
    relayer_wallet: LocalWallet,
    alice_wallet: LocalWallet,
    pool_abi: ethers::abi::Abi,
    weth_abi: ethers::abi::Abi,
}

async fn setup_infrastructure() -> anyhow::Result<TestInfrastructure> {
    let anvil = Anvil::new().spawn();
    let rpc_url = anvil.endpoint();

    let deployer_wallet: LocalWallet = anvil.keys()[0].clone().into();
    let relayer_wallet: LocalWallet = anvil.keys()[1].clone().into();
    let alice_wallet: LocalWallet = anvil.keys()[2].clone().into();

    let provider = Provider::<Http>::try_from(rpc_url.clone())?;
    let client = Arc::new(SignerMiddleware::new(
        provider.clone(),
        deployer_wallet.clone().with_chain_id(31337u64),
    ));

    let root = env!("CARGO_MANIFEST_DIR");
    let abi_path = format!("{}/abi", root);

    let weth_artifact = std::fs::read_to_string(format!("{}/MockERC20.json", abi_path))?;
    let weth_json: serde_json::Value = serde_json::from_str(&weth_artifact)?;
    let weth_bytecode = weth_json["bytecode"].as_str().unwrap();
    let weth_bytes =
        Bytes::from(hex::decode(weth_bytecode.trim().trim_start_matches("0x")).unwrap());
    let weth_abi: ethers::abi::Abi = serde_json::from_value(weth_json["abi"].clone())?;

    let weth_factory = ContractFactory::new(weth_abi.clone(), weth_bytes.clone(), client.clone());
    let weth = weth_factory
        .deploy(("Wrapped Ether".to_string(), "WETH".to_string(), 18u8))
        .unwrap()
        .send()
        .await
        .unwrap();

    let usdc_factory = ContractFactory::new(weth_abi.clone(), weth_bytes, client.clone());
    let usdc = usdc_factory
        .deploy(("USD Coin".to_string(), "USDC".to_string(), 6u8))
        .unwrap()
        .send()
        .await
        .unwrap();

    let pool_artifact = std::fs::read_to_string(format!("{}/NoxRewardPool.json", abi_path))?;
    let pool_json: serde_json::Value = serde_json::from_str(&pool_artifact)?;
    let pool_bytecode = pool_json["bytecode"].as_str().unwrap();
    let pool_bytes =
        Bytes::from(hex::decode(pool_bytecode.trim().trim_start_matches("0x")).unwrap());
    let pool_abi: ethers::abi::Abi = serde_json::from_value(pool_json["abi"].clone())?;

    let pool_factory = ContractFactory::new(pool_abi.clone(), pool_bytes, client.clone());
    let reward_pool = pool_factory
        .deploy(deployer_wallet.address())
        .unwrap()
        .send()
        .await
        .unwrap();

    let pool_contract = Contract::new(reward_pool.address(), pool_abi.clone(), client.clone());
    pool_contract
        .method::<_, ()>("setAssetStatus", (weth.address(), true))
        .unwrap()
        .send()
        .await
        .unwrap();
    pool_contract
        .method::<_, ()>("setAssetStatus", (usdc.address(), true))
        .unwrap()
        .send()
        .await
        .unwrap();

    let rm_artifact = std::fs::read_to_string(format!("{}/RelayerMulticall.json", abi_path))?;
    let rm_json: serde_json::Value = serde_json::from_str(&rm_artifact)?;
    let rm_bytecode = rm_json["bytecode"].as_str().unwrap();
    let rm_bytes = Bytes::from(hex::decode(rm_bytecode.trim().trim_start_matches("0x")).unwrap());
    let rm_abi: ethers::abi::Abi = serde_json::from_value(rm_json["abi"].clone())?;

    let rm_factory = ContractFactory::new(rm_abi, rm_bytes, client.clone());
    let relayer_multicall = rm_factory.deploy(()).unwrap().send().await.unwrap();

    Ok(TestInfrastructure {
        anvil,
        client,
        weth_address: weth.address(),
        usdc_address: usdc.address(),
        reward_pool_address: reward_pool.address(),
        relayer_multicall_address: relayer_multicall.address(),
        relayer_wallet,
        alice_wallet,
        pool_abi,
        weth_abi,
    })
}

#[allow(clippy::too_many_arguments)]
fn create_payment_bundle(
    client: &Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
    token_address: Address,
    token_abi: &ethers::abi::Abi,
    pool_address: Address,
    pool_abi: &ethers::abi::Abi,
    multicall_address: Address,
    amount: U256,
    from: Address,
) -> Bytes {
    let token_contract = Contract::new(token_address, token_abi.clone(), client.clone());
    let pool_contract = Contract::new(pool_address, pool_abi.clone(), client.clone());

    let pull_calldata = token_contract
        .encode("transferFrom", (from, multicall_address, amount))
        .unwrap();
    let approve_calldata = token_contract
        .encode("approve", (pool_address, amount))
        .unwrap();
    let deposit_calldata = pool_contract
        .encode("depositRewards", (token_address, amount))
        .unwrap();

    let calls = vec![
        RelayerCall {
            target: token_address,
            data: pull_calldata,
            value: U256::zero(),
            require_success: true,
        },
        RelayerCall {
            target: token_address,
            data: approve_calldata,
            value: U256::zero(),
            require_success: true,
        },
        RelayerCall {
            target: pool_address,
            data: deposit_calldata,
            value: U256::zero(),
            require_success: true,
        },
    ];

    let rm_contract = RelayerMulticallContract::new(multicall_address, client.clone());
    rm_contract.multicall(calls).calldata().unwrap()
}

#[tokio::test]
#[ignore = "slow integration test (~30s) - run with `cargo test -- --ignored`"]
async fn test_master_darkpool_economics() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_test_writer()
        .try_init();

    info!("MASTER DARKPOOL ECONOMICS TEST");

    let infra = setup_infrastructure().await?;

    let config = {
        let mut c = NoxConfig::default();
        c.eth_rpc_url = infra.anvil.endpoint();
        c.eth_wallet_private_key = hex::encode(infra.relayer_wallet.signer().to_bytes());
        c.min_gas_balance = "0".to_string();
        c.min_profit_margin_percent = 10;
        c.nox_reward_pool_address = format!("{:?}", infra.reward_pool_address);
        c
    };

    let chain_executor = Arc::new(ChainExecutor::new(&config).await?);
    let temp_dir = tempdir()?;
    let sled_repo = Arc::new(SledRepository::new(temp_dir.path())?);
    let metrics = MetricsService::new();
    let tx_manager = Arc::new(
        TransactionManager::new(chain_executor.clone(), sled_repo, metrics.clone()).await?,
    );

    let price_client: Arc<dyn PriceSource> = Arc::new(RealWorldPriceClient {
        eth_price: 3093.01,
        usdc_price: 1.0,
    });

    let mut handler = EthereumHandler::new(
        chain_executor.clone(),
        tx_manager.clone(),
        metrics,
        10,
        price_client,
        infra.reward_pool_address,
        128 * 1024,
    );
    handler.register_token(infra.weth_address, "WETH", 18, "ethereum");
    handler.register_token(infra.usdc_address, "USDC", 6, "usd-coin");

    let alice_client = Arc::new(SignerMiddleware::new(
        Provider::<Http>::try_from(infra.anvil.endpoint())?,
        infra.alice_wallet.clone().with_chain_id(31337u64),
    ));

    let weth_contract = MockERC20::new(infra.weth_address, alice_client.clone());
    let weth_amount = U256::from(100) * U256::exp10(18);
    weth_contract
        .mint(infra.alice_wallet.address(), weth_amount)
        .send()
        .await?;
    weth_contract
        .approve(infra.relayer_multicall_address, weth_amount)
        .send()
        .await?;

    let usdc_contract = MockERC20::new(infra.usdc_address, alice_client.clone());
    let usdc_amount = U256::from(10_000) * U256::exp10(6);
    usdc_contract
        .mint(infra.alice_wallet.address(), usdc_amount)
        .send()
        .await?;
    usdc_contract
        .approve(infra.relayer_multicall_address, usdc_amount)
        .send()
        .await?;

    let payment_weth = U256::from(1) * U256::exp10(18);
    let calldata_a = create_payment_bundle(
        &infra.client,
        infra.weth_address,
        &infra.weth_abi,
        infra.reward_pool_address,
        &infra.pool_abi,
        infra.relayer_multicall_address,
        payment_weth,
        infra.alice_wallet.address(),
    );
    let payload_a = RelayerPayload::SubmitTransaction {
        to: infra.relayer_multicall_address.0,
        data: calldata_a.to_vec(),
    };
    assert!(handler.handle("scenario_a", &payload_a).await.is_ok());
    tokio::time::sleep(Duration::from_secs(2)).await;

    let pool_contract = Contract::new(
        infra.reward_pool_address,
        infra.pool_abi.clone(),
        infra.client.clone(),
    );
    let collected_weth: U256 = pool_contract
        .method("totalCollected", infra.weth_address)
        .unwrap()
        .call()
        .await?;
    assert_eq!(collected_weth, payment_weth);

    let payment_usdc = U256::from(1000) * U256::exp10(6);
    let calldata_b = create_payment_bundle(
        &infra.client,
        infra.usdc_address,
        &infra.weth_abi,
        infra.reward_pool_address,
        &infra.pool_abi,
        infra.relayer_multicall_address,
        payment_usdc,
        infra.alice_wallet.address(),
    );
    let payload_b = RelayerPayload::SubmitTransaction {
        to: infra.relayer_multicall_address.0,
        data: calldata_b.to_vec(),
    };
    assert!(handler.handle("scenario_b", &payload_b).await.is_ok());
    tokio::time::sleep(Duration::from_secs(2)).await;

    let collected_usdc: U256 = pool_contract
        .method("totalCollected", infra.usdc_address)
        .unwrap()
        .call()
        .await?;
    assert_eq!(collected_usdc, payment_usdc);

    let dust_usdc = U256::from(1u64);
    let calldata_c = create_payment_bundle(
        &infra.client,
        infra.usdc_address,
        &infra.weth_abi,
        infra.reward_pool_address,
        &infra.pool_abi,
        infra.relayer_multicall_address,
        dust_usdc,
        infra.alice_wallet.address(),
    );
    let payload_c = RelayerPayload::SubmitTransaction {
        to: infra.relayer_multicall_address.0,
        data: calldata_c.to_vec(),
    };

    let nonce_before = chain_executor.get_nonce().await?;
    let _result_c = handler.handle("scenario_c", &payload_c).await;
    let nonce_after = chain_executor.get_nonce().await?;

    #[cfg(not(feature = "dev-node"))]
    assert_eq!(
        nonce_before, nonce_after,
        "Dust payment should be rejected as unprofitable"
    );
    #[cfg(feature = "dev-node")]
    assert_eq!(
        nonce_before + 1,
        nonce_after,
        "Dev-node bypasses profitability -- dust TX should be submitted"
    );

    let collected_after: U256 = pool_contract
        .method("totalCollected", infra.usdc_address)
        .unwrap()
        .call()
        .await?;
    #[cfg(not(feature = "dev-node"))]
    assert_eq!(collected_after, payment_usdc);
    #[cfg(feature = "dev-node")]
    assert_eq!(collected_after, payment_usdc + dust_usdc);

    let garbage_payload = RelayerPayload::SubmitTransaction {
        to: infra.relayer_multicall_address.0,
        data: vec![0xde, 0xad, 0xbe, 0xef],
    };
    let nonce_d_before = chain_executor.get_nonce().await?;
    let result_d = handler.handle("scenario_d", &garbage_payload).await;
    let nonce_d_after = chain_executor.get_nonce().await?;
    assert!(result_d.is_ok());
    assert_eq!(nonce_d_before, nonce_d_after);

    info!("ALL SCENARIOS PASSED");
    Ok(())
}

#[tokio::test]
#[ignore = "slow integration test (~30s) - run with `cargo test -- --ignored`"]
async fn test_5_node_cluster_economics() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_test_writer()
        .try_init();

    let infra = setup_infrastructure().await?;

    let mut buses: Vec<(Arc<dyn IEventPublisher>, Arc<dyn IEventSubscriber>)> = Vec::new();
    let mut handlers: Vec<Arc<EthereumHandler>> = Vec::new();

    for i in 0..5 {
        let bus = TokioEventBus::new(100);
        let pub_bus: Arc<dyn IEventPublisher> = Arc::new(bus.clone());
        let sub_bus: Arc<dyn IEventSubscriber> = Arc::new(bus.clone());

        let node_wallet: LocalWallet = infra.anvil.keys()[i + 3].clone().into();
        let config = {
            let mut c = NoxConfig::default();
            c.eth_rpc_url = infra.anvil.endpoint();
            c.eth_wallet_private_key = hex::encode(node_wallet.signer().to_bytes());
            c.min_gas_balance = "0".to_string();
            c.min_profit_margin_percent = 10;
            c.nox_reward_pool_address = format!("{:?}", infra.reward_pool_address);
            c
        };

        let executor = Arc::new(ChainExecutor::new(&config).await?);
        let temp_dir = tempdir()?;
        let db = Arc::new(SledRepository::new(temp_dir.path())?);
        let metrics = MetricsService::new();
        let tx_manager =
            Arc::new(TransactionManager::new(executor.clone(), db, metrics.clone()).await?);

        let price_client: Arc<dyn PriceSource> = Arc::new(RealWorldPriceClient {
            eth_price: 3000.0,
            usdc_price: 1.0,
        });

        let mut handler = EthereumHandler::new(
            executor,
            tx_manager,
            metrics.clone(),
            10,
            price_client,
            infra.reward_pool_address,
            128 * 1024,
        );
        handler.register_token(infra.weth_address, "WETH", 18, "ethereum");
        handler.register_token(infra.usdc_address, "USDC", 6, "usd-coin");

        let handler = Arc::new(handler);

        let traffic_handler = Arc::new(nox_node::services::handlers::traffic::TrafficHandler {
            metrics: metrics.clone(),
        });
        let exit = ExitService::new(sub_bus.clone(), handler.clone(), traffic_handler, metrics);
        tokio::spawn(async move { exit.run().await });

        buses.push((pub_bus, sub_bus));
        handlers.push(handler);
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    let alice_client = Arc::new(SignerMiddleware::new(
        Provider::<Http>::try_from(infra.anvil.endpoint())?,
        infra.alice_wallet.clone().with_chain_id(31337u64),
    ));

    let weth_contract = MockERC20::new(infra.weth_address, alice_client.clone());
    let weth_amount = U256::from(100) * U256::exp10(18);
    weth_contract
        .mint(infra.alice_wallet.address(), weth_amount)
        .send()
        .await?;
    weth_contract
        .approve(infra.relayer_multicall_address, weth_amount)
        .send()
        .await?;

    let payment = U256::from(1) * U256::exp10(18);
    let calldata = create_payment_bundle(
        &infra.client,
        infra.weth_address,
        &infra.weth_abi,
        infra.reward_pool_address,
        &infra.pool_abi,
        infra.relayer_multicall_address,
        payment,
        infra.alice_wallet.address(),
    );

    let payload = RelayerPayload::SubmitTransaction {
        to: infra.relayer_multicall_address.0,
        data: calldata.to_vec(),
    };

    let (pub_bus, _) = &buses[0];
    let encoded_payload = nox_core::models::payloads::encode_payload(&payload)
        .map_err(|e| anyhow::anyhow!("encode_payload failed: {e}"))?;
    pub_bus.publish(NoxEvent::PayloadDecrypted {
        packet_id: "cluster_test".to_string(),
        payload: encoded_payload,
    })?;

    let pool_contract = Contract::new(
        infra.reward_pool_address,
        infra.pool_abi.clone(),
        infra.client.clone(),
    );

    let mut collected = U256::zero();
    for attempt in 0..30 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        collected = pool_contract
            .method("totalCollected", infra.weth_address)
            .unwrap()
            .call()
            .await?;
        if collected >= payment {
            info!("Payment detected on attempt {attempt} (collected={collected})");
            break;
        }
    }

    assert!(
        collected >= payment,
        "Payment should be collected by cluster node (collected={collected}, expected>={payment})"
    );

    Ok(())
}
