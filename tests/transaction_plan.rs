use async_trait::async_trait;
use ethers::types::{Address, Bytes, Log, H256, U256};
use ethers::utils::keccak256;
use ethers::utils::Anvil;
use nox_node::blockchain::executor::ChainExecutor;
use nox_node::blockchain::transaction_plan::{buffered, CostCandidate};
use nox_node::price::client::{FixedPriceSource, PriceClientError, PriceQuote};
use nox_node::services::profitability::{ProfitabilityCalculator, ProfitabilityError};
use nox_node::NoxConfig;
use std::sync::Arc;
use std::sync::Mutex;

struct FixedPrices;
struct InvalidNativePrice;
struct RecordingPrices(Mutex<Vec<String>>);

#[async_trait]
impl FixedPriceSource for FixedPrices {
    async fn get_price(&self, asset_id: &str) -> Result<PriceQuote, PriceClientError> {
        let price_e8 = match asset_id {
            "ethereum" => 100_000_000,
            "usd-coin" => 100_000_000,
            _ => {
                return Err(PriceClientError::AssetNotFound {
                    asset_id: asset_id.to_string(),
                })
            }
        };
        Ok(PriceQuote {
            price_e8,
            observed_at_unix: 1,
            asset_id: asset_id.to_string(),
        })
    }
}

#[async_trait]
impl FixedPriceSource for InvalidNativePrice {
    async fn get_price(&self, asset_id: &str) -> Result<PriceQuote, PriceClientError> {
        if asset_id == "ethereum" {
            return Ok(PriceQuote {
                price_e8: 0,
                observed_at_unix: 1,
                asset_id: asset_id.to_string(),
            });
        }
        Ok(PriceQuote {
            price_e8: 100_000_000,
            observed_at_unix: 1,
            asset_id: asset_id.to_string(),
        })
    }
}

#[async_trait]
impl FixedPriceSource for RecordingPrices {
    async fn get_price(&self, asset_id: &str) -> Result<PriceQuote, PriceClientError> {
        self.0.lock().unwrap().push(asset_id.to_string());
        Ok(PriceQuote {
            price_e8: 100_000_000,
            observed_at_unix: 1,
            asset_id: asset_id.to_string(),
        })
    }
}

fn payment_log(pool: Address, amount: U256) -> Log {
    let asset: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        .parse()
        .unwrap();
    let mut topic = [0_u8; 32];
    topic[12..].copy_from_slice(asset.as_bytes());
    let mut encoded_amount = [0_u8; 32];
    amount.to_big_endian(&mut encoded_amount);
    Log {
        address: pool,
        topics: vec![
            H256::from(keccak256(b"RewardsDeposited(address,address,uint256)")),
            H256::from(topic),
            H256::zero(),
        ],
        data: Bytes::from(encoded_amount.to_vec()),
        ..Default::default()
    }
}

#[test]
fn basis_point_buffers_round_up_once() {
    assert_eq!(
        buffered(U256::from(101), 2_000, "gas_limit").unwrap(),
        U256::from(122)
    );
    assert!(buffered(U256::zero(), 2_000, "gas_limit").is_err());
}

#[tokio::test]
async fn exact_margin_boundary_accepts_and_one_unit_below_rejects() {
    let pool = Address::from_low_u64_be(7);
    let calculator = ProfitabilityCalculator::new(0, Arc::new(FixedPrices), pool);
    let candidate = CostCandidate {
        gas_limit: U256::from(1),
        initial_fee_per_gas: U256::from(1_000_000_000_000_000_000_u128),
        chain_data_fee_native: U256::zero(),
    };
    let accepted = calculator
        .authorize(
            candidate.clone(),
            &[payment_log(pool, U256::from(1_000_001_u64))],
        )
        .await
        .unwrap();
    assert_eq!(
        accepted.planned_initial_cost_value_e8,
        U256::from(100_000_001_u64)
    );

    let rejected = calculator
        .authorize(candidate, &[payment_log(pool, U256::from(1_000_000_u64))])
        .await;
    assert!(matches!(
        rejected,
        Err(ProfitabilityError::Unprofitable { .. })
    ));
}

#[tokio::test]
async fn unknown_payment_token_never_receives_a_zero_price() {
    let pool = Address::from_low_u64_be(7);
    let calculator = ProfitabilityCalculator::new(0, Arc::new(FixedPrices), pool);
    let mut log = payment_log(pool, U256::from(10_000_000_u64));
    log.topics[1] = H256::from_low_u64_be(999);
    let rejected = calculator
        .authorize(
            CostCandidate {
                gas_limit: U256::one(),
                initial_fee_per_gas: U256::one(),
                chain_data_fee_native: U256::zero(),
            },
            &[log],
        )
        .await;
    assert_eq!(rejected, Err(ProfitabilityError::PaymentMissing));
}

#[tokio::test]
async fn zero_native_price_is_unavailable() {
    let pool = Address::from_low_u64_be(7);
    let calculator = ProfitabilityCalculator::new(0, Arc::new(InvalidNativePrice), pool);
    let rejected = calculator
        .authorize(
            CostCandidate {
                gas_limit: U256::one(),
                initial_fee_per_gas: U256::one(),
                chain_data_fee_native: U256::zero(),
            },
            &[payment_log(pool, U256::from(1_000_000_u64))],
        )
        .await;
    assert!(matches!(
        rejected,
        Err(ProfitabilityError::PriceUnavailable { .. })
    ));
}

#[tokio::test]
async fn initial_twenty_percent_bid_defeats_apparent_ten_percent_margin() {
    let pool = Address::from_low_u64_be(7);
    let calculator = ProfitabilityCalculator::new(10, Arc::new(FixedPrices), pool);
    let rejected = calculator
        .authorize(
            CostCandidate {
                gas_limit: U256::one(),
                initial_fee_per_gas: U256::from(1_200_000_000_000_000_000_u128),
                chain_data_fee_native: U256::zero(),
            },
            &[payment_log(pool, U256::from(1_100_000_u64))],
        )
        .await;
    assert!(matches!(
        rejected,
        Err(ProfitabilityError::Unprofitable { .. })
    ));
}

#[tokio::test]
async fn signed_quote_cap_clamps_affordable_replacement_and_maximum_cost() {
    let pool = Address::from_low_u64_be(7);
    let calculator = ProfitabilityCalculator::new(0, Arc::new(FixedPrices), pool);
    let fee_asset: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        .parse()
        .unwrap();
    let cap = U256::from(2_000_000_000_u64);
    let authorization = calculator
        .authorize_fee_with_maximum_fee_per_gas(
            CostCandidate {
                gas_limit: U256::from(21_000),
                initial_fee_per_gas: U256::from(1_000_000_000_u64),
                chain_data_fee_native: U256::zero(),
            },
            fee_asset,
            U256::from(1_000_000_u64),
            cap,
        )
        .await
        .unwrap();

    assert_eq!(authorization.plan.maximum_fee_per_gas, cap);
    assert_eq!(authorization.maximum_cost_value_e8, U256::from(4_201_u64));
}

#[tokio::test]
async fn widened_product_overflow_rejects() {
    let pool = Address::from_low_u64_be(7);
    let calculator = ProfitabilityCalculator::new(0, Arc::new(FixedPrices), pool);
    let rejected = calculator
        .authorize(
            CostCandidate {
                gas_limit: U256::MAX,
                initial_fee_per_gas: U256::MAX,
                chain_data_fee_native: U256::zero(),
            },
            &[payment_log(pool, U256::MAX)],
        )
        .await;
    assert!(matches!(
        rejected,
        Err(ProfitabilityError::Arithmetic { .. })
    ));
}

#[tokio::test]
async fn exact_estimate_prices_intrinsic_calldata_and_failure_is_terminal() {
    let anvil = Anvil::new().spawn();
    let mut config = NoxConfig::default();
    config.eth_rpc_url = anvil.endpoint();
    config.chain_id = anvil.chain_id();
    config.eth_wallet_private_key = hex::encode(anvil.keys()[0].to_bytes());
    let executor = ChainExecutor::new(&config).await.unwrap();
    let target = Address::from_low_u64_be(77);
    let short = executor.estimate_gas(target, Bytes::new()).await.unwrap();
    let long = executor
        .estimate_gas(target, Bytes::from(vec![1; 1_024]))
        .await
        .unwrap();
    assert!(long > short);
    let candidate = executor
        .build_cost_candidate(target, Bytes::from(vec![1; 1_024]), 2_000, 2_000)
        .await
        .unwrap();
    assert_eq!(
        candidate.gas_limit,
        buffered(U256::from(long), 2_000, "gas_limit").unwrap()
    );

    let malformed_blake2_input = executor
        .estimate_gas(Address::from_low_u64_be(9), Bytes::from(vec![1]))
        .await;
    assert!(malformed_blake2_input.is_err());
}

#[tokio::test]
async fn configured_avax_price_id_is_requested() {
    let pool = Address::from_low_u64_be(7);
    let prices = Arc::new(RecordingPrices(Mutex::new(Vec::new())));
    let calculator = ProfitabilityCalculator::with_economics(
        0,
        prices.clone(),
        pool,
        nox_node::services::token_registry::TokenRegistry::default(),
        "avalanche-2".to_string(),
        18,
    );
    calculator
        .authorize(
            CostCandidate {
                gas_limit: U256::one(),
                initial_fee_per_gas: U256::one(),
                chain_data_fee_native: U256::zero(),
            },
            &[payment_log(pool, U256::from(1_000_000_u64))],
        )
        .await
        .unwrap();
    let requested = prices.0.lock().unwrap();
    assert!(requested.iter().any(|asset| asset == "avalanche-2"));
    assert!(!requested.iter().any(|asset| asset == "ethereum"));
}
