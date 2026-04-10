//! Profitability calculator using simulation logs as the source of truth.

use ethers::prelude::*;
use ethers::types::U256;
use ethers::utils::keccak256;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::price::client::PriceSource;
use crate::services::token_registry::TokenRegistry;
use nox_core::utils::{token_to_f64, wei_to_eth_f64};

pub struct ProfitabilityCalculator {
    min_profit_margin: f64,
    price_client: Arc<dyn PriceSource>,
    token_registry: TokenRegistry,
    /// Events MUST come from this address to prevent spoofed reward events.
    nox_reward_pool_address: Address,
}

#[derive(Debug)]
pub struct ProfitabilityResult {
    pub is_profitable: bool,
    pub cost_usd: f64,
    pub revenue_usd: f64,
    pub margin: f64,
    pub payment_found: bool,
}

impl ProfitabilityCalculator {
    pub fn new(
        min_profit_margin_percent: u64,
        price_client: Arc<dyn PriceSource>,
        nox_reward_pool_address: Address,
    ) -> Self {
        if nox_reward_pool_address == Address::zero() {
            warn!(
                "ProfitabilityCalculator initialized with zero NoxRewardPool address. \
                 All reward event validation will fail -- no transaction will appear profitable."
            );
        }

        info!(
            "Profitability Calculator initialized. Min margin: {}%, RewardPool: {:?}",
            min_profit_margin_percent, nox_reward_pool_address
        );

        Self {
            min_profit_margin: (min_profit_margin_percent as f64) / 100.0,
            price_client,
            token_registry: TokenRegistry::default(),
            nox_reward_pool_address,
        }
    }

    pub fn with_token_registry(
        min_profit_margin_percent: u64,
        price_client: Arc<dyn PriceSource>,
        nox_reward_pool_address: Address,
        token_registry: TokenRegistry,
    ) -> Self {
        Self {
            min_profit_margin: (min_profit_margin_percent as f64) / 100.0,
            price_client,
            token_registry,
            nox_reward_pool_address,
        }
    }

    pub async fn analyze(
        &self,
        gas_used: u64,
        gas_price: U256,
        logs: &[Log],
    ) -> ProfitabilityResult {
        if gas_price.is_zero() {
            warn!("Gas price is zero -- rejecting transaction (potential manipulation or misconfigured network)");
            return ProfitabilityResult {
                is_profitable: false,
                cost_usd: 0.0,
                revenue_usd: 0.0,
                margin: 0.0,
                payment_found: false,
            };
        }

        let eth_price = match self.price_client.get_price("ethereum").await {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to fetch ETH price: {}. Assuming unprofitable.", e);
                return ProfitabilityResult {
                    is_profitable: false,
                    cost_usd: 0.0,
                    revenue_usd: 0.0,
                    margin: 0.0,
                    payment_found: false,
                };
            }
        };

        let cost_eth = wei_to_eth_f64(U256::from(gas_used) * gas_price);
        let cost_usd = cost_eth * eth_price;

        let rewards_topic = H256::from(keccak256(b"RewardsDeposited(address,address,uint256)"));

        let mut revenue_usd = 0.0;
        let mut payment_found = false;

        for log in logs {
            // Reject events from non-NoxRewardPool addresses (fake contract attack vector).
            if log.address != self.nox_reward_pool_address {
                if log.topics.first() == Some(&rewards_topic) {
                    warn!(
                        "SECURITY: Ignoring RewardsDeposited from WRONG address {:?} (expected {:?})",
                        log.address, self.nox_reward_pool_address
                    );
                }
                continue;
            }

            if log.topics.len() >= 3 && log.topics[0] == rewards_topic {
                let asset_address = Address::from(log.topics[1]);

                let amount = if log.data.len() >= 32 {
                    U256::from_big_endian(&log.data[..32])
                } else {
                    warn!("Invalid RewardsDeposited data length: {}", log.data.len());
                    continue;
                };

                let price = self.get_asset_price(asset_address).await;

                let Some(decimals) = self.get_decimals(asset_address) else {
                    warn!(
                        "Unknown token {:?} -- cannot determine decimals. \
                         Skipping payment to prevent incorrect valuation. \
                         Register this token via `register_token()`.",
                        asset_address
                    );
                    continue;
                };

                let token_amount = token_to_f64(amount, decimals);
                let value_usd = token_amount * price;

                debug!(
                    "Valid Payment: {} {} (decimals: {}, price: ${:.2}) = ${:.4}",
                    token_amount,
                    self.token_registry
                        .get_info(asset_address)
                        .map_or("UNKNOWN", |t| t.symbol.as_str()),
                    decimals,
                    price,
                    value_usd
                );

                revenue_usd += value_usd;
                payment_found = true;
            }
        }

        if !payment_found {
            warn!("No valid RewardsDeposited event found from NoxRewardPool. Transaction provides 0 payment.");
        }

        let margin = if cost_usd > 0.0 {
            revenue_usd / cost_usd
        } else {
            f64::INFINITY
        };

        let is_profitable = cost_usd == 0.0 || margin >= (1.0 + self.min_profit_margin);

        if is_profitable {
            debug!(
                "Profitable: Margin {:.2}x >= {:.2}x (Rev ${:.4} / Cost ${:.4})",
                margin,
                1.0 + self.min_profit_margin,
                revenue_usd,
                cost_usd
            );
        } else {
            warn!(
                "Unprofitable: Margin {:.2}x < {:.2}x (Rev ${:.4} / Cost ${:.4})",
                margin,
                1.0 + self.min_profit_margin,
                revenue_usd,
                cost_usd
            );
        }

        ProfitabilityResult {
            is_profitable,
            cost_usd,
            revenue_usd,
            margin,
            payment_found,
        }
    }

    pub async fn is_profitable(&self, gas_used: u64, gas_price: U256, logs: &[Log]) -> bool {
        self.analyze(gas_used, gas_price, logs).await.is_profitable
    }

    async fn get_asset_price(&self, asset: Address) -> f64 {
        let price_id = self.token_registry.get_price_id(asset);

        if price_id == "unknown" {
            warn!(
                "Unknown asset {:?} - cannot determine price. Assuming $0",
                asset
            );
            return 0.0;
        }

        match self.price_client.get_price(&price_id).await {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    "Failed to fetch price for {} (asset {:?}): {}. Assuming $0",
                    price_id, asset, e
                );
                0.0
            }
        }
    }

    /// Returns `None` for unregistered tokens (callers must not assume 18 decimals).
    fn get_decimals(&self, asset: Address) -> Option<u32> {
        self.token_registry.get_decimals(asset).map(u32::from)
    }

    pub fn register_token(&mut self, address: Address, symbol: &str, decimals: u8, price_id: &str) {
        self.token_registry.register(
            address,
            crate::services::token_registry::TokenInfo {
                symbol: symbol.to_string(),
                decimals,
                price_id: price_id.to_string(),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::price::client::PriceClientError;
    use std::str::FromStr;

    struct MockPriceClient {
        prices: std::collections::HashMap<String, f64>,
    }

    #[async_trait::async_trait]
    impl PriceSource for MockPriceClient {
        async fn get_price(&self, asset: &str) -> Result<f64, PriceClientError> {
            self.prices
                .get(asset)
                .copied()
                .ok_or(PriceClientError::AssetNotFound)
        }
    }

    fn create_rewards_log(pool_address: Address, asset: Address, amount: U256) -> Log {
        let topic0 = H256::from(keccak256(b"RewardsDeposited(address,address,uint256)"));
        let mut topic1 = [0u8; 32];
        topic1[12..].copy_from_slice(asset.as_bytes());
        let topic2 = H256::zero(); // 'from' address, not used

        let mut data = vec![0u8; 32];
        amount.to_big_endian(&mut data);

        Log {
            address: pool_address,
            topics: vec![topic0, H256::from(topic1), topic2],
            data: data.into(),
            block_hash: None,
            block_number: None,
            transaction_hash: None,
            transaction_index: None,
            log_index: None,
            transaction_log_index: None,
            log_type: None,
            removed: None,
        }
    }

    #[tokio::test]
    async fn test_usdc_decimal_handling() {
        let mut prices = std::collections::HashMap::new();
        prices.insert("ethereum".to_string(), 3000.0);
        prices.insert("usd-coin".to_string(), 1.0);

        let price_client = Arc::new(MockPriceClient { prices });
        let pool_address = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let usdc_address = Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();

        let calc = ProfitabilityCalculator::new(10, price_client, pool_address);

        // 10 USDC = 10_000_000 (6 decimals)
        let amount = U256::from(10_000_000u64);
        let log = create_rewards_log(pool_address, usdc_address, amount);

        let result = calc
            .analyze(50_000, U256::from(10_000_000_000u64), &[log])
            .await;

        // Revenue should be ~$10, not $0.00000000001
        assert!(
            result.revenue_usd > 9.0 && result.revenue_usd < 11.0,
            "USDC revenue should be ~$10, got ${:.6}",
            result.revenue_usd
        );
    }

    #[tokio::test]
    async fn test_rejects_fake_reward_pool() {
        let mut prices = std::collections::HashMap::new();
        prices.insert("ethereum".to_string(), 3000.0);
        prices.insert("usd-coin".to_string(), 1.0);

        let price_client = Arc::new(MockPriceClient { prices });
        let real_pool = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let fake_pool = Address::from_str("0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF").unwrap();
        let usdc_address = Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();

        let calc = ProfitabilityCalculator::new(10, price_client, real_pool);

        // Create log from FAKE pool (should be rejected!)
        let amount = U256::from(10_000_000_000u64); // 10,000 USDC
        let fake_log = create_rewards_log(fake_pool, usdc_address, amount);

        let result = calc
            .analyze(50_000, U256::from(10_000_000_000u64), &[fake_log])
            .await;

        // CRITICAL: Should NOT find payment from fake pool
        assert!(
            !result.payment_found,
            "Should reject RewardsDeposited from wrong address"
        );
        assert_eq!(
            result.revenue_usd, 0.0,
            "Revenue should be 0 from fake pool"
        );
    }

    #[tokio::test]
    async fn test_profitable_transaction() {
        let mut prices = std::collections::HashMap::new();
        prices.insert("ethereum".to_string(), 3000.0);
        prices.insert("usd-coin".to_string(), 1.0);

        let price_client = Arc::new(MockPriceClient { prices });
        let pool_address = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let usdc_address = Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();

        let calc = ProfitabilityCalculator::new(10, price_client, pool_address);

        // Gas: 100k gas at 20 gwei = 0.002 ETH = $6 at $3000/ETH
        // Payment: 100 USDC = $100
        // Margin: $100 / $6 = 16.6x >> 1.1x required
        let amount = U256::from(100_000_000u64); // 100 USDC (6 decimals)
        let log = create_rewards_log(pool_address, usdc_address, amount);

        let result = calc
            .analyze(100_000, U256::from(20_000_000_000u64), &[log])
            .await;

        assert!(result.is_profitable);
        assert!(result.payment_found);
        assert!(result.margin > 10.0);
    }

    #[tokio::test]
    async fn test_unprofitable_transaction() {
        let mut prices = std::collections::HashMap::new();
        prices.insert("ethereum".to_string(), 3000.0);
        prices.insert("usd-coin".to_string(), 1.0);

        let price_client = Arc::new(MockPriceClient { prices });
        let pool_address = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let usdc_address = Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();

        let calc = ProfitabilityCalculator::new(10, price_client, pool_address);

        // Gas: 500k gas at 100 gwei = 0.05 ETH = $150 at $3000/ETH
        // Payment: 1 USDC = $1
        // Margin: $1 / $150 = 0.0067x << 1.1x required
        let amount = U256::from(1_000_000u64); // 1 USDC (6 decimals)
        let log = create_rewards_log(pool_address, usdc_address, amount);

        let result = calc
            .analyze(500_000, U256::from(100_000_000_000u64), &[log])
            .await;

        assert!(!result.is_profitable);
        assert!(result.payment_found);
        assert!(result.margin < 0.1);
    }

    #[tokio::test]
    async fn test_zero_gas_price_rejected() {
        let mut prices = std::collections::HashMap::new();
        prices.insert("ethereum".to_string(), 3000.0);
        prices.insert("usd-coin".to_string(), 1.0);

        let price_client = Arc::new(MockPriceClient { prices });
        let pool_address = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let usdc_address = Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();

        let calc = ProfitabilityCalculator::new(10, price_client, pool_address);

        let amount = U256::from(100_000_000u64); // 100 USDC
        let log = create_rewards_log(pool_address, usdc_address, amount);

        let result = calc.analyze(100_000, U256::zero(), &[log]).await;
        assert!(!result.is_profitable, "Zero gas price should be rejected");
        assert!(
            !result.payment_found,
            "Should not even scan logs when gas price is zero"
        );
    }
}
