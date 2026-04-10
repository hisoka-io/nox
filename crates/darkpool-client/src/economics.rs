//! Fee calculation: gas costs to payment-asset fees with configurable premium.

use ethers::types::U256;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct PriceData {
    /// Scaled by 10^8
    pub eth_usd: U256,
    /// Scaled by 10^8
    pub asset_usd: U256,
    pub gas_price: U256,
}

#[derive(Debug, Clone)]
pub struct FeeEstimate {
    pub fee_amount: U256,
    pub gas_limit: U256,
    pub gas_price: U256,
    pub premium_bps: u64,
}

#[derive(Debug, Clone)]
pub struct FeeConfig {
    /// Relayer profit margin in basis points (1200 = 12%).
    pub premium_bps: u64,
    pub default_gas_limit: U256,
}

impl Default for FeeConfig {
    fn default() -> Self {
        Self {
            premium_bps: 1200,
            default_gas_limit: U256::from(300_000),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FeeManager {
    pub config: FeeConfig,
}

impl FeeManager {
    #[must_use]
    pub fn new(config: FeeConfig) -> Self {
        Self { config }
    }

    /// `fee = gas_limit * gas_price * eth_usd * (1 + premium) / asset_usd`
    #[must_use]
    pub fn calculate_fee(&self, gas_limit: U256, prices: &PriceData) -> FeeEstimate {
        let gas_cost_wei = gas_limit * prices.gas_price;
        let premium_multiplier = U256::from(10_000 + self.config.premium_bps);
        let fee_with_premium = (gas_cost_wei * premium_multiplier) / U256::from(10_000);

        let fee_in_asset = if prices.asset_usd > U256::zero() {
            (fee_with_premium * prices.eth_usd) / prices.asset_usd
        } else {
            warn!(
                "Asset price is zero in calculate_fee. Returning max fee to prevent \
                 incorrect fee calculation. Check price oracle."
            );
            U256::MAX
        };

        FeeEstimate {
            fee_amount: fee_in_asset,
            gas_limit,
            gas_price: prices.gas_price,
            premium_bps: self.config.premium_bps,
        }
    }

    /// Adjusts for asset decimals (e.g., USDC has 6 vs ETH's 18).
    #[must_use]
    pub fn calculate_fee_with_decimals(
        &self,
        gas_limit: U256,
        prices: &PriceData,
        asset_decimals: u8,
    ) -> FeeEstimate {
        let mut estimate = self.calculate_fee(gas_limit, prices);
        if asset_decimals < 18 {
            let decimal_diff = 18 - asset_decimals;
            let divisor = U256::from(10u64).pow(U256::from(decimal_diff));
            estimate.fee_amount /= divisor;
        } else if asset_decimals > 18 {
            let decimal_diff = asset_decimals - 18;
            let multiplier = U256::from(10u64).pow(U256::from(decimal_diff));
            estimate.fee_amount *= multiplier;
        }

        estimate
    }
}

impl Default for FeeManager {
    fn default() -> Self {
        Self::new(FeeConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_manager_calculate() {
        let manager = FeeManager::new(FeeConfig {
            premium_bps: 1200,
            default_gas_limit: U256::from(300_000),
        });

        let prices = PriceData {
            eth_usd: U256::from(3000_00000000u64),
            asset_usd: U256::from(1_00000000u64),
            gas_price: U256::from(20_000_000_000u64),
        };

        let estimate = manager.calculate_fee(U256::from(100_000), &prices);
        assert!(estimate.fee_amount > U256::zero());
        assert_eq!(estimate.premium_bps, 1200);
    }

    #[test]
    fn test_fee_manager_with_decimals() {
        let manager = FeeManager::default();

        let prices = PriceData {
            eth_usd: U256::from(3000_00000000u64),
            asset_usd: U256::from(1_00000000u64),
            gas_price: U256::from(20_000_000_000u64),
        };

        let estimate_18 = manager.calculate_fee(U256::from(100_000), &prices);
        let estimate_6 = manager.calculate_fee_with_decimals(U256::from(100_000), &prices, 6);

        assert!(estimate_6.fee_amount < estimate_18.fee_amount);
    }

    #[test]
    fn test_fee_estimate() {
        let prices = PriceData {
            eth_usd: U256::from(3000_00000000u64),
            asset_usd: U256::from(1_00000000u64),
            gas_price: U256::from(20_000_000_000u64),
        };

        let gas_limit = U256::from(100_000);
        let gas_cost = gas_limit * prices.gas_price;
        let with_premium = (gas_cost * U256::from(11200)) / U256::from(10000);
        assert!(with_premium > gas_cost);
    }
}
