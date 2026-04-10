//! Configuration types for `DarkPool` client operations.

use ethers::types::{Address, H256, U256};

use crate::builder::BuilderConfig;

#[derive(Debug, Clone)]
pub struct GasLimits {
    pub withdraw: u64,
    pub split: u64,
    pub transfer: u64,
    pub join: u64,
    pub public_claim: u64,
}

impl Default for GasLimits {
    fn default() -> Self {
        Self {
            withdraw: 400_000,
            split: 500_000,
            transfer: 500_000,
            join: 600_000,
            public_claim: 800_000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DarkPoolConfig {
    pub darkpool_address: Address,
    pub compliance_pk: (U256, U256),
    pub start_block: u64,
    pub builder_config: BuilderConfig,
    pub gas_limits: GasLimits,
    pub provider_timeout_ms: u64,
}

impl Default for DarkPoolConfig {
    fn default() -> Self {
        Self {
            darkpool_address: Address::zero(),
            compliance_pk: (U256::zero(), U256::zero()),
            start_block: 0,
            builder_config: BuilderConfig::default(),
            gas_limits: GasLimits::default(),
            provider_timeout_ms: 30_000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PrivacyTxResult {
    pub tx_hash: H256,
    pub new_commitments: Vec<U256>,
    pub spent_nullifiers: Vec<U256>,
    pub gas_used: U256,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_darkpool_config_default() {
        let config = DarkPoolConfig::default();
        assert_eq!(config.darkpool_address, Address::zero());
        assert_eq!(config.start_block, 0);
        assert_eq!(config.provider_timeout_ms, 30_000);
        assert_eq!(config.gas_limits.withdraw, 400_000);
        assert_eq!(config.gas_limits.split, 500_000);
        assert_eq!(config.gas_limits.transfer, 500_000);
        assert_eq!(config.gas_limits.join, 600_000);
    }

    #[test]
    fn test_gas_limits_custom() {
        let limits = GasLimits {
            withdraw: 300_000,
            split: 400_000,
            transfer: 400_000,
            join: 500_000,
            public_claim: 700_000,
        };
        assert_eq!(limits.withdraw, 300_000);
        assert_eq!(limits.join, 500_000);
        assert_eq!(limits.public_claim, 700_000);
    }
}
