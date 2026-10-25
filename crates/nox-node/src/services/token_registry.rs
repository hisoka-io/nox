//! Token metadata registry: resolves decimals and price oracle IDs per token address.

use alloy::primitives::{address, Address};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub symbol: String,
    pub decimals: u8,
    pub price_id: String,
}

#[derive(Clone)]
pub struct TokenRegistry {
    tokens: HashMap<Address, TokenInfo>,
}

impl TokenRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tokens: HashMap::new(),
        }
    }

    /// Pre-populated with Mainnet token addresses (compile-time byte constants).
    #[must_use]
    pub fn new_mainnet() -> Self {
        const WETH: Address = address!("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");
        const USDC: Address = address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
        const DAI: Address = address!("6b175474e89094c44da98b954eedeac495271d0f");
        const USDT: Address = address!("dac17f958d2ee523a2206206994597c13d831ec7");
        const WBTC: Address = address!("2260fac5e5542a773aa44fbcfedf7c193bc2c599");

        let mut tokens = HashMap::new();

        tokens.insert(
            WETH,
            TokenInfo {
                symbol: "WETH".to_string(),
                decimals: 18,
                price_id: "ethereum".to_string(),
            },
        );

        // USDC: 6 decimals, NOT 18
        tokens.insert(
            USDC,
            TokenInfo {
                symbol: "USDC".to_string(),
                decimals: 6,
                price_id: "usd-coin".to_string(),
            },
        );

        tokens.insert(
            DAI,
            TokenInfo {
                symbol: "DAI".to_string(),
                decimals: 18,
                price_id: "dai".to_string(),
            },
        );

        // USDT: 6 decimals
        tokens.insert(
            USDT,
            TokenInfo {
                symbol: "USDT".to_string(),
                decimals: 6,
                price_id: "tether".to_string(),
            },
        );

        // WBTC: 8 decimals
        tokens.insert(
            WBTC,
            TokenInfo {
                symbol: "WBTC".to_string(),
                decimals: 8,
                price_id: "bitcoin".to_string(),
            },
        );

        Self { tokens }
    }

    pub fn register(&mut self, address: Address, info: TokenInfo) {
        self.tokens.insert(address, info);
    }

    pub(crate) fn clear(&mut self) {
        self.tokens.clear();
    }

    #[must_use]
    pub fn get_decimals(&self, asset: Address) -> Option<u8> {
        self.tokens.get(&asset).map(|t| t.decimals)
    }

    #[must_use]
    pub fn get_price_id(&self, asset: Address) -> Option<&str> {
        self.tokens.get(&asset).map(|token| token.price_id.as_str())
    }

    #[must_use]
    pub fn get_info(&self, asset: Address) -> Option<&TokenInfo> {
        self.tokens.get(&asset)
    }

    #[must_use]
    pub fn is_known(&self, asset: Address) -> bool {
        self.tokens.contains_key(&asset)
    }
}

impl Default for TokenRegistry {
    fn default() -> Self {
        Self::new_mainnet()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_usdc_has_6_decimals() {
        let registry = TokenRegistry::new_mainnet();
        let usdc = Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();

        let decimals = registry.get_decimals(usdc);
        assert_eq!(decimals, Some(6), "USDC must have 6 decimals, not 18!");
    }

    #[test]
    fn test_weth_has_18_decimals() {
        let registry = TokenRegistry::new_mainnet();
        let weth = Address::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();

        let decimals = registry.get_decimals(weth);
        assert_eq!(decimals, Some(18));
    }

    #[test]
    fn test_price_id_mapping() {
        let registry = TokenRegistry::new_mainnet();
        let usdc = Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();

        let price_id = registry.get_price_id(usdc);
        assert_eq!(
            price_id,
            Some("usd-coin"),
            "USDC should map to 'usd-coin' for price API"
        );
    }

    #[test]
    fn configured_tokens_replace_mainnet_defaults() {
        let mut registry = TokenRegistry::default();
        let mainnet_usdc = Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();
        let configured = Address::with_last_byte(77);
        registry.clear();
        registry.register(
            configured,
            TokenInfo {
                symbol: "AVAX-USDC".to_string(),
                decimals: 6,
                price_id: "usd-coin".to_string(),
            },
        );
        assert!(!registry.is_known(mainnet_usdc));
        assert!(registry.is_known(configured));
    }
}
