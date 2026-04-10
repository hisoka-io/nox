//! Token metadata registry: resolves decimals and price oracle IDs per token address.

use ethers::types::{Address, H160};
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
        const WETH: H160 = H160([
            0xc0, 0x2a, 0xaa, 0x39, 0xb2, 0x23, 0xfe, 0x8d, 0x0a, 0x0e, 0x5c, 0x4f, 0x27, 0xea,
            0xd9, 0x08, 0x3c, 0x75, 0x6c, 0xc2,
        ]);
        const USDC: H160 = H160([
            0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e,
            0xb0, 0xce, 0x36, 0x06, 0xeb, 0x48,
        ]);
        const DAI: H160 = H160([
            0x6b, 0x17, 0x54, 0x74, 0xe8, 0x90, 0x94, 0xc4, 0x4d, 0xa9, 0x8b, 0x95, 0x4e, 0xed,
            0xea, 0xc4, 0x95, 0x27, 0x1d, 0x0f,
        ]);
        const USDT: H160 = H160([
            0xda, 0xc1, 0x7f, 0x95, 0x8d, 0x2e, 0xe5, 0x23, 0xa2, 0x20, 0x62, 0x06, 0x99, 0x45,
            0x97, 0xc1, 0x3d, 0x83, 0x1e, 0xc7,
        ]);
        const WBTC: H160 = H160([
            0x22, 0x60, 0xfa, 0xc5, 0xe5, 0x54, 0x2a, 0x77, 0x3a, 0xa4, 0x4f, 0xbc, 0xfe, 0xdf,
            0x7c, 0x19, 0x3b, 0xc2, 0xc5, 0x99,
        ]);

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

    #[must_use]
    pub fn get_decimals(&self, asset: Address) -> Option<u8> {
        self.tokens.get(&asset).map(|t| t.decimals)
    }

    /// Returns "unknown" if the token is not registered.
    #[must_use]
    pub fn get_price_id(&self, asset: Address) -> String {
        self.tokens
            .get(&asset)
            .map_or_else(|| "unknown".to_string(), |t| t.price_id.clone())
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
            price_id, "usd-coin",
            "USDC should map to 'usd-coin' for price API"
        );
    }
}
