use super::PriceProvider;
use crate::error::ProviderError;
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;

/// `CryptoCompare` price provider.
/// Uses the free min-api endpoint -- no API key required.
/// Works from US-based IPs (unlike `CoinGecko`/Binance free tiers).
pub struct CryptoCompareProvider {
    client: Client,
    base_url: String,
}

impl Default for CryptoCompareProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoCompareProvider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            base_url: "https://min-api.cryptocompare.com".to_string(),
        }
    }

    #[must_use]
    pub fn with_base_url(base_url: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
        }
    }

    fn asset_to_symbol(asset: &str) -> Option<&'static str> {
        match asset {
            "ethereum" => Some("ETH"),
            "bitcoin" => Some("BTC"),
            "usd-coin" => Some("USDC"),
            _ => None,
        }
    }

    fn symbol_to_asset(symbol: &str) -> Option<&'static str> {
        match symbol {
            "ETH" => Some("ethereum"),
            "BTC" => Some("bitcoin"),
            "USDC" => Some("usd-coin"),
            _ => None,
        }
    }
}

#[derive(Deserialize)]
struct CcResponse(HashMap<String, HashMap<String, f64>>);

#[async_trait]
impl PriceProvider for CryptoCompareProvider {
    fn id(&self) -> &'static str {
        "cryptocompare"
    }

    async fn get_prices(&self, assets: &[String]) -> Result<HashMap<String, f64>, ProviderError> {
        let symbols: Vec<&str> = assets
            .iter()
            .filter_map(|a| Self::asset_to_symbol(a))
            .collect();

        if symbols.is_empty() {
            return Ok(HashMap::new());
        }

        let fsyms = symbols.join(",");
        let url = format!("{}/data/pricemulti", self.base_url);

        let resp = self
            .client
            .get(&url)
            .query(&[("fsyms", &fsyms), ("tsyms", &"USD".to_string())])
            .send()
            .await
            .map_err(ProviderError::Network)?;

        if !resp.status().is_success() {
            if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                return Err(ProviderError::RateLimited);
            }
            return Err(match resp.error_for_status() {
                Err(e) => ProviderError::Network(e),
                Ok(_) => ProviderError::Other(
                    "Unexpected success status after failure check".to_string(),
                ),
            });
        }

        let data: CcResponse = resp
            .json()
            .await
            .map_err(|e| ProviderError::Parse(e.to_string()))?;

        let mut prices = HashMap::new();
        for (symbol, currency_map) in &data.0 {
            if let Some(price) = currency_map.get("USD") {
                if let Some(asset_id) = Self::symbol_to_asset(symbol) {
                    prices.insert(asset_id.to_string(), *price);
                }
            }
        }

        Ok(prices)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_cryptocompare_valid_response_returns_prices() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/data/pricemulti"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ETH": {"USD": 2400.0},
                "BTC": {"USD": 44000.0}
            })))
            .mount(&mock_server)
            .await;

        let provider = CryptoCompareProvider::with_base_url(mock_server.uri().clone());
        let assets = vec!["ethereum".to_string(), "bitcoin".to_string()];
        let prices = provider.get_prices(&assets).await.unwrap();

        assert!((prices["ethereum"] - 2400.0).abs() < 0.01);
        assert!((prices["bitcoin"] - 44000.0).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_cryptocompare_rate_limited_returns_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/data/pricemulti"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&mock_server)
            .await;

        let provider = CryptoCompareProvider::with_base_url(mock_server.uri().clone());
        let assets = vec!["ethereum".to_string()];
        let result = provider.get_prices(&assets).await;

        assert!(
            matches!(result, Err(ProviderError::RateLimited)),
            "expected RateLimited on 429, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_cryptocompare_unknown_asset_skipped() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/data/pricemulti"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&mock_server)
            .await;

        let provider = CryptoCompareProvider::with_base_url(mock_server.uri().clone());
        let assets = vec!["unknown-token-xyz".to_string()];
        let prices = provider.get_prices(&assets).await.unwrap();

        assert!(prices.is_empty());
    }

    #[tokio::test]
    async fn test_cryptocompare_server_error_returns_network_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/data/pricemulti"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock_server)
            .await;

        let provider = CryptoCompareProvider::with_base_url(mock_server.uri().clone());
        let assets = vec!["ethereum".to_string()];
        let result = provider.get_prices(&assets).await;

        assert!(
            matches!(result, Err(ProviderError::Network(_))),
            "expected Network error on 503, got {result:?}"
        );
    }
}
