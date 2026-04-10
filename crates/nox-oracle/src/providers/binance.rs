use super::PriceProvider;
use crate::error::ProviderError;
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;

pub struct BinanceProvider {
    client: Client,
    base_url: String,
}

impl Default for BinanceProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl BinanceProvider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            base_url: "https://api.binance.com/api/v3".to_string(),
        }
    }

    #[must_use]
    pub fn with_base_url(base_url: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
        }
    }

    fn map_to_symbol(&self, asset: &str) -> Option<&'static str> {
        match asset {
            "ethereum" => Some("ETHUSDT"),
            "bitcoin" => Some("BTCUSDT"),
            "usd-coin" => Some("USDCUSDT"),
            _ => None,
        }
    }
}

#[derive(Deserialize)]
struct TickerPrice {
    symbol: String,
    price: String,
}

#[async_trait]
impl PriceProvider for BinanceProvider {
    fn id(&self) -> &'static str {
        "binance"
    }

    async fn get_prices(&self, assets: &[String]) -> Result<HashMap<String, f64>, ProviderError> {
        let url = format!("{}/ticker/price", self.base_url);

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(ProviderError::Network)?;

        if !resp.status().is_success() {
            return Err(match resp.error_for_status() {
                Err(e) => ProviderError::Network(e),
                Ok(_) => ProviderError::Other(
                    "Unexpected success status after failure check".to_string(),
                ),
            });
        }

        let tickers: Vec<TickerPrice> = resp
            .json()
            .await
            .map_err(|e| ProviderError::Parse(e.to_string()))?;

        let mut prices = HashMap::new();
        for asset in assets {
            if let Some(target_symbol) = self.map_to_symbol(asset) {
                if let Some(ticker) = tickers.iter().find(|t| t.symbol == target_symbol) {
                    if let Ok(p) = ticker.price.parse::<f64>() {
                        prices.insert(asset.clone(), p);
                    }
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
    async fn test_binance_valid_response_returns_prices() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v3/ticker/price"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"symbol": "ETHUSDT", "price": "2500.50"},
                {"symbol": "BTCUSDT", "price": "45000.00"}
            ])))
            .mount(&mock_server)
            .await;

        let provider = BinanceProvider::with_base_url(format!("{}/api/v3", mock_server.uri()));
        let assets = vec!["ethereum".to_string(), "bitcoin".to_string()];
        let prices = provider.get_prices(&assets).await.unwrap();

        assert!((prices["ethereum"] - 2500.50).abs() < 0.01);
        assert!((prices["bitcoin"] - 45000.0).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_binance_unknown_asset_not_in_result() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v3/ticker/price"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"symbol": "ETHUSDT", "price": "2500.00"}
            ])))
            .mount(&mock_server)
            .await;

        let provider = BinanceProvider::with_base_url(format!("{}/api/v3", mock_server.uri()));
        let assets = vec!["unknown-token".to_string()];
        let prices = provider.get_prices(&assets).await.unwrap();

        assert!(
            prices.is_empty(),
            "unknown asset should not appear in result"
        );
    }

    #[tokio::test]
    async fn test_binance_invalid_json_returns_parse_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v3/ticker/price"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json {{{"))
            .mount(&mock_server)
            .await;

        let provider = BinanceProvider::with_base_url(format!("{}/api/v3", mock_server.uri()));
        let assets = vec!["ethereum".to_string()];
        let result = provider.get_prices(&assets).await;

        assert!(
            matches!(result, Err(ProviderError::Parse(_))),
            "expected Parse error, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_binance_server_error_returns_network_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v3/ticker/price"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let provider = BinanceProvider::with_base_url(format!("{}/api/v3", mock_server.uri()));
        let assets = vec!["ethereum".to_string()];
        let result = provider.get_prices(&assets).await;

        assert!(
            matches!(result, Err(ProviderError::Network(_))),
            "expected Network error on 500, got {result:?}"
        );
    }
}
