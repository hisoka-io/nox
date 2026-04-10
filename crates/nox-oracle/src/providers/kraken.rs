use super::PriceProvider;
use crate::error::ProviderError;
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;

/// Kraken public REST API price provider.
/// No API key required. Works from US-based IPs.
pub struct KrakenProvider {
    client: Client,
    base_url: String,
}

impl Default for KrakenProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl KrakenProvider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            base_url: "https://api.kraken.com".to_string(),
        }
    }

    #[must_use]
    pub fn with_base_url(base_url: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
        }
    }

    fn asset_to_pair(asset: &str) -> Option<&'static str> {
        match asset {
            "ethereum" => Some("XETHZUSD"),
            "bitcoin" => Some("XXBTZUSD"),
            "usd-coin" => Some("USDCUSD"),
            _ => None,
        }
    }

    fn pair_to_asset(pair: &str) -> Option<&'static str> {
        match pair {
            "XETHZUSD" => Some("ethereum"),
            "XXBTZUSD" => Some("bitcoin"),
            "USDCUSD" => Some("usd-coin"),
            _ => None,
        }
    }
}

#[derive(Deserialize)]
struct KrakenResponse {
    error: Vec<String>,
    result: Option<HashMap<String, KrakenTicker>>,
}

#[derive(Deserialize)]
struct KrakenTicker {
    c: Vec<String>,
}

#[async_trait]
impl PriceProvider for KrakenProvider {
    fn id(&self) -> &'static str {
        "kraken"
    }

    async fn get_prices(&self, assets: &[String]) -> Result<HashMap<String, f64>, ProviderError> {
        let pairs: Vec<&str> = assets
            .iter()
            .filter_map(|a| Self::asset_to_pair(a))
            .collect();

        if pairs.is_empty() {
            return Ok(HashMap::new());
        }

        let pair_str = pairs.join(",");
        let url = format!("{}/0/public/Ticker", self.base_url);

        let resp = self
            .client
            .get(&url)
            .query(&[("pair", &pair_str)])
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

        let data: KrakenResponse = resp
            .json()
            .await
            .map_err(|e| ProviderError::Parse(e.to_string()))?;

        if !data.error.is_empty() {
            return Err(ProviderError::Other(format!(
                "Kraken API errors: {}",
                data.error.join(", ")
            )));
        }

        let result = data
            .result
            .ok_or_else(|| ProviderError::Parse("Missing 'result' field".to_string()))?;

        let mut prices = HashMap::new();
        for (pair, ticker) in &result {
            if let Some(asset_id) = Self::pair_to_asset(pair) {
                if let Some(price_str) = ticker.c.first() {
                    if let Ok(price) = price_str.parse::<f64>() {
                        prices.insert(asset_id.to_string(), price);
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
    async fn test_kraken_valid_response_returns_prices() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/0/public/Ticker"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "error": [],
                "result": {
                    "XETHZUSD": {"c": ["2400.00", "1.000"]},
                    "XXBTZUSD": {"c": ["44000.00", "0.500"]}
                }
            })))
            .mount(&mock_server)
            .await;

        let provider = KrakenProvider::with_base_url(mock_server.uri().clone());
        let assets = vec!["ethereum".to_string(), "bitcoin".to_string()];
        let prices = provider.get_prices(&assets).await.unwrap();

        assert!((prices["ethereum"] - 2400.0).abs() < 0.01);
        assert!((prices["bitcoin"] - 44000.0).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_kraken_api_error_returns_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/0/public/Ticker"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "error": ["EGeneral:Invalid arguments"],
                "result": null
            })))
            .mount(&mock_server)
            .await;

        let provider = KrakenProvider::with_base_url(mock_server.uri().clone());
        let assets = vec!["ethereum".to_string()];
        let result = provider.get_prices(&assets).await;

        assert!(
            matches!(result, Err(ProviderError::Other(_))),
            "expected Other error for Kraken API error, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_kraken_unknown_asset_skipped() {
        let provider = KrakenProvider::new();
        let assets = vec!["unknown-token-xyz".to_string()];
        let prices = provider.get_prices(&assets).await.unwrap();
        assert!(prices.is_empty());
    }

    #[tokio::test]
    async fn test_kraken_rate_limited_returns_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/0/public/Ticker"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&mock_server)
            .await;

        let provider = KrakenProvider::with_base_url(mock_server.uri().clone());
        let assets = vec!["ethereum".to_string()];
        let result = provider.get_prices(&assets).await;

        assert!(
            matches!(result, Err(ProviderError::RateLimited)),
            "expected RateLimited on 429, got {result:?}"
        );
    }
}
