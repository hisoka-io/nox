use super::PriceProvider;
use crate::error::ProviderError;
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;

pub struct CoinGeckoProvider {
    client: Client,
    base_url: String,
}

impl Default for CoinGeckoProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CoinGeckoProvider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            base_url: "https://api.coingecko.com/api/v3".to_string(),
        }
    }

    #[must_use]
    pub fn with_base_url(base_url: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
        }
    }
}

#[derive(Deserialize)]
struct CgResponse(HashMap<String, HashMap<String, f64>>);

#[async_trait]
impl PriceProvider for CoinGeckoProvider {
    fn id(&self) -> &'static str {
        "coingecko"
    }

    async fn get_prices(&self, assets: &[String]) -> Result<HashMap<String, f64>, ProviderError> {
        let ids = assets.join(",");
        let url = format!("{}/simple/price", self.base_url);

        let resp = self
            .client
            .get(&url)
            .query(&[("ids", &ids), ("vs_currencies", &"usd".to_string())])
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

        let data: CgResponse = resp
            .json()
            .await
            .map_err(|e| ProviderError::Parse(e.to_string()))?;

        let mut prices = HashMap::new();
        for (asset, currency_map) in data.0 {
            if let Some(price) = currency_map.get("usd") {
                prices.insert(asset, *price);
            }
        }

        Ok(prices)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_coingecko_valid_response_returns_prices() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v3/simple/price"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ethereum": {"usd": 2400.0},
                "bitcoin": {"usd": 44000.0}
            })))
            .mount(&mock_server)
            .await;

        let provider = CoinGeckoProvider::with_base_url(format!("{}/api/v3", mock_server.uri()));
        let assets = vec!["ethereum".to_string(), "bitcoin".to_string()];
        let prices = provider.get_prices(&assets).await.unwrap();

        assert!((prices["ethereum"] - 2400.0).abs() < 0.01);
        assert!((prices["bitcoin"] - 44000.0).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_coingecko_rate_limited_returns_rate_limited_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v3/simple/price"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&mock_server)
            .await;

        let provider = CoinGeckoProvider::with_base_url(format!("{}/api/v3", mock_server.uri()));
        let assets = vec!["ethereum".to_string()];
        let result = provider.get_prices(&assets).await;

        assert!(
            matches!(result, Err(ProviderError::RateLimited)),
            "expected RateLimited on 429, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_coingecko_invalid_json_returns_parse_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v3/simple/price"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{ bad json "))
            .mount(&mock_server)
            .await;

        let provider = CoinGeckoProvider::with_base_url(format!("{}/api/v3", mock_server.uri()));
        let assets = vec!["ethereum".to_string()];
        let result = provider.get_prices(&assets).await;

        assert!(
            matches!(result, Err(ProviderError::Parse(_))),
            "expected Parse error, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_coingecko_server_error_returns_network_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v3/simple/price"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock_server)
            .await;

        let provider = CoinGeckoProvider::with_base_url(format!("{}/api/v3", mock_server.uri()));
        let assets = vec!["ethereum".to_string()];
        let result = provider.get_prices(&assets).await;

        assert!(
            matches!(result, Err(ProviderError::Network(_))),
            "expected Network error on 503, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_coingecko_asset_without_usd_skipped() {
        let mock_server = MockServer::start().await;

        // Response has "ethereum" but without a "usd" key
        Mock::given(method("GET"))
            .and(path("/api/v3/simple/price"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"ethereum": {"eur": 2200.0}})),
            )
            .mount(&mock_server)
            .await;

        let provider = CoinGeckoProvider::with_base_url(format!("{}/api/v3", mock_server.uri()));
        let assets = vec!["ethereum".to_string()];
        let prices = provider.get_prices(&assets).await.unwrap();

        assert!(
            prices.is_empty(),
            "asset without 'usd' key should not appear"
        );
    }

    #[tokio::test]
    async fn test_coingecko_query_params_include_assets() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v3/simple/price"))
            .and(query_param("vs_currencies", "usd"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"ethereum": {"usd": 2500.0}})),
            )
            .mount(&mock_server)
            .await;

        let provider = CoinGeckoProvider::with_base_url(format!("{}/api/v3", mock_server.uri()));
        let assets = vec!["ethereum".to_string()];
        let prices = provider.get_prices(&assets).await.unwrap();

        assert!(prices.contains_key("ethereum"));
    }
}
