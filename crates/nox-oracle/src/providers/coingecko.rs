use super::PriceProvider;
use crate::error::ProviderError;
use crate::types::PriceE8;
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;

pub const DEFAULT_BASE_URL: &str = "https://api.coingecko.com/api/v3";
const API_KEY_HEADER: &str = "x-cg-demo-api-key";

pub struct CoinGeckoProvider {
    client: Client,
    base_url: String,
    api_key: Option<String>,
}

impl Default for CoinGeckoProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CoinGeckoProvider {
    #[must_use]
    pub fn new() -> Self {
        Self::with_client(
            crate::http::default_provider_client(),
            DEFAULT_BASE_URL.to_string(),
        )
    }

    #[must_use]
    pub fn with_base_url(base_url: String) -> Self {
        Self::with_client(crate::http::default_provider_client(), base_url)
    }

    /// Uses a caller-supplied client (see [`crate::http::provider_client`]).
    #[must_use]
    pub fn with_client(client: Client, base_url: String) -> Self {
        Self {
            client,
            base_url,
            api_key: None,
        }
    }

    /// Sends a `CoinGecko` demo API key. The keyless public API also works when the
    /// request carries a descriptive User-Agent.
    #[must_use]
    pub fn with_api_key(mut self, api_key: Option<String>) -> Self {
        self.api_key = api_key.filter(|key| !key.trim().is_empty());
        self
    }
}

#[derive(Deserialize)]
struct CgResponse(HashMap<String, HashMap<String, serde_json::Number>>);

#[async_trait]
impl PriceProvider for CoinGeckoProvider {
    fn id(&self) -> &'static str {
        "coingecko"
    }

    async fn get_prices(
        &self,
        assets: &[String],
    ) -> Result<HashMap<String, PriceE8>, ProviderError> {
        let ids = assets.join(",");
        let url = format!("{}/simple/price", self.base_url);

        let mut request = self
            .client
            .get(&url)
            .query(&[("ids", &ids), ("vs_currencies", &"usd".to_string())]);
        if let Some(api_key) = &self.api_key {
            request = request.header(API_KEY_HEADER, api_key);
        }
        let resp = request.send().await.map_err(ProviderError::Network)?;

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
                prices.insert(
                    asset,
                    PriceE8::parse_decimal(&price.to_string())
                        .map_err(|error| ProviderError::Parse(error.to_string()))?,
                );
            }
        }

        Ok(prices)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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

        assert_eq!(prices["ethereum"].get(), 240_000_000_000);
        assert_eq!(prices["bitcoin"].get(), 4_400_000_000_000);
    }

    #[tokio::test]
    async fn default_client_sends_user_agent_and_optional_demo_key() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/simple/price"))
            .and(wiremock::matchers::header(
                "user-agent",
                crate::http::PROVIDER_USER_AGENT,
            ))
            .and(wiremock::matchers::header("x-cg-demo-api-key", "demo-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ethereum": {"usd": 2500.0}
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = CoinGeckoProvider::with_base_url(mock_server.uri())
            .with_api_key(Some("demo-key".to_string()));
        let prices = provider
            .get_prices(&["ethereum".to_string()])
            .await
            .unwrap();
        assert_eq!(prices["ethereum"].get(), 250_000_000_000);
    }

    #[tokio::test]
    async fn preserves_decimal_lexeme_above_ieee_754_integer_precision() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v3/simple/price"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                r#"{"ethereum":{"usd":90071992.54740993}}"#,
                "application/json",
            ))
            .mount(&mock_server)
            .await;

        let provider = CoinGeckoProvider::with_base_url(format!("{}/api/v3", mock_server.uri()));
        let prices = provider
            .get_prices(&["ethereum".to_string()])
            .await
            .unwrap();

        assert_eq!(prices["ethereum"].get(), 9_007_199_254_740_993);
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
