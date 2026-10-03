use super::PriceProvider;
use crate::error::ProviderError;
use crate::types::PriceE8;
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;

pub const DEFAULT_BASE_URL: &str = "https://min-api.cryptocompare.com";

/// `CryptoCompare` price provider (min-api endpoint).
/// The endpoint now answers 401 without an API key, so the price server only enables this
/// provider when a key is configured.
pub struct CryptoCompareProvider {
    client: Client,
    base_url: String,
    api_key: Option<String>,
}

impl Default for CryptoCompareProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoCompareProvider {
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

    /// Sends the API key as `authorization: Apikey <key>`.
    #[must_use]
    pub fn with_api_key(mut self, api_key: Option<String>) -> Self {
        self.api_key = api_key.filter(|key| !key.trim().is_empty());
        self
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
struct CcResponse(HashMap<String, HashMap<String, serde_json::Number>>);

#[async_trait]
impl PriceProvider for CryptoCompareProvider {
    fn id(&self) -> &'static str {
        "cryptocompare"
    }

    async fn get_prices(
        &self,
        assets: &[String],
    ) -> Result<HashMap<String, PriceE8>, ProviderError> {
        let symbols: Vec<&str> = assets
            .iter()
            .filter_map(|a| Self::asset_to_symbol(a))
            .collect();

        if symbols.is_empty() {
            return Ok(HashMap::new());
        }

        let fsyms = symbols.join(",");
        let url = format!("{}/data/pricemulti", self.base_url);

        let mut request = self
            .client
            .get(&url)
            .query(&[("fsyms", &fsyms), ("tsyms", &"USD".to_string())]);
        if let Some(api_key) = &self.api_key {
            request = request.header(reqwest::header::AUTHORIZATION, format!("Apikey {api_key}"));
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

        let data: CcResponse = resp
            .json()
            .await
            .map_err(|e| ProviderError::Parse(e.to_string()))?;

        let mut prices = HashMap::new();
        for (symbol, currency_map) in &data.0 {
            if let Some(price) = currency_map.get("USD") {
                if let Some(asset_id) = Self::symbol_to_asset(symbol) {
                    prices.insert(
                        asset_id.to_string(),
                        PriceE8::parse_decimal(&price.to_string())
                            .map_err(|error| ProviderError::Parse(error.to_string()))?,
                    );
                }
            }
        }

        Ok(prices)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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

        assert_eq!(prices["ethereum"].get(), 240_000_000_000);
        assert_eq!(prices["bitcoin"].get(), 4_400_000_000_000);
    }

    #[tokio::test]
    async fn preserves_decimal_lexeme_above_ieee_754_integer_precision() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/data/pricemulti"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(r#"{"ETH":{"USD":90071992.54740993}}"#, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let provider = CryptoCompareProvider::with_base_url(mock_server.uri());
        let prices = provider
            .get_prices(&["ethereum".to_string()])
            .await
            .unwrap();

        assert_eq!(prices["ethereum"].get(), 9_007_199_254_740_993);
    }

    #[tokio::test]
    async fn configured_api_key_is_sent_as_authorization_header() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/data/pricemulti"))
            .and(wiremock::matchers::header(
                "authorization",
                "Apikey test-key",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ETH": {"USD": 2400.0}
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = CryptoCompareProvider::with_base_url(mock_server.uri())
            .with_api_key(Some("test-key".to_string()));
        let prices = provider
            .get_prices(&["ethereum".to_string()])
            .await
            .unwrap();
        assert_eq!(prices["ethereum"].get(), 240_000_000_000);
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
