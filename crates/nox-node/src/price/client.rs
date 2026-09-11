use crate::telemetry::metrics::MetricsService;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::warn;

const PRICE_HTTP_TIMEOUT_SECS: u64 = 5;

#[derive(Error, Debug)]
pub enum PriceClientError {
    #[error("price oracle request failed: {0}")]
    Network(#[from] reqwest::Error),
    #[error("asset {asset_id} not found")]
    AssetNotFound { asset_id: String },
    #[error("invalid price for {asset_id}: {detail}")]
    InvalidPrice { asset_id: String, detail: String },
    #[error("stale price for {asset_id}: age {age_secs}s exceeds max {max_secs}s")]
    StalePrice {
        asset_id: String,
        age_secs: u64,
        max_secs: u64,
    },
    #[error("future price for {asset_id}: skew {skew_secs}s exceeds max {max_secs}s")]
    FuturePrice {
        asset_id: String,
        skew_secs: u64,
        max_secs: u64,
    },
    #[error("system clock is before the Unix epoch")]
    Clock,
}

#[derive(Deserialize, Debug, Clone)]
struct PriceEntryDto {
    price_e8: String,
    observed_at_unix: u64,
    asset_id: String,
    source: String,
}

type PriceMap = HashMap<String, PriceEntryDto>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceQuote {
    pub price_e8: u128,
    pub observed_at_unix: u64,
    pub asset_id: String,
}

#[async_trait::async_trait]
pub trait FixedPriceSource: Send + Sync {
    async fn get_price(&self, asset_id: &str) -> Result<PriceQuote, PriceClientError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriceFreshness {
    pub cache_ttl: Duration,
    pub max_observation_age: Duration,
    pub max_future_skew: Duration,
}

impl Default for PriceFreshness {
    fn default() -> Self {
        Self {
            cache_ttl: Duration::from_secs(crate::config::DEFAULT_ORACLE_CACHE_TTL_SECS),
            max_observation_age: Duration::from_secs(
                crate::config::DEFAULT_ORACLE_MAX_OBSERVATION_AGE_SECS,
            ),
            max_future_skew: Duration::from_secs(
                crate::config::DEFAULT_ORACLE_MAX_FUTURE_SKEW_SECS,
            ),
        }
    }
}

#[derive(Clone)]
pub struct PriceClient {
    client: Client,
    base_url: String,
    cache: Arc<RwLock<(Instant, PriceMap)>>,
    freshness: PriceFreshness,
    metrics: Option<MetricsService>,
}

impl PriceClient {
    pub fn new(base_url: &str, freshness: PriceFreshness) -> Result<Self, PriceClientError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(PRICE_HTTP_TIMEOUT_SECS))
            .build()?;
        Ok(Self {
            client,
            base_url: base_url.to_string(),
            cache: Arc::new(RwLock::new((
                Instant::now()
                    .checked_sub(freshness.cache_ttl)
                    .unwrap_or_else(Instant::now),
                HashMap::new(),
            ))),
            freshness,
            metrics: None,
        })
    }

    #[must_use]
    pub fn with_metrics(mut self, metrics: MetricsService) -> Self {
        self.metrics = Some(metrics);
        self
    }

    async fn fetch_prices(&self) -> Result<PriceMap, PriceClientError> {
        let url = format!("{}/prices", self.base_url);
        Ok(self.client.get(&url).send().await?.json().await?)
    }

    fn validate_quote(
        &self,
        requested_asset: &str,
        entry: &PriceEntryDto,
    ) -> Result<PriceQuote, PriceClientError> {
        if requested_asset != entry.asset_id {
            return Err(PriceClientError::InvalidPrice {
                asset_id: requested_asset.to_string(),
                detail: "response map key does not match asset_id".to_string(),
            });
        }
        if entry.price_e8.is_empty() || !entry.price_e8.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(PriceClientError::InvalidPrice {
                asset_id: requested_asset.to_string(),
                detail: "price_e8 must be a canonical unsigned integer".to_string(),
            });
        }
        if entry.price_e8.len() > 1 && entry.price_e8.starts_with('0') {
            return Err(PriceClientError::InvalidPrice {
                asset_id: requested_asset.to_string(),
                detail: "price_e8 has a leading zero".to_string(),
            });
        }
        let price_e8 =
            entry
                .price_e8
                .parse::<u128>()
                .map_err(|_| PriceClientError::InvalidPrice {
                    asset_id: requested_asset.to_string(),
                    detail: "price_e8 exceeds u128".to_string(),
                })?;
        if price_e8 == 0 {
            return Err(PriceClientError::InvalidPrice {
                asset_id: requested_asset.to_string(),
                detail: "price_e8 must be positive".to_string(),
            });
        }
        if entry.source.is_empty() {
            return Err(PriceClientError::InvalidPrice {
                asset_id: requested_asset.to_string(),
                detail: "source must not be empty".to_string(),
            });
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PriceClientError::Clock)?
            .as_secs();
        if entry.observed_at_unix > now {
            let skew_secs = entry.observed_at_unix - now;
            if skew_secs > self.freshness.max_future_skew.as_secs() {
                return Err(PriceClientError::FuturePrice {
                    asset_id: requested_asset.to_string(),
                    skew_secs,
                    max_secs: self.freshness.max_future_skew.as_secs(),
                });
            }
        } else {
            let age_secs = now - entry.observed_at_unix;
            if age_secs > self.freshness.max_observation_age.as_secs() {
                return Err(PriceClientError::StalePrice {
                    asset_id: requested_asset.to_string(),
                    age_secs,
                    max_secs: self.freshness.max_observation_age.as_secs(),
                });
            }
        }
        Ok(PriceQuote {
            price_e8,
            observed_at_unix: entry.observed_at_unix,
            asset_id: entry.asset_id.clone(),
        })
    }
}

#[async_trait::async_trait]
impl FixedPriceSource for PriceClient {
    async fn get_price(&self, asset_id: &str) -> Result<PriceQuote, PriceClientError> {
        {
            let cache_guard = self.cache.read().await;
            if cache_guard.0.elapsed() < self.freshness.cache_ttl {
                if let Some(entry) = cache_guard.1.get(asset_id) {
                    return self.validate_quote(asset_id, entry);
                }
            }
        }

        let prices = match self.fetch_prices().await {
            Ok(prices) => {
                if let Some(metrics) = &self.metrics {
                    metrics
                        .oracle_fetch_total
                        .get_or_create(&vec![("result".into(), "success".into())])
                        .inc();
                }
                prices
            }
            Err(fetch_error) => {
                if let Some(metrics) = &self.metrics {
                    metrics
                        .oracle_fetch_total
                        .get_or_create(&vec![("result".into(), "error".into())])
                        .inc();
                }
                warn!("Price fetch failed; checking validated cached observation");
                let cache_guard = self.cache.read().await;
                if let Some(entry) = cache_guard.1.get(asset_id) {
                    let quote = self.validate_quote(asset_id, entry)?;
                    if let Some(metrics) = &self.metrics {
                        metrics
                            .oracle_fetch_total
                            .get_or_create(&vec![("result".into(), "stale_cache".into())])
                            .inc();
                    }
                    return Ok(quote);
                }
                return Err(fetch_error);
            }
        };

        let entry = prices
            .get(asset_id)
            .ok_or_else(|| PriceClientError::AssetNotFound {
                asset_id: asset_id.to_string(),
            })?;
        let quote = self.validate_quote(asset_id, entry)?;
        *self.cache.write().await = (Instant::now(), prices);
        Ok(quote)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> PriceClient {
        PriceClient::new(
            "http://127.0.0.1:1",
            PriceFreshness {
                cache_ttl: Duration::from_secs(10),
                max_observation_age: Duration::from_mins(5),
                max_future_skew: Duration::from_secs(30),
            },
        )
        .expect("price client")
    }

    fn entry(price_e8: &str, observed_at_unix: u64, asset_id: &str) -> PriceEntryDto {
        PriceEntryDto {
            price_e8: price_e8.to_string(),
            observed_at_unix,
            asset_id: asset_id.to_string(),
            source: "aggregate".to_string(),
        }
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn accepts_canonical_fresh_quote() {
        let quote = client()
            .validate_quote("ethereum", &entry("250012345678", now(), "ethereum"))
            .unwrap();
        assert_eq!(quote.price_e8, 250_012_345_678);
    }

    #[test]
    fn rejects_malformed_zero_and_mismatched_quotes() {
        for price in ["", "0", "01", "1.0", "abc"] {
            assert!(client()
                .validate_quote("ethereum", &entry(price, now(), "ethereum"))
                .is_err());
        }
        assert!(client()
            .validate_quote("ethereum", &entry("1", now(), "bitcoin"))
            .is_err());
    }

    #[test]
    fn rejects_stale_and_excessively_future_observations() {
        assert!(matches!(
            client().validate_quote("ethereum", &entry("1", now() - 301, "ethereum")),
            Err(PriceClientError::StalePrice { .. })
        ));
        assert!(matches!(
            client().validate_quote("ethereum", &entry("1", now() + 31, "ethereum")),
            Err(PriceClientError::FuturePrice { .. })
        ));
    }
}
