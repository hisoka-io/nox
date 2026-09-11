use crate::providers::PriceProvider;
use crate::types::{OracleConfig, PriceCache, PriceEntry};
use chrono::Utc;
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{error, info};

pub struct OracleFetcher {
    cache: PriceCache,
    provider: Arc<dyn PriceProvider>,
    config: OracleConfig,
}

impl OracleFetcher {
    pub fn new(cache: PriceCache, provider: Arc<dyn PriceProvider>, config: OracleConfig) -> Self {
        Self {
            cache,
            provider,
            config,
        }
    }

    pub async fn run(&self) {
        let mut interval = interval(Duration::from_secs(self.config.update_interval_secs));
        info!(
            "Starting Oracle Fetcher loop (Interval: {}s)",
            self.config.update_interval_secs
        );

        loop {
            interval.tick().await;

            match self.provider.get_prices(&self.config.assets).await {
                Ok(prices) => {
                    let mut cache_guard = self.cache.write().await;
                    let observed_at_unix = Utc::now().timestamp().unsigned_abs();
                    for (asset, price) in prices {
                        cache_guard.insert(
                            asset.clone(),
                            PriceEntry {
                                price_e8: price.get().to_string(),
                                observed_at_unix,
                                asset_id: asset,
                                source: self.provider.id().to_string(),
                            },
                        );
                    }
                    info!("Oracle Updated: {} prices updated", cache_guard.len());
                }
                Err(e) => {
                    error!("Failed to fetch prices: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::error::ProviderError;
    use crate::types::PriceE8;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use tokio::sync::RwLock;

    struct MockProvider {
        prices: HashMap<String, PriceE8>,
        id: &'static str,
    }

    impl MockProvider {
        fn new(prices: HashMap<String, PriceE8>) -> Self {
            Self { prices, id: "mock" }
        }

        fn failing() -> Self {
            Self {
                prices: HashMap::new(),
                id: "mock-fail",
            }
        }
    }

    #[async_trait]
    impl PriceProvider for MockProvider {
        fn id(&self) -> &'static str {
            self.id
        }

        async fn get_prices(
            &self,
            _assets: &[String],
        ) -> Result<HashMap<String, PriceE8>, ProviderError> {
            if self.id == "mock-fail" {
                return Err(ProviderError::Other("simulated failure".to_string()));
            }
            Ok(self.prices.clone())
        }
    }

    #[tokio::test]
    async fn test_fetcher_updates_cache_on_success() {
        let cache: PriceCache = Arc::new(RwLock::new(HashMap::new()));
        let mut prices = HashMap::new();
        prices.insert(
            "ethereum".to_string(),
            PriceE8::parse_decimal("2500").unwrap(),
        );
        prices.insert(
            "bitcoin".to_string(),
            PriceE8::parse_decimal("45000").unwrap(),
        );

        let provider = Arc::new(MockProvider::new(prices));
        let config = OracleConfig {
            assets: vec!["ethereum".to_string(), "bitcoin".to_string()],
            update_interval_secs: 60,
            staleness_threshold_secs: 300,
        };

        let fetcher = OracleFetcher::new(cache.clone(), provider, config);

        {
            let result = fetcher
                .provider
                .get_prices(&fetcher.config.assets)
                .await
                .unwrap();
            let mut guard = cache.write().await;
            let observed_at_unix = Utc::now().timestamp().unsigned_abs();
            for (asset, price) in result {
                guard.insert(
                    asset.clone(),
                    PriceEntry {
                        price_e8: price.get().to_string(),
                        observed_at_unix,
                        asset_id: asset,
                        source: fetcher.provider.id().to_string(),
                    },
                );
            }
        }

        let guard = cache.read().await;
        assert_eq!(guard["ethereum"].price_e8, "250000000000");
        assert_eq!(guard["bitcoin"].price_e8, "4500000000000");
        assert_eq!(guard["ethereum"].source, "mock");
    }

    #[tokio::test]
    async fn test_fetcher_leaves_cache_unchanged_on_failure() {
        let cache: PriceCache = Arc::new(RwLock::new(HashMap::new()));

        {
            let mut guard = cache.write().await;
            guard.insert(
                "ethereum".to_string(),
                PriceEntry {
                    price_e8: "100000000000".to_string(),
                    observed_at_unix: Utc::now().timestamp().unsigned_abs(),
                    asset_id: "ethereum".to_string(),
                    source: "old".to_string(),
                },
            );
        }

        let provider = Arc::new(MockProvider::failing());
        let config = OracleConfig::default();
        let fetcher = OracleFetcher::new(cache.clone(), provider, config);

        let result = fetcher.provider.get_prices(&fetcher.config.assets).await;
        assert!(result.is_err());

        let guard = cache.read().await;
        assert_eq!(guard["ethereum"].price_e8, "100000000000");
    }

    #[tokio::test]
    async fn test_fetcher_price_entry_has_correct_source() {
        let cache: PriceCache = Arc::new(RwLock::new(HashMap::new()));
        let mut prices = HashMap::new();
        prices.insert(
            "ethereum".to_string(),
            PriceE8::parse_decimal("3000").unwrap(),
        );

        let provider = Arc::new(MockProvider::new(prices));
        let config = OracleConfig {
            assets: vec!["ethereum".to_string()],
            update_interval_secs: 60,
            staleness_threshold_secs: 300,
        };
        let fetcher = OracleFetcher::new(cache.clone(), provider, config);

        {
            let result = fetcher
                .provider
                .get_prices(&fetcher.config.assets)
                .await
                .unwrap();
            let mut guard = cache.write().await;
            let observed_at_unix = Utc::now().timestamp().unsigned_abs();
            for (asset, price) in result {
                guard.insert(
                    asset.clone(),
                    PriceEntry {
                        price_e8: price.get().to_string(),
                        observed_at_unix,
                        asset_id: asset,
                        source: fetcher.provider.id().to_string(),
                    },
                );
            }
        }

        let guard = cache.read().await;
        assert_eq!(guard["ethereum"].source, "mock");
    }

    #[tokio::test]
    async fn test_fetcher_staleness_detection() {
        let cache: PriceCache = Arc::new(RwLock::new(HashMap::new()));
        let stale_threshold_secs = 60_i64;
        let stale_time = (Utc::now() - chrono::Duration::seconds(stale_threshold_secs + 10))
            .timestamp()
            .unsigned_abs();

        {
            let mut guard = cache.write().await;
            guard.insert(
                "ethereum".to_string(),
                PriceEntry {
                    price_e8: "200000000000".to_string(),
                    observed_at_unix: stale_time,
                    asset_id: "ethereum".to_string(),
                    source: "old".to_string(),
                },
            );
        }

        let guard = cache.read().await;
        let entry = &guard["ethereum"];
        let age_secs = Utc::now().timestamp().unsigned_abs() - entry.observed_at_unix;
        assert!(
            age_secs > stale_threshold_secs.unsigned_abs(),
            "entry should be considered stale: age={age_secs}s, threshold={stale_threshold_secs}s"
        );
    }
}
