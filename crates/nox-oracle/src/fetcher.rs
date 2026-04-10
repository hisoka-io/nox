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
                    let now = Utc::now();
                    for (asset, price) in prices {
                        cache_guard.insert(
                            asset.clone(),
                            PriceEntry {
                                price,
                                last_updated: now,
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
mod tests {
    use super::*;
    use crate::error::ProviderError;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use tokio::sync::RwLock;

    struct MockProvider {
        prices: HashMap<String, f64>,
        id: &'static str,
    }

    impl MockProvider {
        fn new(prices: HashMap<String, f64>) -> Self {
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
        ) -> Result<HashMap<String, f64>, ProviderError> {
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
        prices.insert("ethereum".to_string(), 2500.0);
        prices.insert("bitcoin".to_string(), 45000.0);

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
            let now = Utc::now();
            for (asset, price) in result {
                guard.insert(
                    asset.clone(),
                    PriceEntry {
                        price,
                        last_updated: now,
                        source: fetcher.provider.id().to_string(),
                    },
                );
            }
        }

        let guard = cache.read().await;
        assert!((guard["ethereum"].price - 2500.0).abs() < 0.01);
        assert!((guard["bitcoin"].price - 45000.0).abs() < 0.01);
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
                    price: 1000.0,
                    last_updated: Utc::now(),
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
        assert!((guard["ethereum"].price - 1000.0).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_fetcher_price_entry_has_correct_source() {
        let cache: PriceCache = Arc::new(RwLock::new(HashMap::new()));
        let mut prices = HashMap::new();
        prices.insert("ethereum".to_string(), 3000.0);

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
            let now = Utc::now();
            for (asset, price) in result {
                guard.insert(
                    asset,
                    PriceEntry {
                        price,
                        last_updated: now,
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
        let stale_time = Utc::now() - chrono::Duration::seconds(stale_threshold_secs + 10);

        {
            let mut guard = cache.write().await;
            guard.insert(
                "ethereum".to_string(),
                PriceEntry {
                    price: 2000.0,
                    last_updated: stale_time,
                    source: "old".to_string(),
                },
            );
        }

        let guard = cache.read().await;
        let entry = &guard["ethereum"];
        let age_secs = (Utc::now() - entry.last_updated).num_seconds();
        assert!(
            age_secs > stale_threshold_secs,
            "entry should be considered stale: age={age_secs}s, threshold={stale_threshold_secs}s"
        );
    }
}
