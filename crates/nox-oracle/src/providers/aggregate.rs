use super::PriceProvider;
use crate::error::ProviderError;
use crate::types::PriceE8;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, warn};

/// Minimum number of independent providers that must agree on an asset before its price
/// is published. One source alone cannot be checked for outliers.
pub const DEFAULT_MIN_SOURCES: usize = 2;

pub struct AggregateProvider {
    providers: Vec<Arc<dyn PriceProvider>>,
    min_sources: usize,
}

impl AggregateProvider {
    /// Aggregates `providers` and requires [`DEFAULT_MIN_SOURCES`] agreeing sources per asset.
    #[must_use]
    pub fn new(providers: Vec<Arc<dyn PriceProvider>>) -> Self {
        Self {
            providers,
            min_sources: DEFAULT_MIN_SOURCES,
        }
    }

    /// Overrides the per-asset source quorum. Values below 1 are treated as 1.
    #[must_use]
    pub fn with_min_sources(mut self, min_sources: usize) -> Self {
        self.min_sources = min_sources.max(1);
        self
    }

    #[must_use]
    pub fn min_sources(&self) -> usize {
        self.min_sources
    }

    #[must_use]
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Queries every provider concurrently, so one slow upstream cannot delay the others.
    async fn fetch_all(&self, assets: &[String]) -> Vec<(String, HashMap<String, PriceE8>)> {
        let mut tasks = tokio::task::JoinSet::new();
        for (index, provider) in self.providers.iter().enumerate() {
            let provider = Arc::clone(provider);
            let assets = assets.to_vec();
            tasks.spawn(async move {
                let result = provider.get_prices(&assets).await;
                (index, provider.id(), result)
            });
        }
        let mut results = Vec::with_capacity(self.providers.len());
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((index, id, Ok(prices))) if !prices.is_empty() => {
                    info!("Fetched prices from provider: {id}");
                    results.push((index, id.to_string(), prices));
                }
                Ok((_, id, Ok(_))) => {
                    warn!("Provider {id} returned empty prices");
                }
                Ok((_, id, Err(error))) => {
                    warn!("Provider {id} failed: {error}");
                }
                Err(error) => {
                    warn!("Provider task failed: {error}");
                }
            }
        }
        results.sort_by_key(|(index, _, _)| *index);
        results
            .into_iter()
            .map(|(_, id, prices)| (id, prices))
            .collect()
    }
}

#[async_trait]
impl PriceProvider for AggregateProvider {
    fn id(&self) -> &'static str {
        "aggregate"
    }

    /// Queries all providers, takes the median per asset and rejects >50% outliers.
    /// An asset is published only when at least `min_sources` providers agree on it.
    async fn get_prices(
        &self,
        assets: &[String],
    ) -> Result<HashMap<String, PriceE8>, ProviderError> {
        let all_results = self.fetch_all(assets).await;

        if all_results.is_empty() {
            return Err(ProviderError::Other("All providers failed".to_string()));
        }
        if all_results.len() < self.min_sources {
            let healthy: Vec<&str> = all_results.iter().map(|(id, _)| id.as_str()).collect();
            return Err(ProviderError::Other(format!(
                "Insufficient price sources: {} healthy ({}), {} required",
                all_results.len(),
                healthy.join(","),
                self.min_sources
            )));
        }

        let mut aggregated: HashMap<String, PriceE8> = HashMap::new();

        for asset in assets {
            let mut quotes: Vec<PriceE8> = all_results
                .iter()
                .filter_map(|(_, prices)| prices.get(asset).copied())
                .collect();

            if quotes.len() < self.min_sources {
                if !quotes.is_empty() {
                    warn!(
                        "Only {} source(s) priced {asset}; {} required",
                        quotes.len(),
                        self.min_sources
                    );
                }
                continue;
            }

            quotes.sort_unstable();
            let median = if quotes.len().is_multiple_of(2) {
                midpoint(quotes[quotes.len() / 2 - 1], quotes[quotes.len() / 2])?
            } else {
                quotes[quotes.len() / 2]
            };

            let filtered: Vec<PriceE8> = quotes
                .iter()
                .filter(|&&price| {
                    let deviation = price.get().abs_diff(median.get());
                    let is_outlier = deviation
                        .checked_mul(2)
                        .is_none_or(|twice_deviation| twice_deviation > median.get());
                    if is_outlier {
                        warn!(
                            "Outlier rejected for {}: {} (median: {})",
                            asset,
                            price.get(),
                            median.get()
                        );
                        false
                    } else {
                        true
                    }
                })
                .copied()
                .collect();

            if filtered.is_empty() || filtered.len() < self.min_sources {
                warn!("No acceptable price quorum for {asset}");
            } else if filtered.len().is_multiple_of(2) {
                let mid = filtered.len() / 2;
                aggregated.insert(asset.clone(), midpoint(filtered[mid - 1], filtered[mid])?);
            } else {
                aggregated.insert(asset.clone(), filtered[filtered.len() / 2]);
            }
        }

        if aggregated.is_empty() {
            return Err(ProviderError::Other(format!(
                "No asset reached a {}-source price quorum",
                self.min_sources
            )));
        }

        info!(
            "Aggregated prices from {} providers for {} assets",
            all_results.len(),
            aggregated.len()
        );

        Ok(aggregated)
    }
}

fn midpoint(lower: PriceE8, upper: PriceE8) -> Result<PriceE8, ProviderError> {
    let value = lower
        .get()
        .checked_add((upper.get() - lower.get()) / 2)
        .ok_or_else(|| ProviderError::Other("Price midpoint overflow".to_string()))?;
    PriceE8::parse_decimal(&format!("{value}e-8"))
        .map_err(|error| ProviderError::Parse(error.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex;

    struct MockProvider {
        id: &'static str,
        should_fail: bool,
        prices: HashMap<String, PriceE8>,
        call_count: Arc<Mutex<usize>>,
    }

    impl MockProvider {
        fn new(id: &'static str, should_fail: bool, prices: HashMap<String, PriceE8>) -> Self {
            Self {
                id,
                should_fail,
                prices,
                call_count: Arc::new(Mutex::new(0)),
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
            *self.call_count.lock().unwrap() += 1;
            if self.should_fail {
                Err(ProviderError::Network(
                    reqwest::Client::new()
                        .get("http://fail")
                        .send()
                        .await
                        .unwrap_err(),
                )) // Dummy network error
            } else {
                Ok(self.prices.clone())
            }
        }
    }

    fn mock_with_prices(id: &'static str, prices: &[(&str, f64)]) -> Arc<MockProvider> {
        let map: HashMap<String, PriceE8> = prices
            .iter()
            .map(|(asset, value)| {
                (
                    (*asset).to_string(),
                    PriceE8::parse_decimal(&value.to_string()).expect("valid test price"),
                )
            })
            .collect();
        Arc::new(MockProvider::new(id, false, map))
    }

    #[tokio::test]
    async fn test_failover_logic() {
        let mut p1_prices = HashMap::new();
        p1_prices.insert("A".to_string(), PriceE8::parse_decimal("100").unwrap());
        let p1 = Arc::new(MockProvider::new("p1", true, p1_prices)); // Fails

        let mut p2_prices = HashMap::new();
        p2_prices.insert("A".to_string(), PriceE8::parse_decimal("200").unwrap());
        let p2 = Arc::new(MockProvider::new("p2", false, p2_prices)); // Succeeds

        let agg = AggregateProvider::new(vec![p1.clone(), p2.clone()]).with_min_sources(1);

        let prices = agg.get_prices(&["A".to_string()]).await.unwrap();

        // Should get price from P2
        assert_eq!(prices.get("A").unwrap().get(), 20_000_000_000);

        // P1 should be called
        assert_eq!(*p1.call_count.lock().unwrap(), 1);
        // P2 should be called
        assert_eq!(*p2.call_count.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn test_median_odd_number_of_providers() {
        let p1 = mock_with_prices("p1", &[("ETH", 1000.0)]);
        let p2 = mock_with_prices("p2", &[("ETH", 2000.0)]);
        let p3 = mock_with_prices("p3", &[("ETH", 3000.0)]);

        let agg = AggregateProvider::new(vec![p1, p2, p3]);
        let prices = agg.get_prices(&["ETH".to_string()]).await.unwrap();

        assert!(
            prices["ETH"].get() == 200_000_000_000,
            "median of [1000, 2000, 3000] should be 2000, got {}",
            prices["ETH"].get()
        );
    }

    #[tokio::test]
    async fn test_median_even_number_of_providers() {
        let p1 = mock_with_prices("p1", &[("ETH", 1000.0)]);
        let p2 = mock_with_prices("p2", &[("ETH", 2000.0)]);
        let p3 = mock_with_prices("p3", &[("ETH", 3000.0)]);
        let p4 = mock_with_prices("p4", &[("ETH", 4000.0)]);

        let agg = AggregateProvider::new(vec![p1, p2, p3, p4]);
        let prices = agg.get_prices(&["ETH".to_string()]).await.unwrap();

        assert!(
            prices["ETH"].get() == 250_000_000_000,
            "median of [1000, 2000, 3000, 4000] should be 2500, got {}",
            prices["ETH"].get()
        );
    }

    #[tokio::test]
    async fn test_outlier_rejection() {
        // Two providers agree at ~100, one is 10x higher -- should be rejected
        let p1 = mock_with_prices("p1", &[("ETH", 100.0)]);
        let p2 = mock_with_prices("p2", &[("ETH", 110.0)]);
        let p3 = mock_with_prices("p3", &[("ETH", 1000.0)]); // 10x outlier

        let agg = AggregateProvider::new(vec![p1, p2, p3]);
        let prices = agg.get_prices(&["ETH".to_string()]).await.unwrap();

        // Median of [100, 110, 1000] = 110
        // 1000 is ~809% away from median -> rejected
        // Filtered set: [100, 110] -> median = 105
        assert!(
            prices["ETH"].get() == 10_500_000_000,
            "outlier should be rejected, expected 105.0, got {}",
            prices["ETH"].get()
        );
    }

    #[tokio::test]
    async fn test_all_providers_fail() {
        let p1 = Arc::new(MockProvider::new("p1", true, HashMap::new()));
        let p2 = Arc::new(MockProvider::new("p2", true, HashMap::new()));

        let agg = AggregateProvider::new(vec![p1, p2]);
        let result = agg.get_prices(&["ETH".to_string()]).await;

        assert!(result.is_err(), "should error when all providers fail");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("All providers failed"),
            "error should mention all providers failed: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_single_provider_returns_directly() {
        let p1 = mock_with_prices("p1", &[("ETH", 42.0), ("BTC", 99.0)]);

        let agg = AggregateProvider::new(vec![p1]).with_min_sources(1);
        let prices = agg
            .get_prices(&["ETH".to_string(), "BTC".to_string()])
            .await
            .unwrap();

        assert!(
            prices["ETH"].get() == 4_200_000_000,
            "single provider should return ETH directly"
        );
        assert!(
            prices["BTC"].get() == 9_900_000_000,
            "single provider should return BTC directly"
        );
    }

    #[tokio::test]
    async fn test_multiple_assets_aggregated_independently() {
        let p1 = mock_with_prices("p1", &[("ETH", 100.0), ("BTC", 50000.0)]);
        let p2 = mock_with_prices("p2", &[("ETH", 120.0), ("BTC", 51000.0)]);
        let p3 = mock_with_prices("p3", &[("ETH", 110.0), ("BTC", 49000.0)]);

        let agg = AggregateProvider::new(vec![p1, p2, p3]);
        let prices = agg
            .get_prices(&["ETH".to_string(), "BTC".to_string()])
            .await
            .unwrap();

        // ETH: median of [100, 110, 120] = 110
        assert!(
            prices["ETH"].get() == 11_000_000_000,
            "ETH median should be 110.0, got {}",
            prices["ETH"].get()
        );
        // BTC: median of [49000, 50000, 51000] = 50000
        assert!(
            prices["BTC"].get() == 5_000_000_000_000,
            "BTC median should be 50000.0, got {}",
            prices["BTC"].get()
        );
    }

    #[tokio::test]
    async fn test_partial_asset_coverage() {
        // p1 has ETH only, p2 has BTC only, p3 has both
        let p1 = mock_with_prices("p1", &[("ETH", 100.0)]);
        let p2 = mock_with_prices("p2", &[("BTC", 50000.0)]);
        let p3 = mock_with_prices("p3", &[("ETH", 110.0), ("BTC", 51000.0)]);

        let agg = AggregateProvider::new(vec![p1, p2, p3]);
        let prices = agg
            .get_prices(&["ETH".to_string(), "BTC".to_string()])
            .await
            .unwrap();

        // ETH: [100, 110] -> median = 105
        assert!(
            prices["ETH"].get() == 10_500_000_000,
            "ETH should be 105.0, got {}",
            prices["ETH"].get()
        );
        // BTC: [50000, 51000] -> median = 50500
        assert!(
            prices["BTC"].get() == 5_050_000_000_000,
            "BTC should be 50500.0, got {}",
            prices["BTC"].get()
        );
    }

    #[tokio::test]
    async fn disputed_asset_is_omitted_while_agreed_asset_remains() {
        let first = mock_with_prices("first", &[("fee", 100.0), ("native", 100.0)]);
        let second = mock_with_prices("second", &[("fee", 1000.0), ("native", 100.0)]);
        let aggregate = AggregateProvider::new(vec![first, second]);
        let prices = aggregate
            .get_prices(&["fee".to_string(), "native".to_string()])
            .await
            .unwrap();

        assert!(!prices.contains_key("fee"));
        assert_eq!(prices["native"].get(), 10_000_000_000);
    }

    #[tokio::test]
    async fn single_healthy_source_is_not_published_by_default() {
        let failing = Arc::new(MockProvider::new("down", true, HashMap::new()));
        let healthy = mock_with_prices("up", &[("ETH", 2500.0)]);

        let agg = AggregateProvider::new(vec![failing, healthy]);
        assert_eq!(agg.min_sources(), DEFAULT_MIN_SOURCES);
        let error = agg.get_prices(&["ETH".to_string()]).await.unwrap_err();

        assert!(
            error.to_string().contains("Insufficient price sources"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn asset_priced_by_one_source_is_omitted() {
        let p1 = mock_with_prices("p1", &[("ETH", 100.0), ("BTC", 50000.0)]);
        let p2 = mock_with_prices("p2", &[("ETH", 102.0)]);

        let agg = AggregateProvider::new(vec![p1, p2]);
        let prices = agg
            .get_prices(&["ETH".to_string(), "BTC".to_string()])
            .await
            .unwrap();

        assert_eq!(prices["ETH"].get(), 10_100_000_000);
        assert!(!prices.contains_key("BTC"));
    }

    #[tokio::test]
    async fn quorum_counts_sources_left_after_outlier_rejection() {
        let p1 = mock_with_prices("p1", &[("ETH", 100.0), ("BTC", 50000.0)]);
        let p2 = mock_with_prices("p2", &[("ETH", 1000.0), ("BTC", 50100.0)]);
        let p3 = mock_with_prices("p3", &[("ETH", 5000.0), ("BTC", 49900.0)]);

        let agg = AggregateProvider::new(vec![p1, p2, p3]);
        let prices = agg
            .get_prices(&["ETH".to_string(), "BTC".to_string()])
            .await
            .unwrap();

        assert!(!prices.contains_key("ETH"));
        assert_eq!(prices["BTC"].get(), 5_000_000_000_000);
    }

    #[tokio::test]
    async fn no_asset_reaching_quorum_is_an_error() {
        let p1 = mock_with_prices("p1", &[("ETH", 100.0)]);
        let p2 = mock_with_prices("p2", &[("BTC", 50000.0)]);

        let agg = AggregateProvider::new(vec![p1, p2]);
        let error = agg
            .get_prices(&["ETH".to_string(), "BTC".to_string()])
            .await
            .unwrap_err();

        assert!(
            error.to_string().contains("quorum"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn min_sources_below_one_is_clamped() {
        let p1 = mock_with_prices("p1", &[("ETH", 42.0)]);
        let agg = AggregateProvider::new(vec![p1]).with_min_sources(0);
        assert_eq!(agg.min_sources(), 1);
        assert_eq!(agg.provider_count(), 1);
    }
}
