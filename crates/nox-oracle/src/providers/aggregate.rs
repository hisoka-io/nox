use super::PriceProvider;
use crate::error::ProviderError;
use crate::types::PriceE8;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, warn};

pub struct AggregateProvider {
    providers: Vec<Arc<dyn PriceProvider>>,
}

impl AggregateProvider {
    #[must_use]
    pub fn new(providers: Vec<Arc<dyn PriceProvider>>) -> Self {
        Self { providers }
    }
}

#[async_trait]
impl PriceProvider for AggregateProvider {
    fn id(&self) -> &'static str {
        "aggregate"
    }

    /// Queries all providers, takes median per asset, rejects >50% outliers.
    async fn get_prices(
        &self,
        assets: &[String],
    ) -> Result<HashMap<String, PriceE8>, ProviderError> {
        let mut all_results: Vec<(String, HashMap<String, PriceE8>)> = Vec::new();

        for provider in &self.providers {
            match provider.get_prices(assets).await {
                Ok(prices) if !prices.is_empty() => {
                    info!("Fetched prices from provider: {}", provider.id());
                    all_results.push((provider.id().to_string(), prices));
                }
                Ok(_) => {
                    warn!("Provider {} returned empty prices", provider.id());
                }
                Err(e) => {
                    warn!("Provider {} failed: {}", provider.id(), e);
                }
            }
        }

        if all_results.is_empty() {
            return Err(ProviderError::Other("All providers failed".to_string()));
        }

        if all_results.len() == 1 {
            return all_results
                .into_iter()
                .next()
                .map(|(_, prices)| prices)
                .ok_or_else(|| ProviderError::Other("No provider results".to_string()));
        }

        let mut aggregated: HashMap<String, PriceE8> = HashMap::new();

        for asset in assets {
            let mut quotes: Vec<PriceE8> = all_results
                .iter()
                .filter_map(|(_, prices)| prices.get(asset).copied())
                .collect();

            if quotes.is_empty() {
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

            if filtered.is_empty() {
                warn!("No acceptable price quorum for {asset}");
            } else if filtered.len().is_multiple_of(2) {
                let mid = filtered.len() / 2;
                aggregated.insert(asset.clone(), midpoint(filtered[mid - 1], filtered[mid])?);
            } else {
                aggregated.insert(asset.clone(), filtered[filtered.len() / 2]);
            }
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

        let agg = AggregateProvider::new(vec![p1.clone(), p2.clone()]);

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

        let agg = AggregateProvider::new(vec![p1]);
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
}
