use crate::telemetry::metrics::MetricsService;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::warn;

#[derive(Error, Debug)]
pub enum PriceClientError {
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Asset not found")]
    AssetNotFound,
    #[error("Stale price for {asset}: age {age_secs}s exceeds max {max_secs}s")]
    StalePrice {
        asset: String,
        age_secs: u64,
        max_secs: u64,
    },
}

#[derive(Deserialize, Debug, Clone)]
pub struct PriceEntry {
    pub price: f64,
}

type PriceMap = HashMap<String, PriceEntry>;

#[async_trait::async_trait]
pub trait PriceSource: Send + Sync {
    async fn get_price(&self, asset: &str) -> Result<f64, PriceClientError>;
}

#[derive(Clone)]
pub struct PriceClient {
    client: Client,
    base_url: String,
    cache: Arc<RwLock<(Instant, PriceMap)>>,
    ttl: Duration,
    /// Maximum age for stale cache fallback (reject if older)
    max_staleness: Duration,
    metrics: Option<MetricsService>,
}

impl PriceClient {
    #[must_use]
    pub fn new(base_url: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        Self {
            client,
            base_url: base_url.to_string(),
            cache: Arc::new(RwLock::new((
                Instant::now()
                    .checked_sub(Duration::from_secs(60))
                    .unwrap_or_else(Instant::now),
                HashMap::new(),
            ))),
            ttl: Duration::from_secs(10), // Cache for 10 seconds
            max_staleness: Duration::from_secs(300), // Reject stale cache older than 5 minutes
            metrics: None,
        }
    }

    /// Attach metrics for oracle fetch tracking.
    #[must_use]
    pub fn with_metrics(mut self, metrics: MetricsService) -> Self {
        self.metrics = Some(metrics);
        self
    }

    async fn fetch_prices(&self) -> Result<PriceMap, PriceClientError> {
        let url = format!("{}/prices", self.base_url);
        let prices: PriceMap = self.client.get(&url).send().await?.json().await?;
        Ok(prices)
    }
}

#[async_trait::async_trait]
impl PriceSource for PriceClient {
    async fn get_price(&self, asset: &str) -> Result<f64, PriceClientError> {
        {
            let cache_guard = self.cache.read().await;
            let (last_updated, map) = &*cache_guard;
            if last_updated.elapsed() < self.ttl {
                if let Some(entry) = map.get(asset) {
                    return Ok(entry.price);
                }
            }
        }

        let prices = match self.fetch_prices().await {
            Ok(p) => {
                if let Some(m) = &self.metrics {
                    m.oracle_fetch_total
                        .get_or_create(&vec![("result".into(), "success".into())])
                        .inc();
                }
                p
            }
            Err(e) => {
                if let Some(m) = &self.metrics {
                    m.oracle_fetch_total
                        .get_or_create(&vec![("result".into(), "error".into())])
                        .inc();
                }
                warn!("Price fetch failed: {}. Checking stale cache.", e);
                let cache_guard = self.cache.read().await;
                let (last_updated, map) = &*cache_guard;
                if let Some(entry) = map.get(asset) {
                    let age = last_updated.elapsed();
                    if age <= self.max_staleness {
                        if let Some(m) = &self.metrics {
                            m.oracle_fetch_total
                                .get_or_create(&vec![("result".into(), "stale_cache".into())])
                                .inc();
                        }
                        warn!(
                            "Serving stale price for {} (age: {:.0}s, max: {:.0}s)",
                            asset,
                            age.as_secs_f64(),
                            self.max_staleness.as_secs_f64()
                        );
                        return Ok(entry.price);
                    }
                    warn!(
                        "Stale cache for {} too old (age: {:.0}s > max: {:.0}s). Rejecting.",
                        asset,
                        age.as_secs_f64(),
                        self.max_staleness.as_secs_f64()
                    );
                    return Err(PriceClientError::StalePrice {
                        asset: asset.to_string(),
                        age_secs: age.as_secs(),
                        max_secs: self.max_staleness.as_secs(),
                    });
                }
                return Err(e);
            }
        };

        {
            let mut cache_guard = self.cache.write().await;
            *cache_guard = (Instant::now(), prices.clone());
        }

        if let Some(entry) = prices.get(asset) {
            Ok(entry.price)
        } else {
            Err(PriceClientError::AssetNotFound)
        }
    }
}
