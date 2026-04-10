use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceEntry {
    pub price: f64,
    pub last_updated: DateTime<Utc>,
    pub source: String,
}

pub type PriceCache = Arc<RwLock<HashMap<String, PriceEntry>>>;

#[derive(Debug, Clone)]
pub struct OracleConfig {
    pub assets: Vec<String>,
    pub update_interval_secs: u64,
    pub staleness_threshold_secs: i64,
}

impl Default for OracleConfig {
    fn default() -> Self {
        Self {
            assets: vec![
                "ethereum".to_string(),
                "usd-coin".to_string(),
                "bitcoin".to_string(),
            ],
            update_interval_secs: 60,
            staleness_threshold_secs: 300, // 5 minutes
        }
    }
}
