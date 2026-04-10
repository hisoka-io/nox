use crate::error::ProviderError;
use async_trait::async_trait;
use std::collections::HashMap;

#[async_trait]
pub trait PriceProvider: Send + Sync {
    fn id(&self) -> &'static str;
    async fn get_prices(&self, assets: &[String]) -> Result<HashMap<String, f64>, ProviderError>;
}

pub mod aggregate;
pub mod binance;
pub mod coingecko;
pub mod cryptocompare;
pub mod kraken;
