//! Standalone price oracle for NOX node profitability calculations.
//! Multi-provider (Binance, `CoinGecko`, Kraken, `CryptoCompare`) with median aggregation.

pub mod error;
pub mod fetcher;
pub mod providers;
pub mod server;
pub mod types;
