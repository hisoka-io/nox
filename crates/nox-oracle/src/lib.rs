//! Standalone price oracle for NOX node profitability calculations.
//! Multi-provider (Kraken, `CoinGecko`, Binance.US, optional `CryptoCompare`) with median
//! aggregation and a minimum source quorum.

pub mod error;
pub mod fetcher;
pub mod http;
pub mod providers;
pub mod server;
pub mod types;
