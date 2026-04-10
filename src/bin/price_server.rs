use nox_oracle::{
    fetcher::OracleFetcher,
    providers::{
        aggregate::AggregateProvider, binance::BinanceProvider, coingecko::CoinGeckoProvider,
        cryptocompare::CryptoCompareProvider, kraken::KrakenProvider,
    },
    server::PriceServerState,
    types::{OracleConfig, PriceCache},
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Initializing Price Oracle Service...");

    let config = OracleConfig::default();
    let cache: PriceCache = Arc::new(RwLock::new(HashMap::new()));

    let cg = Arc::new(CoinGeckoProvider::new());
    let bin = Arc::new(BinanceProvider::new());
    let cc = Arc::new(CryptoCompareProvider::new());
    let kraken = Arc::new(KrakenProvider::new());
    let agg_provider = Arc::new(AggregateProvider::new(vec![cg, bin, cc, kraken]));

    let fetcher = OracleFetcher::new(cache.clone(), agg_provider, config.clone());
    tokio::spawn(async move {
        fetcher.run().await;
    });

    let app = nox_oracle::server::router(PriceServerState { cache, config });

    let port: u16 = std::env::var("PRICE_SERVER_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3000);
    let bind_addr: std::net::IpAddr = std::env::var("PRICE_SERVER_BIND")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let addr = SocketAddr::from((bind_addr, port));
    info!("Price Server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to bind to {addr}: {e}"))?;
    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {e}"))?;

    Ok(())
}
