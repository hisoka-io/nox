use nox_oracle::{
    fetcher::OracleFetcher,
    http::{provider_client, DEFAULT_PROVIDER_TIMEOUT},
    providers::{
        aggregate::{AggregateProvider, DEFAULT_MIN_SOURCES},
        binance::{self, BinanceProvider},
        coingecko::{self, CoinGeckoProvider},
        cryptocompare::{self, CryptoCompareProvider},
        kraken::{self, KrakenProvider},
        PriceProvider,
    },
    server::PriceServerState,
    types::{OracleConfig, PriceCache},
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Reads a non-empty environment variable.
fn env_value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_parsed<T: std::str::FromStr>(name: &str, default: T) -> anyhow::Result<T> {
    match env_value(name) {
        None => Ok(default),
        Some(raw) => raw
            .parse()
            .map_err(|_| anyhow::anyhow!("{name} has an invalid value: {raw}")),
    }
}

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

    let timeout = Duration::from_secs(env_parsed(
        "PRICE_HTTP_TIMEOUT_SECS",
        DEFAULT_PROVIDER_TIMEOUT.as_secs(),
    )?);
    if timeout.is_zero() {
        anyhow::bail!("PRICE_HTTP_TIMEOUT_SECS must be positive");
    }
    let client = provider_client(timeout)
        .map_err(|error| anyhow::anyhow!("price provider HTTP client failed: {error}"))?;

    let mut providers: Vec<Arc<dyn PriceProvider>> = vec![
        Arc::new(KrakenProvider::with_client(
            client.clone(),
            env_value("PRICE_KRAKEN_BASE_URL").unwrap_or_else(|| kraken::DEFAULT_BASE_URL.into()),
        )),
        Arc::new(
            CoinGeckoProvider::with_client(
                client.clone(),
                env_value("PRICE_COINGECKO_BASE_URL")
                    .unwrap_or_else(|| coingecko::DEFAULT_BASE_URL.into()),
            )
            .with_api_key(env_value("PRICE_COINGECKO_API_KEY")),
        ),
        Arc::new(BinanceProvider::with_client(
            client.clone(),
            env_value("PRICE_BINANCE_BASE_URL").unwrap_or_else(|| binance::DEFAULT_BASE_URL.into()),
        )),
    ];
    let cryptocompare_key = env_value("PRICE_CRYPTOCOMPARE_API_KEY");
    let cryptocompare_enabled = cryptocompare_key.is_some();
    if cryptocompare_enabled {
        providers.push(Arc::new(
            CryptoCompareProvider::with_client(
                client.clone(),
                env_value("PRICE_CRYPTOCOMPARE_BASE_URL")
                    .unwrap_or_else(|| cryptocompare::DEFAULT_BASE_URL.into()),
            )
            .with_api_key(cryptocompare_key),
        ));
    }

    let min_sources: usize = env_parsed("PRICE_MIN_SOURCES", DEFAULT_MIN_SOURCES)?;
    if min_sources == 0 || min_sources > providers.len() {
        anyhow::bail!(
            "PRICE_MIN_SOURCES must be in 1..={} (configured providers)",
            providers.len()
        );
    }
    let provider_ids: Vec<&str> = providers.iter().map(|provider| provider.id()).collect();
    info!(
        providers = %provider_ids.join(","),
        min_sources,
        timeout_secs = timeout.as_secs(),
        coingecko_key = env_value("PRICE_COINGECKO_API_KEY").is_some(),
        cryptocompare_enabled,
        "Price providers configured"
    );
    let agg_provider = Arc::new(AggregateProvider::new(providers).with_min_sources(min_sources));

    let fetcher = OracleFetcher::new(cache.clone(), agg_provider, config.clone());
    tokio::spawn(async move {
        fetcher.run().await;
    });

    let app = nox_oracle::server::router(PriceServerState { cache, config });

    let port: u16 = env_parsed("PRICE_SERVER_PORT", 3000)?;
    let bind_addr: std::net::IpAddr = env_parsed(
        "PRICE_SERVER_BIND",
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
    )?;
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
