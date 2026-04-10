use thiserror::Error;

#[derive(Error, Debug)]
pub enum OracleError {
    #[error("Provider failed: {0}")]
    ProviderError(String),

    #[error("Data too stale (last updated: {0})")]
    StaleData(String),

    #[error("Asset not found: {0}")]
    AssetNotFound(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

#[derive(Error, Debug)]
pub enum ProviderError {
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Rate limited")]
    RateLimited,

    #[error("Other: {0}")]
    Other(String),
}
