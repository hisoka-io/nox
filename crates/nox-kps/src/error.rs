//! Typed errors. Every message names the thing that failed and the value or
//! path involved, so an operator can act on it without reading the code.

use std::net::SocketAddr;
use std::path::PathBuf;

/// Loading or validating the configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("config file {path} does not exist (given with --config or NOX_KPS_CONFIG)")]
    Missing { path: PathBuf },
    #[error("cannot load configuration from {path}: {source}")]
    Load {
        path: PathBuf,
        #[source]
        source: Box<config::ConfigError>,
    },
    #[error("invalid configuration:\n  - {}", .0.join("\n  - "))]
    Invalid(Vec<String>),
}

/// Loading, creating or inspecting the persistent KPS identity.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("cannot create the identity key directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot load or create the KPS identity key at {path}: {source}")]
    LoadOrCreate {
        path: PathBuf,
        #[source]
        source: kps::Error,
    },
    #[error("cannot read the KPS identity key at {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("the KPS identity key at {path} is not a valid PEM key + certificate: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: kps::Error,
    },
}

/// Scanning the worker-bundle directory.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("cannot read the bundle directory {path}: {source}")]
    ReadDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot compress bundle {hash}: {source}")]
    Compress {
        hash: String,
        #[source]
        source: std::io::Error,
    },
}

/// Starting the server.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error("cannot load worker bundles: {0}")]
    Bundles(#[from] BundleError),
    #[error("cannot bind the KPS UDP listener on {addr}: {source}")]
    Listen {
        addr: SocketAddr,
        #[source]
        source: kps::Error,
    },
    #[error("cannot bind the metrics TCP listener on {addr}: {source}")]
    MetricsBind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot register metric {name}: {reason}")]
    Metrics { name: &'static str, reason: String },
}

/// Forwarding one exchange to an upstream.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("cannot reach upstream {upstream} ({authority}): {reason}")]
    Connect {
        upstream: String,
        authority: String,
        reason: String,
    },
    #[error("upstream {upstream} did not answer within {timeout_ms} ms")]
    Timeout { upstream: String, timeout_ms: u128 },
    #[error("upstream {upstream} response body exceeds {limit} bytes")]
    ResponseTooLarge { upstream: String, limit: usize },
    #[error("upstream {upstream} exchange failed: {reason}")]
    Upstream { upstream: String, reason: String },
    #[error("cannot build the upstream request for {upstream}: {reason}")]
    BuildRequest { upstream: String, reason: String },
}

impl ProxyError {
    /// Short label for metrics.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Connect { .. } => "connect",
            Self::Timeout { .. } => "timeout",
            Self::ResponseTooLarge { .. } => "response_too_large",
            Self::Upstream { .. } => "upstream",
            Self::BuildRequest { .. } => "build_request",
        }
    }
}

/// Probing the local health endpoint (`nox-kps healthcheck`).
#[derive(Debug, thiserror::Error)]
pub enum HealthcheckError {
    #[error("metrics/health endpoint is disabled (metrics.listen is empty)")]
    Disabled,
    #[error("cannot connect to {addr}: {source}")]
    Connect {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("health request to {addr} failed: {reason}")]
    Request { addr: SocketAddr, reason: String },
    #[error("health endpoint {addr} answered {status}")]
    Unhealthy { addr: SocketAddr, status: u16 },
    #[error("health endpoint {addr} did not answer within {timeout_ms} ms")]
    Timeout { addr: SocketAddr, timeout_ms: u128 },
}

/// Initialising logging.
#[derive(Debug, thiserror::Error)]
pub enum LogInitError {
    #[error("invalid log filter \"{filter}\": {reason}")]
    Filter { filter: String, reason: String },
    #[error("cannot install the log subscriber: {0}")]
    Install(String),
}
