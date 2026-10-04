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

/// Creating, loading or inspecting the persistent KPS identity.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error(
        "no KPS identity key at {path}; create it once with `nox-kps init` (run never generates a key, because the certhash is the published address)"
    )]
    Missing { path: PathBuf },
    #[error(
        "a KPS identity key already exists at {path}; init refuses to replace it (a new key changes the published address; delete the file deliberately to rotate)"
    )]
    AlreadyExists { path: PathBuf },
    #[error("the KPS identity key at {path} has mode {mode:o}; it must be private: run chmod 600 {path}")]
    Permissions { path: PathBuf, mode: u32 },
    #[error("cannot create the identity key directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot create the KPS identity key at {path}: {source}")]
    Create {
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

/// Scanning, adding or verifying worker bundles.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("cannot read the bundle directory {path}: {source}")]
    ReadDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot read bundle file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("bundle file {path} is {size} bytes, over limits.max_bundle_bytes ({limit})")]
    TooLarge {
        path: PathBuf,
        size: u64,
        limit: usize,
    },
    #[error("cannot write bundle {hash} into {dir}: {source}")]
    Write {
        hash: String,
        dir: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("bundle {hash} already exists in {dir} with different bytes ({path}); remove the damaged file and add it again")]
    Conflict {
        hash: String,
        dir: PathBuf,
        path: PathBuf,
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
    #[error("cannot encode /metadata.json: {0}")]
    Metadata(#[source] serde_json::Error),
    #[error("cannot bind the admin TCP listener (metrics, healthz) on {addr}: {source}")]
    AdminBind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
}

/// Forwarding one exchange to an upstream.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error(
        "route {route}: cannot reach {upstream} ({authority}) after {elapsed_ms} ms: {reason}"
    )]
    Connect {
        route: &'static str,
        upstream: &'static str,
        authority: String,
        elapsed_ms: u128,
        reason: String,
    },
    #[error("route {route}: {upstream} did not answer within {timeout_ms} ms")]
    Timeout {
        route: &'static str,
        upstream: &'static str,
        timeout_ms: u128,
    },
    #[error("route {route}: {upstream} response body exceeds {limit} bytes")]
    ResponseTooLarge {
        route: &'static str,
        upstream: &'static str,
        limit: usize,
    },
    #[error("route {route}: {upstream} exchange failed after {elapsed_ms} ms: {reason}")]
    Upstream {
        route: &'static str,
        upstream: &'static str,
        elapsed_ms: u128,
        reason: String,
    },
    #[error("route {route}: cannot build the request for {upstream}: {reason}")]
    BuildRequest {
        route: &'static str,
        upstream: &'static str,
        reason: String,
    },
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

/// `nox-kps healthcheck`.
#[derive(Debug, thiserror::Error)]
pub enum HealthcheckError {
    #[error("cannot connect to {addr}: {source}")]
    Connect {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("health request to {target} failed: {reason}")]
    Request { target: String, reason: String },
    #[error("health endpoint {target} answered {status}")]
    Unhealthy { target: String, status: u16 },
    #[error("health endpoint {target} did not answer within {timeout_ms} ms")]
    Timeout { target: String, timeout_ms: u128 },
    #[error("cannot dial the local KPS listener {target}: {reason}")]
    Dial { target: String, reason: String },
    #[error(transparent)]
    Identity(#[from] IdentityError),
}

/// Initialising logging.
#[derive(Debug, thiserror::Error)]
pub enum LogInitError {
    #[error("invalid log filter \"{filter}\": {reason}")]
    Filter { filter: String, reason: String },
    #[error("cannot install the log subscriber: {0}")]
    Install(String),
}
