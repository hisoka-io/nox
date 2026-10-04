//! Log setup. Logs never contain client IPs, request bodies, packet bytes or
//! SURB identifiers: per-request events carry the route name, status and
//! timing only, at `debug`. `RUST_LOG` replaces the configured filter.

use std::io::IsTerminal;

use tracing_subscriber::EnvFilter;

use crate::config::{LogConfig, LogFormat};
use crate::error::LogInitError;

/// Installs the global subscriber (text or JSON lines on stdout).
pub fn init(log: &LogConfig) -> Result<(), LogInitError> {
    let directives = match std::env::var("RUST_LOG") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => log.filter.clone(),
    };
    let filter = EnvFilter::try_new(&directives).map_err(|e| LogInitError::Filter {
        filter: directives.clone(),
        reason: e.to_string(),
    })?;
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_ansi(std::io::stdout().is_terminal());
    let result = match log.format {
        LogFormat::Text => builder.try_init(),
        LogFormat::Json => builder
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .try_init(),
    };
    result.map_err(|e| LogInitError::Install(e.to_string()))
}
