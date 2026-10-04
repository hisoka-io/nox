//! Log setup and the periodic counter summary.
//!
//! Logs never contain client IPs, request bodies, packet bytes or SURB
//! identifiers: per-request events carry the route name, status and timing
//! only, at `debug`; `info` carries startup facts and counter summaries.
//! `RUST_LOG` replaces the configured filter.

use std::io::IsTerminal;

use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::config::LogFormat;
use crate::error::LogInitError;
use crate::metrics::Metrics;

/// Installs the global subscriber (text or JSON lines on stdout).
pub fn init(filter: &str, format: LogFormat) -> Result<(), LogInitError> {
    let directives = match std::env::var("RUST_LOG") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => filter.to_string(),
    };
    let env_filter = EnvFilter::try_new(&directives).map_err(|e| LogInitError::Filter {
        filter: directives.clone(),
        reason: e.to_string(),
    })?;
    let builder = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .with_ansi(std::io::stdout().is_terminal());
    let result = match format {
        LogFormat::Text => builder.try_init(),
        LogFormat::Json => builder
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .try_init(),
    };
    result.map_err(|e| LogInitError::Install(e.to_string()))
}

/// Logs cumulative counters at `info`: counts only.
pub fn log_summary(metrics: &Metrics, connections_active: usize) {
    let rejected = Metrics::total(
        &metrics.connections_rejected,
        &["global_limit", "per_ip_limit"],
    );
    let stream_failures = Metrics::total(
        &metrics.stream_failures,
        &[
            "header_timeout",
            "stream_timeout",
            "protocol_error",
            "abandoned",
            "io",
        ],
    );
    let rate_limited: u64 = crate::routes::Route::ALL
        .iter()
        .map(|r| {
            metrics
                .rate_limited
                .get_or_create(&crate::metrics::RouteLabels { route: r.label() })
                .get()
        })
        .sum();
    info!(
        connections_active,
        connections_accepted = metrics.connections_accepted.get(),
        connections_rejected = rejected,
        streams_active = metrics.streams_active.get(),
        stream_failures,
        rate_limited,
        upstream_inflight = metrics.upstream_inflight.get(),
        bundles_loaded = metrics.bundles_loaded.get(),
        "summary"
    );
}
