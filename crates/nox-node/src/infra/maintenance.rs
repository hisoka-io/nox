//! Periodic storage maintenance: retention sweep, record and blob gauges,
//! flush. Runs on every node; on relays the sweep finds nothing to remove.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nox_core::traits::InfrastructureError;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::StorageConfig;
use crate::infra::retention::{blob_usage, RetentionPolicy, RetentionReport};
use crate::infra::storage::SledRepository;
use crate::telemetry::metrics::MetricsService;

pub struct StorageMaintenance {
    storage: Arc<SledRepository>,
    metrics: MetricsService,
    policy: RetentionPolicy,
    interval: Duration,
    cancel_token: CancellationToken,
}

fn gauge_value(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

impl StorageMaintenance {
    #[must_use]
    pub fn new(
        storage: Arc<SledRepository>,
        metrics: MetricsService,
        config: &StorageConfig,
    ) -> Self {
        Self {
            storage,
            metrics,
            policy: RetentionPolicy::from_config(config),
            interval: Duration::from_secs(config.maintenance_interval_secs),
            cancel_token: CancellationToken::new(),
        }
    }

    #[must_use]
    pub fn with_cancel_token(mut self, token: CancellationToken) -> Self {
        self.cancel_token = token;
        self
    }

    /// Runs a pass immediately, then every `maintenance_interval_secs`.
    pub async fn run(&self) {
        let mut tick = tokio::time::interval(self.interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    if let Err(error) = self.run_once().await {
                        self.metrics.storage_maintenance_errors_total.inc();
                        warn!(error = %error, "Storage maintenance pass failed");
                    }
                }
                () = self.cancel_token.cancelled() => break,
            }
        }
    }

    /// One pass. Errors in the gauges do not undo the sweep.
    pub async fn run_once(&self) -> Result<RetentionReport, InfrastructureError> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                InfrastructureError::Database(format!(
                    "storage maintenance: system clock is before the unix epoch: {error}"
                ))
            })?
            .as_secs();
        let report = self.storage.apply_retention(self.policy, now_unix).await?;
        self.record_report(&report);
        self.refresh_gauges().await?;
        self.storage.compact().await?;
        Ok(report)
    }

    fn record_report(&self, report: &RetentionReport) {
        for (record, action, count) in [
            ("outbox", "slimmed", report.outbox_slimmed),
            ("transaction", "slimmed", report.transactions_slimmed),
            ("outbox", "pruned", report.outbox_pruned),
            ("transaction", "pruned", report.transactions_pruned),
            ("quote", "pruned", report.quotes_pruned),
            (
                "quote_payment_index",
                "pruned",
                report.payment_indexes_pruned,
            ),
        ] {
            if count > 0 {
                self.metrics
                    .storage_retention_total
                    .get_or_create(&vec![
                        ("record".to_string(), record.to_string()),
                        ("action".to_string(), action.to_string()),
                    ])
                    .inc_by(count as u64);
            }
        }
        if report.changed() > 0 {
            info!(
                outbox_slimmed = report.outbox_slimmed,
                transactions_slimmed = report.transactions_slimmed,
                outbox_pruned = report.outbox_pruned,
                transactions_pruned = report.transactions_pruned,
                quotes_pruned = report.quotes_pruned,
                more_pending = report.budget_exhausted,
                "Storage retention removed finished records"
            );
        }
        if report.undecodable > 0 {
            warn!(
                records = report.undecodable,
                "Storage retention found records that do not decode; they were left in place"
            );
        }
        if report.budget_exhausted {
            debug!(
                "Storage retention hit maintenance_batch_limit; the rest waits for the next pass"
            );
        }
    }

    async fn refresh_gauges(&self) -> Result<(), InfrastructureError> {
        for count in self.storage.record_counts().await? {
            self.metrics
                .storage_records
                .get_or_create(&vec![
                    ("tree".to_string(), count.tree.to_string()),
                    ("kind".to_string(), count.kind.to_string()),
                ])
                .set(gauge_value(count.count));
        }
        let path = self.storage.path().to_path_buf();
        let (files, bytes) = tokio::task::spawn_blocking(move || blob_usage(&path))
            .await
            .map_err(|error| {
                InfrastructureError::Database(format!("blob usage task failed: {error}"))
            })??;
        self.metrics.storage_blob_files.set(gauge_value(files));
        self.metrics.storage_blob_bytes.set(gauge_value(bytes));
        Ok(())
    }
}
