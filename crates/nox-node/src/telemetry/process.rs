//! Process metrics: polls `/proc/self/status` for memory and FD counts (Linux only).

use crate::telemetry::metrics::MetricsService;
use std::time::Duration;
use tracing::{debug, warn};

const POLL_INTERVAL: Duration = Duration::from_secs(30);

pub struct ProcessMonitor {
    metrics: MetricsService,
    start_epoch: i64,
}

impl ProcessMonitor {
    #[must_use]
    pub fn new(metrics: MetricsService, start_epoch: i64) -> Self {
        Self {
            metrics,
            start_epoch,
        }
    }

    /// Call once at startup before spawning `run()`.
    pub fn record_build_info(&self, version: &str, role: &str) {
        self.metrics
            .build_info
            .get_or_create(&vec![
                ("version".to_string(), version.to_string()),
                ("role".to_string(), role.to_string()),
            ])
            .set(1);
        // 2 = healthy (node started successfully)
        self.metrics.health_status.set(2);
    }

    pub async fn run(self) {
        let mut tick = tokio::time::interval(POLL_INTERVAL);
        loop {
            tick.tick().await;
            self.update_uptime();
            self.update_proc_metrics();
        }
    }

    fn update_uptime(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.metrics
            .uptime_seconds
            .set((now - self.start_epoch).max(0));
    }

    #[cfg(target_os = "linux")]
    fn update_proc_metrics(&self) {
        match std::fs::read_to_string("/proc/self/status") {
            Ok(content) => {
                for line in content.lines() {
                    if let Some(rest) = line.strip_prefix("VmRSS:") {
                        if let Some(kb) = parse_kb(rest) {
                            self.metrics.process_resident_memory_bytes.set(kb * 1024);
                        }
                    } else if let Some(rest) = line.strip_prefix("VmSize:") {
                        if let Some(kb) = parse_kb(rest) {
                            self.metrics.process_virtual_memory_bytes.set(kb * 1024);
                        }
                    }
                }
                debug!("Process memory metrics updated");
            }
            Err(e) => warn!(error = %e, "Failed to read /proc/self/status"),
        }

        match std::fs::read_dir("/proc/self/fd") {
            Ok(entries) => {
                self.metrics.process_open_fds.set(entries.count() as i64);
            }
            Err(e) => warn!(error = %e, "Failed to read /proc/self/fd"),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn update_proc_metrics(&self) {
        debug!("Process /proc metrics not available on this platform");
    }
}

#[cfg(target_os = "linux")]
fn parse_kb(s: &str) -> Option<i64> {
    s.split_whitespace().next()?.parse::<i64>().ok()
}
