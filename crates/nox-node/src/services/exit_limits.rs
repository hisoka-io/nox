//! Per-destination and per-credential rate limits at an exit.
//!
//! Each limiter keeps one token bucket per key. Keys are stored only as a keyed hash
//! (random per process), so the exit never holds a destination host or a payment
//! credential here, and metrics carry the scope and service only.
//!
//! Memory is bounded: a bucket that has refilled to its burst carries no state and is
//! dropped at the next sweep, and at most `exit_limits.max_tracked` keys are held.
//! When the table is full of keys that are all still refilling, a new key is let through
//! untracked and counted (`nox_exit_rate_limit_untracked_total`); reaching that needs
//! more new keys per refill time than the exit's lane and tunnel limits admit.

use crate::config::ExitLimitsConfig;
use crate::telemetry::metrics::MetricsService;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Longest time between two sweeps of refilled buckets.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(10);
/// Shortest time between two sweeps forced by a full table, so a full table costs one
/// scan per this interval instead of one per request.
pub const FULL_SWEEP_MIN_GAP: Duration = Duration::from_secs(1);

/// What a limiter keys on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitScope {
    /// One upstream host (HTTP proxy requests and tunnel opens together).
    Destination,
    /// One payment credential of a paid quote (payment adapter and payment id).
    Credential,
}

impl LimitScope {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Destination => "destination",
            Self::Credential => "credential",
        }
    }

    const fn subject(self) -> &'static str {
        match self {
            Self::Destination => "destination host",
            Self::Credential => "payment credential",
        }
    }
}

/// A request refused by an exit rate limit.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "exit rate limit for this {subject} reached ({limit} per {period}, burst {burst}); retry in {retry_after_ms} ms",
    subject = .scope.subject()
)]
pub struct RateLimitExceeded {
    pub scope: LimitScope,
    pub limit: u32,
    pub period: &'static str,
    pub burst: u32,
    pub retry_after_ms: u64,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    refilled: Instant,
}

struct Table {
    buckets: HashMap<u64, Bucket>,
    last_sweep: Instant,
    next_sweep: Instant,
}

/// Token buckets keyed by a hash of the destination or credential.
pub struct KeyedRateLimiter {
    scope: LimitScope,
    limit: u32,
    period: &'static str,
    burst: u32,
    tokens_per_sec: f64,
    max_tracked: usize,
    hasher: RandomState,
    table: Mutex<Table>,
    metrics: MetricsService,
}

impl KeyedRateLimiter {
    /// The per-destination limiter, or `None` when `destination_per_sec` is 0.
    #[must_use]
    pub fn destination(config: &ExitLimitsConfig, metrics: &MetricsService) -> Option<Arc<Self>> {
        Self::build(
            LimitScope::Destination,
            config.destination_per_sec,
            "second",
            1.0,
            config.destination_burst,
            config.max_tracked,
            metrics,
        )
    }

    /// The per-credential limiter, or `None` when `credential_per_min` is 0.
    #[must_use]
    pub fn credential(config: &ExitLimitsConfig, metrics: &MetricsService) -> Option<Arc<Self>> {
        Self::build(
            LimitScope::Credential,
            config.credential_per_min,
            "minute",
            60.0,
            config.credential_burst,
            config.max_tracked,
            metrics,
        )
    }

    fn build(
        scope: LimitScope,
        limit: u32,
        period: &'static str,
        period_secs: f64,
        burst: u32,
        max_tracked: usize,
        metrics: &MetricsService,
    ) -> Option<Arc<Self>> {
        if limit == 0 || burst == 0 || max_tracked == 0 {
            return None;
        }
        let now = Instant::now();
        Some(Arc::new(Self {
            scope,
            limit,
            period,
            burst,
            tokens_per_sec: f64::from(limit) / period_secs,
            max_tracked,
            hasher: RandomState::new(),
            table: Mutex::new(Table {
                buckets: HashMap::new(),
                last_sweep: now,
                next_sweep: now + SWEEP_INTERVAL,
            }),
            metrics: metrics.clone(),
        }))
    }

    #[must_use]
    pub const fn scope(&self) -> LimitScope {
        self.scope
    }

    /// Keys held now.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.table.lock().buckets.len()
    }

    /// Takes one token for `key`. `service` labels the refusal counter (`http`, `tunnel`,
    /// `quote`); the key itself never leaves this limiter.
    pub fn check(&self, key: &[u8], service: &str) -> Result<(), RateLimitExceeded> {
        self.check_at(key, service, Instant::now())
    }

    fn check_at(&self, key: &[u8], service: &str, now: Instant) -> Result<(), RateLimitExceeded> {
        let hash = self.hasher.hash_one(key);
        let burst = f64::from(self.burst);
        let mut table = self.table.lock();
        let full = table.buckets.len() >= self.max_tracked
            && now.saturating_duration_since(table.last_sweep) >= FULL_SWEEP_MIN_GAP;
        if full || now >= table.next_sweep {
            self.sweep(&mut table, now);
        }
        let tracked = table.buckets.len();
        let bucket = match table.buckets.get_mut(&hash) {
            Some(bucket) => bucket,
            None if tracked >= self.max_tracked => {
                drop(table);
                self.metrics
                    .exit_rate_limit_untracked_total
                    .get_or_create(&vec![("scope".into(), self.scope.as_str().into())])
                    .inc();
                return Ok(());
            }
            None => {
                let entry = table.buckets.entry(hash).or_insert(Bucket {
                    tokens: burst,
                    refilled: now,
                });
                self.set_tracked_gauge(tracked + 1);
                entry
            }
        };
        let elapsed = now.saturating_duration_since(bucket.refilled).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.tokens_per_sec).min(burst);
        bucket.refilled = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return Ok(());
        }
        let missing = 1.0 - bucket.tokens;
        drop(table);
        self.metrics
            .exit_rate_limited_total
            .get_or_create(&vec![
                ("scope".into(), self.scope.as_str().into()),
                ("service".into(), service.into()),
            ])
            .inc();
        Err(RateLimitExceeded {
            scope: self.scope,
            limit: self.limit,
            period: self.period,
            burst: self.burst,
            retry_after_ms: retry_after_ms(missing, self.tokens_per_sec),
        })
    }

    /// Drops every bucket that has refilled to its burst: it holds no state.
    fn sweep(&self, table: &mut Table, now: Instant) {
        let burst = f64::from(self.burst);
        let rate = self.tokens_per_sec;
        table.buckets.retain(|_, bucket| {
            let elapsed = now.saturating_duration_since(bucket.refilled).as_secs_f64();
            bucket.tokens + elapsed * rate < burst
        });
        table
            .buckets
            .shrink_to(self.max_tracked.min(table.buckets.len() * 2));
        table.last_sweep = now;
        table.next_sweep = now + SWEEP_INTERVAL;
        self.set_tracked_gauge(table.buckets.len());
    }

    fn set_tracked_gauge(&self, tracked: usize) {
        self.metrics
            .exit_rate_limit_tracked
            .get_or_create(&vec![("scope".into(), self.scope.as_str().into())])
            .set(i64::try_from(tracked).unwrap_or(i64::MAX));
    }
}

fn retry_after_ms(missing_tokens: f64, tokens_per_sec: f64) -> u64 {
    let ms = (missing_tokens / tokens_per_sec * 1000.0).ceil();
    if ms.is_finite() && ms >= 1.0 {
        // `ms` is finite and positive; saturating float-to-int cast.
        ms as u64
    } else {
        1
    }
}

/// Destination key of a host name: ASCII lower case, without a trailing dot.
#[must_use]
pub fn destination_key(host: &str) -> Vec<u8> {
    host.trim_end_matches('.').to_ascii_lowercase().into_bytes()
}

/// Destination key of a URL the client names (an RPC or broadcast URL), or `None` when it
/// has no host; such a URL is refused by the SSRF check that follows.
#[must_use]
pub fn url_destination_key(url: &str) -> Option<Vec<u8>> {
    let parsed = url::Url::parse(url).ok()?;
    parsed.host_str().map(destination_key)
}

/// Credential key of a paid quote: payment adapter, then payment id.
#[must_use]
pub fn credential_key(payment_adapter: &[u8; 20], payment_id: &[u8; 32]) -> [u8; 52] {
    let mut key = [0u8; 52];
    key[..20].copy_from_slice(payment_adapter);
    key[20..].copy_from_slice(payment_id);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(per_sec: u32, burst: u32, max_tracked: usize) -> ExitLimitsConfig {
        ExitLimitsConfig {
            destination_per_sec: per_sec,
            destination_burst: burst,
            credential_per_min: per_sec,
            credential_burst: burst,
            max_tracked,
        }
    }

    fn counter(metrics: &MetricsService, scope: &str, service: &str) -> u64 {
        metrics
            .exit_rate_limited_total
            .get_or_create(&vec![
                ("scope".into(), scope.into()),
                ("service".into(), service.into()),
            ])
            .get()
    }

    #[test]
    fn burst_then_refusal_then_refill() {
        let metrics = MetricsService::new();
        let limiter =
            KeyedRateLimiter::destination(&config(10, 3, 16), &metrics).expect("limit is enabled");
        let start = Instant::now();
        for _ in 0..3 {
            assert!(limiter.check_at(b"rpc.example", "tunnel", start).is_ok());
        }
        let refused = limiter
            .check_at(b"rpc.example", "tunnel", start)
            .expect_err("burst is spent");
        assert_eq!(refused.scope, LimitScope::Destination);
        assert_eq!(refused.retry_after_ms, 100);
        assert_eq!(counter(&metrics, "destination", "tunnel"), 1);
        // 10 per second: one token back after 100 ms.
        let later = start + Duration::from_millis(100);
        assert!(limiter.check_at(b"rpc.example", "tunnel", later).is_ok());
        assert!(limiter.check_at(b"rpc.example", "tunnel", later).is_err());
    }

    #[test]
    fn keys_are_independent() {
        let metrics = MetricsService::new();
        let limiter =
            KeyedRateLimiter::destination(&config(1, 1, 16), &metrics).expect("limit is enabled");
        let now = Instant::now();
        assert!(limiter.check_at(b"a.example", "http", now).is_ok());
        assert!(limiter.check_at(b"a.example", "http", now).is_err());
        assert!(limiter.check_at(b"b.example", "http", now).is_ok());
    }

    #[test]
    fn refilled_buckets_are_swept() {
        let metrics = MetricsService::new();
        let limiter =
            KeyedRateLimiter::destination(&config(10, 2, 16), &metrics).expect("limit is enabled");
        let start = Instant::now();
        for host in [&b"a.example"[..], b"b.example", b"c.example"] {
            assert!(limiter.check_at(host, "http", start).is_ok());
        }
        assert_eq!(limiter.tracked(), 3);
        // Past the sweep interval every bucket has refilled; the next check sweeps them.
        let later = start + SWEEP_INTERVAL;
        assert!(limiter.check_at(b"d.example", "http", later).is_ok());
        assert_eq!(limiter.tracked(), 1);
    }

    #[test]
    fn full_table_lets_new_keys_through_untracked() {
        let metrics = MetricsService::new();
        let limiter =
            KeyedRateLimiter::credential(&config(1, 1, 2), &metrics).expect("limit is enabled");
        let now = Instant::now();
        assert!(limiter.check_at(b"one", "quote", now).is_ok());
        assert!(limiter.check_at(b"two", "quote", now).is_ok());
        assert!(limiter.check_at(b"three", "quote", now).is_ok());
        assert!(limiter.check_at(b"three", "quote", now).is_ok());
        assert_eq!(limiter.tracked(), 2);
        assert_eq!(
            metrics
                .exit_rate_limit_untracked_total
                .get_or_create(&vec![("scope".into(), "credential".into())])
                .get(),
            2
        );
        // Tracked keys stay limited.
        assert!(limiter.check_at(b"one", "quote", now).is_err());
    }

    #[test]
    fn per_minute_rate_and_message() {
        let metrics = MetricsService::new();
        let limiter =
            KeyedRateLimiter::credential(&config(6, 1, 16), &metrics).expect("limit is enabled");
        let now = Instant::now();
        assert!(limiter.check_at(b"cred", "quote", now).is_ok());
        let refused = limiter
            .check_at(b"cred", "quote", now)
            .expect_err("burst is spent");
        assert_eq!(refused.retry_after_ms, 10_000);
        assert_eq!(
            refused.to_string(),
            "exit rate limit for this payment credential reached (6 per minute, burst 1); retry in 10000 ms"
        );
    }

    #[test]
    fn zero_disables() {
        let metrics = MetricsService::new();
        assert!(KeyedRateLimiter::destination(&config(0, 10, 16), &metrics).is_none());
        assert!(KeyedRateLimiter::credential(&config(0, 10, 16), &metrics).is_none());
    }

    #[test]
    fn keys_normalise() {
        assert_eq!(
            destination_key("RPC.Example.ORG."),
            b"rpc.example.org".to_vec()
        );
        assert_eq!(
            url_destination_key("https://RPC.example.org:8545/v2/key"),
            Some(b"rpc.example.org".to_vec())
        );
        assert_eq!(url_destination_key("not a url"), None);
        let key = credential_key(&[1u8; 20], &[2u8; 32]);
        assert_eq!(&key[..20], &[1u8; 20]);
        assert_eq!(&key[20..], &[2u8; 32]);
    }
}
