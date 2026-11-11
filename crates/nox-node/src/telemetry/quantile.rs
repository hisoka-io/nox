//! A Prometheus histogram that also keeps its own bucket counts, so the JSON
//! projection can report percentiles. `prometheus_client::Histogram` does not
//! expose its buckets outside the crate.

use prometheus_client::metrics::histogram::Histogram;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Histogram with readable bucket counts. Clones share state.
#[derive(Clone, Debug)]
pub struct QuantileHistogram {
    inner: Histogram,
    /// Upper bounds of the finite buckets, ascending.
    bounds: Arc<[f64]>,
    /// One count per finite bucket plus a final overflow bucket.
    counts: Arc<[AtomicU64]>,
}

impl QuantileHistogram {
    #[must_use]
    pub fn new(buckets: impl Iterator<Item = f64>) -> Self {
        let bounds: Arc<[f64]> = buckets.collect::<Vec<_>>().into();
        let inner = Histogram::new(bounds.iter().copied());
        let counts = (0..=bounds.len()).map(|_| AtomicU64::new(0)).collect();
        Self {
            inner,
            bounds,
            counts,
        }
    }

    /// The Prometheus histogram to register.
    #[must_use]
    pub fn histogram(&self) -> Histogram {
        self.inner.clone()
    }

    pub fn observe(&self, v: f64) {
        self.inner.observe(v);
        let idx = self
            .bounds
            .iter()
            .position(|b| v <= *b)
            .unwrap_or(self.bounds.len());
        if let Some(count) = self.counts.get(idx) {
            count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Estimates quantile `q` (0.0 to 1.0) by linear interpolation inside the
    /// bucket that holds it, as Prometheus `histogram_quantile` does. Values in
    /// the overflow bucket report the highest finite bound. `None` without samples.
    #[must_use]
    pub fn quantile(&self, q: f64) -> Option<f64> {
        let counts: Vec<u64> = self
            .counts
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .collect();
        let total: u64 = counts.iter().sum();
        if total == 0 || !(0.0..=1.0).contains(&q) {
            return None;
        }
        let rank = q * total as f64;
        let mut below = 0u64;
        for (i, &count) in counts.iter().enumerate() {
            let cumulative = below + count;
            if count > 0 && cumulative as f64 >= rank {
                let Some(&upper) = self.bounds.get(i) else {
                    return self.bounds.last().copied();
                };
                let lower = if i == 0 {
                    0.0
                } else {
                    self.bounds.get(i - 1).copied().unwrap_or(0.0)
                };
                let within = (rank - below as f64) / count as f64;
                return Some(lower + (upper - lower) * within);
            }
            below = cumulative;
        }
        self.bounds.last().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus_client::metrics::histogram::exponential_buckets;

    #[test]
    fn empty_has_no_quantile() {
        let h = QuantileHistogram::new(exponential_buckets(0.05, 2.0, 12));
        assert_eq!(h.quantile(0.5), None);
    }

    #[test]
    fn quantiles_interpolate_within_buckets() {
        let h = QuantileHistogram::new([1.0, 2.0, 4.0].into_iter());
        for _ in 0..50 {
            h.observe(0.5);
        }
        for _ in 0..50 {
            h.observe(1.5);
        }
        // Rank 50 of 100 ends the first bucket exactly.
        assert_eq!(h.quantile(0.5), Some(1.0));
        // Rank 75 sits halfway through the (1, 2] bucket.
        assert_eq!(h.quantile(0.75), Some(1.5));
        assert_eq!(h.quantile(1.0), Some(2.0));
        assert_eq!(h.quantile(1.5), None);
    }

    #[test]
    fn overflow_reports_highest_bound() {
        let h = QuantileHistogram::new([1.0, 2.0].into_iter());
        h.observe(10.0);
        assert_eq!(h.quantile(0.99), Some(2.0));
    }

    #[test]
    fn quantiles_are_ordered() {
        let h = QuantileHistogram::new(exponential_buckets(0.05, 2.0, 12));
        for i in 0..1000u32 {
            h.observe(0.05 + f64::from(i) * 0.002);
        }
        let p50 = h.quantile(0.5).expect("p50");
        let p95 = h.quantile(0.95).expect("p95");
        let p99 = h.quantile(0.99).expect("p99");
        assert!(p50 <= p95 && p95 <= p99, "{p50} {p95} {p99}");
        assert!(p50 > 0.0);
    }
}
