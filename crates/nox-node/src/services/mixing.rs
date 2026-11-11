use rand_distr::{Distribution, Exp};
use std::time::Duration;
use tracing::warn;

use nox_core::traits::IMixStrategy;

/// Loopix-style Poisson mixing: delays drawn from an exponential distribution.
pub struct PoissonMixStrategy {
    lambda: f64,
}

impl PoissonMixStrategy {
    #[must_use]
    pub fn new(average_delay_ms: f64) -> Self {
        let lambda = if average_delay_ms > 0.0 {
            1.0 / average_delay_ms
        } else {
            warn!(
                "PoissonMixStrategy: average_delay_ms={} is invalid (<= 0). \
                 Using 100ms default. This degrades anonymity. \
                 Use NoMixStrategy for zero-delay benchmarking.",
                average_delay_ms
            );
            1.0 / 100.0 // 100ms default, not ~0ms which destroys anonymity
        };
        Self { lambda }
    }
}

impl IMixStrategy for PoissonMixStrategy {
    fn get_delay(&self) -> Duration {
        let mut rng = rand::rngs::OsRng;
        // lambda is guaranteed > 0 by constructor, so Exp::new cannot fail
        let exp = if let Ok(e) = Exp::new(self.lambda) {
            e
        } else {
            warn!("Exp::new({}) failed, using 100ms fallback", self.lambda);
            #[allow(clippy::expect_used)]
            Exp::new(0.01).expect("valid lambda")
        };
        delay_from_ms(exp.sample(&mut rng), 1.0 / self.lambda)
    }
}

/// Converts a sampled delay in milliseconds to a `Duration` without truncating
/// to whole milliseconds, so draws below 1 ms stay non-zero. The timer that
/// consumes the delay (`DelayQueue` in the mix stage) still fires on whole
/// millisecond ticks. A sample that is not a finite non-negative number falls
/// back to the configured mean.
fn delay_from_ms(delay_ms: f64, mean_ms: f64) -> Duration {
    Duration::try_from_secs_f64(delay_ms / 1000.0)
        .or_else(|_| Duration::try_from_secs_f64(mean_ms / 1000.0))
        .unwrap_or(Duration::ZERO)
}

/// Zero-delay strategy for benchmarking only. Destroys timing anonymity.
pub struct NoMixStrategy;

impl IMixStrategy for NoMixStrategy {
    fn get_delay(&self) -> Duration {
        Duration::ZERO
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poisson_delay_is_positive() {
        let strategy = PoissonMixStrategy::new(50.0);
        for _ in 0..1000 {
            let d = strategy.get_delay();
            assert!(d.as_millis() < 10_000, "delay out of bounds: {d:?}");
        }
    }

    #[test]
    fn test_poisson_delay_mean_in_range() {
        let strategy = PoissonMixStrategy::new(100.0);
        let total: f64 = (0..2000)
            .map(|_| strategy.get_delay().as_secs_f64() * 1000.0)
            .sum();
        let mean = total / 2000.0;
        assert!(
            (50.0..=250.0).contains(&mean),
            "mean {mean}ms outside expected 50-250ms for 100ms Poisson"
        );
    }

    #[test]
    fn test_sub_millisecond_draw_is_kept() {
        assert_eq!(delay_from_ms(0.4, 40.0), Duration::from_micros(400));
        assert_eq!(delay_from_ms(12.5, 40.0), Duration::from_micros(12_500));
        assert_eq!(delay_from_ms(0.0, 40.0), Duration::ZERO);
    }

    #[test]
    fn test_invalid_draw_falls_back_to_mean() {
        assert_eq!(delay_from_ms(f64::NAN, 40.0), Duration::from_millis(40));
        assert_eq!(delay_from_ms(-1.0, 40.0), Duration::from_millis(40));
        assert_eq!(
            delay_from_ms(f64::INFINITY, 40.0),
            Duration::from_millis(40)
        );
    }

    #[test]
    fn test_no_zero_delays_at_fleet_mean() {
        // With whole-ms truncation about 2.5% of draws at a 40 ms mean became 0.
        let strategy = PoissonMixStrategy::new(40.0);
        let draws = 20_000;
        let zero = (0..draws)
            .filter(|_| strategy.get_delay() == Duration::ZERO)
            .count();
        let sub_ms = (0..draws)
            .filter(|_| strategy.get_delay() < Duration::from_millis(1))
            .count();
        assert_eq!(zero, 0, "{zero} of {draws} draws were exactly zero");
        assert!(sub_ms > 0, "expected some sub-millisecond draws");
    }

    #[test]
    fn test_poisson_zero_delay_uses_default() {
        let strategy = PoissonMixStrategy::new(0.0);
        let d = strategy.get_delay();
        // Should produce a valid duration, not panic
        let _ = d.as_millis();
    }

    #[test]
    fn test_poisson_negative_delay_uses_default() {
        let strategy = PoissonMixStrategy::new(-50.0);
        let d = strategy.get_delay();
        let _ = d.as_millis();
    }

    #[test]
    fn test_no_mix_strategy_is_zero() {
        let strategy = NoMixStrategy;
        assert_eq!(strategy.get_delay(), Duration::ZERO);
    }
}
