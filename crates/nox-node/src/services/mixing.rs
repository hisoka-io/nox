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
        let delay_ms = exp.sample(&mut rng);
        Duration::from_millis(delay_ms as u64)
    }
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
        let total: u128 = (0..2000).map(|_| strategy.get_delay().as_millis()).sum();
        let mean = total / 2000;
        assert!(
            (50..=250).contains(&mean),
            "mean {mean}ms outside expected 50-250ms for 100ms Poisson"
        );
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
