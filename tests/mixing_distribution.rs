use nox_core::IMixStrategy;
use nox_node::services::mixing::PoissonMixStrategy;

#[test]
fn test_poisson_distribution_properties() {
    let average_delay_ms = 100.0;
    let strategy = PoissonMixStrategy::new(average_delay_ms);
    let mut sum = 0.0;
    let n = 100_000;
    let mut min_delay = u64::MAX;
    let mut max_delay = 0;

    for _ in 0..n {
        let delay = strategy.get_delay();
        let millis = delay.as_millis() as u64;
        sum += millis as f64;
        if millis < min_delay {
            min_delay = millis;
        }
        if millis > max_delay {
            max_delay = millis;
        }
    }

    let actual_average = sum / n as f64;
    println!("Expected Average: {} ms", average_delay_ms);
    println!("Actual Average:   {:.2} ms", actual_average);
    println!("Min Delay:        {} ms", min_delay);
    println!("Max Delay:        {} ms", max_delay);

    // Verify Mean (allow 5% variance, usually much tighter for N=100k)
    let margin = average_delay_ms * 0.05;
    assert!(
        (actual_average - average_delay_ms).abs() < margin,
        "Distribution mean {:.2} deviates from expected {} by more than 5%",
        actual_average,
        average_delay_ms
    );

    // Verify Variability (Exponential distribution starts at 0 and has long tail)
    // Theoretically min can be 0 (or close to it)
    assert!(
        min_delay < 10,
        "Exponential distribution should produce very short delays"
    );

    // Max should be significantly larger than average (e.g., > 4x for 98th percentile coverage)
    assert!(
        max_delay > (average_delay_ms as u64 * 4),
        "Exponential distribution should have a long tail"
    );
}
