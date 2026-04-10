//! Calculates SURB count for anonymous requests based on expected response size.
//! Each SURB carries ~30 KB; adaptive budgeting via EMA tracks per-operation sizes.

use nox_core::protocol::fragmentation::{
    FRAGMENT_OVERHEAD, MAX_FRAGMENTS_PER_MESSAGE, SURB_PAYLOAD_SIZE,
};
use nox_crypto::sphinx::packet::MAX_PAYLOAD_SIZE;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

/// Estimated bincode-serialized SURB size. Rounded to 700.
pub const ESTIMATED_SURB_SERIALIZED_SIZE: usize = 700;

pub const USABLE_RESPONSE_PER_SURB: usize = SURB_PAYLOAD_SIZE - FRAGMENT_OVERHEAD;

/// Capped at 9,000 (post-Lioness SPRP SURB size increase).
pub const MAX_SURBS: usize = 9_000;

pub const DEFAULT_RPC_SURBS: usize = 3;

pub const DEFAULT_MEDIUM_SURBS: usize = 10;

#[derive(Debug, Clone)]
pub struct SurbBudget {
    /// 0 = unknown, use `min_surbs`
    pub expected_response_bytes: usize,
    pub min_surbs: usize,
    pub max_surbs: usize,
}

impl SurbBudget {
    #[must_use]
    pub fn rpc() -> Self {
        Self {
            expected_response_bytes: 0,
            min_surbs: DEFAULT_RPC_SURBS,
            max_surbs: DEFAULT_MEDIUM_SURBS,
        }
    }

    #[must_use]
    pub fn for_response_size(expected_bytes: usize) -> Self {
        let min = if expected_bytes == 0 {
            DEFAULT_RPC_SURBS
        } else {
            Self::surbs_for_bytes(expected_bytes).max(1)
        };
        Self {
            expected_response_bytes: expected_bytes,
            min_surbs: min,
            max_surbs: MAX_SURBS,
        }
    }

    #[must_use]
    pub fn large_query(expected_bytes: usize) -> Self {
        let needed = Self::surbs_for_bytes(expected_bytes).max(DEFAULT_MEDIUM_SURBS);
        Self {
            expected_response_bytes: expected_bytes,
            min_surbs: needed,
            max_surbs: MAX_SURBS,
        }
    }

    #[must_use]
    pub fn max_capacity() -> Self {
        Self {
            expected_response_bytes: MAX_SURBS * USABLE_RESPONSE_PER_SURB,
            min_surbs: MAX_SURBS,
            max_surbs: MAX_SURBS,
        }
    }

    #[must_use]
    pub fn surb_count(&self) -> usize {
        let needed = if self.expected_response_bytes == 0 {
            self.min_surbs
        } else {
            Self::surbs_for_bytes(self.expected_response_bytes).max(self.min_surbs)
        };
        needed.clamp(1, self.max_surbs)
    }

    /// Forward Sphinx packets needed to carry SURBs + inner request.
    #[must_use]
    pub fn forward_fragments_needed(&self, inner_request_bytes: usize) -> usize {
        self.forward_fragments_for_surb_count(inner_request_bytes, self.surb_count())
    }

    #[must_use]
    pub fn forward_fragments_for_surb_count(
        &self,
        inner_request_bytes: usize,
        surb_count: usize,
    ) -> usize {
        let total_surb_bytes = surb_count * ESTIMATED_SURB_SERIALIZED_SIZE;

        let request_overhead = 50; // bincode: enum variant + length prefixes
        let total_payload = inner_request_bytes + total_surb_bytes + request_overhead;

        let usable_per_fragment = MAX_PAYLOAD_SIZE.saturating_sub(FRAGMENT_OVERHEAD);
        if usable_per_fragment == 0 {
            return MAX_FRAGMENTS_PER_MESSAGE as usize;
        }

        let fragments = total_payload.div_ceil(usable_per_fragment);
        fragments.min(MAX_FRAGMENTS_PER_MESSAGE as usize)
    }

    #[must_use]
    pub fn response_capacity(&self) -> usize {
        self.surb_count() * USABLE_RESPONSE_PER_SURB
    }

    /// FEC-inflated count: D data + P parity SURBs, capped at `max_surbs`.
    /// D is never reduced; single fragment (D=1) gets P=1 if `fec_ratio > 0`.
    #[must_use]
    pub fn surb_count_with_fec(&self, fec_ratio: f64) -> usize {
        let d = self.surb_count();
        if fec_ratio <= 0.0 || d == 0 {
            return d;
        }

        let p = if d == 1 {
            1
        } else {
            (d as f64 * fec_ratio).ceil() as usize
        };

        (d + p).min(self.max_surbs)
    }

    /// Fill remaining space in a single Sphinx packet with as many SURBs as fit.
    /// Returns the number of SURBs that can be packed alongside `inner_request_bytes`
    /// in a single forward packet. This maximizes initial SURB allocation at zero extra cost.
    #[must_use]
    pub fn fill_remaining_packet(inner_request_bytes: usize) -> usize {
        let overhead = 50; // bincode: enum variant + length prefixes
        let used = inner_request_bytes + overhead;
        let remaining = MAX_PAYLOAD_SIZE.saturating_sub(used + 1); // -1 for type tag
        if remaining < ESTIMATED_SURB_SERIALIZED_SIZE {
            return 0;
        }
        // Cap at DEFAULT_MEDIUM_SURBS to avoid overwhelming mix nodes with response traffic.
        // For large responses, the budget-calculated count (from SurbBudget::surb_count) will
        // exceed this cap and take precedence via the .max() in send_request_with_budget.
        (remaining / ESTIMATED_SURB_SERIALIZED_SIZE).min(DEFAULT_MEDIUM_SURBS)
    }

    fn surbs_for_bytes(bytes: usize) -> usize {
        if bytes == 0 {
            return 0;
        }
        bytes.div_ceil(USABLE_RESPONSE_PER_SURB)
    }
}

impl Default for SurbBudget {
    fn default() -> Self {
        Self::rpc()
    }
}

/// α=0.2: new observation 20%, history 80%.
const EMA_ALPHA: f64 = 0.2;

/// 1.5x headroom over EMA to absorb response-size growth.
const EMA_HEADROOM: f64 = 1.5;

const EMA_MIN_SAMPLES: u32 = 3;

#[derive(Debug, Clone)]
struct EmaState {
    ema_bytes: f64,
    samples: u32,
}

impl EmaState {
    fn new(initial_bytes: usize) -> Self {
        Self {
            ema_bytes: initial_bytes as f64,
            samples: 1,
        }
    }

    fn update(&mut self, observed_bytes: usize) {
        self.ema_bytes = EMA_ALPHA * (observed_bytes as f64) + (1.0 - EMA_ALPHA) * self.ema_bytes;
        self.samples = self.samples.saturating_add(1);
    }

    /// Returns `None` when fewer than `EMA_MIN_SAMPLES` observations.
    fn estimate(&self) -> Option<usize> {
        if self.samples < EMA_MIN_SAMPLES {
            return None;
        }
        Some(((self.ema_bytes * EMA_HEADROOM).ceil() as usize).max(1))
    }
}

/// Per-operation EMA tracker that sizes SURB budgets from historical response sizes.
#[derive(Debug, Clone)]
pub struct AdaptiveSurbBudget {
    inner: Arc<Mutex<HashMap<String, EmaState>>>,
}

impl AdaptiveSurbBudget {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[must_use]
    pub fn budget_for(&self, operation: &str) -> SurbBudget {
        let guard = self.inner.lock();
        match guard.get(operation).and_then(EmaState::estimate) {
            Some(estimated_bytes) => SurbBudget::for_response_size(estimated_bytes),
            None => SurbBudget::rpc(),
        }
    }

    pub fn record(&self, operation: &str, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let mut guard = self.inner.lock();
        guard
            .entry(operation.to_string())
            .and_modify(|s| s.update(bytes))
            .or_insert_with(|| EmaState::new(bytes));
    }

    #[must_use]
    pub fn tracked_operations(&self) -> usize {
        self.inner.lock().len()
    }

    #[must_use]
    pub fn estimate_bytes(&self, operation: &str) -> Option<usize> {
        self.inner.lock().get(operation)?.estimate()
    }
}

impl Default for AdaptiveSurbBudget {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_budget() {
        let budget = SurbBudget::rpc();
        assert_eq!(budget.surb_count(), DEFAULT_RPC_SURBS);
        assert!(budget.response_capacity() >= DEFAULT_RPC_SURBS * USABLE_RESPONSE_PER_SURB);
    }

    #[test]
    fn test_for_response_size_small() {
        let budget = SurbBudget::for_response_size(10_000);
        assert_eq!(budget.surb_count(), 1);
    }

    #[test]
    fn test_for_response_size_medium() {
        let budget = SurbBudget::for_response_size(100_000);
        let count = budget.surb_count();
        assert!(count >= 4, "Expected >= 4 SURBs, got {}", count);
        assert!(budget.response_capacity() >= 100_000);
    }

    #[test]
    fn test_for_response_size_large() {
        let budget = SurbBudget::for_response_size(10 * 1024 * 1024);
        let count = budget.surb_count();
        assert!(budget.response_capacity() >= 10 * 1024 * 1024);
        assert!(count <= MAX_SURBS);
    }

    #[test]
    fn test_large_query() {
        let budget = SurbBudget::large_query(5_000_000);
        let count = budget.surb_count();
        assert!(budget.response_capacity() >= 5_000_000);
        assert!(count >= DEFAULT_MEDIUM_SURBS);
    }

    #[test]
    fn test_max_capacity() {
        let budget = SurbBudget::max_capacity();
        assert_eq!(budget.surb_count(), MAX_SURBS);
        assert!(budget.response_capacity() >= 260 * 1024 * 1024);
    }

    #[test]
    fn test_surb_count_never_zero() {
        let budget = SurbBudget::for_response_size(0);
        assert!(budget.surb_count() >= 1);
    }

    #[test]
    fn test_surb_count_clamped_to_max() {
        let budget = SurbBudget::for_response_size(usize::MAX / 2);
        assert_eq!(budget.surb_count(), MAX_SURBS);
    }

    #[test]
    fn test_forward_fragments_single_packet() {
        let budget = SurbBudget::rpc();
        assert_eq!(budget.forward_fragments_needed(100), 1);
    }

    #[test]
    fn test_forward_fragments_multiple_packets() {
        let budget = SurbBudget::for_response_size(30_000_000); // ~1000 SURBs
        let fragments = budget.forward_fragments_needed(100);
        assert!(fragments > 1);
        assert!(fragments <= MAX_FRAGMENTS_PER_MESSAGE as usize);
    }

    #[test]
    fn test_response_capacity_consistency() {
        for size in [1, 1_000, 100_000, 10_000_000] {
            let budget = SurbBudget::for_response_size(size);
            assert!(
                budget.response_capacity() >= size,
                "Budget for {} bytes has insufficient capacity: {}",
                size,
                budget.response_capacity()
            );
        }
    }

    #[test]
    fn test_usable_response_per_surb() {
        assert_eq!(
            USABLE_RESPONSE_PER_SURB,
            SURB_PAYLOAD_SIZE - FRAGMENT_OVERHEAD
        );
        assert_eq!(USABLE_RESPONSE_PER_SURB, 30_699);
    }

    #[test]
    fn test_constants_consistency() {
        let forward_capacity =
            MAX_FRAGMENTS_PER_MESSAGE as usize * (MAX_PAYLOAD_SIZE - FRAGMENT_OVERHEAD);
        let theoretical_max_surbs = forward_capacity / ESTIMATED_SURB_SERIALIZED_SIZE;
        assert!(
            theoretical_max_surbs >= MAX_SURBS,
            "Theoretical max {} < MAX_SURBS {}",
            theoretical_max_surbs,
            MAX_SURBS
        );
    }

    #[test]
    fn test_forward_fragments_exceeds_limit() {
        let budget = SurbBudget::max_capacity();
        let large_request = 500_000;
        let fragments = budget.forward_fragments_needed(large_request);
        assert!(
            fragments >= 190,
            "Expected >= 190 fragments, got {}",
            fragments
        );
    }

    #[test]
    fn test_rpc_budget_fits_single_fragment() {
        let budget = SurbBudget::rpc();
        let fragments = budget.forward_fragments_needed(200);
        assert_eq!(fragments, 1, "RPC budget should fit in a single fragment");
    }

    #[test]
    fn test_fec_ratio_zero_unchanged() {
        let budget = SurbBudget::for_response_size(100_000);
        let d = budget.surb_count();
        assert_eq!(budget.surb_count_with_fec(0.0), d);
        assert_eq!(budget.surb_count_with_fec(-1.0), d);
    }

    #[test]
    fn test_fec_ratio_adds_parity() {
        let budget = SurbBudget::for_response_size(100_000);
        let d = budget.surb_count();
        assert!(d >= 4, "Expected D >= 4, got {}", d);

        let total = budget.surb_count_with_fec(0.3);
        assert_eq!(total, d + 2, "Expected D + 2 parity, got {}", total);
    }

    #[test]
    fn test_fec_single_fragment_gets_one_parity() {
        let budget = SurbBudget::for_response_size(100);
        assert_eq!(budget.surb_count(), 1);
        assert_eq!(budget.surb_count_with_fec(0.3), 2);
        assert_eq!(budget.surb_count_with_fec(0.01), 2);
        assert_eq!(budget.surb_count_with_fec(1.0), 2);
    }

    #[test]
    fn test_fec_capped_by_max_surbs() {
        let budget = SurbBudget {
            expected_response_bytes: MAX_SURBS * USABLE_RESPONSE_PER_SURB,
            min_surbs: MAX_SURBS,
            max_surbs: MAX_SURBS,
        };
        let total = budget.surb_count_with_fec(1.0);
        assert_eq!(total, MAX_SURBS, "Should be capped at MAX_SURBS");
    }

    #[test]
    fn test_fec_d_zero_returns_zero() {
        let budget = SurbBudget::rpc();
        let total = budget.surb_count_with_fec(0.3);
        assert_eq!(total, DEFAULT_RPC_SURBS + 1);
    }

    #[test]
    fn test_fec_forward_fragments_with_surb_count() {
        let budget = SurbBudget::rpc();
        let d = budget.surb_count();
        let fec_total = budget.surb_count_with_fec(0.3);
        assert!(fec_total > d);

        let frags_d = budget.forward_fragments_for_surb_count(100, d);
        let frags_fec = budget.forward_fragments_for_surb_count(100, fec_total);
        assert!(frags_fec >= frags_d);
    }

    #[test]
    fn test_adaptive_fallback_before_enough_samples() {
        let adaptive = AdaptiveSurbBudget::new();
        let budget = adaptive.budget_for("eth_call");
        assert_eq!(budget.surb_count(), DEFAULT_RPC_SURBS);
    }

    #[test]
    fn test_adaptive_learns_after_min_samples() {
        let adaptive = AdaptiveSurbBudget::new();
        for _ in 0..3 {
            adaptive.record("eth_getLogs", 512_000);
        }
        let budget = adaptive.budget_for("eth_getLogs");
        assert!(
            budget.surb_count() > DEFAULT_RPC_SURBS,
            "adaptive budget should exceed rpc() default after learning"
        );
        let expected_min = (512_000.0 * EMA_HEADROOM) as usize;
        assert!(
            budget.response_capacity() >= expected_min,
            "capacity {} < headroom estimate {}",
            budget.response_capacity(),
            expected_min
        );
    }

    #[test]
    fn test_adaptive_ema_converges() {
        let adaptive = AdaptiveSurbBudget::new();
        for _ in 0..20 {
            adaptive.record("eth_call", 100_000);
        }
        let est = adaptive
            .estimate_bytes("eth_call")
            .expect("should have estimate");
        assert!(est >= 100_000, "estimate {est} < 100_000");
        assert!(est <= 200_000, "estimate {est} suspiciously large");
    }

    #[test]
    fn test_adaptive_isolates_operations() {
        let adaptive = AdaptiveSurbBudget::new();
        for _ in 0..5 {
            adaptive.record("eth_call", 1_000);
            adaptive.record("eth_getLogs", 1_000_000);
        }
        let small = adaptive.budget_for("eth_call");
        let large = adaptive.budget_for("eth_getLogs");
        assert!(
            large.surb_count() > small.surb_count(),
            "large-response op should get more SURBs than small-response op"
        );
    }

    #[test]
    fn test_adaptive_zero_bytes_ignored() {
        let adaptive = AdaptiveSurbBudget::new();
        adaptive.record("eth_call", 0);
        adaptive.record("eth_call", 0);
        let budget = adaptive.budget_for("eth_call");
        assert_eq!(budget.surb_count(), DEFAULT_RPC_SURBS);
        assert_eq!(adaptive.tracked_operations(), 0);
    }

    #[test]
    fn test_adaptive_tracked_operations_count() {
        let adaptive = AdaptiveSurbBudget::new();
        adaptive.record("a", 1_000);
        adaptive.record("b", 2_000);
        adaptive.record("a", 3_000);
        assert_eq!(adaptive.tracked_operations(), 2);
    }
}
