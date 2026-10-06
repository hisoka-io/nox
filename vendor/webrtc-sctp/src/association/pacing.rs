//! nox: pacing for the bursts the sender writes in one go (vendor/README.md).
//!
//! A KPS reply leaves as one burst of up to a congestion window. Sent at line
//! rate, a burst larger than the bottleneck queue of a home link loses its
//! tail. The write loop therefore passes every packet through a token
//! bucket: up to `PACING_BURST_BYTES` leave back to back after an idle
//! period, the rest at a rate derived from the measured delivery rate.
//!
//! The delivery rate is measured from ack trains: when a burst sits in the
//! bottleneck queue, the peer's SACKs come back spaced by the bottleneck, so
//! bytes acked over the time since the first SACK of the train is the
//! bottleneck rate. On a fast path the SACKs arrive bunched together and the
//! estimate is high, so pacing then costs next to nothing.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Bytes that may leave back to back after an idle period: 10 packets at
/// the 1,228-byte MTU, the burst of a TCP initial window.
pub(crate) const PACING_BURST_BYTES: u64 = 10 * 1_228;
/// Pacing rate until the first ack train is measured: 2,500 bytes/ms
/// (20 Mbit/s).
pub(crate) const PACING_INITIAL_BYTES_PER_MS: u64 = 2_500;
/// Lowest pacing rate: 250 bytes/ms (2 Mbit/s).
pub(crate) const PACING_MIN_BYTES_PER_MS: u64 = 250;
/// Pacing rate in quarters of the measured delivery rate (5/4 = 1.25×), so
/// the sender keeps probing for more bandwidth.
pub(crate) const PACING_GAIN_QUARTERS: u64 = 5;
/// An ack-train sample needs at least this many bytes acked after the first
/// SACK of the train.
pub(crate) const ACK_TRAIN_MIN_BYTES: u64 = 8 * 1_200;
/// Shortest span an ack-train sample is measured over. Trains that arrive
/// faster are counted at this span, which caps the estimate on fast paths
/// instead of dividing by a near-zero span.
pub(crate) const ACK_TRAIN_MIN_SPAN: Duration = Duration::from_millis(1);
/// A SACK that comes this many times later than the train's average SACK
/// spacing (and at least `ACK_TRAIN_GAP_FLOOR` after the previous one) is not
/// part of the train: typically the peer's delayed SACK for the last packet.
pub(crate) const ACK_TRAIN_GAP_FACTOR: u32 = 4;
/// See `ACK_TRAIN_GAP_FACTOR`.
pub(crate) const ACK_TRAIN_GAP_FLOOR: Duration = Duration::from_millis(5);
/// After a congestion loss, recent estimates are scaled to this many quarters
/// (3/4); with `PACING_GAIN_QUARTERS` the pace is then just under the rate
/// measured before the loss.
pub(crate) const CONGESTION_RATE_QUARTERS: u64 = 3;
/// Ack trains whose estimates feed the max filter.
pub(crate) const RATE_SAMPLES: usize = 4;

#[derive(Debug, Clone, Copy)]
struct Train {
    started: Instant,
    last: Instant,
    sacks: u32,
    acked: u64,
}

impl Train {
    fn new(now: Instant) -> Self {
        Self {
            started: now,
            last: now,
            sacks: 1,
            acked: 0,
        }
    }

    /// Bytes per ms over the whole train, if it is long enough.
    fn rate(&self) -> Option<u64> {
        if self.acked < ACK_TRAIN_MIN_BYTES {
            return None;
        }
        let span = self.last.duration_since(self.started).max(ACK_TRAIN_MIN_SPAN);
        let micros = span.as_micros().max(1) as u64;
        Some(self.acked.saturating_mul(1_000) / micros)
    }
}

/// Delivery-rate estimate from ack trains, and the pacing rate it gives.
///
/// A train's rate is the bytes acked after its first SACK over the time to
/// its last SACK, so SACKs the peer happens to send in bunches average out.
#[derive(Debug, Default)]
pub(crate) struct DeliveryRate {
    train: Option<Train>,
    recent: VecDeque<u64>,
}

impl DeliveryRate {
    /// A SACK acked `bytes` new bytes at `now`. The first SACK of a train is
    /// its time reference; its own bytes arrived before that reference.
    pub(crate) fn on_sack(&mut self, now: Instant, bytes: u64) {
        let Some(train) = &mut self.train else {
            self.train = Some(Train::new(now));
            return;
        };
        let gap = now.duration_since(train.last);
        if train.sacks >= 2 {
            let average = train.last.duration_since(train.started) / (train.sacks - 1);
            if gap > (average * ACK_TRAIN_GAP_FACTOR).max(ACK_TRAIN_GAP_FLOOR) {
                self.end_train();
                self.train = Some(Train::new(now));
                return;
            }
        }
        train.last = now;
        train.sacks += 1;
        train.acked += bytes;
    }

    /// Ends the current ack train: everything sent has been acked, or the
    /// train was interrupted.
    pub(crate) fn end_train(&mut self) {
        if let Some(rate) = self.train.take().and_then(|t| t.rate()) {
            if self.recent.len() == RATE_SAMPLES {
                self.recent.pop_front();
            }
            self.recent.push_back(rate);
        }
    }

    /// The window overran the path (several packets lost at once): the
    /// current train is unreliable and every recent estimate drops to
    /// `CONGESTION_RATE_QUARTERS`/4, so the next bursts are paced just below
    /// the rate that was measured.
    pub(crate) fn on_congestion(&mut self) {
        self.train = None;
        for rate in &mut self.recent {
            *rate = (*rate * CONGESTION_RATE_QUARTERS / 4).max(1);
        }
    }

    /// Pacing rate for the packets after the initial burst of a write.
    pub(crate) fn pacing_bytes_per_ms(&self) -> u64 {
        let measured = self
            .recent
            .iter()
            .copied()
            .chain(self.train.and_then(|t| t.rate()))
            .max()
            .unwrap_or(0);
        if measured == 0 {
            return PACING_INITIAL_BYTES_PER_MS;
        }
        (measured.saturating_mul(PACING_GAIN_QUARTERS) / 4).max(PACING_MIN_BYTES_PER_MS)
    }
}

/// Token bucket the write loop sends every packet through.
#[derive(Debug)]
pub(crate) struct Pacer {
    tokens: u64,
    refilled: tokio::time::Instant,
}

impl Pacer {
    pub(crate) fn new(now: tokio::time::Instant) -> Self {
        Self {
            tokens: PACING_BURST_BYTES,
            refilled: now,
        }
    }

    /// Takes `len` bytes from the bucket at `now` and returns when the packet
    /// may leave: `None` for at once.
    pub(crate) fn admit(
        &mut self,
        now: tokio::time::Instant,
        len: u64,
        bytes_per_ms: u64,
    ) -> Option<tokio::time::Instant> {
        let rate = bytes_per_ms.max(1);
        if now > self.refilled {
            let micros = now.duration_since(self.refilled).as_micros() as u64;
            self.tokens = self
                .tokens
                .saturating_add(micros.saturating_mul(rate) / 1_000)
                .min(PACING_BURST_BYTES);
            self.refilled = now;
        }
        if self.tokens >= len {
            self.tokens -= len;
            return None;
        }
        let wait = Duration::from_micros((len - self.tokens).saturating_mul(1_000) / rate);
        self.tokens = 0;
        self.refilled += wait;
        Some(self.refilled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_rate_until_a_train_is_measured() {
        let mut rate = DeliveryRate::default();
        assert_eq!(rate.pacing_bytes_per_ms(), PACING_INITIAL_BYTES_PER_MS);
        let t0 = Instant::now();
        rate.on_sack(t0, 2_400);
        rate.on_sack(t0 + Duration::from_millis(1), 2_400);
        // Below ACK_TRAIN_MIN_BYTES: no sample yet.
        assert_eq!(rate.pacing_bytes_per_ms(), PACING_INITIAL_BYTES_PER_MS);
    }

    #[test]
    fn bottleneck_spaced_train_sets_the_rate() {
        // 20 Mbit/s = 2,500 bytes/ms: one 2,400-byte SACK every 0.96 ms.
        let mut rate = DeliveryRate::default();
        let t0 = Instant::now();
        for i in 0..20u64 {
            rate.on_sack(t0 + Duration::from_micros(960 * i), 2_400);
        }
        rate.end_train();
        let pace = rate.pacing_bytes_per_ms();
        assert!((3_000..=3_300).contains(&pace), "pace {pace} should be about 1.25 x 2,500");
    }

    #[test]
    fn bunched_sacks_average_out_over_the_train() {
        // The same 2,500 bytes/ms, but the peer sends its SACKs in pairs.
        let mut rate = DeliveryRate::default();
        let t0 = Instant::now();
        for i in 0..20u64 {
            let at = t0 + Duration::from_micros(1_920 * (i / 2) + 10 * (i % 2));
            rate.on_sack(at, 2_400);
        }
        rate.end_train();
        let pace = rate.pacing_bytes_per_ms();
        assert!(pace <= 3_600, "pace {pace} should stay near 1.25 x 2,500");
    }

    #[test]
    fn a_delayed_last_sack_does_not_lower_the_rate() {
        let mut rate = DeliveryRate::default();
        let t0 = Instant::now();
        for i in 0..10u64 {
            rate.on_sack(t0 + Duration::from_millis(i), 2_400);
        }
        // The peer's delayed SACK for the odd last packet, 200 ms later.
        rate.on_sack(t0 + Duration::from_millis(209), 1_200);
        rate.end_train();
        assert_eq!(rate.pacing_bytes_per_ms(), 2_400 * 5 / 4);
    }

    #[test]
    fn bunched_train_on_a_fast_path_gives_a_high_rate() {
        let mut rate = DeliveryRate::default();
        let t0 = Instant::now();
        for i in 0..28u64 {
            rate.on_sack(t0 + Duration::from_micros(10 * i), 2_400);
        }
        rate.end_train();
        assert!(rate.pacing_bytes_per_ms() >= 60_000);
    }

    #[test]
    fn max_filter_keeps_the_best_recent_trains() {
        let mut rate = DeliveryRate::default();
        let mut t = Instant::now();
        let mut train = |rate: &mut DeliveryRate, gap_us: u64| {
            for _ in 0..12 {
                rate.on_sack(t, 2_400);
                t += Duration::from_micros(gap_us);
            }
            rate.end_train();
            t += Duration::from_secs(1);
        };
        train(&mut rate, 1_000); // 2,400 B/ms
        train(&mut rate, 4_000); // 600 B/ms
        assert_eq!(rate.pacing_bytes_per_ms(), 2_400 * 5 / 4);
        for _ in 0..RATE_SAMPLES {
            train(&mut rate, 4_000);
        }
        assert_eq!(rate.pacing_bytes_per_ms(), 600 * 5 / 4);
    }

    #[test]
    fn congestion_lowers_the_pace_below_the_measured_rate() {
        let mut rate = DeliveryRate::default();
        let t0 = Instant::now();
        for i in 0..12u64 {
            rate.on_sack(t0 + Duration::from_millis(i), 2_400);
        }
        rate.end_train();
        rate.on_congestion();
        assert_eq!(rate.pacing_bytes_per_ms(), 2_400 * 3 / 4 * 5 / 4);
    }

    #[test]
    fn burst_leaves_at_once_and_the_rest_is_paced() {
        let start = tokio::time::Instant::now();
        let mut pacer = Pacer::new(start);
        for _ in 0..10 {
            assert!(pacer.admit(start, 1_228, 1_228).is_none());
        }
        // One packet per ms at 1,228 bytes/ms, across writes.
        assert_eq!(pacer.admit(start, 1_228, 1_228), Some(start + Duration::from_millis(1)));
        assert_eq!(pacer.admit(start, 1_228, 1_228), Some(start + Duration::from_millis(2)));
        // After an idle period the burst allowance is back, capped.
        let later = start + Duration::from_secs(1);
        for _ in 0..10 {
            assert!(pacer.admit(later, 1_228, 1_228).is_none());
        }
        assert!(pacer.admit(later, 1_228, 1_228).is_some());
    }
}
