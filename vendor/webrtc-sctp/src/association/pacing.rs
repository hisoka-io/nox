//! nox: pacing for the bursts the sender writes in one go (vendor/README.md).
//!
//! A KPS reply leaves as one burst of up to a congestion window. Sent at line
//! rate, a burst larger than the bottleneck queue of a home link loses its
//! tail. The write loop therefore sends the first `PACING_BURST_PACKETS`
//! packets of a write back to back and paces the rest at a rate derived from
//! the measured delivery rate.
//!
//! The delivery rate is measured from ack trains: when a burst sits in the
//! bottleneck queue, the peer's SACKs come back spaced by the bottleneck, so
//! bytes acked over the time since the first SACK of the train is the
//! bottleneck rate. On a fast path the SACKs arrive bunched together and the
//! estimate is high, so pacing then costs next to nothing.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Packets of one write that leave back to back before pacing starts.
pub(crate) const PACING_BURST_PACKETS: usize = 16;
/// Pacing rate until the first ack train is measured: 5,000 bytes/ms
/// (40 Mbit/s).
pub(crate) const PACING_INITIAL_BYTES_PER_MS: u64 = 5_000;
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
/// Ack trains whose estimates feed the max filter.
pub(crate) const RATE_SAMPLES: usize = 4;

#[derive(Debug, Clone, Copy)]
struct Train {
    started: Instant,
    acked: u64,
    best_bytes_per_ms: u64,
}

/// Delivery-rate estimate from ack trains, and the pacing rate it gives.
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
            self.train = Some(Train {
                started: now,
                acked: 0,
                best_bytes_per_ms: 0,
            });
            return;
        };
        train.acked += bytes;
        if train.acked < ACK_TRAIN_MIN_BYTES {
            return;
        }
        let span = now.duration_since(train.started).max(ACK_TRAIN_MIN_SPAN);
        let micros = span.as_micros().max(1) as u64;
        let rate = train.acked.saturating_mul(1_000) / micros;
        train.best_bytes_per_ms = train.best_bytes_per_ms.max(rate);
    }

    /// Ends the current ack train: everything sent has been acked, or a new
    /// burst starts after an idle period.
    pub(crate) fn end_train(&mut self) {
        if let Some(train) = self.train.take() {
            if train.best_bytes_per_ms > 0 {
                if self.recent.len() == RATE_SAMPLES {
                    self.recent.pop_front();
                }
                self.recent.push_back(train.best_bytes_per_ms);
            }
        }
    }

    /// Pacing rate for the packets after the initial burst of a write.
    pub(crate) fn pacing_bytes_per_ms(&self) -> u64 {
        let measured = self
            .recent
            .iter()
            .copied()
            .chain(self.train.map(|t| t.best_bytes_per_ms))
            .max()
            .unwrap_or(0);
        if measured == 0 {
            return PACING_INITIAL_BYTES_PER_MS;
        }
        (measured.saturating_mul(PACING_GAIN_QUARTERS) / 4).max(PACING_MIN_BYTES_PER_MS)
    }
}

/// When packet number `index` of a write may leave, given `paced_bytes` sent
/// after the initial burst so far, the write's start and the pacing rate.
pub(crate) fn send_at(
    started: tokio::time::Instant,
    index: usize,
    paced_bytes: u64,
    bytes_per_ms: u64,
) -> Option<tokio::time::Instant> {
    if index < PACING_BURST_PACKETS || bytes_per_ms == 0 {
        return None;
    }
    let micros = paced_bytes.saturating_mul(1_000) / bytes_per_ms;
    Some(started + Duration::from_micros(micros))
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
        };
        train(&mut rate, 1_000); // 2,400 B/ms
        train(&mut rate, 4_000); // 600 B/ms, e.g. a delayed SACK
        assert_eq!(rate.pacing_bytes_per_ms(), 2_400 * 5 / 4);
        for _ in 0..RATE_SAMPLES {
            train(&mut rate, 4_000);
        }
        assert_eq!(rate.pacing_bytes_per_ms(), 600 * 5 / 4);
    }

    #[test]
    fn burst_packets_are_not_paced() {
        let start = tokio::time::Instant::now();
        assert!(send_at(start, 0, 0, 1_000).is_none());
        assert!(send_at(start, PACING_BURST_PACKETS - 1, 0, 1_000).is_none());
        assert_eq!(
            send_at(start, PACING_BURST_PACKETS + 3, 5_000, 1_000),
            Some(start + Duration::from_millis(5))
        );
    }
}
