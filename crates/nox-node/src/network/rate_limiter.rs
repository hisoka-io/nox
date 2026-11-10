//! Token bucket rate limiter with adaptive reputation-based limits per peer.

use dashmap::DashMap;
use governor::{
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use libp2p::PeerId;
use std::{
    num::NonZeroU32,
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::{debug, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitResult {
    Allowed,
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PeerReputation {
    #[default]
    Unknown,
    Trusted,
    Penalized,
}

#[derive(Debug, Clone)]
struct ViolationTracker {
    count: u32,
    first_violation: Instant,
    first_seen: Instant,
    last_active: Instant,
}

impl Default for ViolationTracker {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            count: 0,
            first_violation: now,
            first_seen: now,
            last_active: now,
        }
    }
}

use crate::config::RateLimitConfig;

type DirectRateLimiter = RateLimiter<NotKeyed, InMemoryState, governor::clock::DefaultClock>;

struct PeerEntry {
    limiter: Arc<DirectRateLimiter>,
    reputation: PeerReputation,
    violations: ViolationTracker,
}

pub struct PeerRateLimiter {
    peers: DashMap<PeerId, PeerEntry>,
    config: RateLimitConfig,
}

impl PeerRateLimiter {
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(RateLimitConfig::default())
    }

    #[must_use]
    pub fn with_config(config: RateLimitConfig) -> Self {
        Self {
            peers: DashMap::new(),
            config,
        }
    }

    fn create_limiter(&self, reputation: PeerReputation) -> Arc<DirectRateLimiter> {
        let (burst, rate) = match reputation {
            PeerReputation::Unknown => (self.config.burst_unknown, self.config.rate_unknown),
            PeerReputation::Trusted => (self.config.burst_trusted, self.config.rate_trusted),
            PeerReputation::Penalized => (self.config.burst_penalized, self.config.rate_penalized),
        };

        // SAFETY: 1 is always non-zero.
        let one = NonZeroU32::MIN;
        let burst = NonZeroU32::new(burst).unwrap_or(one);
        let rate = NonZeroU32::new(rate).unwrap_or(one);

        Arc::new(RateLimiter::direct(
            Quota::per_second(rate).allow_burst(burst),
        ))
    }

    fn get_or_create_entry(
        &self,
        peer: &PeerId,
    ) -> dashmap::mapref::one::RefMut<'_, PeerId, PeerEntry> {
        self.peers.entry(*peer).or_insert_with(|| {
            let reputation = PeerReputation::Unknown;
            PeerEntry {
                limiter: self.create_limiter(reputation),
                reputation,
                violations: ViolationTracker::default(),
            }
        })
    }

    pub fn check(&self, peer: &PeerId) -> RateLimitResult {
        let mut entry = self.get_or_create_entry(peer);
        entry.violations.last_active = Instant::now();

        if entry.reputation == PeerReputation::Unknown
            && entry.violations.first_seen.elapsed()
                >= Duration::from_secs(self.config.trust_promotion_time_secs)
            && entry.violations.count == 0
        {
            debug!(peer = %peer, "Promoting peer to trusted status");
            entry.reputation = PeerReputation::Trusted;
            entry.limiter = self.create_limiter(PeerReputation::Trusted);
        }

        if let Ok(()) = entry.limiter.check() {
            RateLimitResult::Allowed
        } else {
            let now = Instant::now();
            if now.duration_since(entry.violations.first_violation)
                > Duration::from_secs(self.config.violation_window_secs)
            {
                entry.violations.count = 1;
                entry.violations.first_violation = now;
            } else {
                entry.violations.count += 1;
            }

            if entry.reputation != PeerReputation::Penalized && entry.violations.count > 1 {
                warn!(peer = %peer, "Penalizing peer for repeated rate limit violations");
                entry.reputation = PeerReputation::Penalized;
                entry.limiter = self.create_limiter(PeerReputation::Penalized);
            }

            RateLimitResult::Denied
        }
    }

    #[must_use]
    pub fn should_disconnect(&self, peer: &PeerId) -> bool {
        if let Some(entry) = self.peers.get(peer) {
            let in_window = entry.violations.first_violation.elapsed()
                <= Duration::from_secs(self.config.violation_window_secs);
            in_window && entry.violations.count >= self.config.violations_before_disconnect
        } else {
            false
        }
    }

    pub fn promote_to_trusted(&self, peer: &PeerId) {
        if let Some(mut entry) = self.peers.get_mut(peer) {
            if entry.reputation != PeerReputation::Trusted {
                debug!(peer = %peer, "Manually promoting peer to trusted");
                entry.reputation = PeerReputation::Trusted;
                entry.limiter = self.create_limiter(PeerReputation::Trusted);
            }
        }
    }

    #[must_use]
    pub fn get_reputation(&self, peer: &PeerId) -> Option<PeerReputation> {
        self.peers.get(peer).map(|e| e.reputation)
    }

    #[must_use]
    pub fn get_violation_count(&self, peer: &PeerId) -> u32 {
        self.peers.get(peer).map_or(0, |e| e.violations.count)
    }

    pub fn remove_peer(&self, peer: &PeerId) {
        self.peers.remove(peer);
    }

    /// Drops limiter state for peers idle for `inactive_peer_ttl_secs`. Peers
    /// with violations inside the violation window keep their state.
    pub fn cleanup_inactive(&self) {
        let max_idle = Duration::from_secs(self.config.inactive_peer_ttl_secs);
        let window = Duration::from_secs(self.config.violation_window_secs);
        self.peers.retain(|peer, entry| {
            let recent_violation =
                entry.violations.count > 0 && entry.violations.first_violation.elapsed() <= window;
            let keep = recent_violation || entry.violations.last_active.elapsed() < max_idle;
            if !keep {
                debug!(peer = %peer, "Cleaning up inactive peer rate limiter");
            }
            keep
        });
    }

    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
}

impl Default for PeerRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn test_allows_burst() {
        let limiter = PeerRateLimiter::with_config(RateLimitConfig {
            burst_unknown: 5,
            rate_unknown: 2,
            ..Default::default()
        });
        let peer = test_peer();

        for _ in 0..5 {
            assert_eq!(limiter.check(&peer), RateLimitResult::Allowed);
        }

        assert_eq!(limiter.check(&peer), RateLimitResult::Denied);
    }

    #[test]
    fn test_tracks_violations() {
        let limiter = PeerRateLimiter::with_config(RateLimitConfig {
            burst_unknown: 1,
            rate_unknown: 1,
            violations_before_disconnect: 3,
            ..Default::default()
        });
        let peer = test_peer();

        assert_eq!(limiter.check(&peer), RateLimitResult::Allowed);

        // Governor GCRA refills continuously, so send enough to guarantee denials
        let mut violations = 0;
        for _ in 0..20 {
            if limiter.check(&peer) == RateLimitResult::Denied {
                violations += 1;
            }
        }

        assert!(
            violations >= 3,
            "Should have at least 3 violations, got {}",
            violations
        );

        assert!(
            limiter.should_disconnect(&peer),
            "Peer should be marked for disconnect after {} violations",
            limiter.get_violation_count(&peer)
        );
    }

    #[test]
    fn test_penalizes_abusers() {
        let limiter = PeerRateLimiter::with_config(RateLimitConfig {
            burst_unknown: 2,
            rate_unknown: 1,
            ..Default::default()
        });
        let peer = test_peer();

        limiter.check(&peer);
        limiter.check(&peer);

        limiter.check(&peer);
        limiter.check(&peer);

        assert_eq!(
            limiter.get_reputation(&peer),
            Some(PeerReputation::Penalized)
        );
    }

    #[test]
    fn test_manual_trust_promotion() {
        let limiter = PeerRateLimiter::new();
        let peer = test_peer();

        limiter.check(&peer);
        assert_eq!(limiter.get_reputation(&peer), Some(PeerReputation::Unknown));

        limiter.promote_to_trusted(&peer);
        assert_eq!(limiter.get_reputation(&peer), Some(PeerReputation::Trusted));
    }

    fn short_ttl_config() -> RateLimitConfig {
        RateLimitConfig {
            burst_unknown: 1,
            rate_unknown: 1,
            inactive_peer_ttl_secs: 0,
            violation_window_secs: 3600,
            trust_promotion_time_secs: 3600,
            ..RateLimitConfig::default()
        }
    }

    #[test]
    fn test_cleanup_keeps_recent_violations() {
        let limiter = PeerRateLimiter::with_config(short_ttl_config());
        let peer = test_peer();
        let mut denied = 0;
        for _ in 0..5 {
            if limiter.check(&peer) == RateLimitResult::Denied {
                denied += 1;
            }
        }
        assert!(denied > 0);
        let reputation = limiter.get_reputation(&peer);
        limiter.cleanup_inactive();
        assert_eq!(limiter.peer_count(), 1, "violation history dropped");
        assert_eq!(limiter.get_reputation(&peer), reputation);
    }

    #[test]
    fn test_cleanup_drops_idle_clean_peers_only() {
        let config = RateLimitConfig {
            inactive_peer_ttl_secs: 3600,
            ..RateLimitConfig::default()
        };
        let limiter = PeerRateLimiter::with_config(config);
        let peer = test_peer();
        assert_eq!(limiter.check(&peer), RateLimitResult::Allowed);
        limiter.cleanup_inactive();
        assert_eq!(limiter.peer_count(), 1, "active peer dropped");

        let idle = PeerRateLimiter::with_config(RateLimitConfig {
            inactive_peer_ttl_secs: 0,
            ..RateLimitConfig::default()
        });
        assert_eq!(idle.check(&peer), RateLimitResult::Allowed);
        idle.cleanup_inactive();
        assert_eq!(idle.peer_count(), 0);
    }

    #[test]
    fn test_inactive_ttl_defaults_when_absent() {
        let config: RateLimitConfig = serde_json::from_str(
            r#"{"burst_unknown": 50, "rate_unknown": 100, "burst_trusted": 100,
                "rate_trusted": 200, "burst_penalized": 10, "rate_penalized": 25,
                "violations_before_disconnect": 5, "violation_window_secs": 60,
                "trust_promotion_time_secs": 3600}"#,
        )
        .expect("config parses");
        assert_eq!(config.inactive_peer_ttl_secs, 600);
    }
}
