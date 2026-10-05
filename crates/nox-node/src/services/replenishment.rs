//! Bounded exit-side state for responses that wait for more SURBs.
//!
//! A large response that runs out of SURBs is stashed until the client sends
//! `ReplenishSurbs`; SURBs that arrive before such a stash exists are kept for
//! it. Both are filled by anonymous clients, so every dimension is capped:
//! number of entries, stashed bytes, SURBs per request, and age. When a cap is
//! reached the oldest entry goes first.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use nox_crypto::sphinx::surb::Surb;
use tracing::debug;

use crate::config::ReplenishmentConfig;
use crate::services::response_packer::PendingResponseState;

/// Limits for [`PendingResponses`] and [`SurbStash`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplenishmentLimits {
    pub max_pending_responses: usize,
    pub max_pending_bytes: usize,
    pub max_surb_requests: usize,
    pub max_surbs_per_request: usize,
    pub entry_ttl: Duration,
}

impl From<&ReplenishmentConfig> for ReplenishmentLimits {
    fn from(config: &ReplenishmentConfig) -> Self {
        Self {
            max_pending_responses: config.max_pending_responses,
            max_pending_bytes: config.max_pending_bytes,
            max_surb_requests: config.max_surb_requests,
            max_surbs_per_request: config.max_surbs_per_request,
            entry_ttl: Duration::from_secs(config.entry_ttl_secs),
        }
    }
}

impl Default for ReplenishmentLimits {
    fn default() -> Self {
        Self::from(&ReplenishmentConfig::default())
    }
}

fn oldest<T>(entries: &HashMap<u64, (T, Instant)>) -> Option<u64> {
    entries
        .iter()
        .min_by_key(|(_, (_, stored_at))| *stored_at)
        .map(|(id, _)| *id)
}

/// Partial responses waiting for SURBs, keyed by request ID.
#[derive(Debug)]
pub struct PendingResponses {
    entries: HashMap<u64, (PendingResponseState, Instant)>,
    bytes: usize,
    limits: ReplenishmentLimits,
}

impl PendingResponses {
    #[must_use]
    pub fn new(limits: ReplenishmentLimits) -> Self {
        Self {
            entries: HashMap::new(),
            bytes: 0,
            limits,
        }
    }

    /// Stashes `state`, evicting the oldest entries until the caps hold.
    /// A state larger than the byte cap on its own is dropped. Returns how
    /// many entries were evicted or dropped.
    pub fn insert(&mut self, request_id: u64, state: PendingResponseState) -> usize {
        let size = state.remaining_data.len();
        self.remove(&request_id);
        let mut dropped = 0;
        if size > self.limits.max_pending_bytes {
            debug!(
                request_id,
                bytes = size,
                limit = self.limits.max_pending_bytes,
                "Partial response exceeds the replenishment byte cap; dropped"
            );
            return dropped + 1;
        }
        while self.entries.len() >= self.limits.max_pending_responses
            || self.bytes + size > self.limits.max_pending_bytes
        {
            let Some(victim) = oldest(&self.entries) else {
                break;
            };
            self.remove(&victim);
            dropped += 1;
        }
        self.bytes += size;
        self.entries.insert(request_id, (state, Instant::now()));
        if dropped > 0 {
            debug!(
                evicted = dropped,
                "Replenishment caps reached; evicted the oldest partial responses"
            );
        }
        dropped
    }

    pub fn remove(&mut self, request_id: &u64) -> Option<PendingResponseState> {
        let (state, _) = self.entries.remove(request_id)?;
        self.bytes = self.bytes.saturating_sub(state.remaining_data.len());
        Some(state)
    }

    #[must_use]
    pub fn contains_key(&self, request_id: &u64) -> bool {
        self.entries.contains_key(request_id)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Undelivered bytes held.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Drops entries older than the TTL. Returns how many were dropped.
    pub fn prune_expired(&mut self, now: Instant) -> usize {
        let ttl = self.limits.entry_ttl;
        let expired: Vec<u64> = self
            .entries
            .iter()
            .filter(|(_, (_, stored_at))| now.saturating_duration_since(*stored_at) >= ttl)
            .map(|(id, _)| *id)
            .collect();
        for id in &expired {
            self.remove(id);
        }
        expired.len()
    }
}

impl Default for PendingResponses {
    fn default() -> Self {
        Self::new(ReplenishmentLimits::default())
    }
}

/// SURBs that arrived before the response they are for was stashed.
#[derive(Debug)]
pub struct SurbStash {
    entries: HashMap<u64, (Vec<Surb>, Instant)>,
    limits: ReplenishmentLimits,
}

impl SurbStash {
    #[must_use]
    pub fn new(limits: ReplenishmentLimits) -> Self {
        Self {
            entries: HashMap::new(),
            limits,
        }
    }

    /// Adds SURBs for `request_id`, up to the per-request cap. A new request
    /// beyond the request cap evicts the oldest one. Returns how many SURBs
    /// were dropped.
    pub fn add(&mut self, request_id: u64, surbs: Vec<Surb>) -> usize {
        if !self.entries.contains_key(&request_id) {
            while self.entries.len() >= self.limits.max_surb_requests {
                let Some(victim) = oldest(&self.entries) else {
                    break;
                };
                self.entries.remove(&victim);
            }
        }
        let cap = self.limits.max_surbs_per_request;
        let (held, _) = self
            .entries
            .entry(request_id)
            .or_insert_with(|| (Vec::new(), Instant::now()));
        let room = cap.saturating_sub(held.len());
        let offered = surbs.len();
        held.extend(surbs.into_iter().take(room));
        let dropped = offered.saturating_sub(room);
        if dropped > 0 {
            debug!(
                request_id,
                dropped, cap, "SURBs beyond the per-request cap were dropped"
            );
        }
        dropped
    }

    /// Replaces the SURBs held for `request_id`.
    pub fn insert(&mut self, request_id: u64, surbs: Vec<Surb>) -> usize {
        self.entries.remove(&request_id);
        self.add(request_id, surbs)
    }

    pub fn remove(&mut self, request_id: &u64) -> Option<Vec<Surb>> {
        self.entries.remove(request_id).map(|(surbs, _)| surbs)
    }

    #[must_use]
    pub fn contains_key(&self, request_id: &u64) -> bool {
        self.entries.contains_key(request_id)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// SURBs held across all requests.
    #[must_use]
    pub fn surb_count(&self) -> usize {
        self.entries.values().map(|(surbs, _)| surbs.len()).sum()
    }

    /// Drops entries older than the TTL. Returns how many were dropped.
    pub fn prune_expired(&mut self, now: Instant) -> usize {
        let ttl = self.limits.entry_ttl;
        let before = self.entries.len();
        self.entries
            .retain(|_, (_, stored_at)| now.saturating_duration_since(*stored_at) < ttl);
        before - self.entries.len()
    }
}

impl Default for SurbStash {
    fn default() -> Self {
        Self::new(ReplenishmentLimits::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::response_packer::ContinuationState;
    use nox_crypto::sphinx::PathHop;
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    fn limits() -> ReplenishmentLimits {
        ReplenishmentLimits {
            max_pending_responses: 3,
            max_pending_bytes: 1_000,
            max_surb_requests: 2,
            max_surbs_per_request: 4,
            entry_ttl: Duration::from_mins(1),
        }
    }

    fn state(bytes: usize) -> PendingResponseState {
        PendingResponseState {
            remaining_data: vec![0; bytes],
            continuation: ContinuationState {
                original_total_fragments: 2,
                fragments_already_sent: 1,
                original_data_len: bytes * 2,
            },
        }
    }

    fn surb(id: u8) -> Surb {
        let secret = StaticSecret::from([id.max(1); 32]);
        let path = vec![PathHop {
            public_key: X25519PublicKey::from(&secret),
            address: "/ip4/127.0.0.1/tcp/1".to_string(),
        }];
        Surb::new(&path, [id; 16], 0).unwrap().0
    }

    #[test]
    fn pending_entry_cap_evicts_the_oldest() {
        let mut pending = PendingResponses::new(limits());
        for id in 0..3 {
            assert_eq!(pending.insert(id, state(10)), 0);
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(pending.insert(3, state(10)), 1);
        assert_eq!(pending.len(), 3);
        assert!(!pending.contains_key(&0));
        assert!(pending.contains_key(&3));
    }

    #[test]
    fn pending_byte_cap_holds_and_oversized_states_are_dropped() {
        let mut pending = PendingResponses::new(limits());
        pending.insert(1, state(600));
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(pending.insert(2, state(600)), 1);
        assert_eq!(pending.bytes(), 600);
        assert!(pending.contains_key(&2));
        assert_eq!(pending.insert(3, state(1_001)), 1);
        assert!(!pending.contains_key(&3));
        assert_eq!(
            pending.remove(&2).map(|s| s.remaining_data.len()),
            Some(600)
        );
        assert_eq!(pending.bytes(), 0);
    }

    #[test]
    fn reinserting_a_request_replaces_its_bytes() {
        let mut pending = PendingResponses::new(limits());
        pending.insert(1, state(400));
        pending.insert(1, state(100));
        assert_eq!(pending.len(), 1);
        assert_eq!(pending.bytes(), 100);
    }

    #[test]
    fn pending_entries_expire() {
        let mut pending = PendingResponses::new(limits());
        pending.insert(1, state(10));
        let later = Instant::now() + Duration::from_secs(61);
        assert_eq!(pending.prune_expired(Instant::now()), 0);
        assert_eq!(pending.prune_expired(later), 1);
        assert!(pending.is_empty());
        assert_eq!(pending.bytes(), 0);
    }

    #[test]
    fn surb_stash_caps_requests_and_surbs_per_request() {
        let mut stash = SurbStash::new(limits());
        assert_eq!(stash.add(1, (0..3).map(surb).collect()), 0);
        assert_eq!(stash.add(1, (3..6).map(surb).collect()), 2);
        assert_eq!(stash.surb_count(), 4);
        std::thread::sleep(Duration::from_millis(2));
        stash.add(2, vec![surb(9)]);
        std::thread::sleep(Duration::from_millis(2));
        stash.add(3, vec![surb(10)]);
        assert_eq!(stash.len(), 2);
        assert!(!stash.contains_key(&1), "the oldest request was evicted");
        assert_eq!(stash.remove(&3).map(|s| s.len()), Some(1));
        let later = Instant::now() + Duration::from_secs(61);
        assert_eq!(stash.prune_expired(later), 1);
        assert!(stash.is_empty());
    }
}
