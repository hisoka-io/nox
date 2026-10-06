//! Storage for format 2 replies, filed under their delivery ID.
//!
//! Kept apart from the handle-keyed buffer so that these entries can never
//! push handle-keyed replies out. It is bounded by entry count and by bytes,
//! and no single previous-hop peer may hold more than a fixed share of either.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::response_buffer::{SurbId, DEFAULT_CLAIM_GRACE};

/// Default entry cap.
pub const DEFAULT_DELIVERY_MAX_ENTRIES: usize = 1_000;
/// Default byte cap (64 MiB).
pub const DEFAULT_DELIVERY_MAX_BYTES: usize = 64 * 1024 * 1024;
/// Largest share of the entry cap and of the byte cap one source peer may hold.
pub const DELIVERY_SOURCE_SHARE_PERCENT: usize = 25;

/// Limits for a [`DeliveryBuffer`].
#[derive(Debug, Clone, Copy)]
pub struct DeliveryLimits {
    pub max_entries: usize,
    pub max_bytes: usize,
    pub source_share_percent: usize,
}

impl Default for DeliveryLimits {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_DELIVERY_MAX_ENTRIES,
            max_bytes: DEFAULT_DELIVERY_MAX_BYTES,
            source_share_percent: DELIVERY_SOURCE_SHARE_PERCENT,
        }
    }
}

impl DeliveryLimits {
    fn source_max_entries(&self) -> usize {
        (self.max_entries * self.source_share_percent / 100).max(1)
    }

    fn source_max_bytes(&self) -> usize {
        (self.max_bytes * self.source_share_percent / 100).max(1)
    }
}

/// Result of [`DeliveryBuffer::store`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryStore {
    /// Stored. `evicted` older entries were removed to make room.
    Stored { evicted: usize },
    /// A reply for this delivery ID is already held; the new one is dropped.
    Duplicate,
    /// The source peer already holds its share; the new reply is dropped.
    SourceQuota,
    /// The reply alone is larger than the source share of the byte cap.
    TooLarge,
    /// The client acked this ID before the reply arrived (it decoded the
    /// request's other replies); the reply is dropped.
    Acked,
}

struct Entry {
    data: Vec<u8>,
    created_at: Instant,
    /// Set by the first retaining claim; the entry then lives until acked or
    /// until the claim grace has passed.
    claimed_at: Option<Instant>,
    source: String,
}

impl Entry {
    fn is_live(&self, ttl: Duration, grace: Duration) -> bool {
        self.created_at.elapsed() < ttl && self.claimed_at.is_none_or(|at| at.elapsed() < grace)
    }
}

#[derive(Default, Clone, Copy)]
struct Usage {
    entries: usize,
    bytes: usize,
}

/// Format 2 replies by delivery ID.
pub struct DeliveryBuffer {
    entries: HashMap<SurbId, Entry>,
    per_source: HashMap<String, Usage>,
    bytes: usize,
    limits: DeliveryLimits,
    claim_grace: Duration,
}

impl DeliveryBuffer {
    #[must_use]
    pub fn new(limits: DeliveryLimits) -> Self {
        Self {
            entries: HashMap::new(),
            per_source: HashMap::new(),
            bytes: 0,
            limits,
            claim_grace: DEFAULT_CLAIM_GRACE,
        }
    }

    /// How long a reply stays re-claimable after its first retaining claim.
    #[must_use]
    pub fn with_claim_grace(mut self, grace: Duration) -> Self {
        self.claim_grace = grace;
        self
    }

    /// Oldest entry to evict: replies already handed out by a retaining claim
    /// go first (oldest claim first), then the oldest unclaimed reply.
    fn eviction_candidate(&self) -> Option<SurbId> {
        self.entries
            .iter()
            .filter_map(|(id, entry)| entry.claimed_at.map(|at| (at, *id)))
            .min_by_key(|(at, _)| *at)
            .map(|(_, id)| id)
            .or_else(|| {
                self.entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.created_at)
                    .map(|(id, _)| *id)
            })
    }

    fn remove(&mut self, id: &SurbId) -> Option<Entry> {
        let entry = self.entries.remove(id)?;
        self.bytes -= entry.data.len();
        if let Some(usage) = self.per_source.get_mut(&entry.source) {
            usage.entries -= 1;
            usage.bytes -= entry.data.len();
            if usage.entries == 0 {
                self.per_source.remove(&entry.source);
            }
        }
        Some(entry)
    }

    /// Removes entries older than `ttl` and claimed entries past the claim
    /// grace. Returns how many were removed.
    pub fn prune(&mut self, ttl: Duration) -> usize {
        let grace = self.claim_grace;
        let expired: Vec<SurbId> = self
            .entries
            .iter()
            .filter(|(_, entry)| !entry.is_live(ttl, grace))
            .map(|(id, _)| *id)
            .collect();
        for id in &expired {
            self.remove(id);
        }
        expired.len()
    }

    /// Stores a reply from `source`. Expired entries are pruned first; if the
    /// buffer is still full, the oldest entries are evicted.
    pub fn store(
        &mut self,
        id: SurbId,
        source: &str,
        data: Vec<u8>,
        ttl: Duration,
    ) -> DeliveryStore {
        let size = data.len();
        if size > self.limits.source_max_bytes() {
            return DeliveryStore::TooLarge;
        }
        if let Some(existing) = self.entries.get(&id) {
            if existing.is_live(ttl, self.claim_grace) {
                return DeliveryStore::Duplicate;
            }
            self.remove(&id);
        }

        let usage = self.per_source.get(source).copied().unwrap_or_default();
        let over_quota = usage.entries + 1 > self.limits.source_max_entries()
            || usage.bytes + size > self.limits.source_max_bytes();
        if over_quota {
            self.prune(ttl);
            let usage = self.per_source.get(source).copied().unwrap_or_default();
            if usage.entries + 1 > self.limits.source_max_entries()
                || usage.bytes + size > self.limits.source_max_bytes()
            {
                return DeliveryStore::SourceQuota;
            }
        }

        let mut evicted = 0;
        if self.entries.len() + 1 > self.limits.max_entries
            || self.bytes + size > self.limits.max_bytes
        {
            self.prune(ttl);
            while self.entries.len() + 1 > self.limits.max_entries
                || self.bytes + size > self.limits.max_bytes
            {
                let Some(oldest) = self.eviction_candidate() else {
                    break;
                };
                self.remove(&oldest);
                evicted += 1;
            }
        }

        self.bytes += size;
        let usage = self.per_source.entry(source.to_string()).or_default();
        usage.entries += 1;
        usage.bytes += size;
        self.entries.insert(
            id,
            Entry {
                data,
                created_at: Instant::now(),
                claimed_at: None,
                source: source.to_string(),
            },
        );
        DeliveryStore::Stored { evicted }
    }

    /// Removes and returns the reply for `id` if it is still live. The flag
    /// says whether a retaining claim had already handed it out.
    pub fn take(&mut self, id: &SurbId, ttl: Duration) -> Option<(Vec<u8>, bool)> {
        let entry = self.remove(id)?;
        let reclaimed = entry.claimed_at.is_some();
        entry
            .is_live(ttl, self.claim_grace)
            .then_some((entry.data, reclaimed))
    }

    /// Returns a copy of the reply for `id` and keeps it until it is acked or
    /// the claim grace has passed (counted from the first such claim, never
    /// extended). The flag says whether it had been handed out before.
    pub fn claim_retained(&mut self, id: &SurbId, ttl: Duration) -> Option<(Vec<u8>, bool)> {
        let grace = self.claim_grace;
        let live = self.entries.get(id)?.is_live(ttl, grace);
        if !live {
            self.remove(id);
            return None;
        }
        let entry = self.entries.get_mut(id)?;
        let reclaimed = entry.claimed_at.is_some();
        if !reclaimed {
            entry.claimed_at = Some(Instant::now());
        }
        Some((entry.data.clone(), reclaimed))
    }

    /// Whether a live reply is held for `id`.
    #[must_use]
    pub fn contains_live(&self, id: &SurbId, ttl: Duration) -> bool {
        self.entries
            .get(id)
            .is_some_and(|entry| entry.is_live(ttl, self.claim_grace))
    }

    /// When the live reply for `id` was stored, if one is held.
    #[must_use]
    pub fn live_created_at(&self, id: &SurbId, ttl: Duration) -> Option<Instant> {
        self.entries
            .get(id)
            .filter(|entry| entry.is_live(ttl, self.claim_grace))
            .map(|entry| entry.created_at)
    }

    /// The limits this buffer was built with.
    #[must_use]
    pub fn limits(&self) -> DeliveryLimits {
        self.limits
    }

    /// Removes the reply for `id` (the client has it). Returns whether one
    /// was held.
    pub fn ack(&mut self, id: &SurbId) -> bool {
        self.remove(id).is_some()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: Duration = Duration::from_mins(5);

    fn limits(max_entries: usize, max_bytes: usize) -> DeliveryLimits {
        DeliveryLimits {
            max_entries,
            max_bytes,
            source_share_percent: 25,
        }
    }

    fn id(n: u16) -> SurbId {
        let mut id = [0u8; 16];
        id[..2].copy_from_slice(&n.to_be_bytes());
        id
    }

    #[test]
    fn defaults_are_one_thousand_entries_and_64_mib() {
        let l = DeliveryLimits::default();
        assert_eq!(l.max_entries, 1_000);
        assert_eq!(l.max_bytes, 64 * 1024 * 1024);
        assert_eq!(l.source_max_entries(), 250);
        assert_eq!(l.source_max_bytes(), 16 * 1024 * 1024);
    }

    #[test]
    fn one_source_cannot_hold_more_than_its_share_of_entries() {
        let mut buf = DeliveryBuffer::new(limits(8, 1 << 20));
        assert_eq!(
            buf.store(id(1), "a", vec![1], TTL),
            DeliveryStore::Stored { evicted: 0 }
        );
        assert_eq!(
            buf.store(id(2), "a", vec![1], TTL),
            DeliveryStore::Stored { evicted: 0 }
        );
        assert_eq!(
            buf.store(id(3), "a", vec![1], TTL),
            DeliveryStore::SourceQuota
        );
        assert_eq!(
            buf.store(id(3), "b", vec![1], TTL),
            DeliveryStore::Stored { evicted: 0 }
        );
        assert_eq!(buf.len(), 3);
    }

    #[test]
    fn one_source_cannot_hold_more_than_its_share_of_bytes() {
        let mut buf = DeliveryBuffer::new(limits(100, 400));
        assert_eq!(
            buf.store(id(1), "a", vec![0; 60], TTL),
            DeliveryStore::Stored { evicted: 0 }
        );
        assert_eq!(
            buf.store(id(2), "a", vec![0; 60], TTL),
            DeliveryStore::SourceQuota
        );
        assert_eq!(
            buf.store(id(3), "a", vec![0; 101], TTL),
            DeliveryStore::TooLarge
        );
        assert_eq!(buf.bytes(), 60);
    }

    #[test]
    fn quota_frees_up_when_a_reply_is_claimed() {
        let mut buf = DeliveryBuffer::new(limits(4, 1 << 20));
        assert_eq!(
            buf.store(id(1), "a", vec![1], TTL),
            DeliveryStore::Stored { evicted: 0 }
        );
        assert_eq!(
            buf.store(id(2), "a", vec![1], TTL),
            DeliveryStore::SourceQuota
        );
        assert_eq!(buf.take(&id(1), TTL), Some((vec![1], false)));
        assert_eq!(
            buf.store(id(2), "a", vec![1], TTL),
            DeliveryStore::Stored { evicted: 0 }
        );
    }

    #[test]
    fn full_buffer_evicts_oldest() {
        let mut buf = DeliveryBuffer::new(limits(4, 1 << 20));
        for (n, src) in ["a", "b", "c", "d"].iter().enumerate() {
            let n = u16::try_from(n).expect("small");
            assert_eq!(
                buf.store(id(n), src, vec![1], TTL),
                DeliveryStore::Stored { evicted: 0 }
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(
            buf.store(id(9), "e", vec![2], TTL),
            DeliveryStore::Stored { evicted: 1 }
        );
        assert_eq!(buf.len(), 4);
        assert!(buf.take(&id(0), TTL).is_none());
        assert_eq!(buf.take(&id(9), TTL), Some((vec![2], false)));
    }

    #[test]
    fn byte_cap_evicts_until_the_reply_fits() {
        let mut buf = DeliveryBuffer::new(DeliveryLimits {
            max_entries: 100,
            max_bytes: 100,
            source_share_percent: 100,
        });
        buf.store(id(1), "a", vec![0; 40], TTL);
        std::thread::sleep(Duration::from_millis(2));
        buf.store(id(2), "b", vec![0; 40], TTL);
        assert_eq!(
            buf.store(id(3), "c", vec![0; 40], TTL),
            DeliveryStore::Stored { evicted: 1 }
        );
        assert_eq!(buf.bytes(), 80);
        assert!(buf.take(&id(1), TTL).is_none());
    }

    #[test]
    fn duplicate_delivery_id_keeps_the_first_reply() {
        let mut buf = DeliveryBuffer::new(DeliveryLimits::default());
        buf.store(id(1), "a", vec![1], TTL);
        assert_eq!(
            buf.store(id(1), "b", vec![2], TTL),
            DeliveryStore::Duplicate
        );
        assert_eq!(buf.take(&id(1), TTL), Some((vec![1], false)));
    }

    #[test]
    fn expired_entries_are_pruned_and_not_returned() {
        let ttl = Duration::from_millis(1);
        let mut buf = DeliveryBuffer::new(DeliveryLimits::default());
        buf.store(id(1), "a", vec![1; 10], ttl);
        buf.store(id(2), "a", vec![1; 10], ttl);
        std::thread::sleep(Duration::from_millis(5));
        assert!(buf.take(&id(1), ttl).is_none());
        assert_eq!(buf.prune(ttl), 1);
        assert!(buf.is_empty());
        assert_eq!(buf.bytes(), 0);
    }

    #[test]
    fn retained_claim_is_reclaimable_until_acked() {
        let mut buf = DeliveryBuffer::new(DeliveryLimits::default());
        buf.store(id(1), "a", vec![7], TTL);
        assert_eq!(buf.claim_retained(&id(1), TTL), Some((vec![7], false)));
        assert_eq!(buf.claim_retained(&id(1), TTL), Some((vec![7], true)));
        assert_eq!(buf.len(), 1);
        assert!(buf.ack(&id(1)));
        assert!(!buf.ack(&id(1)));
        assert!(buf.claim_retained(&id(1), TTL).is_none());
        assert_eq!(buf.bytes(), 0);
    }

    #[test]
    fn retained_claim_expires_after_the_grace() {
        let mut buf = DeliveryBuffer::new(DeliveryLimits::default())
            .with_claim_grace(Duration::from_millis(5));
        buf.store(id(1), "a", vec![7], TTL);
        buf.store(id(2), "a", vec![8], TTL);
        assert!(buf.claim_retained(&id(1), TTL).is_some());
        std::thread::sleep(Duration::from_millis(10));
        assert!(buf.claim_retained(&id(1), TTL).is_none());
        assert_eq!(buf.prune(TTL), 0, "the expired claim was dropped on access");
        assert_eq!(buf.len(), 1, "the unclaimed reply keeps its full TTL");
    }

    #[test]
    fn claimed_replies_are_evicted_before_unclaimed_ones() {
        let mut buf = DeliveryBuffer::new(DeliveryLimits {
            max_entries: 2,
            max_bytes: 1 << 20,
            source_share_percent: 100,
        });
        buf.store(id(1), "a", vec![1], TTL);
        std::thread::sleep(Duration::from_millis(2));
        buf.store(id(2), "b", vec![2], TTL);
        assert!(buf.claim_retained(&id(2), TTL).is_some());
        assert_eq!(
            buf.store(id(3), "c", vec![3], TTL),
            DeliveryStore::Stored { evicted: 1 }
        );
        assert!(buf.claim_retained(&id(2), TTL).is_none());
        assert_eq!(buf.take(&id(1), TTL), Some((vec![1], false)));
    }
}
