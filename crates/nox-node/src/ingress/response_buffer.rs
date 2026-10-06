//! `ResponseBuffer` -- Thread-safe buffer for SURB responses.
//!
//! Exit nodes send SURB responses back through the mixnet. When a response
//! arrives at the entry node, it is stored here under `reply-0-{surb_id_hex}`
//! (see `ResponseRouter`). Clients retrieve their own responses by the exact
//! 16-byte SURB IDs they generated.
//!
//! Format 2 replies live in a separate [`DeliveryBuffer`] under their
//! delivery ID. Each reply is filed under exactly one key, and a claim
//! returns it as `reply-0-{the ID the client claimed with}`.
//!
//! A claim either takes a reply ([`ClaimMode::Take`], the original
//! behaviour) or retains it ([`ClaimMode::Retain`]): the reply is returned
//! and stays in the buffer until the client acks it or until the claim grace
//! has passed, counted from the first retaining claim. A transfer that is cut
//! off mid-way can then be claimed again with the same ID. Retained replies
//! count against the same entry and byte caps and are evicted first.

use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tracing::{debug, warn};

use super::delivery_buffer::{DeliveryBuffer, DeliveryLimits, DeliveryStore};

/// Default TTL for buffered responses (5 minutes).
const DEFAULT_TTL: Duration = Duration::from_mins(5);

/// Default time a reply stays re-claimable after its first retaining claim.
pub const DEFAULT_CLAIM_GRACE: Duration = Duration::from_secs(20);

/// Default maximum number of buffered responses.
///
/// Prevents unbounded memory growth between prune cycles.
/// At ~1 KB average response size, 10 000 entries ≈ 10 MB.
const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// Default number of IDs remembered as acked before their reply arrived.
/// Each costs about 50 bytes; they expire after the claim grace.
const DEFAULT_MAX_ACKED_AHEAD: usize = 10_000;

/// SURB identifier: 16 bytes, written as 32 hex characters on the wire.
pub type SurbId = [u8; 16];

/// Length of a hex-encoded [`SurbId`].
pub const SURB_ID_HEX_LEN: usize = 32;

/// Parses a hex SURB ID. Accepts exactly 32 hex characters, nothing else.
#[must_use]
pub fn parse_surb_id(hex_id: &str) -> Option<SurbId> {
    if hex_id.len() != SURB_ID_HEX_LEN {
        return None;
    }
    let mut id = [0u8; 16];
    hex::decode_to_slice(hex_id, &mut id).ok()?;
    Some(id)
}

/// Extracts the SURB ID from a buffer key such as `reply-0-{surb_id_hex}`:
/// the text after the last `-`.
#[must_use]
pub fn surb_id_from_packet_id(packet_id: &str) -> Option<SurbId> {
    let (_, suffix) = packet_id.rsplit_once('-')?;
    parse_surb_id(suffix)
}

struct BufferedResponse {
    data: Vec<u8>,
    created_at: Instant,
    /// Set by the first retaining claim.
    claimed_at: Option<Instant>,
    surb_id: Option<SurbId>,
}

impl BufferedResponse {
    fn is_live(&self, ttl: Duration, grace: Duration) -> bool {
        self.created_at.elapsed() < ttl && self.claimed_at.is_none_or(|at| at.elapsed() < grace)
    }
}

/// How a claim treats the replies it returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimMode {
    /// Remove each reply as it is returned.
    Take,
    /// Keep each reply until it is acked or the claim grace has passed.
    Retain,
}

/// One reply returned by [`ResponseBuffer::claim`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedReply {
    /// `reply-0-{claimed ID}` for format 2, the stored key for format 1.
    pub id: String,
    pub data: Vec<u8>,
    /// A retaining claim had already returned this reply.
    pub reclaimed: bool,
}

#[derive(Default)]
struct Entries {
    by_packet_id: HashMap<String, BufferedResponse>,
    /// SURB ID -> `packet_id` key in `by_packet_id`.
    by_surb_id: HashMap<SurbId, String>,
    bytes: usize,
}

impl Entries {
    fn remove(&mut self, packet_id: &str) -> Option<BufferedResponse> {
        let entry = self.by_packet_id.remove(packet_id)?;
        self.bytes -= entry.data.len();
        if let Some(surb_id) = entry.surb_id {
            if self
                .by_surb_id
                .get(&surb_id)
                .is_some_and(|key| key == packet_id)
            {
                self.by_surb_id.remove(&surb_id);
            }
        }
        Some(entry)
    }

    fn retain_fresh(&mut self, ttl: Duration, grace: Duration) -> usize {
        let expired: Vec<String> = self
            .by_packet_id
            .iter()
            .filter(|(_, entry)| !entry.is_live(ttl, grace))
            .map(|(key, _)| key.clone())
            .collect();
        for key in &expired {
            self.remove(key);
        }
        expired.len()
    }

    /// Entry to evict at capacity: replies already handed out by a retaining
    /// claim go first (oldest claim first), then the oldest unclaimed reply.
    fn eviction_candidate(&self) -> Option<String> {
        self.by_packet_id
            .iter()
            .filter_map(|(key, entry)| entry.claimed_at.map(|at| (at, key)))
            .min_by_key(|(at, _)| *at)
            .map(|(_, key)| key.clone())
            .or_else(|| {
                self.by_packet_id
                    .iter()
                    .min_by_key(|(_, entry)| entry.created_at)
                    .map(|(key, _)| key.clone())
            })
    }
}

/// IDs the client acked before any reply was held under them. A reply that
/// arrives for one of them later is dropped instead of being buffered: the
/// client already decoded its request from the other replies (claim v2
/// ack-ahead). Bounded in count and age.
#[derive(Default)]
struct AckedAhead {
    at: HashMap<SurbId, Instant>,
    order: VecDeque<(SurbId, Instant)>,
}

impl AckedAhead {
    fn insert(&mut self, id: SurbId, max: usize) {
        if max == 0 {
            return;
        }
        // `order` also holds stale positions of IDs taken or re-acked since;
        // bound both.
        while self.at.len() >= max || self.order.len() >= 2 * max {
            if !self.pop_oldest() {
                break;
            }
        }
        let now = Instant::now();
        self.at.insert(id, now);
        self.order.push_back((id, now));
    }

    fn pop_oldest(&mut self) -> bool {
        let Some((id, at)) = self.order.pop_front() else {
            return false;
        };
        if self.at.get(&id) == Some(&at) {
            self.at.remove(&id);
        }
        true
    }

    /// Removes `id` and returns whether it was acked within `grace`.
    fn take(&mut self, id: &SurbId, grace: Duration) -> bool {
        self.at.remove(id).is_some_and(|at| at.elapsed() < grace)
    }

    fn prune(&mut self, grace: Duration) {
        while self
            .order
            .front()
            .is_some_and(|(_, at)| at.elapsed() >= grace)
        {
            self.pop_oldest();
        }
    }
}

/// Long-poll waiters by reply ID, so a stored reply wakes only the claims
/// that wait for it.
#[derive(Default)]
struct Waiters {
    next_key: u64,
    by_id: HashMap<SurbId, Vec<(u64, Arc<Notify>)>>,
}

/// A registration that is woken when a reply is stored under one of its IDs.
/// Dropping it unregisters.
pub struct ReplyWaiter {
    waiters: Arc<Mutex<Waiters>>,
    key: u64,
    ids: Vec<SurbId>,
    notify: Arc<Notify>,
}

impl ReplyWaiter {
    /// Completes when a reply has been stored under one of the IDs since
    /// the registration or since the previous wake-up. A store that happens
    /// before this is awaited is not lost.
    pub async fn notified(&self) {
        self.notify.notified().await;
    }
}

impl Drop for ReplyWaiter {
    fn drop(&mut self) {
        let mut waiters = self.waiters.lock();
        for id in &self.ids {
            if let Some(list) = waiters.by_id.get_mut(id) {
                list.retain(|(key, _)| *key != self.key);
                if list.is_empty() {
                    waiters.by_id.remove(id);
                }
            }
        }
    }
}

/// Outcome of [`ResponseBuffer::store_reply`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyStore {
    /// Stored. `evicted` older entries were removed to make room.
    Stored { evicted: usize },
    /// A reply for this SURB ID is already buffered; the new one is dropped.
    Duplicate,
    /// The client acked this ID before the reply arrived; it is dropped.
    Acked,
}

/// Thread-safe buffer for SURB responses.
///
/// Responses are stored with a TTL and automatically pruned on access.
/// A hard cap (`max_entries`) prevents unbounded memory growth between
/// prune cycles -- when the cap is reached, the oldest entry is evicted.
pub struct ResponseBuffer {
    entries: Mutex<Entries>,
    delivery: Mutex<DeliveryBuffer>,
    ttl: Duration,
    /// How long a retained reply stays re-claimable after its first claim.
    claim_grace: Duration,
    max_entries: usize,
    /// Wakes the WebSocket and by-packet-ID poll handlers when any response
    /// is stored.
    notify: Arc<Notify>,
    /// Long-poll claims and SSE streams, woken per reply ID.
    waiters: Arc<Mutex<Waiters>>,
    acked_ahead: Mutex<AckedAhead>,
    max_acked_ahead: usize,
}

impl Default for ResponseBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl ResponseBuffer {
    #[must_use]
    pub fn new() -> Self {
        Self::with_ttl_and_capacity(DEFAULT_TTL, DEFAULT_MAX_ENTRIES)
    }

    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self::with_ttl_and_capacity(ttl, DEFAULT_MAX_ENTRIES)
    }

    /// Create a `ResponseBuffer` with custom TTL and max entry count.
    #[must_use]
    pub fn with_ttl_and_capacity(ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(Entries::default()),
            delivery: Mutex::new(DeliveryBuffer::new(DeliveryLimits::default())),
            ttl,
            claim_grace: DEFAULT_CLAIM_GRACE,
            max_entries,
            notify: Arc::new(Notify::new()),
            waiters: Arc::new(Mutex::new(Waiters::default())),
            acked_ahead: Mutex::new(AckedAhead::default()),
            max_acked_ahead: DEFAULT_MAX_ACKED_AHEAD,
        }
    }

    /// Replace the limits of the format 2 store. Drops anything already in it.
    #[must_use]
    pub fn with_delivery_limits(self, limits: DeliveryLimits) -> Self {
        *self.delivery.lock() = DeliveryBuffer::new(limits).with_claim_grace(self.claim_grace);
        self
    }

    /// Set how long a reply stays re-claimable after its first retaining
    /// claim. Drops anything already in the format 2 store.
    #[must_use]
    pub fn with_claim_grace(mut self, grace: Duration) -> Self {
        self.claim_grace = grace;
        let limits = self.delivery.lock().limits();
        *self.delivery.lock() = DeliveryBuffer::new(limits).with_claim_grace(grace);
        self
    }

    /// How long a retained reply stays re-claimable.
    #[must_use]
    pub fn claim_grace(&self) -> Duration {
        self.claim_grace
    }

    /// Store a format 2 reply under its delivery ID, on behalf of the peer
    /// it came from. Never touches handle-keyed entries.
    pub fn store_delivery(
        &self,
        delivery_id: SurbId,
        source_peer: &str,
        data: Vec<u8>,
    ) -> DeliveryStore {
        if self.acked_ahead.lock().take(&delivery_id, self.claim_grace) {
            debug!("Dropping a format 2 reply the client acked before it arrived");
            return DeliveryStore::Acked;
        }
        let outcome = self
            .delivery
            .lock()
            .store(delivery_id, source_peer, data, self.ttl);
        if matches!(outcome, DeliveryStore::Stored { .. }) {
            debug!("Buffered format 2 reply");
            self.wake(&delivery_id);
            self.notify.notify_waiters();
        }
        outcome
    }

    /// Store a response under its `packet_id`. Returns how many older entries
    /// were evicted to make room (see [`ResponseBuffer::store_reply`]).
    pub fn store_response(&self, packet_id: &str, data: Vec<u8>) -> usize {
        match self.store_reply(packet_id, data) {
            ReplyStore::Stored { evicted } => evicted,
            ReplyStore::Duplicate | ReplyStore::Acked => 0,
        }
    }

    /// Store a response under its `packet_id`.
    ///
    /// If the buffer is at capacity, the oldest entry is evicted first. If a
    /// response for the same SURB ID is already buffered under another
    /// `packet_id`, the new one is dropped: a SURB is single-use. A response
    /// whose SURB ID the client acked before it arrived is dropped too.
    pub fn store_reply(&self, packet_id: &str, data: Vec<u8>) -> ReplyStore {
        let mut evicted = 0;
        let surb_id = surb_id_from_packet_id(packet_id);
        if let Some(id) = surb_id {
            if self.acked_ahead.lock().take(&id, self.claim_grace) {
                debug!("Dropping a response the client acked before it arrived");
                return ReplyStore::Acked;
            }
        }
        let mut entries = self.entries.lock();

        if let Some(id) = surb_id {
            if let Some(existing) = entries.by_surb_id.get(&id).cloned() {
                let expired = entries
                    .by_packet_id
                    .get(&existing)
                    .is_none_or(|entry| !entry.is_live(self.ttl, self.claim_grace));
                if expired {
                    entries.remove(&existing);
                } else if existing != packet_id {
                    debug!("Dropping response for a SURB ID that is already buffered");
                    return ReplyStore::Duplicate;
                }
            }
        }

        // Evict the oldest entry if at capacity
        if entries.by_packet_id.len() >= self.max_entries
            && !entries.by_packet_id.contains_key(packet_id)
        {
            // First try pruning expired entries
            entries.retain_fresh(self.ttl, self.claim_grace);

            // If still at capacity, evict (claimed replies first, then the oldest)
            if entries.by_packet_id.len() >= self.max_entries {
                if let Some(oldest_key) = entries.eviction_candidate() {
                    warn!(
                        buffer_size = entries.by_packet_id.len(),
                        max = self.max_entries,
                        "ResponseBuffer at capacity, evicting oldest entry"
                    );
                    entries.remove(&oldest_key);
                    evicted += 1;
                }
            }
        }

        debug!("Buffered SURB response");
        entries.remove(packet_id);
        entries.bytes += data.len();
        if let Some(id) = surb_id {
            entries.by_surb_id.insert(id, packet_id.to_string());
        }
        entries.by_packet_id.insert(
            packet_id.to_string(),
            BufferedResponse {
                data,
                created_at: Instant::now(),
                claimed_at: None,
                surb_id,
            },
        );

        drop(entries);

        // Wake the claims waiting for this ID, then the handlers that watch
        // every store.
        if let Some(id) = surb_id {
            self.wake(&id);
        }
        self.notify.notify_waiters();
        ReplyStore::Stored { evicted }
    }

    /// Returns a future that completes when any new response is stored.
    ///
    /// Used by the WebSocket and by-packet-ID poll handlers. Claims and
    /// streams with known IDs use [`ResponseBuffer::waiter`], which wakes
    /// only for their own IDs.
    pub fn notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.notify.notified()
    }

    /// Registers a waiter that is woken when a reply is stored under one of
    /// `surb_ids`. Register before checking the buffer, then await
    /// [`ReplyWaiter::notified`]: a reply stored in between is not missed.
    #[must_use]
    pub fn waiter(&self, surb_ids: &[SurbId]) -> ReplyWaiter {
        let notify = Arc::new(Notify::new());
        let mut ids = surb_ids.to_vec();
        ids.sort_unstable();
        ids.dedup();
        let mut waiters = self.waiters.lock();
        let key = waiters.next_key;
        waiters.next_key = waiters.next_key.wrapping_add(1);
        for id in &ids {
            waiters
                .by_id
                .entry(*id)
                .or_default()
                .push((key, Arc::clone(&notify)));
        }
        drop(waiters);
        ReplyWaiter {
            waiters: Arc::clone(&self.waiters),
            key,
            ids,
            notify,
        }
    }

    /// Wakes the waiters registered for `id`.
    fn wake(&self, id: &SurbId) {
        let waiters = self.waiters.lock();
        if let Some(list) = waiters.by_id.get(id) {
            for (_, notify) in list {
                notify.notify_one();
            }
        }
    }

    /// Number of (waiter, ID) registrations, for tests and metrics.
    #[must_use]
    pub fn waiter_registrations(&self) -> usize {
        self.waiters.lock().by_id.values().map(Vec::len).sum()
    }

    /// Take (remove and return) the response stored under exactly `packet_id`.
    /// Returns `None` if no response is available or if the entry has expired.
    pub fn take_response(&self, packet_id: &str) -> Option<Vec<u8>> {
        let mut entries = self.entries.lock();
        let entry = entries.remove(packet_id)?;
        entry
            .is_live(self.ttl, self.claim_grace)
            .then_some(entry.data)
    }

    /// Claim the responses for exactly these IDs (SURB IDs for format 1,
    /// delivery IDs for format 2), removing them. Returns `(id, data)` pairs
    /// where `id` is `reply-0-{the claimed ID}` for format 2; all other
    /// entries remain.
    ///
    /// The client knows which IDs it generated and passes them here to
    /// claim only its own responses.
    pub fn claim_by_surb_ids(&self, surb_ids: &[SurbId]) -> Vec<(String, Vec<u8>)> {
        self.claim(surb_ids, ClaimMode::Take)
            .into_iter()
            .map(|reply| (reply.id, reply.data))
            .collect()
    }

    /// Claim the responses for exactly these IDs. With [`ClaimMode::Take`]
    /// each returned reply is removed; with [`ClaimMode::Retain`] it stays
    /// until [`ResponseBuffer::ack`] or until the claim grace has passed
    /// since its first retaining claim, and a repeated claim returns it again
    /// (`reclaimed`). Only the exact ID matches.
    pub fn claim(&self, surb_ids: &[SurbId], mode: ClaimMode) -> Vec<ClaimedReply> {
        self.claim_at_most(surb_ids, mode, usize::MAX)
    }

    /// [`ResponseBuffer::claim`], returning at most `max_replies` replies:
    /// the ones that arrived first, in arrival order. The others stay for a
    /// later claim.
    pub fn claim_at_most(
        &self,
        surb_ids: &[SurbId],
        mode: ClaimMode,
        max_replies: usize,
    ) -> Vec<ClaimedReply> {
        if surb_ids.is_empty() || max_replies == 0 {
            return Vec::new();
        }

        let mut entries = self.entries.lock();
        let mut delivery = self.delivery.lock();
        let mut claimed = Vec::new();

        let limited: Vec<SurbId>;
        let surb_ids = if max_replies < surb_ids.len() {
            let mut arrived: Vec<(Instant, SurbId)> = surb_ids
                .iter()
                .filter_map(|surb_id| {
                    let handle = entries
                        .by_surb_id
                        .get(surb_id)
                        .and_then(|key| entries.by_packet_id.get(key))
                        .filter(|entry| entry.is_live(self.ttl, self.claim_grace))
                        .map(|entry| entry.created_at);
                    let format2 = delivery.live_created_at(surb_id, self.ttl);
                    handle
                        .into_iter()
                        .chain(format2)
                        .min()
                        .map(|at| (at, *surb_id))
                })
                .collect();
            arrived.sort_unstable_by_key(|(at, _)| *at);
            limited = arrived
                .into_iter()
                .take(max_replies)
                .map(|(_, id)| id)
                .collect();
            limited.as_slice()
        } else {
            surb_ids
        };

        for surb_id in surb_ids {
            // Stop before taking a reply that would not be returned.
            if claimed.len() >= max_replies {
                break;
            }
            if let Some(key) = entries.by_surb_id.get(surb_id).cloned() {
                let live = entries
                    .by_packet_id
                    .get(&key)
                    .is_some_and(|entry| entry.is_live(self.ttl, self.claim_grace));
                if !live {
                    entries.remove(&key);
                } else if mode == ClaimMode::Take {
                    if let Some(entry) = entries.remove(&key) {
                        claimed.push(ClaimedReply {
                            id: key,
                            data: entry.data,
                            reclaimed: entry.claimed_at.is_some(),
                        });
                    }
                } else if let Some(entry) = entries.by_packet_id.get_mut(&key) {
                    let reclaimed = entry.claimed_at.is_some();
                    if !reclaimed {
                        entry.claimed_at = Some(Instant::now());
                    }
                    claimed.push(ClaimedReply {
                        id: key,
                        data: entry.data.clone(),
                        reclaimed,
                    });
                }
            }
            if claimed.len() >= max_replies {
                break;
            }
            let from_delivery = match mode {
                ClaimMode::Take => delivery.take(surb_id, self.ttl),
                ClaimMode::Retain => delivery.claim_retained(surb_id, self.ttl),
            };
            if let Some((data, reclaimed)) = from_delivery {
                claimed.push(ClaimedReply {
                    id: format!("reply-0-{}", hex::encode(surb_id)),
                    data,
                    reclaimed,
                });
            }
        }

        claimed
    }

    /// Remove the replies held under exactly these IDs: the client confirms
    /// it has them, or no longer needs them. Returns how many were removed.
    ///
    /// An ID with no reply held yet is remembered for the claim grace, and a
    /// reply that arrives for it in that time is dropped (ack-ahead: the
    /// client acks the sibling replies of a request it already decoded).
    pub fn ack(&self, surb_ids: &[SurbId]) -> usize {
        if surb_ids.is_empty() {
            return 0;
        }
        let mut entries = self.entries.lock();
        let mut delivery = self.delivery.lock();
        let mut acked_ahead = self.acked_ahead.lock();
        let mut removed = 0;
        for surb_id in surb_ids {
            let mut held = false;
            if let Some(key) = entries.by_surb_id.get(surb_id).cloned() {
                if entries.remove(&key).is_some() {
                    removed += 1;
                    held = true;
                }
            }
            if delivery.ack(surb_id) {
                removed += 1;
                held = true;
            }
            if !held {
                acked_ahead.insert(*surb_id, self.max_acked_ahead);
            }
        }
        removed
    }

    /// Number of IDs acked before their reply arrived that are still
    /// remembered.
    #[must_use]
    pub fn acked_ahead_len(&self) -> usize {
        self.acked_ahead.lock().at.len()
    }

    /// Whether a live reply is held under any of these IDs (long-poll wake-up
    /// check; does not claim).
    #[must_use]
    pub fn has_any(&self, surb_ids: &[SurbId]) -> bool {
        let entries = self.entries.lock();
        let delivery = self.delivery.lock();
        surb_ids.iter().any(|surb_id| {
            entries
                .by_surb_id
                .get(surb_id)
                .and_then(|key| entries.by_packet_id.get(key))
                .is_some_and(|entry| entry.is_live(self.ttl, self.claim_grace))
                || delivery.contains_live(surb_id, self.ttl)
        })
    }

    /// Prune all expired entries. Returns the number of entries removed.
    pub fn prune_expired(&self) -> usize {
        let (handle, delivery) = self.prune_expired_by_key();
        handle + delivery
    }

    /// Prune all expired entries. Returns the number removed from the
    /// handle-keyed and the delivery-keyed stores.
    pub fn prune_expired_by_key(&self) -> (usize, usize) {
        self.acked_ahead.lock().prune(self.claim_grace);
        let handle = self.entries.lock().retain_fresh(self.ttl, self.claim_grace);
        let delivery = self.delivery.lock().prune(self.ttl);
        (handle, delivery)
    }

    /// Number of currently buffered responses, of both kinds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().by_packet_id.len() + self.delivery.lock().len()
    }

    /// Number of buffered format 2 replies.
    #[must_use]
    pub fn delivery_len(&self) -> usize {
        self.delivery.lock().len()
    }

    /// Bytes held by handle-keyed and by delivery-keyed replies.
    #[must_use]
    pub fn bytes_by_key(&self) -> (usize, usize) {
        (self.entries.lock().bytes, self.delivery.lock().bytes())
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SURB_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa1111";
    const SURB_B: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa2222";
    const SURB_C: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbb3333";
    const SURB_D: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbb4444";

    fn id(hex_id: &str) -> SurbId {
        parse_surb_id(hex_id).expect("valid SURB ID")
    }

    #[test]
    fn test_store_and_take() {
        let buf = ResponseBuffer::new();
        buf.store_response("req-1", vec![1, 2, 3]);

        assert_eq!(buf.len(), 1);
        let data = buf.take_response("req-1");
        assert_eq!(data, Some(vec![1, 2, 3]));
        assert!(buf.is_empty());
    }

    #[test]
    fn test_take_nonexistent() {
        let buf = ResponseBuffer::new();
        assert!(buf.take_response("nope").is_none());
    }

    #[test]
    fn test_ttl_expiry() {
        let buf = ResponseBuffer::with_ttl(Duration::from_millis(1));
        buf.store_response("req-1", vec![42]);

        // Sleep past TTL
        std::thread::sleep(Duration::from_millis(10));

        assert!(buf.take_response("req-1").is_none());
    }

    #[test]
    fn test_prune_expired() {
        let buf = ResponseBuffer::with_ttl(Duration::from_millis(1));
        buf.store_response("req-1", vec![1]);
        buf.store_response(&format!("echo-1-{SURB_A}"), vec![2]);

        std::thread::sleep(Duration::from_millis(10));

        let pruned = buf.prune_expired();
        assert_eq!(pruned, 2);
        assert!(buf.is_empty());
        assert!(buf.claim_by_surb_ids(&[id(SURB_A)]).is_empty());
    }

    #[test]
    fn test_max_entries_eviction() {
        let buf = ResponseBuffer::with_ttl_and_capacity(Duration::from_mins(1), 3);
        buf.store_response("a", vec![1]);
        buf.store_response("b", vec![2]);
        buf.store_response("c", vec![3]);
        assert_eq!(buf.len(), 3);

        // This should evict the oldest entry ("a")
        buf.store_response("d", vec![4]);
        assert_eq!(buf.len(), 3);

        // "a" was evicted, "b", "c", "d" remain
        assert!(buf.take_response("a").is_none());
        assert_eq!(buf.take_response("d"), Some(vec![4]));
    }

    #[test]
    fn test_max_entries_cap_of_one() {
        let buf = ResponseBuffer::with_ttl_and_capacity(Duration::from_mins(1), 1);
        buf.store_response("first", vec![1]);
        buf.store_response("second", vec![2]);

        assert_eq!(buf.len(), 1);
        assert!(buf.take_response("first").is_none());
        assert_eq!(buf.take_response("second"), Some(vec![2]));
    }

    #[test]
    fn test_eviction_clears_surb_index() {
        let buf = ResponseBuffer::with_ttl_and_capacity(Duration::from_mins(1), 1);
        buf.store_response(&format!("echo-1-{SURB_A}"), vec![1]);
        buf.store_response(&format!("echo-2-{SURB_B}"), vec![2]);

        assert!(buf.claim_by_surb_ids(&[id(SURB_A)]).is_empty());
        assert_eq!(buf.claim_by_surb_ids(&[id(SURB_B)]).len(), 1);
    }

    #[test]
    fn test_parse_surb_id_requires_exact_hex() {
        assert!(parse_surb_id(SURB_A).is_some());
        assert!(parse_surb_id(&SURB_A.to_uppercase()).is_some());
        for bad in [
            "",
            "-",
            "rpc",
            "reply",
            "aabbccdd",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaa111",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaa11111",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            " aaaaaaaaaaaaaaaaaaaaaaaaaaa1111",
        ] {
            assert!(parse_surb_id(bad).is_none(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn test_surb_id_from_packet_id() {
        assert_eq!(
            surb_id_from_packet_id(&format!("reply-7-{SURB_A}")),
            Some(id(SURB_A))
        );
        assert_eq!(surb_id_from_packet_id(SURB_A), None);
        assert_eq!(surb_id_from_packet_id("http-00000000deadbeef"), None);
        assert_eq!(surb_id_from_packet_id(&format!("reply-7-{SURB_A}-")), None);
    }

    #[test]
    fn test_claim_by_surb_ids_returns_matching() {
        let buf = ResponseBuffer::new();
        // packet_id format: "{handler}-{request_id}-{surb_id_hex}"
        buf.store_response(&format!("echo-12345-{SURB_A}"), vec![1, 2]);
        buf.store_response(&format!("rpc-67890-{SURB_C}"), vec![3, 4]);
        buf.store_response(&format!("echo-99999-{SURB_B}"), vec![5, 6]);

        let claimed = buf.claim_by_surb_ids(&[id(SURB_A), id(SURB_B)]);
        assert_eq!(claimed.len(), 2);
        // Only the non-matching entry should remain
        assert_eq!(buf.len(), 1);
        assert!(buf.take_response(&format!("rpc-67890-{SURB_C}")).is_some());
    }

    #[test]
    fn test_claim_returns_full_packet_id() {
        let buf = ResponseBuffer::new();
        let packet_id = format!("reply-42-{SURB_A}");
        buf.store_response(&packet_id, vec![9]);

        let claimed = buf.claim_by_surb_ids(&[id(SURB_A)]);
        assert_eq!(claimed, vec![(packet_id, vec![9])]);
    }

    #[test]
    fn test_claim_by_surb_ids_empty_input() {
        let buf = ResponseBuffer::new();
        buf.store_response(&format!("echo-12345-{SURB_A}"), vec![1, 2]);

        let claimed = buf.claim_by_surb_ids(&[]);
        assert!(claimed.is_empty());
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn test_claim_by_surb_ids_no_match() {
        let buf = ResponseBuffer::new();
        buf.store_response(&format!("echo-12345-{SURB_A}"), vec![1, 2]);

        let claimed = buf.claim_by_surb_ids(&[id(SURB_D)]);
        assert!(claimed.is_empty());
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn test_claim_never_matches_partial_ids() {
        let buf = ResponseBuffer::new();
        buf.store_response(&format!("echo-1-{SURB_A}"), vec![1]);
        buf.store_response(&format!("rpc-2-{SURB_C}"), vec![2]);

        // A SURB ID that shares a prefix or suffix with a stored one claims nothing.
        let mut near = id(SURB_A);
        near[15] ^= 0x01;
        assert!(buf.claim_by_surb_ids(&[near]).is_empty());
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn test_entries_without_surb_id_are_not_claimable() {
        let buf = ResponseBuffer::new();
        buf.store_response("http-00000000deadbeef", vec![1]);
        assert!(buf.claim_by_surb_ids(&[[0u8; 16]]).is_empty());
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn test_duplicate_surb_id_keeps_first_response() {
        let buf = ResponseBuffer::new();
        buf.store_response(&format!("reply-1-{SURB_A}"), vec![1]);
        buf.store_response(&format!("other-9-{SURB_A}"), vec![2]);

        assert_eq!(buf.len(), 1);
        let claimed = buf.claim_by_surb_ids(&[id(SURB_A)]);
        assert_eq!(claimed, vec![(format!("reply-1-{SURB_A}"), vec![1])]);
    }

    #[test]
    fn test_claim_by_surb_ids_skips_expired() {
        let buf = ResponseBuffer::with_ttl(Duration::from_millis(1));
        buf.store_response(&format!("echo-12345-{SURB_A}"), vec![1, 2]);
        std::thread::sleep(Duration::from_millis(10));

        let claimed = buf.claim_by_surb_ids(&[id(SURB_A)]);
        assert!(claimed.is_empty());
    }

    #[test]
    fn test_claim_isolation_between_clients() {
        let buf = ResponseBuffer::new();
        // Client A's SURBs
        buf.store_response(&format!("echo-100-{SURB_A}"), vec![10]);
        buf.store_response(&format!("echo-100-{SURB_B}"), vec![20]);
        // Client B's SURBs
        buf.store_response(&format!("echo-200-{SURB_C}"), vec![30]);
        buf.store_response(&format!("echo-200-{SURB_D}"), vec![40]);

        // Client A claims only its responses
        let a_claimed = buf.claim_by_surb_ids(&[id(SURB_A), id(SURB_B)]);
        assert_eq!(a_claimed.len(), 2);

        // Client B's responses are untouched
        assert_eq!(buf.len(), 2);
        let b_claimed = buf.claim_by_surb_ids(&[id(SURB_C), id(SURB_D)]);
        assert_eq!(b_claimed.len(), 2);
        assert!(buf.is_empty());
    }

    fn delivery_buffer(max_entries: usize) -> ResponseBuffer {
        ResponseBuffer::new().with_delivery_limits(DeliveryLimits {
            max_entries,
            max_bytes: 1 << 20,
            source_share_percent: 100,
        })
    }

    #[test]
    fn test_delivery_entry_is_claimed_as_reply_0_of_the_claimed_id() {
        let buf = ResponseBuffer::new();
        assert!(matches!(
            buf.store_delivery(id(SURB_A), "peer", vec![7]),
            DeliveryStore::Stored { .. }
        ));
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.delivery_len(), 1);
        let claimed = buf.claim_by_surb_ids(&[id(SURB_A)]);
        assert_eq!(claimed, vec![(format!("reply-0-{SURB_A}"), vec![7])]);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_delivery_entries_never_evict_handle_entries() {
        let buf = ResponseBuffer::with_ttl_and_capacity(Duration::from_mins(1), 2)
            .with_delivery_limits(DeliveryLimits {
                max_entries: 2,
                max_bytes: 1 << 20,
                source_share_percent: 100,
            });
        buf.store_response(&format!("reply-0-{SURB_A}"), vec![1]);
        buf.store_response(&format!("reply-0-{SURB_B}"), vec![2]);
        for n in 0u8..50 {
            buf.store_delivery([n; 16], "peer", vec![n]);
        }
        assert_eq!(buf.delivery_len(), 2);
        assert_eq!(buf.claim_by_surb_ids(&[id(SURB_A), id(SURB_B)]).len(), 2);
    }

    #[test]
    fn test_handle_claim_does_not_reach_delivery_entries() {
        let buf = delivery_buffer(10);
        buf.store_delivery(id(SURB_C), "peer", vec![3]);
        buf.store_response(&format!("reply-0-{SURB_A}"), vec![1]);
        assert_eq!(buf.claim_by_surb_ids(&[id(SURB_A)]).len(), 1);
        assert_eq!(buf.delivery_len(), 1);
        assert!(buf.take_response(&format!("reply-0-{SURB_C}")).is_none());
    }

    #[test]
    fn test_bytes_are_tracked_per_key() {
        let buf = delivery_buffer(10);
        buf.store_response(&format!("reply-0-{SURB_A}"), vec![0; 10]);
        buf.store_delivery(id(SURB_B), "peer", vec![0; 30]);
        assert_eq!(buf.bytes_by_key(), (10, 30));
        buf.claim_by_surb_ids(&[id(SURB_A), id(SURB_B)]);
        assert_eq!(buf.bytes_by_key(), (0, 0));
    }

    #[test]
    fn test_store_reports_evictions() {
        let buf = ResponseBuffer::with_ttl_and_capacity(Duration::from_mins(1), 1);
        assert_eq!(buf.store_response("a", vec![1]), 0);
        assert_eq!(buf.store_response("b", vec![1]), 1);
    }

    #[test]
    fn test_retained_claim_is_reclaimable_with_the_exact_id_only() {
        let buf = ResponseBuffer::new();
        buf.store_response(&format!("reply-0-{SURB_A}"), vec![1, 2]);

        let first = buf.claim(&[id(SURB_A)], ClaimMode::Retain);
        assert_eq!(first.len(), 1);
        assert!(!first[0].reclaimed);
        assert_eq!(buf.len(), 1, "a retained reply stays buffered");

        let mut near = id(SURB_A);
        near[0] ^= 0x80;
        assert!(buf.claim(&[near], ClaimMode::Retain).is_empty());
        assert_eq!(buf.ack(&[near]), 0);

        let again = buf.claim(&[id(SURB_A)], ClaimMode::Retain);
        assert_eq!(again.len(), 1);
        assert!(again[0].reclaimed);
        assert_eq!(again[0].data, vec![1, 2]);

        assert_eq!(buf.ack(&[id(SURB_A)]), 1);
        assert!(buf.is_empty());
        assert!(buf.claim(&[id(SURB_A)], ClaimMode::Retain).is_empty());
    }

    #[test]
    fn test_retained_claim_expires_after_grace_from_first_claim() {
        let buf = ResponseBuffer::new().with_claim_grace(Duration::from_millis(30));
        buf.store_response(&format!("reply-0-{SURB_A}"), vec![1]);
        buf.store_response(&format!("reply-0-{SURB_B}"), vec![2]);
        assert_eq!(buf.claim(&[id(SURB_A)], ClaimMode::Retain).len(), 1);
        std::thread::sleep(Duration::from_millis(15));
        assert_eq!(
            buf.claim(&[id(SURB_A)], ClaimMode::Retain).len(),
            1,
            "a re-claim inside the grace succeeds"
        );
        std::thread::sleep(Duration::from_millis(20));
        assert!(
            buf.claim(&[id(SURB_A)], ClaimMode::Retain).is_empty(),
            "a re-claim never extends the grace"
        );
        assert_eq!(buf.prune_expired(), 0);
        assert_eq!(buf.len(), 1, "the unclaimed reply keeps its TTL");
    }

    #[test]
    fn test_take_after_retain_removes_and_reports_reclaim() {
        let buf = ResponseBuffer::new();
        buf.store_response(&format!("reply-0-{SURB_A}"), vec![1]);
        buf.claim(&[id(SURB_A)], ClaimMode::Retain);
        let taken = buf.claim(&[id(SURB_A)], ClaimMode::Take);
        assert_eq!(taken.len(), 1);
        assert!(taken[0].reclaimed);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_retained_replies_respect_the_entry_cap_and_go_first() {
        let buf = ResponseBuffer::with_ttl_and_capacity(Duration::from_mins(1), 2);
        buf.store_response(&format!("reply-0-{SURB_A}"), vec![1]);
        std::thread::sleep(Duration::from_millis(2));
        buf.store_response(&format!("reply-0-{SURB_B}"), vec![2]);
        buf.claim(&[id(SURB_B)], ClaimMode::Retain);
        assert_eq!(buf.store_response(&format!("reply-0-{SURB_C}"), vec![3]), 1);
        assert_eq!(buf.len(), 2);
        assert!(
            buf.claim(&[id(SURB_B)], ClaimMode::Retain).is_empty(),
            "the retained reply was evicted before the older unclaimed one"
        );
        assert_eq!(
            buf.claim(&[id(SURB_A), id(SURB_C)], ClaimMode::Take).len(),
            2
        );
    }

    #[test]
    fn test_retained_delivery_entries_and_bytes() {
        let buf = delivery_buffer(10);
        buf.store_delivery(id(SURB_C), "peer", vec![0; 30]);
        let first = buf.claim(&[id(SURB_C)], ClaimMode::Retain);
        assert_eq!(first[0].id, format!("reply-0-{SURB_C}"));
        assert!(!first[0].reclaimed);
        assert_eq!(buf.bytes_by_key(), (0, 30));
        assert!(buf.claim(&[id(SURB_C)], ClaimMode::Retain)[0].reclaimed);
        assert!(buf.has_any(&[id(SURB_C)]));
        assert_eq!(buf.ack(&[id(SURB_C)]), 1);
        assert_eq!(buf.bytes_by_key(), (0, 0));
        assert!(!buf.has_any(&[id(SURB_C)]));
    }

    #[tokio::test]
    async fn test_waiter_wakes_only_for_its_ids() {
        let buf = ResponseBuffer::new();
        let waiter = buf.waiter(&[id(SURB_A), id(SURB_A)]);
        assert_eq!(buf.waiter_registrations(), 1, "duplicate IDs register once");

        buf.store_response(&format!("reply-0-{SURB_B}"), vec![1]);
        let woken = tokio::time::timeout(Duration::from_millis(50), waiter.notified()).await;
        assert!(woken.is_err(), "a reply for another ID must not wake it");

        // Stored before the wait starts: the permit is kept.
        buf.store_response(&format!("reply-0-{SURB_A}"), vec![2]);
        let woken = tokio::time::timeout(Duration::from_millis(50), waiter.notified()).await;
        assert!(woken.is_ok(), "a reply for its ID wakes it");

        drop(waiter);
        assert_eq!(buf.waiter_registrations(), 0);
    }

    #[tokio::test]
    async fn test_waiter_wakes_for_format_2_replies() {
        let buf = delivery_buffer(8);
        let waiter = buf.waiter(&[id(SURB_C)]);
        buf.store_delivery(id(SURB_C), "peer-1", vec![7]);
        let woken = tokio::time::timeout(Duration::from_millis(50), waiter.notified()).await;
        assert!(woken.is_ok());
    }

    #[test]
    fn test_ack_ahead_drops_replies_of_both_formats() {
        let buf = delivery_buffer(8);
        assert_eq!(buf.ack(&[id(SURB_A), id(SURB_C)]), 0);
        assert_eq!(buf.acked_ahead_len(), 2);
        assert_eq!(
            buf.store_reply(&format!("reply-0-{SURB_A}"), vec![1]),
            ReplyStore::Acked
        );
        assert_eq!(
            buf.store_delivery(id(SURB_C), "peer-1", vec![2]),
            DeliveryStore::Acked
        );
        assert!(buf.is_empty());
        assert_eq!(buf.acked_ahead_len(), 0, "each ack-ahead drops one reply");

        // An ID acked after its reply was taken is not remembered twice.
        buf.store_response(&format!("reply-0-{SURB_B}"), vec![3]);
        assert_eq!(buf.ack(&[id(SURB_B)]), 1);
        assert_eq!(buf.acked_ahead_len(), 0);
    }

    #[test]
    fn test_ack_ahead_expires_after_the_claim_grace() {
        let buf = ResponseBuffer::new().with_claim_grace(Duration::from_millis(5));
        buf.ack(&[id(SURB_A)]);
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(
            buf.store_reply(&format!("reply-0-{SURB_A}"), vec![1]),
            ReplyStore::Stored { evicted: 0 }
        );
        buf.ack(&[id(SURB_B)]);
        std::thread::sleep(Duration::from_millis(10));
        buf.prune_expired();
        assert_eq!(buf.acked_ahead_len(), 0);
    }

    #[test]
    fn test_ack_ahead_is_bounded() {
        let mut buf = ResponseBuffer::new();
        buf.max_acked_ahead = 3;
        for i in 0..10u8 {
            buf.ack(&[[i; 16]]);
        }
        assert_eq!(buf.acked_ahead_len(), 3);
        assert_eq!(
            buf.store_reply("reply-0-09090909090909090909090909090909", vec![1]),
            ReplyStore::Acked
        );
        assert_eq!(
            buf.store_reply("reply-0-00000000000000000000000000000000", vec![1]),
            ReplyStore::Stored { evicted: 0 },
            "the oldest ack-ahead was forgotten"
        );
    }

    #[test]
    fn test_claim_at_most_returns_the_earliest_replies() {
        let buf = delivery_buffer(8);
        buf.store_response(&format!("reply-0-{SURB_B}"), vec![1]);
        std::thread::sleep(Duration::from_millis(2));
        buf.store_delivery(id(SURB_C), "peer-1", vec![2]);
        std::thread::sleep(Duration::from_millis(2));
        buf.store_response(&format!("reply-0-{SURB_A}"), vec![3]);

        let ids = [id(SURB_A), id(SURB_C), id(SURB_B), id(SURB_D)];
        let first = buf.claim_at_most(&ids, ClaimMode::Take, 1);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].data, vec![1]);
        let next = buf.claim_at_most(&ids, ClaimMode::Take, 2);
        assert_eq!(
            next.iter().map(|r| r.data.clone()).collect::<Vec<_>>(),
            vec![vec![2], vec![3]],
            "the two earliest, in arrival order"
        );
        assert!(buf.claim_at_most(&ids, ClaimMode::Take, 0).is_empty());
        assert!(buf.is_empty());
    }

    #[test]
    fn test_claim_at_most_never_takes_a_reply_it_does_not_return() {
        // One ID with a reply in both stores: a take limited to one reply
        // must leave the second in place for the next claim.
        let buf = delivery_buffer(8);
        buf.store_response(&format!("reply-0-{SURB_A}"), vec![1]);
        buf.store_delivery(id(SURB_A), "peer-1", vec![2]);
        let first = buf.claim_at_most(&[id(SURB_A)], ClaimMode::Take, 1);
        assert_eq!(first.len(), 1);
        let next = buf.claim_at_most(&[id(SURB_A)], ClaimMode::Take, 1);
        assert_eq!(next.len(), 1, "the other reply was kept");
        assert!(buf.is_empty());
    }

    #[test]
    fn test_ack_drops_unclaimed_reply_too() {
        let buf = ResponseBuffer::new();
        buf.store_response(&format!("reply-0-{SURB_A}"), vec![1]);
        buf.store_response(&format!("reply-0-{SURB_B}"), vec![2]);
        assert_eq!(buf.ack(&[id(SURB_B)]), 1);
        assert_eq!(buf.len(), 1);
        assert!(buf.has_any(&[id(SURB_A)]));
    }
}
