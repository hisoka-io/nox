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

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tracing::{debug, warn};

use super::delivery_buffer::{DeliveryBuffer, DeliveryLimits, DeliveryStore};

/// Default TTL for buffered responses (5 minutes).
const DEFAULT_TTL: Duration = Duration::from_mins(5);

/// Default maximum number of buffered responses.
///
/// Prevents unbounded memory growth between prune cycles.
/// At ~1 KB average response size, 10 000 entries ≈ 10 MB.
const DEFAULT_MAX_ENTRIES: usize = 10_000;

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
    surb_id: Option<SurbId>,
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

    fn retain_fresh(&mut self, ttl: Duration) -> usize {
        let expired: Vec<String> = self
            .by_packet_id
            .iter()
            .filter(|(_, entry)| entry.created_at.elapsed() >= ttl)
            .map(|(key, _)| key.clone())
            .collect();
        for key in &expired {
            self.remove(key);
        }
        expired.len()
    }
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
    max_entries: usize,
    /// Wakes waiting handlers (WebSocket, SSE, long-poll) when a new response is stored.
    notify: Arc<Notify>,
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
            max_entries,
            notify: Arc::new(Notify::new()),
        }
    }

    /// Replace the limits of the format 2 store. Drops anything already in it.
    #[must_use]
    pub fn with_delivery_limits(self, limits: DeliveryLimits) -> Self {
        *self.delivery.lock() = DeliveryBuffer::new(limits);
        self
    }

    /// Store a format 2 reply under its delivery ID, on behalf of the peer
    /// it came from. Never touches handle-keyed entries.
    pub fn store_delivery(
        &self,
        delivery_id: SurbId,
        source_peer: &str,
        data: Vec<u8>,
    ) -> DeliveryStore {
        let outcome = self
            .delivery
            .lock()
            .store(delivery_id, source_peer, data, self.ttl);
        if matches!(outcome, DeliveryStore::Stored { .. }) {
            debug!("Buffered format 2 reply");
            self.notify.notify_waiters();
        }
        outcome
    }

    /// Store a response under its `packet_id`. Returns how many older entries
    /// were evicted to make room.
    ///
    /// If the buffer is at capacity, the oldest entry is evicted first. If a
    /// response for the same SURB ID is already buffered under another
    /// `packet_id`, the new one is dropped: a SURB is single-use.
    pub fn store_response(&self, packet_id: &str, data: Vec<u8>) -> usize {
        let mut evicted = 0;
        let surb_id = surb_id_from_packet_id(packet_id);
        let mut entries = self.entries.lock();

        if let Some(id) = surb_id {
            if let Some(existing) = entries.by_surb_id.get(&id).cloned() {
                let expired = entries
                    .by_packet_id
                    .get(&existing)
                    .is_none_or(|entry| entry.created_at.elapsed() >= self.ttl);
                if expired {
                    entries.remove(&existing);
                } else if existing != packet_id {
                    debug!("Dropping response for a SURB ID that is already buffered");
                    return 0;
                }
            }
        }

        // Evict the oldest entry if at capacity
        if entries.by_packet_id.len() >= self.max_entries
            && !entries.by_packet_id.contains_key(packet_id)
        {
            // First try pruning expired entries
            entries.retain_fresh(self.ttl);

            // If still at capacity, evict the oldest
            if entries.by_packet_id.len() >= self.max_entries {
                if let Some(oldest_key) = entries
                    .by_packet_id
                    .iter()
                    .min_by_key(|(_, entry)| entry.created_at)
                    .map(|(key, _)| key.clone())
                {
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
                surb_id,
            },
        );

        // Wake any waiting handlers (WebSocket, SSE, long-poll) immediately.
        self.notify.notify_waiters();
        evicted
    }

    /// Returns a future that completes when a new response is stored.
    ///
    /// Used by WebSocket, SSE, and long-poll handlers to wake immediately
    /// on new data instead of fixed-interval polling.
    pub fn notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.notify.notified()
    }

    /// Take (remove and return) the response stored under exactly `packet_id`.
    /// Returns `None` if no response is available or if the entry has expired.
    pub fn take_response(&self, packet_id: &str) -> Option<Vec<u8>> {
        let mut entries = self.entries.lock();
        let entry = entries.remove(packet_id)?;
        (entry.created_at.elapsed() < self.ttl).then_some(entry.data)
    }

    /// Claim the responses for exactly these IDs (SURB IDs for format 1,
    /// delivery IDs for format 2). Returns `(id, data)` pairs where `id` is
    /// `reply-0-{the claimed ID}`; matching entries are removed, all others
    /// remain.
    ///
    /// The client knows which IDs it generated and passes them here to
    /// claim only its own responses.
    pub fn claim_by_surb_ids(&self, surb_ids: &[SurbId]) -> Vec<(String, Vec<u8>)> {
        if surb_ids.is_empty() {
            return Vec::new();
        }

        let mut entries = self.entries.lock();
        let mut delivery = self.delivery.lock();
        let mut claimed = Vec::new();

        for surb_id in surb_ids {
            if let Some(key) = entries.by_surb_id.get(surb_id).cloned() {
                if let Some(entry) = entries.remove(&key) {
                    if entry.created_at.elapsed() < self.ttl {
                        claimed.push((key, entry.data));
                    }
                }
            }
            if let Some(data) = delivery.take(surb_id, self.ttl) {
                claimed.push((format!("reply-0-{}", hex::encode(surb_id)), data));
            }
        }

        claimed
    }

    /// Prune all expired entries. Returns the number of entries removed.
    pub fn prune_expired(&self) -> usize {
        let (handle, delivery) = self.prune_expired_by_key();
        handle + delivery
    }

    /// Prune all expired entries. Returns the number removed from the
    /// handle-keyed and the delivery-keyed stores.
    pub fn prune_expired_by_key(&self) -> (usize, usize) {
        let handle = self.entries.lock().retain_fresh(self.ttl);
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
}
