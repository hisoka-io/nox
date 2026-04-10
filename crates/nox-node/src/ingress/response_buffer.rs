//! `ResponseBuffer` -- Thread-safe buffer for SURB responses keyed by `request_id`.
//!
//! Exit nodes send SURB responses back through the mixnet. When a response
//! arrives at the entry node, it is stored here. Clients long-poll via HTTP
//! to retrieve their responses.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tracing::{debug, warn};

/// Default TTL for buffered responses (5 minutes).
const DEFAULT_TTL: Duration = Duration::from_secs(300);

/// Default maximum number of buffered responses.
///
/// Prevents unbounded memory growth between prune cycles.
/// At ~1 KB average response size, 10 000 entries ≈ 10 MB.
const DEFAULT_MAX_ENTRIES: usize = 10_000;

struct BufferedResponse {
    data: Vec<u8>,
    created_at: Instant,
}

/// Thread-safe buffer for SURB responses.
///
/// Responses are stored with a TTL and automatically pruned on access.
/// A hard cap (`max_entries`) prevents unbounded memory growth between
/// prune cycles -- when the cap is reached, the oldest entry is evicted.
pub struct ResponseBuffer {
    entries: Mutex<HashMap<String, BufferedResponse>>,
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
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl: DEFAULT_TTL,
            max_entries: DEFAULT_MAX_ENTRIES,
            notify: Arc::new(Notify::new()),
        }
    }

    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
            max_entries: DEFAULT_MAX_ENTRIES,
            notify: Arc::new(Notify::new()),
        }
    }

    /// Create a `ResponseBuffer` with custom TTL and max entry count.
    #[must_use]
    pub fn with_ttl_and_capacity(ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
            max_entries,
            notify: Arc::new(Notify::new()),
        }
    }

    /// Store a response for a given `request_id`.
    ///
    /// If the buffer is at capacity, the oldest entry is evicted first.
    pub fn store_response(&self, request_id: &str, data: Vec<u8>) {
        let mut entries = self.entries.lock();

        // Evict the oldest entry if at capacity
        if entries.len() >= self.max_entries {
            // First try pruning expired entries
            entries.retain(|_, entry| entry.created_at.elapsed() < self.ttl);

            // If still at capacity, evict the oldest
            if entries.len() >= self.max_entries {
                if let Some(oldest_key) = entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.created_at)
                    .map(|(key, _)| key.clone())
                {
                    warn!(
                        evicted_id = %oldest_key,
                        buffer_size = entries.len(),
                        max = self.max_entries,
                        "ResponseBuffer at capacity, evicting oldest entry"
                    );
                    entries.remove(&oldest_key);
                }
            }
        }

        debug!(
            request_id = request_id,
            bytes = data.len(),
            "Buffered SURB response"
        );
        entries.insert(
            request_id.to_string(),
            BufferedResponse {
                data,
                created_at: Instant::now(),
            },
        );

        // Wake any waiting handlers (WebSocket, SSE, long-poll) immediately.
        self.notify.notify_waiters();
    }

    /// Returns a future that completes when a new response is stored.
    ///
    /// Used by WebSocket, SSE, and long-poll handlers to wake immediately
    /// on new data instead of fixed-interval polling.
    pub fn notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.notify.notified()
    }

    /// Take (remove and return) a response for a given `request_id`.
    /// Returns `None` if no response is available or if the entry has expired.
    pub fn take_response(&self, request_id: &str) -> Option<Vec<u8>> {
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.remove(request_id) {
            if entry.created_at.elapsed() < self.ttl {
                return Some(entry.data);
            }
        }
        None
    }

    /// Take all non-expired responses. Returns `(key, data)` pairs.
    /// Entries are removed from the buffer.
    ///
    /// **Privacy warning:** drains ALL responses regardless of ownership.
    /// Prefer [`claim_by_surb_ids`] when multiple clients share an entry node.
    pub fn take_all(&self) -> Vec<(String, Vec<u8>)> {
        let mut entries = self.entries.lock();
        entries
            .drain()
            .filter(|(_, entry)| entry.created_at.elapsed() < self.ttl)
            .map(|(key, entry)| (key, entry.data))
            .collect()
    }

    /// Claim responses whose `packet_id` contains one of the given SURB ID hex
    /// strings. Only matching, non-expired entries are removed; others remain.
    ///
    /// SURB response `packet_id` format: `"{handler}-{request_id}-{surb_id_hex}"`.
    /// The client knows which SURB IDs it generated and passes them here to
    /// claim only its own responses -- preventing cross-client response leakage.
    pub fn claim_by_surb_ids(&self, surb_ids: &[String]) -> Vec<(String, Vec<u8>)> {
        if surb_ids.is_empty() {
            return Vec::new();
        }

        let mut entries = self.entries.lock();
        let mut claimed = Vec::new();
        let mut to_remove = Vec::new();

        for (key, entry) in entries.iter() {
            if entry.created_at.elapsed() >= self.ttl {
                continue;
            }
            if surb_ids.iter().any(|sid| key.contains(sid.as_str())) {
                to_remove.push(key.clone());
            }
        }

        for key in to_remove {
            if let Some(entry) = entries.remove(&key) {
                claimed.push((key, entry.data));
            }
        }

        claimed
    }

    /// Prune all expired entries. Returns the number of entries removed.
    pub fn prune_expired(&self) -> usize {
        let mut entries = self.entries.lock();
        let before = entries.len();
        entries.retain(|_, entry| entry.created_at.elapsed() < self.ttl);
        before - entries.len()
    }

    /// Number of currently buffered responses.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_take_all_returns_entries() {
        let buf = ResponseBuffer::new();
        buf.store_response("a", vec![1]);
        buf.store_response("b", vec![2]);
        buf.store_response("c", vec![3]);

        let all = buf.take_all();
        assert_eq!(all.len(), 3);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_take_all_skips_expired() {
        let buf = ResponseBuffer::with_ttl(Duration::from_millis(1));
        buf.store_response("old", vec![1]);
        std::thread::sleep(Duration::from_millis(10));
        // Insert a fresh one after the old one has expired
        let buf2 = ResponseBuffer::new();
        buf2.store_response("new", vec![2]);

        let all = buf.take_all();
        assert!(all.is_empty(), "expired entries should be filtered out");
    }

    #[test]
    fn test_prune_expired() {
        let buf = ResponseBuffer::with_ttl(Duration::from_millis(1));
        buf.store_response("req-1", vec![1]);
        buf.store_response("req-2", vec![2]);

        std::thread::sleep(Duration::from_millis(10));

        let pruned = buf.prune_expired();
        assert_eq!(pruned, 2);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_max_entries_eviction() {
        let buf = ResponseBuffer::with_ttl_and_capacity(Duration::from_secs(60), 3);
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
        let buf = ResponseBuffer::with_ttl_and_capacity(Duration::from_secs(60), 1);
        buf.store_response("first", vec![1]);
        buf.store_response("second", vec![2]);

        assert_eq!(buf.len(), 1);
        assert!(buf.take_response("first").is_none());
        assert_eq!(buf.take_response("second"), Some(vec![2]));
    }

    #[test]
    fn test_claim_by_surb_ids_returns_matching() {
        let buf = ResponseBuffer::new();
        // Simulate packet_id format: "{handler}-{request_id}-{surb_id_hex}"
        buf.store_response("echo-12345-aabbccdd", vec![1, 2]);
        buf.store_response("rpc-67890-eeff0011", vec![3, 4]);
        buf.store_response("echo-99999-22334455", vec![5, 6]);

        let claimed = buf.claim_by_surb_ids(&["aabbccdd".to_string(), "22334455".to_string()]);
        assert_eq!(claimed.len(), 2);
        // Only the non-matching entry should remain
        assert_eq!(buf.len(), 1);
        assert!(buf.take_response("rpc-67890-eeff0011").is_some());
    }

    #[test]
    fn test_claim_by_surb_ids_empty_input() {
        let buf = ResponseBuffer::new();
        buf.store_response("echo-12345-aabbccdd", vec![1, 2]);

        let claimed = buf.claim_by_surb_ids(&[]);
        assert!(claimed.is_empty());
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn test_claim_by_surb_ids_no_match() {
        let buf = ResponseBuffer::new();
        buf.store_response("echo-12345-aabbccdd", vec![1, 2]);

        let claimed = buf.claim_by_surb_ids(&["deadbeef".to_string()]);
        assert!(claimed.is_empty());
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn test_claim_by_surb_ids_skips_expired() {
        let buf = ResponseBuffer::with_ttl(Duration::from_millis(1));
        buf.store_response("echo-12345-aabbccdd", vec![1, 2]);
        std::thread::sleep(Duration::from_millis(10));

        let claimed = buf.claim_by_surb_ids(&["aabbccdd".to_string()]);
        assert!(claimed.is_empty());
    }

    #[test]
    fn test_claim_isolation_between_clients() {
        let buf = ResponseBuffer::new();
        // Client A's SURBs
        buf.store_response("echo-100-aaaa1111", vec![10]);
        buf.store_response("echo-100-aaaa2222", vec![20]);
        // Client B's SURBs
        buf.store_response("echo-200-bbbb3333", vec![30]);
        buf.store_response("echo-200-bbbb4444", vec![40]);

        // Client A claims only its responses
        let a_claimed = buf.claim_by_surb_ids(&["aaaa1111".to_string(), "aaaa2222".to_string()]);
        assert_eq!(a_claimed.len(), 2);

        // Client B's responses are untouched
        assert_eq!(buf.len(), 2);
        let b_claimed = buf.claim_by_surb_ids(&["bbbb3333".to_string(), "bbbb4444".to_string()]);
        assert_eq!(b_claimed.len(), 2);
        assert!(buf.is_empty());
    }
}
