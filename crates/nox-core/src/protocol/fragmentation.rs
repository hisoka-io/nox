//! Fragmentation and reassembly for messages over unreliable, unordered Sphinx packet streams.

use bincode::Options;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Max fragments per message. Set to 9,500 to support ~275 MB via multi-round SURB replenishment.
pub const MAX_FRAGMENTS_PER_MESSAGE: u32 = 9_500;

/// Maximum forward-path message size (~6 MB). Response-path is not subject to this limit.
pub const MAX_MESSAGE_SIZE: usize = 200 * 32 * 1024;

/// Default max pending bytes in reassembly buffer (300 MB).
pub const DEFAULT_MAX_BUFFER_BYTES: usize = 300 * 1024 * 1024;

pub const DEFAULT_MAX_CONCURRENT_MESSAGES: usize = 50;
pub const DEFAULT_STALE_TIMEOUT_SECS: u64 = 120;
/// Single fragment: 32KB + overhead.
pub const MAX_FRAGMENT_DESERIALIZE_SIZE: u64 = 33 * 1024;
/// Bincode overhead per Fragment (~21 bytes without FEC, ~33 with FEC).
pub const FRAGMENT_OVERHEAD: usize = 21;
/// Sphinx body (~31KB) minus `ServiceResponse` wrapper overhead (~50 bytes).
pub const SURB_PAYLOAD_SIZE: usize = 30 * 1024;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum FragmentationError {
    #[error("Message too large: {size} bytes exceeds max {max} bytes")]
    MessageTooLarge { size: usize, max: usize },

    #[error("Invalid sequence {got} >= total_fragments {total}")]
    InvalidSequence { got: u32, total: u32 },

    #[error("Too many fragments: {total} exceeds max {max}")]
    TooManyFragments { total: u32, max: u32 },

    #[error("Inconsistent metadata: expected total={expected}, got total={got}")]
    InconsistentMetadata { expected: u32, got: u32 },

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Empty message")]
    EmptyMessage,

    #[error("Invalid chunk size: {0}")]
    InvalidChunkSize(usize),

    #[error("Internal logic error: {0}")]
    InternalError(String),

    #[error("Duplicate fragment seq={sequence} for message {message_id} with different data")]
    DuplicateDataMismatch { message_id: u64, sequence: u32 },

    #[error("Invalid FEC metadata: {reason}")]
    InvalidFec { reason: String },

    #[error("FEC decode failed: {0}")]
    FecDecodeFailed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Fragment {
    pub message_id: u64,
    /// D+P when FEC is active.
    pub total_fragments: u32,
    /// 0-indexed. With FEC: 0..D-1 are data, D..D+P-1 are parity.
    pub sequence: u32,
    pub data: Vec<u8>,
    /// Present on every FEC-protected fragment; `None` for non-FEC traffic.
    pub fec: Option<super::fec::FecInfo>,
}

impl Fragment {
    pub fn new(
        message_id: u64,
        total_fragments: u32,
        sequence: u32,
        data: Vec<u8>,
    ) -> Result<Self, FragmentationError> {
        if total_fragments > MAX_FRAGMENTS_PER_MESSAGE {
            return Err(FragmentationError::TooManyFragments {
                total: total_fragments,
                max: MAX_FRAGMENTS_PER_MESSAGE,
            });
        }
        if sequence >= total_fragments {
            return Err(FragmentationError::InvalidSequence {
                got: sequence,
                total: total_fragments,
            });
        }
        Ok(Self {
            message_id,
            total_fragments,
            sequence,
            data,
            fec: None,
        })
    }

    pub fn new_with_fec(
        message_id: u64,
        total_fragments: u32,
        sequence: u32,
        data: Vec<u8>,
        fec_info: super::fec::FecInfo,
    ) -> Result<Self, FragmentationError> {
        if total_fragments > MAX_FRAGMENTS_PER_MESSAGE {
            return Err(FragmentationError::TooManyFragments {
                total: total_fragments,
                max: MAX_FRAGMENTS_PER_MESSAGE,
            });
        }
        if sequence >= total_fragments {
            return Err(FragmentationError::InvalidSequence {
                got: sequence,
                total: total_fragments,
            });
        }
        if fec_info.data_shard_count == 0 || fec_info.data_shard_count > total_fragments {
            return Err(FragmentationError::InvalidFec {
                reason: format!(
                    "data_shard_count {} must be in 1..={}",
                    fec_info.data_shard_count, total_fragments
                ),
            });
        }
        Ok(Self {
            message_id,
            total_fragments,
            sequence,
            data,
            fec: Some(fec_info),
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, FragmentationError> {
        bincode::serialize(self).map_err(|e| FragmentationError::SerializationError(e.to_string()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FragmentationError> {
        let frag: Fragment = bincode::DefaultOptions::new()
            .with_limit(MAX_FRAGMENT_DESERIALIZE_SIZE)
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .deserialize(bytes)
            .map_err(|e| FragmentationError::SerializationError(e.to_string()))?;
        frag.validate()?;
        Ok(frag)
    }

    pub fn validate(&self) -> Result<(), FragmentationError> {
        if self.total_fragments > MAX_FRAGMENTS_PER_MESSAGE {
            return Err(FragmentationError::TooManyFragments {
                total: self.total_fragments,
                max: MAX_FRAGMENTS_PER_MESSAGE,
            });
        }
        if self.sequence >= self.total_fragments {
            return Err(FragmentationError::InvalidSequence {
                got: self.sequence,
                total: self.total_fragments,
            });
        }
        if let Some(ref fec_info) = self.fec {
            if fec_info.data_shard_count == 0 || fec_info.data_shard_count > self.total_fragments {
                return Err(FragmentationError::InvalidFec {
                    reason: format!(
                        "data_shard_count {} must be in 1..={}",
                        fec_info.data_shard_count, self.total_fragments
                    ),
                });
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn size(&self) -> usize {
        let fec_overhead = if self.fec.is_some() { 13 } else { 1 };
        FRAGMENT_OVERHEAD + self.data.len() + fec_overhead
    }
}

#[derive(Debug, Clone)]
pub struct Fragmenter {
    max_message_size: usize,
}

impl Default for Fragmenter {
    fn default() -> Self {
        Self::new()
    }
}

impl Fragmenter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_message_size: MAX_MESSAGE_SIZE,
        }
    }

    #[must_use]
    pub fn with_max_size(max_message_size: usize) -> Self {
        Self { max_message_size }
    }

    pub fn fragment(
        &self,
        message_id: u64,
        data: &[u8],
        max_chunk_size: usize,
    ) -> Result<Vec<Fragment>, FragmentationError> {
        if data.is_empty() {
            return Err(FragmentationError::EmptyMessage);
        }

        if data.len() > self.max_message_size {
            return Err(FragmentationError::MessageTooLarge {
                size: data.len(),
                max: self.max_message_size,
            });
        }

        let usable_payload = max_chunk_size.saturating_sub(FRAGMENT_OVERHEAD);
        if usable_payload == 0 {
            return Err(FragmentationError::InvalidChunkSize(max_chunk_size));
        }

        let total_fragments = data.len().div_ceil(usable_payload);

        if total_fragments > MAX_FRAGMENTS_PER_MESSAGE as usize {
            return Err(FragmentationError::TooManyFragments {
                total: total_fragments as u32,
                max: MAX_FRAGMENTS_PER_MESSAGE,
            });
        }

        let total_fragments = total_fragments as u32;
        let mut fragments = Vec::with_capacity(total_fragments as usize);

        for (seq, chunk) in data.chunks(usable_payload).enumerate() {
            fragments.push(Fragment {
                message_id,
                total_fragments,
                sequence: seq as u32,
                data: chunk.to_vec(),
                fec: None,
            });
        }

        Ok(fragments)
    }

    #[must_use]
    pub fn usable_payload_size(max_packet_size: usize) -> usize {
        max_packet_size.saturating_sub(FRAGMENT_OVERHEAD)
    }
}

#[derive(Debug)]
struct ReassemblyBuffer {
    fragments: HashMap<u32, Fragment>,
    expected_total: u32,
    received_count: u32,
    buffered_bytes: usize,
    created_at: Instant,
    last_activity: Instant,
    /// When present, completion requires D-of-(D+P) shards instead of all.
    fec_info: Option<super::fec::FecInfo>,
}

impl ReassemblyBuffer {
    fn new(first_fragment: &Fragment) -> Self {
        let now = Instant::now();
        Self {
            fragments: HashMap::with_capacity(first_fragment.total_fragments as usize),
            expected_total: first_fragment.total_fragments,
            received_count: 0,
            buffered_bytes: 0,
            created_at: now,
            last_activity: now,
            fec_info: first_fragment.fec.clone(),
        }
    }

    /// Returns true if this was a new (non-duplicate) fragment.
    /// Rejects duplicate sequences with different data; accepts exact duplicates idempotently.
    fn add(&mut self, fragment: Fragment) -> Result<bool, FragmentationError> {
        if fragment.total_fragments != self.expected_total {
            return Err(FragmentationError::InconsistentMetadata {
                expected: self.expected_total,
                got: fragment.total_fragments,
            });
        }

        if let Some(ref incoming_fec) = fragment.fec {
            match &self.fec_info {
                Some(existing_fec) => {
                    if incoming_fec != existing_fec {
                        return Err(FragmentationError::InvalidFec {
                            reason: format!(
                                "FEC mismatch: buffer has D={} len={}, fragment has D={} len={}",
                                existing_fec.data_shard_count,
                                existing_fec.original_data_len,
                                incoming_fec.data_shard_count,
                                incoming_fec.original_data_len,
                            ),
                        });
                    }
                }
                None => {
                    self.fec_info = Some(incoming_fec.clone());
                }
            }
        }

        self.last_activity = Instant::now();

        if let Some(existing) = self.fragments.get(&fragment.sequence) {
            if existing.data != fragment.data {
                return Err(FragmentationError::DuplicateDataMismatch {
                    message_id: fragment.message_id,
                    sequence: fragment.sequence,
                });
            }
            return Ok(false);
        }

        self.buffered_bytes += fragment.size();
        self.received_count += 1;
        self.fragments.insert(fragment.sequence, fragment);

        Ok(true)
    }

    fn is_complete(&self) -> bool {
        match &self.fec_info {
            Some(fec) => self.received_count >= fec.data_shard_count,
            None => self.received_count == self.expected_total,
        }
    }

    fn has_sequence(&self, sequence: u32) -> bool {
        self.fragments.contains_key(&sequence)
    }

    fn assemble(mut self) -> Result<Vec<u8>, FragmentationError> {
        match &self.fec_info {
            None => {
                let mut result = Vec::new();
                for seq in 0..self.expected_total {
                    if let Some(frag) = self.fragments.remove(&seq) {
                        result.extend(frag.data);
                    }
                }
                Ok(result)
            }
            Some(fec) => {
                let d = fec.data_shard_count as usize;
                let total = self.expected_total as usize;
                let original_len = fec.original_data_len;

                let mut shards: Vec<Option<Vec<u8>>> = (0..total)
                    .map(|seq| self.fragments.remove(&(seq as u32)).map(|f| f.data))
                    .collect();

                super::fec::decode_shards(&mut shards, d, original_len)
                    .map_err(|e| FragmentationError::FecDecodeFailed(e.to_string()))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReassemblerConfig {
    pub max_buffer_bytes: usize,
    pub max_concurrent_messages: usize,
    pub stale_timeout: Duration,
}

impl Default for ReassemblerConfig {
    fn default() -> Self {
        Self {
            max_buffer_bytes: DEFAULT_MAX_BUFFER_BYTES,
            max_concurrent_messages: DEFAULT_MAX_CONCURRENT_MESSAGES,
            stale_timeout: Duration::from_secs(DEFAULT_STALE_TIMEOUT_SECS),
        }
    }
}

/// Reassembles fragments into complete messages with bounded memory, LRU eviction,
/// stale pruning, and duplicate integrity checks.
#[derive(Debug)]
pub struct Reassembler {
    buffers: HashMap<u64, ReassemblyBuffer>,
    config: ReassemblerConfig,
    total_buffered_bytes: usize,
}

impl Reassembler {
    #[must_use]
    pub fn new(config: ReassemblerConfig) -> Self {
        Self {
            buffers: HashMap::new(),
            config,
            total_buffered_bytes: 0,
        }
    }

    /// Returns `Ok(Some(data))` if this fragment completed a message, `Ok(None)` if more needed.
    pub fn add_fragment(
        &mut self,
        fragment: Fragment,
    ) -> Result<Option<Vec<u8>>, FragmentationError> {
        fragment.validate()?;

        let message_id = fragment.message_id;
        let fragment_size = fragment.size();

        // Early duplicate detection before ensure_capacity() to avoid evicting valid sessions
        if let Some(buffer) = self.buffers.get(&message_id) {
            if buffer.has_sequence(fragment.sequence) {
                let buffer = self.buffers.get_mut(&message_id).ok_or_else(|| {
                    FragmentationError::InternalError(
                        "Buffer vanished during duplicate check".to_string(),
                    )
                })?;
                buffer.add(fragment)?;
                return Ok(None);
            }
        }

        self.ensure_capacity(fragment_size)?;

        let buffer = self
            .buffers
            .entry(message_id)
            .or_insert_with(|| ReassemblyBuffer::new(&fragment));

        let is_new = buffer.add(fragment)?;

        if is_new {
            self.total_buffered_bytes += fragment_size;
        }

        let is_complete = buffer.is_complete();

        if is_complete {
            let buffer = self.buffers.remove(&message_id).ok_or_else(|| {
                FragmentationError::InternalError("Buffer vanished during processing".to_string())
            })?;

            self.total_buffered_bytes = self
                .total_buffered_bytes
                .saturating_sub(buffer.buffered_bytes);
            Ok(Some(buffer.assemble()?))
        } else {
            Ok(None)
        }
    }

    fn ensure_capacity(&mut self, needed_bytes: usize) -> Result<(), FragmentationError> {
        while (self.total_buffered_bytes + needed_bytes > self.config.max_buffer_bytes
            || self.buffers.len() >= self.config.max_concurrent_messages)
            && !self.buffers.is_empty()
        {
            self.evict_oldest();
        }
        Ok(())
    }

    fn evict_oldest(&mut self) {
        if let Some((&oldest_id, _)) = self.buffers.iter().min_by_key(|(_, buf)| buf.last_activity)
        {
            if let Some(buffer) = self.buffers.remove(&oldest_id) {
                self.total_buffered_bytes = self
                    .total_buffered_bytes
                    .saturating_sub(buffer.buffered_bytes);
                tracing::debug!(
                    message_id = oldest_id,
                    bytes = buffer.buffered_bytes,
                    "Evicted stale reassembly buffer"
                );
            }
        }
    }

    pub fn prune_stale(&mut self, timeout: Duration) -> usize {
        let now = Instant::now();
        let stale_ids: Vec<u64> = self
            .buffers
            .iter()
            .filter(|(_, buf)| now.duration_since(buf.created_at) > timeout)
            .map(|(&id, _)| id)
            .collect();

        let count = stale_ids.len();
        for id in stale_ids {
            if let Some(buffer) = self.buffers.remove(&id) {
                self.total_buffered_bytes = self
                    .total_buffered_bytes
                    .saturating_sub(buffer.buffered_bytes);
                tracing::debug!(
                    message_id = id,
                    age_secs = now.duration_since(buffer.created_at).as_secs(),
                    "Pruned stale reassembly buffer"
                );
            }
        }
        count
    }

    pub fn prune_stale_default(&mut self) -> usize {
        self.prune_stale(self.config.stale_timeout)
    }

    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.total_buffered_bytes
    }

    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.buffers.len()
    }

    #[must_use]
    pub fn has_message(&self, message_id: u64) -> bool {
        self.buffers.contains_key(&message_id)
    }

    #[must_use]
    pub fn message_progress(&self, message_id: u64) -> Option<(u32, u32)> {
        self.buffers
            .get(&message_id)
            .map(|buf| (buf.received_count, buf.expected_total))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_roundtrip() {
        let frag = Fragment::new(12345, 10, 5, vec![1, 2, 3, 4, 5]).unwrap();
        let bytes = frag.to_bytes().unwrap();
        let recovered = Fragment::from_bytes(&bytes).unwrap();
        assert_eq!(frag, recovered);
    }

    #[test]
    fn test_fragment_validation() {
        assert!(Fragment::new(1, 10, 10, vec![]).is_err());
        assert!(Fragment::new(1, 10, 15, vec![]).is_err());
        assert!(Fragment::new(1, MAX_FRAGMENTS_PER_MESSAGE + 1, 0, vec![]).is_err());
    }

    #[test]
    fn test_fragmenter_basic() {
        let fragmenter = Fragmenter::new();
        let data: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
        let fragments = fragmenter.fragment(1, &data, 1000).unwrap();

        assert!(fragments.len() > 1);
        assert!(fragments.iter().all(|f| f.message_id == 1));
        assert!(fragments
            .iter()
            .all(|f| f.total_fragments == fragments.len() as u32));

        for (i, f) in fragments.iter().enumerate() {
            assert_eq!(f.sequence, i as u32);
        }
    }

    #[test]
    fn test_fragmenter_empty_message() {
        let fragmenter = Fragmenter::new();
        assert!(matches!(
            fragmenter.fragment(1, &[], 1000),
            Err(FragmentationError::EmptyMessage)
        ));
    }

    #[test]
    fn test_fragmenter_message_too_large() {
        let fragmenter = Fragmenter::with_max_size(1000);
        let data = vec![0u8; 2000];
        assert!(matches!(
            fragmenter.fragment(1, &data, 100),
            Err(FragmentationError::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn test_reassembler_in_order() {
        let fragmenter = Fragmenter::new();
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());

        let original: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
        let fragments = fragmenter.fragment(42, &original, 500).unwrap();

        for (i, frag) in fragments.into_iter().enumerate() {
            let result = reassembler.add_fragment(frag).unwrap();
            if i < 10 {
                assert!(result.is_none());
            }
        }
    }

    #[test]
    fn test_reassembler_out_of_order() {
        let fragmenter = Fragmenter::new();
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());

        let original: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
        let mut fragments = fragmenter.fragment(42, &original, 500).unwrap();
        fragments.reverse();

        let mut result = None;
        for frag in fragments {
            if let Some(data) = reassembler.add_fragment(frag).unwrap() {
                result = Some(data);
            }
        }

        assert_eq!(result.unwrap(), original);
    }

    #[test]
    fn test_reassembler_duplicate_handling() {
        let fragmenter = Fragmenter::new();
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());

        let original: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let fragments = fragmenter.fragment(42, &original, 500).unwrap();

        let first = fragments[0].clone();
        assert!(reassembler.add_fragment(first.clone()).unwrap().is_none());
        assert!(reassembler.add_fragment(first.clone()).unwrap().is_none());
        assert!(reassembler.add_fragment(first).unwrap().is_none());

        let mut result = None;
        for frag in fragments.into_iter().skip(1) {
            if let Some(data) = reassembler.add_fragment(frag).unwrap() {
                result = Some(data);
            }
        }

        assert_eq!(result.unwrap(), original);
    }

    #[test]
    fn test_reassembler_inconsistent_metadata() {
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());

        let frag1 = Fragment::new(100, 5, 0, vec![1, 2, 3]).unwrap();
        reassembler.add_fragment(frag1).unwrap();

        let frag2 = Fragment {
            message_id: 100,
            total_fragments: 10,
            sequence: 1,
            data: vec![4, 5, 6],
            fec: None,
        };

        assert!(matches!(
            reassembler.add_fragment(frag2),
            Err(FragmentationError::InconsistentMetadata {
                expected: 5,
                got: 10
            })
        ));
    }

    #[test]
    fn test_reassembler_memory_limit() {
        let config = ReassemblerConfig {
            max_buffer_bytes: 1000,
            max_concurrent_messages: 2,
            stale_timeout: Duration::from_secs(60),
        };
        let mut reassembler = Reassembler::new(config);

        let frag1 = Fragment::new(1, 5, 0, vec![0u8; 200]).unwrap();
        reassembler.add_fragment(frag1).unwrap();

        let frag2 = Fragment::new(2, 5, 0, vec![0u8; 200]).unwrap();
        reassembler.add_fragment(frag2).unwrap();

        let frag3 = Fragment::new(3, 5, 0, vec![0u8; 200]).unwrap();
        reassembler.add_fragment(frag3).unwrap();

        assert!(!reassembler.has_message(1));
        assert!(reassembler.has_message(2));
        assert!(reassembler.has_message(3));
    }

    #[test]
    fn test_reassembler_prune_stale() {
        let config = ReassemblerConfig {
            max_buffer_bytes: 10_000,
            max_concurrent_messages: 100,
            stale_timeout: Duration::from_millis(50),
        };
        let mut reassembler = Reassembler::new(config);

        let frag = Fragment::new(999, 10, 0, vec![1, 2, 3]).unwrap();
        reassembler.add_fragment(frag).unwrap();
        assert_eq!(reassembler.pending_count(), 1);

        std::thread::sleep(Duration::from_millis(100));
        let pruned = reassembler.prune_stale(Duration::from_millis(50));
        assert_eq!(pruned, 1);
        assert_eq!(reassembler.pending_count(), 0);
    }

    #[test]
    fn test_duplicate_sequence_same_data_accepted() {
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());

        let frag = Fragment::new(1, 3, 0, vec![1, 2, 3]).unwrap();
        assert!(reassembler.add_fragment(frag.clone()).unwrap().is_none());
        assert!(reassembler.add_fragment(frag).unwrap().is_none());
        assert_eq!(reassembler.message_progress(1), Some((1, 3)));
    }

    #[test]
    fn test_duplicate_sequence_different_data_rejected() {
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());

        let frag1 = Fragment::new(1, 3, 0, vec![1, 2, 3]).unwrap();
        reassembler.add_fragment(frag1).unwrap();

        let frag2 = Fragment {
            message_id: 1,
            total_fragments: 3,
            sequence: 0,
            data: vec![4, 5, 6],
            fec: None,
        };
        assert!(matches!(
            reassembler.add_fragment(frag2),
            Err(FragmentationError::DuplicateDataMismatch {
                message_id: 1,
                sequence: 0,
            })
        ));
    }

    #[test]
    fn test_duplicate_does_not_evict() {
        let config = ReassemblerConfig {
            max_buffer_bytes: 1000,
            max_concurrent_messages: 2,
            stale_timeout: Duration::from_secs(60),
        };
        let mut reassembler = Reassembler::new(config);

        let frag1 = Fragment::new(1, 5, 0, vec![0u8; 200]).unwrap();
        reassembler.add_fragment(frag1).unwrap();

        let frag2 = Fragment::new(2, 5, 0, vec![0u8; 200]).unwrap();
        reassembler.add_fragment(frag2).unwrap();

        let dup = Fragment::new(1, 5, 0, vec![0u8; 200]).unwrap();
        reassembler.add_fragment(dup).unwrap();

        assert!(
            reassembler.has_message(1),
            "Message 1 should still be present"
        );
        assert!(
            reassembler.has_message(2),
            "Message 2 should still be present"
        );
    }

    use super::super::fec::{encode_parity_shards, pad_to_uniform, FecInfo};

    fn make_fec_fragments(
        message_id: u64,
        data: &[u8],
        shard_size: usize,
        parity_count: usize,
    ) -> Vec<Fragment> {
        let chunks: Vec<Vec<u8>> = data.chunks(shard_size).map(|c| c.to_vec()).collect();
        let (padded, _) = pad_to_uniform(&chunks).unwrap();
        let d = padded.len();

        let parity = encode_parity_shards(&padded, parity_count).unwrap();
        let total = (d + parity_count) as u32;

        let fec_info = FecInfo {
            data_shard_count: d as u32,
            original_data_len: data.len() as u64,
        };

        let mut fragments = Vec::new();
        for (seq, shard) in padded.into_iter().enumerate() {
            fragments.push(Fragment {
                message_id,
                total_fragments: total,
                sequence: seq as u32,
                data: shard,
                fec: Some(fec_info.clone()),
            });
        }
        for (i, shard) in parity.into_iter().enumerate() {
            fragments.push(Fragment {
                message_id,
                total_fragments: total,
                sequence: (d + i) as u32,
                data: shard,
                fec: Some(fec_info.clone()),
            });
        }
        fragments
    }

    #[test]
    fn test_fec_all_data_present_fast_path() {
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());
        let original: Vec<u8> = (0..300).map(|i| (i % 256) as u8).collect();
        let fragments = make_fec_fragments(1, &original, 100, 2); // D=3, P=2

        let mut result = None;
        for frag in fragments {
            if let Some(data) = reassembler.add_fragment(frag).unwrap() {
                result = Some(data);
            }
        }

        assert_eq!(result.unwrap(), original);
    }

    #[test]
    fn test_fec_drop_one_data_shard_rs_recovery() {
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());
        let original: Vec<u8> = (0..300).map(|i| (i % 256) as u8).collect();
        let mut fragments = make_fec_fragments(1, &original, 100, 2); // D=3, P=2

        fragments.remove(1);

        let mut result = None;
        for frag in fragments {
            if let Some(data) = reassembler.add_fragment(frag).unwrap() {
                result = Some(data);
            }
        }

        assert_eq!(result.unwrap(), original);
    }

    #[test]
    fn test_fec_drop_all_parity_fast_path() {
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());
        let original: Vec<u8> = (0..300).map(|i| (i % 256) as u8).collect();
        let fragments = make_fec_fragments(1, &original, 100, 2); // D=3, P=2

        let mut result = None;
        for frag in fragments.into_iter().take(3) {
            if let Some(data) = reassembler.add_fragment(frag).unwrap() {
                result = Some(data);
            }
        }

        assert_eq!(result.unwrap(), original);
    }

    #[test]
    fn test_fec_drop_p_shards_rs_recovers() {
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());
        let original: Vec<u8> = (0..500).map(|i| (i % 256) as u8).collect();
        let mut fragments = make_fec_fragments(1, &original, 100, 3); // D=5, P=3

        fragments.remove(6);
        fragments.remove(3);
        fragments.remove(0);

        let mut result = None;
        for frag in fragments {
            if let Some(data) = reassembler.add_fragment(frag).unwrap() {
                result = Some(data);
            }
        }

        assert_eq!(result.unwrap(), original);
    }

    #[test]
    fn test_fec_drop_too_many_incomplete() {
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());
        let original: Vec<u8> = (0..300).map(|i| (i % 256) as u8).collect();
        let mut fragments = make_fec_fragments(1, &original, 100, 2); // D=3, P=2

        fragments.remove(4);
        fragments.remove(2);
        fragments.remove(0);

        let mut result = None;
        for frag in fragments {
            if let Some(data) = reassembler.add_fragment(frag).unwrap() {
                result = Some(data);
            }
        }

        assert!(result.is_none());
        assert_eq!(reassembler.pending_count(), 1);
    }

    #[test]
    fn test_fec_single_fragment_d1_p1() {
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());
        let original = b"Small message".to_vec();
        let fragments = make_fec_fragments(1, &original, original.len(), 1); // D=1, P=1

        assert_eq!(fragments.len(), 2);

        let parity = fragments[1].clone();
        let result = reassembler.add_fragment(parity).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), original);
    }

    #[test]
    fn test_fec_backward_compat_no_fec() {
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());
        let original: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();

        let fragmenter = Fragmenter::new();
        let fragments = fragmenter.fragment(42, &original, 500).unwrap();

        let mut result = None;
        for frag in fragments {
            assert!(frag.fec.is_none());
            if let Some(data) = reassembler.add_fragment(frag).unwrap() {
                result = Some(data);
            }
        }

        assert_eq!(result.unwrap(), original);
    }

    #[test]
    fn test_fec_consistency_validation() {
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());

        let fec1 = FecInfo {
            data_shard_count: 3,
            original_data_len: 300,
        };
        let fec2 = FecInfo {
            data_shard_count: 5,
            original_data_len: 500,
        };

        let frag1 = Fragment {
            message_id: 1,
            total_fragments: 5,
            sequence: 0,
            data: vec![0u8; 100],
            fec: Some(fec1),
        };
        reassembler.add_fragment(frag1).unwrap();

        let frag2 = Fragment {
            message_id: 1,
            total_fragments: 5,
            sequence: 1,
            data: vec![0u8; 100],
            fec: Some(fec2),
        };

        assert!(matches!(
            reassembler.add_fragment(frag2),
            Err(FragmentationError::InvalidFec { .. })
        ));
    }

    #[test]
    fn test_fec_mixed_data_parity_drops() {
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());
        let original: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let mut fragments = make_fec_fragments(1, &original, 200, 3); // D=5, P=3

        fragments.remove(6);
        fragments.remove(2);
        fragments.remove(0);

        let mut result = None;
        for frag in fragments {
            if let Some(data) = reassembler.add_fragment(frag).unwrap() {
                result = Some(data);
            }
        }

        assert_eq!(result.unwrap(), original);
    }

    #[test]
    fn test_fec_info_inconsistency_rejected() {
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());

        let fec_info_a = FecInfo {
            data_shard_count: 3,
            original_data_len: 600,
        };
        let fec_info_b = FecInfo {
            data_shard_count: 5,
            original_data_len: 600,
        };

        let frag1 = Fragment {
            message_id: 42,
            total_fragments: 4,
            sequence: 0,
            data: vec![1u8; 200],
            fec: Some(fec_info_a),
        };
        reassembler.add_fragment(frag1).unwrap();

        let frag2 = Fragment {
            message_id: 42,
            total_fragments: 4,
            sequence: 1,
            data: vec![2u8; 200],
            fec: Some(fec_info_b),
        };
        let result = reassembler.add_fragment(frag2);
        assert!(
            result.is_err(),
            "expected error on inconsistent FEC metadata, got Ok"
        );
    }
}
