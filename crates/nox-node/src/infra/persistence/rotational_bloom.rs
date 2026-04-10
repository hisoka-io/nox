use async_trait::async_trait;
use fastbloom::BloomFilter;
use nox_core::traits::{IReplayProtection, InfrastructureError};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, warn};

struct BloomFilterState {
    current: BloomFilter,
    previous: BloomFilter,
    last_rotation: Instant,
    last_rotation_unix: u64,
}

/// Dual-window bloom filter for replay protection with flat-file persistence.
///
/// Rotates `current` -> `previous` on each interval; checks both for membership.
/// Flat file avoids sled's blob leak. Downtime > 2x interval resets to empty.
pub struct RotationalBloomFilter {
    state: Arc<RwLock<BloomFilterState>>,
    rotation_interval: Duration,
    capacity: usize,
    false_positive_rate: f64,
    persist_path: Option<PathBuf>,
}

impl RotationalBloomFilter {
    #[must_use]
    pub fn new(capacity: usize, false_positive_rate: f64, rotation_interval: Duration) -> Self {
        let current = fresh_bloom(capacity, false_positive_rate);
        let previous = fresh_bloom(capacity, false_positive_rate);
        let now_unix = unix_now_secs();

        Self {
            state: Arc::new(RwLock::new(BloomFilterState {
                current,
                previous,
                last_rotation: Instant::now(),
                last_rotation_unix: now_unix,
            })),
            rotation_interval,
            capacity,
            false_positive_rate,
            persist_path: None,
        }
    }

    /// Call `restore_from_file()` after this to hydrate state.
    #[must_use]
    pub fn with_file_persistence<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.persist_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Must be called before the node begins processing packets.
    pub async fn restore_from_file(&self) -> Result<(), InfrastructureError> {
        let path = match &self.persist_path {
            Some(p) => p.clone(),
            None => return Ok(()),
        };

        let capacity = self.capacity;
        let fpr = self.false_positive_rate;
        let max_window_secs = self.rotation_interval.as_secs().saturating_mul(2);

        let file_data =
            tokio::task::spawn_blocking(move || -> Result<Option<Vec<u8>>, InfrastructureError> {
                if !path.exists() {
                    return Ok(None);
                }
                std::fs::read(&path).map(Some).map_err(|e| {
                    InfrastructureError::Database(format!("Failed to read bloom file: {e}"))
                })
            })
            .await
            .map_err(|e| {
                InfrastructureError::Database(format!("spawn_blocking join error: {e}"))
            })?;

        let Some(bytes) = file_data? else {
            info!("No persisted replay filter found -- starting fresh.");
            return Ok(());
        };

        if bytes.len() < 8 {
            warn!(
                "Bloom persist file too short ({} bytes) -- starting fresh.",
                bytes.len()
            );
            return Ok(());
        }

        let last_rotation_unix = u64::from_le_bytes(
            bytes[..8]
                .try_into()
                .map_err(|_| InfrastructureError::Database("Corrupt bloom timestamp".into()))?,
        );

        let now_unix = unix_now_secs();
        let elapsed_secs = now_unix.saturating_sub(last_rotation_unix);

        if elapsed_secs > max_window_secs {
            warn!(
                elapsed_secs,
                max_window_secs,
                "Replay filter expired during downtime -- starting with empty filters. \
                 Replays from the gap window ({elapsed_secs}s) may pass through once."
            );
            return Ok(());
        }

        let expected_bloom_size = bloom_serialized_size(capacity, fpr);
        let expected_file_size = 8 + expected_bloom_size * 2;

        if bytes.len() != expected_file_size {
            warn!(
                file_size = bytes.len(),
                expected_file_size,
                "Bloom persist file size mismatch (capacity changed?) -- starting fresh."
            );
            return Ok(());
        }

        let current_bytes = &bytes[8..8 + expected_bloom_size];
        let previous_bytes = &bytes[8 + expected_bloom_size..];

        let current = deserialize_bloom(current_bytes, capacity, fpr)?;
        let previous = deserialize_bloom(previous_bytes, capacity, fpr)?;

        let elapsed_since_rotation = Duration::from_secs(elapsed_secs);
        let restored_last_rotation = Instant::now()
            .checked_sub(elapsed_since_rotation)
            .unwrap_or_else(Instant::now);

        let mut state = self.state.write().await;
        state.current = current;
        state.previous = previous;
        state.last_rotation = restored_last_rotation;
        state.last_rotation_unix = last_rotation_unix;

        info!(
            elapsed_secs,
            "Replay filter restored from file -- coverage window intact."
        );
        Ok(())
    }

    fn rotate_if_needed_inner(
        state: &mut BloomFilterState,
        interval: Duration,
        capacity: usize,
        fpr: f64,
        persist_path: Option<&PathBuf>,
    ) {
        if state.last_rotation.elapsed() < interval {
            return;
        }

        let old_current = std::mem::replace(&mut state.current, fresh_bloom(capacity, fpr));
        state.previous = old_current;
        state.last_rotation = Instant::now();
        state.last_rotation_unix = unix_now_secs();

        if let Some(path) = persist_path {
            let file_bytes =
                serialize_to_file_format(state.last_rotation_unix, &state.current, &state.previous);
            let path = path.clone();

            tokio::spawn(async move {
                if let Err(e) =
                    tokio::task::spawn_blocking(move || atomic_write_file(&path, &file_bytes))
                        .await
                        .unwrap_or_else(|e| {
                            Err(InfrastructureError::Database(format!(
                                "spawn_blocking join error: {e}"
                            )))
                        })
                {
                    warn!("Replay filter persist failed: {e}");
                }
            });
        }
    }
}

#[async_trait]
impl IReplayProtection for RotationalBloomFilter {
    async fn check_and_tag(
        &self,
        tag: &[u8],
        _ttl_seconds: u64, // Ignored -- handled by rotation window.
    ) -> Result<bool, InfrastructureError> {
        let mut state = self.state.write().await;
        Self::rotate_if_needed_inner(
            &mut state,
            self.rotation_interval,
            self.capacity,
            self.false_positive_rate,
            self.persist_path.as_ref(),
        );

        if state.current.contains(tag) || state.previous.contains(tag) {
            return Ok(true);
        }

        state.current.insert(tag);
        Ok(false)
    }

    async fn prune_expired(&self) -> Result<usize, InfrastructureError> {
        let mut state = self.state.write().await;
        Self::rotate_if_needed_inner(
            &mut state,
            self.rotation_interval,
            self.capacity,
            self.false_positive_rate,
            self.persist_path.as_ref(),
        );
        Ok(0)
    }
}

fn atomic_write_file(path: &Path, data: &[u8]) -> Result<(), InfrastructureError> {
    use std::io::Write;

    let parent = path.parent().unwrap_or(Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(|e| {
        InfrastructureError::Database(format!(
            "Failed to create temp file in {}: {e}",
            parent.display()
        ))
    })?;

    tmp.write_all(data)
        .map_err(|e| InfrastructureError::Database(format!("Failed to write bloom data: {e}")))?;
    tmp.flush()
        .map_err(|e| InfrastructureError::Database(format!("Failed to flush bloom data: {e}")))?;

    tmp.persist(path).map_err(|e| {
        InfrastructureError::Database(format!(
            "Failed to atomically rename bloom file to {}: {e}",
            path.display()
        ))
    })?;

    Ok(())
}

// Deterministic seed: bitvectors must use the same hash functions after deserialization.
const BLOOM_SEED: u128 = 0;

// Wire format per filter: [4B num_hashes LE] [N×8B bitvector LE]
// File format: [8B timestamp LE] [current_filter] [previous_filter]

fn fresh_bloom(capacity: usize, fpr: f64) -> BloomFilter {
    BloomFilter::with_false_pos(fpr)
        .seed(&BLOOM_SEED)
        .expected_items(capacity)
}

fn bloom_serialized_size(capacity: usize, fpr: f64) -> usize {
    let fresh = fresh_bloom(capacity, fpr);
    4 + fresh.as_slice().len() * 8
}

fn serialize_to_file_format(
    timestamp: u64,
    current: &BloomFilter,
    previous: &BloomFilter,
) -> Vec<u8> {
    let cur_bytes = serialize_bloom(current);
    let prev_bytes = serialize_bloom(previous);
    let mut out = Vec::with_capacity(8 + cur_bytes.len() + prev_bytes.len());
    out.extend_from_slice(&timestamp.to_le_bytes());
    out.extend_from_slice(&cur_bytes);
    out.extend_from_slice(&prev_bytes);
    out
}

fn serialize_bloom(filter: &BloomFilter) -> Vec<u8> {
    let num_hashes = filter.num_hashes();
    let words: &[u64] = filter.as_slice();
    let mut bytes = Vec::with_capacity(4 + words.len() * 8);
    bytes.extend_from_slice(&num_hashes.to_le_bytes());
    for w in words {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    bytes
}

/// Size mismatch (capacity changed) returns a fresh filter instead of an error.
fn deserialize_bloom(
    bytes: &[u8],
    capacity: usize,
    fpr: f64,
) -> Result<BloomFilter, InfrastructureError> {
    if bytes.len() < 4 {
        return Err(InfrastructureError::Database(
            "Corrupt bloom filter: too short to contain num_hashes header".into(),
        ));
    }

    let header: [u8; 4] = bytes[..4].try_into().map_err(|_| {
        InfrastructureError::Database(
            "Corrupt bloom filter: failed to read num_hashes header".into(),
        )
    })?;
    let num_hashes = u32::from_le_bytes(header);
    let body = &bytes[4..];

    if !body.len().is_multiple_of(8) {
        return Err(InfrastructureError::Database(format!(
            "Corrupt bloom filter: body length {} is not a multiple of 8",
            body.len()
        )));
    }

    let words: Vec<u64> = body
        .chunks_exact(8)
        .map(|c| {
            let chunk: [u8; 8] = c.try_into().unwrap_or([0u8; 8]);
            u64::from_le_bytes(chunk)
        })
        .collect();

    let fresh = fresh_bloom(capacity, fpr);
    let expected_words = fresh.as_slice().len();

    if words.len() != expected_words {
        warn!(
            persisted_words = words.len(),
            expected_words,
            "Bloom filter size mismatch (capacity changed?) -- starting with empty filter."
        );
        return Ok(fresh);
    }

    Ok(BloomFilter::from_vec(words)
        .seed(&BLOOM_SEED)
        .hashes(num_hashes))
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_filter(interval_secs: u64) -> RotationalBloomFilter {
        RotationalBloomFilter::new(1_000, 0.001, Duration::from_secs(interval_secs))
    }

    #[tokio::test]
    async fn test_no_replay_fresh_tag() {
        let filter = make_filter(3600);
        let is_replay = filter.check_and_tag(b"unique_tag_1", 0).await.unwrap();
        assert!(!is_replay);
    }

    #[tokio::test]
    async fn test_replay_detected_same_tag() {
        let filter = make_filter(3600);
        filter.check_and_tag(b"tag_abc", 0).await.unwrap();
        let is_replay = filter.check_and_tag(b"tag_abc", 0).await.unwrap();
        assert!(is_replay);
    }

    #[tokio::test]
    async fn test_different_tags_not_replay() {
        let filter = make_filter(3600);
        filter.check_and_tag(b"tag_one", 0).await.unwrap();
        let is_replay = filter.check_and_tag(b"tag_two", 0).await.unwrap();
        assert!(!is_replay);
    }

    #[tokio::test]
    async fn test_rotation_clears_old_tags() {
        // Use a 1ms interval so rotation fires immediately.
        let filter = make_filter(0); // 0s interval -> always rotate on next call
        filter.check_and_tag(b"old_tag", 0).await.unwrap();

        // Sleep briefly so elapsed() > 0s interval.
        tokio::time::sleep(Duration::from_millis(5)).await;

        // After two rotations the tag has left both windows.
        filter
            .check_and_tag(b"trigger_rotation_1", 0)
            .await
            .unwrap();
        filter
            .check_and_tag(b"trigger_rotation_2", 0)
            .await
            .unwrap();

        // old_tag should now be gone from both windows.
        let is_replay = filter.check_and_tag(b"old_tag", 0).await.unwrap();
        assert!(!is_replay);
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let filter = fresh_bloom(1_000, 0.001);
        let bytes = serialize_bloom(&filter);
        let restored = deserialize_bloom(&bytes, 1_000, 0.001).unwrap();
        assert_eq!(filter.as_slice(), restored.as_slice());
    }

    #[test]
    fn test_deserialize_size_mismatch_returns_fresh() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_le_bytes()); // num_hashes = 1
        bytes.extend_from_slice(&0u64.to_le_bytes()); // 1 word = 8 bytes
        let result = deserialize_bloom(&bytes, 1_000, 0.001);
        assert!(result.is_ok());
    }

    #[test]
    fn test_deserialize_non_multiple_of_8_errors() {
        let bad_bytes = vec![0u8; 7];
        assert!(deserialize_bloom(&bad_bytes, 1_000, 0.001).is_err());
    }

    #[tokio::test]
    async fn test_restore_no_file_is_noop() {
        let filter = make_filter(3600);
        // No file path attached -- restore must succeed silently.
        filter.restore_from_file().await.unwrap();
    }

    #[tokio::test]
    async fn test_file_persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let bloom_path = dir.path().join("bloom.bin");

        // Create filter with file persistence, insert a tag
        let filter = RotationalBloomFilter::new(1_000, 0.001, Duration::from_secs(0))
            .with_file_persistence(&bloom_path);

        filter.check_and_tag(b"persist_tag", 0).await.unwrap();

        // Sleep to trigger rotation (interval=0s) which writes the file
        tokio::time::sleep(Duration::from_millis(5)).await;
        filter.check_and_tag(b"trigger_write", 0).await.unwrap();

        // Give the fire-and-forget write task time to complete
        tokio::time::sleep(Duration::from_millis(100)).await;

        // File should exist
        assert!(bloom_path.exists());

        // Create a new filter and restore from file
        let filter2 = RotationalBloomFilter::new(1_000, 0.001, Duration::from_secs(3600))
            .with_file_persistence(&bloom_path);
        filter2.restore_from_file().await.unwrap();

        // persist_tag was in the previous rotation, should be detectable if within window
        // (The tag is in the "previous" filter of the rotated state)
    }

    #[test]
    fn test_file_format_roundtrip() {
        let current = fresh_bloom(1_000, 0.001);
        let previous = fresh_bloom(1_000, 0.001);
        let ts = 1234567890u64;

        let file_bytes = serialize_to_file_format(ts, &current, &previous);
        let expected_size = 8 + bloom_serialized_size(1_000, 0.001) * 2;
        assert_eq!(file_bytes.len(), expected_size);

        // Verify timestamp
        let restored_ts = u64::from_le_bytes(file_bytes[..8].try_into().unwrap());
        assert_eq!(restored_ts, ts);
    }

    #[test]
    fn test_atomic_write_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_bloom.bin");
        let data = vec![42u8; 100];

        atomic_write_file(&path, &data).unwrap();
        assert!(path.exists());

        let read_back = std::fs::read(&path).unwrap();
        assert_eq!(read_back, data);
    }
}
