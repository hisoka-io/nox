use async_trait::async_trait;
use fastbloom::BloomFilter;
use nox_core::traits::{IReplayProtection, InfrastructureError};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

struct BloomFilterState {
    current: BloomFilter,
    previous: BloomFilter,
    last_rotation: Instant,
    last_rotation_unix: u64,
}

/// Serializes snapshot writes and remembers the newest snapshot on disk, so an
/// older snapshot that finishes late never overwrites a newer one.
struct PersistState {
    next_seq: AtomicU64,
    written_seq: Mutex<u64>,
    dirty: AtomicBool,
}

/// Dual-window bloom filter for replay protection with flat-file persistence.
///
/// Rotates `current` -> `previous` on each interval; checks both for membership.
/// Flat file avoids sled's blob leak. Downtime > 2x interval resets to empty.
///
/// The file is written on every rotation, by [`Self::run_persistence`] on a
/// fixed interval while tags change, and once more on graceful shutdown.
pub struct RotationalBloomFilter {
    state: Arc<RwLock<BloomFilterState>>,
    rotation_interval: Duration,
    capacity: usize,
    false_positive_rate: f64,
    persist_path: Option<PathBuf>,
    persist: Arc<PersistState>,
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
            persist: Arc::new(PersistState {
                next_seq: AtomicU64::new(0),
                written_seq: Mutex::new(0),
                dirty: AtomicBool::new(false),
            }),
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

    /// Writes the current filter state to disk now, if persistence is enabled.
    /// Returns `Ok(true)` when a snapshot was written.
    pub async fn persist_now(&self) -> Result<bool, InfrastructureError> {
        let Some(path) = self.persist_path.clone() else {
            return Ok(false);
        };
        let (seq, bytes) = {
            let state = self.state.read().await;
            self.persist.dirty.store(false, Ordering::Release);
            (self.next_snapshot_seq(), Self::snapshot(&state))
        };
        let result = write_snapshot(Arc::clone(&self.persist), path, seq, bytes).await;
        if result.is_err() {
            self.persist.dirty.store(true, Ordering::Release);
        }
        result
    }

    /// Writes a snapshot only if a tag was recorded since the last one.
    pub async fn persist_if_dirty(&self) -> Result<bool, InfrastructureError> {
        if !self.persist.dirty.load(Ordering::Acquire) {
            return Ok(false);
        }
        self.persist_now().await
    }

    /// Persists the filter every `interval` while it changes, and once more when
    /// `cancel` fires, so a restart does not forget recently seen tags.
    /// A zero `interval` keeps only the shutdown and rotation writes.
    pub async fn run_persistence(self: Arc<Self>, interval: Duration, cancel: CancellationToken) {
        if self.persist_path.is_none() {
            return;
        }
        if interval.is_zero() {
            cancel.cancelled().await;
        } else {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        match self.persist_if_dirty().await {
                            Ok(true) => debug!("Replay filter snapshot written"),
                            Ok(false) => {}
                            Err(e) => warn!("Replay filter periodic persist failed: {e}"),
                        }
                    }
                    () = cancel.cancelled() => break,
                }
            }
        }
        match self.persist_now().await {
            Ok(_) => info!("Replay filter persisted for shutdown"),
            Err(e) => warn!("Replay filter shutdown persist failed: {e}"),
        }
    }

    fn next_snapshot_seq(&self) -> u64 {
        self.persist.next_seq.fetch_add(1, Ordering::AcqRel) + 1
    }

    fn snapshot(state: &BloomFilterState) -> Vec<u8> {
        serialize_to_file_format(state.last_rotation_unix, &state.current, &state.previous)
    }

    fn rotate_if_needed(&self, state: &mut BloomFilterState) {
        if state.last_rotation.elapsed() < self.rotation_interval {
            return;
        }

        let old_current = std::mem::replace(
            &mut state.current,
            fresh_bloom(self.capacity, self.false_positive_rate),
        );
        state.previous = old_current;
        state.last_rotation = Instant::now();
        state.last_rotation_unix = unix_now_secs();

        if let Some(path) = self.persist_path.clone() {
            let file_bytes = Self::snapshot(state);
            let seq = self.next_snapshot_seq();
            let persist = Arc::clone(&self.persist);

            tokio::spawn(async move {
                if let Err(e) = write_snapshot(Arc::clone(&persist), path, seq, file_bytes).await {
                    persist.dirty.store(true, Ordering::Release);
                    warn!("Replay filter persist failed: {e}");
                }
            });
        }
    }
}

/// Writes `bytes` unless a newer snapshot (higher `seq`) is already on disk.
async fn write_snapshot(
    persist: Arc<PersistState>,
    path: PathBuf,
    seq: u64,
    bytes: Vec<u8>,
) -> Result<bool, InfrastructureError> {
    let mut written = persist.written_seq.lock().await;
    if seq <= *written {
        return Ok(false);
    }
    tokio::task::spawn_blocking(move || atomic_write_file(&path, &bytes))
        .await
        .map_err(|e| InfrastructureError::Database(format!("spawn_blocking join error: {e}")))??;
    *written = seq;
    Ok(true)
}

#[async_trait]
impl IReplayProtection for RotationalBloomFilter {
    async fn check_and_tag(
        &self,
        tag: &[u8],
        _ttl_seconds: u64, // Ignored -- handled by rotation window.
    ) -> Result<bool, InfrastructureError> {
        let mut state = self.state.write().await;
        self.rotate_if_needed(&mut state);

        if state.current.contains(tag) || state.previous.contains(tag) {
            return Ok(true);
        }

        state.current.insert(tag);
        self.persist.dirty.store(true, Ordering::Release);
        Ok(false)
    }

    async fn prune_expired(&self) -> Result<usize, InfrastructureError> {
        let mut state = self.state.write().await;
        self.rotate_if_needed(&mut state);
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
        let filter2 = RotationalBloomFilter::new(1_000, 0.001, Duration::from_hours(1))
            .with_file_persistence(&bloom_path);
        filter2.restore_from_file().await.unwrap();

        // persist_tag was in the previous rotation, should be detectable if within window
        // (The tag is in the "previous" filter of the rotated state)
    }

    fn persistent_filter(path: &Path) -> RotationalBloomFilter {
        RotationalBloomFilter::new(1_000, 0.001, Duration::from_hours(1))
            .with_file_persistence(path)
    }

    async fn restored_sees(path: &Path, tag: &[u8]) -> bool {
        let restored = persistent_filter(path);
        restored.restore_from_file().await.unwrap();
        restored.check_and_tag(tag, 0).await.unwrap()
    }

    #[tokio::test]
    async fn test_persist_now_survives_restart_without_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bloom.bin");
        let filter = persistent_filter(&path);
        filter
            .check_and_tag(b"seen_before_restart", 0)
            .await
            .unwrap();

        assert!(filter.persist_now().await.unwrap());
        assert!(restored_sees(&path, b"seen_before_restart").await);
        assert!(!restored_sees(&path, b"never_seen").await);
    }

    #[tokio::test]
    async fn test_persist_if_dirty_skips_unchanged_filter() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bloom.bin");
        let filter = persistent_filter(&path);

        assert!(!filter.persist_if_dirty().await.unwrap());
        assert!(!path.exists());

        filter.check_and_tag(b"tag", 0).await.unwrap();
        assert!(filter.persist_if_dirty().await.unwrap());
        assert!(!filter.persist_if_dirty().await.unwrap());

        // A replayed tag does not change the filter.
        filter.check_and_tag(b"tag", 0).await.unwrap();
        assert!(!filter.persist_if_dirty().await.unwrap());
    }

    #[tokio::test]
    async fn test_run_persistence_writes_on_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bloom.bin");
        let filter = Arc::new(persistent_filter(&path));
        let cancel = CancellationToken::new();
        let task = tokio::spawn(
            Arc::clone(&filter).run_persistence(Duration::from_hours(1), cancel.clone()),
        );

        filter.check_and_tag(b"tag_at_shutdown", 0).await.unwrap();
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();

        assert!(restored_sees(&path, b"tag_at_shutdown").await);
    }

    #[tokio::test]
    async fn test_run_persistence_writes_periodically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bloom.bin");
        let filter = Arc::new(persistent_filter(&path));
        let cancel = CancellationToken::new();
        let task = tokio::spawn(
            Arc::clone(&filter).run_persistence(Duration::from_millis(20), cancel.clone()),
        );

        filter.check_and_tag(b"periodic_tag", 0).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !path.exists() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(restored_sees(&path, b"periodic_tag").await);

        cancel.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn test_older_snapshot_never_overwrites_newer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bloom.bin");
        let persist = Arc::new(PersistState {
            next_seq: AtomicU64::new(0),
            written_seq: Mutex::new(0),
            dirty: AtomicBool::new(false),
        });

        assert!(
            write_snapshot(Arc::clone(&persist), path.clone(), 2, vec![2])
                .await
                .unwrap()
        );
        assert!(
            !write_snapshot(Arc::clone(&persist), path.clone(), 1, vec![1])
                .await
                .unwrap()
        );
        assert_eq!(std::fs::read(&path).unwrap(), vec![2]);
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
