use async_trait::async_trait;
use sled::Db;
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::warn;

use nox_core::traits::{IReplayProtection, IStorageRepository, InfrastructureError};

/// Retry once on transient sled IO errors (100ms backoff). Non-IO errors are not retried.
fn with_retry<T, F: Fn() -> Result<T, sled::Error>>(
    op_name: &str,
    f: F,
) -> Result<T, InfrastructureError> {
    match f() {
        Ok(val) => Ok(val),
        Err(first_err) => {
            if matches!(first_err, sled::Error::Io(_)) {
                warn!("Sled {op_name}: transient IO error, retrying in 100ms: {first_err}");
                std::thread::sleep(Duration::from_millis(100));
                f().map_err(|e| InfrastructureError::Database(e.to_string()))
            } else {
                Err(InfrastructureError::Database(first_err.to_string()))
            }
        }
    }
}

#[derive(Clone)]
pub struct SledRepository {
    db: Db,
}

impl SledRepository {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, InfrastructureError> {
        let db = sled::open(path).map_err(|e| InfrastructureError::Database(e.to_string()))?;
        Ok(Self { db })
    }

    /// Flush and scan to trigger GC on old log segments. Call periodically.
    pub async fn compact(&self) -> Result<(), InfrastructureError> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            db.flush().map_err(|e| {
                InfrastructureError::Database(format!("Sled flush before compact failed: {e}"))
            })?;
            // sled 0.34 doesn't have an explicit compact() method on Db.
            // The best we can do is flush + iterate to trigger GC on old segments.
            // Force GC by scanning all entries (triggers internal page cache eviction).
            let count = db.len();
            tracing::debug!(entries = count, "Sled compaction: scanned all entries");
            Ok(())
        })
        .await
        .map_err(|e| InfrastructureError::Database(format!("spawn_blocking join error: {e}")))?
    }
}

#[async_trait]
impl IStorageRepository for SledRepository {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, InfrastructureError> {
        let db = self.db.clone();
        let key = key.to_vec();
        tokio::task::spawn_blocking(move || {
            with_retry("get", || {
                db.get(&key).map(|opt| opt.map(|ivec| ivec.to_vec()))
            })
        })
        .await
        .map_err(|e| InfrastructureError::Database(format!("spawn_blocking join error: {e}")))?
    }

    async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), InfrastructureError> {
        let db = self.db.clone();
        let key = key.to_vec();
        let value = value.to_vec();
        tokio::task::spawn_blocking(move || {
            with_retry("put", || db.insert(&key, value.as_slice()).map(|_| ()))
        })
        .await
        .map_err(|e| InfrastructureError::Database(format!("spawn_blocking join error: {e}")))?
    }

    async fn exists(&self, key: &[u8]) -> Result<bool, InfrastructureError> {
        let db = self.db.clone();
        let key = key.to_vec();
        tokio::task::spawn_blocking(move || with_retry("exists", || db.contains_key(&key)))
            .await
            .map_err(|e| InfrastructureError::Database(format!("spawn_blocking join error: {e}")))?
    }

    async fn delete(&self, key: &[u8]) -> Result<(), InfrastructureError> {
        let db = self.db.clone();
        let key = key.to_vec();
        tokio::task::spawn_blocking(move || with_retry("delete", || db.remove(&key).map(|_| ())))
            .await
            .map_err(|e| InfrastructureError::Database(format!("spawn_blocking join error: {e}")))?
    }

    async fn scan(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, InfrastructureError> {
        let db = self.db.clone();
        let prefix = prefix.to_vec();
        tokio::task::spawn_blocking(move || {
            let mut results = Vec::new();
            for item in db.scan_prefix(&prefix) {
                let (k, v) = item.map_err(|e| InfrastructureError::Database(e.to_string()))?;
                results.push((k.to_vec(), v.to_vec()));
            }
            Ok(results)
        })
        .await
        .map_err(|e| InfrastructureError::Database(format!("spawn_blocking join error: {e}")))?
    }
}

#[async_trait]
impl IReplayProtection for SledRepository {
    async fn check_and_tag(
        &self,
        tag: &[u8],
        ttl_seconds: u64,
    ) -> Result<bool, InfrastructureError> {
        // Expiry stored in milliseconds to avoid rounding issues
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;
        let expiry = now + (ttl_seconds * 1000);
        let expiry_bytes = expiry.to_be_bytes();

        if let Some(existing) = self
            .db
            .get(tag)
            .map_err(|e| InfrastructureError::Database(e.to_string()))?
        {
            if existing.len() == 8 {
                let existing_expiry =
                    u64::from_be_bytes(existing.as_ref().try_into().map_err(|_| {
                        InfrastructureError::Database("Invalid expiry bytes".into())
                    })?);
                if existing_expiry < now {
                    // Expired, fall through to overwrite
                } else {
                    return Ok(true);
                }
            } else {
                return Ok(true);
            }
        }

        self.db
            .insert(tag, &expiry_bytes)
            .map_err(|e| InfrastructureError::Database(e.to_string()))?;

        Ok(false)
    }

    async fn prune_expired(&self) -> Result<usize, InfrastructureError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;
        let mut count = 0;

        for item in self.db.iter() {
            let (key, value) = item.map_err(|e| InfrastructureError::Database(e.to_string()))?;

            if value.len() == 8 {
                if let Ok(bytes) = value.as_ref().try_into() {
                    let expiry = u64::from_be_bytes(bytes);
                    if expiry < now {
                        self.db
                            .remove(key)
                            .map_err(|e| InfrastructureError::Database(e.to_string()))?;
                        count += 1;
                    }
                }
            }
        }

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_storage_lifecycle() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test_db");
        let repo = SledRepository::new(&db_path).unwrap();

        let key = b"test_key";
        let val = b"test_value";

        repo.put(key, val).await.unwrap();
        assert!(repo.exists(key).await.unwrap());

        let retrieved = repo.get(key).await.unwrap();
        assert_eq!(retrieved, Some(val.to_vec()));

        let missing = repo.get(b"missing").await.unwrap();
        assert_eq!(missing, None);
    }

    #[tokio::test]
    async fn test_replay_protection() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("replay_db");
        let repo = SledRepository::new(&db_path).unwrap();

        let tag = b"packet_hash_123";

        let is_replay = repo.check_and_tag(tag, 2).await.unwrap();
        assert!(!is_replay);

        let is_replay_2 = repo.check_and_tag(tag, 2).await.unwrap();
        assert!(is_replay_2);

        sleep(Duration::from_secs(3)).await;

        let is_replay_3 = repo.check_and_tag(tag, 2).await.unwrap();
        assert!(!is_replay_3);
    }

    #[tokio::test]
    async fn test_crud_lifecycle() {
        let dir = tempdir().unwrap();
        let repo = SledRepository::new(dir.path()).unwrap();

        repo.put(b"key1", b"val1").await.unwrap();
        assert!(repo.exists(b"key1").await.unwrap());

        let val = repo.get(b"key1").await.unwrap();
        assert_eq!(val, Some(b"val1".to_vec()));

        repo.delete(b"key1").await.unwrap();
        assert!(!repo.exists(b"key1").await.unwrap());
        assert_eq!(repo.get(b"key1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_prefix_scan() {
        let dir = tempdir().unwrap();
        let repo = SledRepository::new(dir.path()).unwrap();

        repo.put(b"peer:A", b"infoA").await.unwrap();
        repo.put(b"peer:B", b"infoB").await.unwrap();
        repo.put(b"other:C", b"infoC").await.unwrap();

        let peers = repo.scan(b"peer:").await.unwrap();
        assert_eq!(peers.len(), 2);

        assert_eq!(peers[0].0, b"peer:A");
        assert_eq!(peers[1].0, b"peer:B");
    }

    #[tokio::test]
    async fn test_pruning() {
        let dir = tempdir().unwrap();
        let repo = SledRepository::new(dir.path()).unwrap();

        repo.check_and_tag(b"old", 0).await.unwrap();

        // Wait to guarantee 'now' > 'expiry'
        sleep(Duration::from_millis(2000)).await;

        repo.check_and_tag(b"fresh", 100).await.unwrap();

        let pruned = repo.prune_expired().await.unwrap();
        assert_eq!(pruned, 1, "Should prune exactly one expired item");

        assert!(!repo.exists(b"old").await.unwrap());
        assert!(repo.exists(b"fresh").await.unwrap());
    }

    #[test]
    fn test_with_retry_succeeds_on_first_try() {
        let result = with_retry("test", || Ok::<_, sled::Error>(42));
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_with_retry_fails_on_non_io_error() {
        let result: Result<(), _> = with_retry("test", || {
            Err(sled::Error::CollectionNotFound(sled::IVec::from(
                b"missing" as &[u8],
            )))
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_with_retry_retries_io_error() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let call_count = AtomicU32::new(0);

        let result = with_retry("test", || {
            let count = call_count.fetch_add(1, Ordering::Relaxed);
            if count == 0 {
                Err(sled::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "transient disk error",
                )))
            } else {
                Ok(99)
            }
        });
        assert_eq!(result.unwrap(), 99);
        assert_eq!(call_count.load(Ordering::Relaxed), 2);
    }
}
