//! Offline compaction of the node database.
//!
//! sled 0.34 never reclaims some blob files: a blob that was pending deletion
//! when the process stopped is forgotten, and nothing removes it later (nox-7
//! kept ~390 MB of them). Which blobs are still referenced is internal to
//! sled, so they cannot be told apart from outside. The safe way to drop them
//! is to copy every live record into a fresh database and swap it in.
//!
//! Steps, all inside `db_path` so every rename stays on one filesystem (a
//! Docker volume mount point cannot itself be renamed):
//!
//! 1. Open the database. sled holds an exclusive lock, so this fails while a
//!    node is running on it.
//! 2. Copy every tree into `compact-staging-<unix>/new` and flush.
//! 3. Compare a digest of every tree name, key and value in both.
//! 4. Write [`COMPACTION_MARKER`] (still holding the lock). While it exists
//!    [`SledRepository::new`](crate::infra::storage::SledRepository::new)
//!    refuses to open the directory, so a node started mid-swap cannot create
//!    an empty database in place of the real one.
//! 5. Move the old sled files (`conf`, `db`, `snap.*`, `blobs/`) into
//!    `compact-staging-<unix>/old`, then move the new ones into `db_path`.
//!    The marker records which of the two moves is under way.
//! 6. Reopen `db_path`, check its digest against the marker, remove the marker.
//!
//! Files that are not sled's (for example `bloom.bin`) are never moved. A run
//! interrupted after step 4 is finished by running the command again.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ethers::utils::keccak256;
use nox_core::traits::InfrastructureError;
use serde::{Deserialize, Serialize};

/// Present in `db_path` while a compaction swap is under way.
pub const COMPACTION_MARKER: &str = "NOX_COMPACTION_IN_PROGRESS";

/// Directory name prefix for staging and backup copies inside `db_path`.
pub const STAGING_PREFIX: &str = "compact-staging-";

/// Records copied per sled batch.
const COPY_BATCH_RECORDS: usize = 512;

/// Longest wait for sled's background work to release the database lock.
const SLED_RELEASE_TIMEOUT: Duration = Duration::from_secs(30);

/// Poll interval while waiting for the lock.
const SLED_RELEASE_POLL: Duration = Duration::from_millis(20);

#[derive(Debug, thiserror::Error)]
pub enum CompactionError {
    #[error("no sled database found in {0}")]
    Missing(PathBuf),
    #[error(
        "cannot open the database at {path}; stop the node that uses it before compacting ({detail})"
    )]
    Open { path: PathBuf, detail: String },
    #[error("{context} at {path}: {source}")]
    Io {
        context: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("sled {context}: {detail}")]
    Sled { context: String, detail: String },
    #[error("compacted copy does not match the original: {detail}")]
    Verification { detail: String },
    #[error("compaction marker {path} is unreadable: {detail}")]
    Marker { path: PathBuf, detail: String },
}

fn io_error(context: &'static str, path: &Path, source: std::io::Error) -> CompactionError {
    CompactionError::Io {
        context,
        path: path.to_path_buf(),
        source,
    }
}

fn sled_error(context: impl Into<String>, error: impl std::fmt::Display) -> CompactionError {
    CompactionError::Sled {
        context: context.into(),
        detail: error.to_string(),
    }
}

/// Content fingerprint of a whole sled database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseDigest {
    /// Tree name to record count.
    pub trees: BTreeMap<Vec<u8>, u64>,
    /// Chained Keccak-256 over every framed tree name, key and value.
    pub digest: [u8; 32],
}

impl DatabaseDigest {
    #[must_use]
    pub fn records(&self) -> u64 {
        self.trees.values().copied().sum()
    }
}

/// Order-dependent digest: `state = keccak256(state || len || bytes)` per item.
struct ChainedDigest {
    state: [u8; 32],
    buffer: Vec<u8>,
}

impl ChainedDigest {
    fn new() -> Self {
        Self {
            state: [0; 32],
            buffer: Vec::new(),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.buffer.clear();
        self.buffer.extend_from_slice(&self.state);
        self.buffer
            .extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        self.buffer.extend_from_slice(bytes);
        self.state = keccak256(&self.buffer);
    }

    fn finalize(self) -> [u8; 32] {
        self.state
    }
}

/// Hashes every tree name, key and value in a fixed order.
pub fn database_digest(db: &sled::Db) -> Result<DatabaseDigest, CompactionError> {
    let mut names = db.tree_names();
    names.sort();
    let mut hasher = ChainedDigest::new();
    let mut trees = BTreeMap::new();
    for name in names {
        let tree = db
            .open_tree(&name)
            .map_err(|error| sled_error("open tree for digest", error))?;
        hasher.update(&name);
        let mut records = 0_u64;
        for item in &tree {
            let (key, value) = item.map_err(|error| sled_error("digest scan", error))?;
            hasher.update(&key);
            hasher.update(&value);
            records = records.saturating_add(1);
        }
        hasher.update(&records.to_le_bytes());
        trees.insert(name.to_vec(), records);
    }
    Ok(DatabaseDigest {
        trees,
        digest: hasher.finalize(),
    })
}

fn copy_database(source: &sled::Db, target: &sled::Db) -> Result<(), CompactionError> {
    for name in source.tree_names() {
        let from = source
            .open_tree(&name)
            .map_err(|error| sled_error("open source tree", error))?;
        let to = target
            .open_tree(&name)
            .map_err(|error| sled_error("open target tree", error))?;
        let mut batch = sled::Batch::default();
        let mut pending = 0_usize;
        for item in &from {
            let (key, value) = item.map_err(|error| sled_error("copy scan", error))?;
            batch.insert(key, value);
            pending += 1;
            if pending == COPY_BATCH_RECORDS {
                to.apply_batch(std::mem::take(&mut batch))
                    .map_err(|error| sled_error("copy batch", error))?;
                pending = 0;
            }
        }
        if pending > 0 {
            to.apply_batch(batch)
                .map_err(|error| sled_error("copy batch", error))?;
        }
    }
    target
        .flush()
        .map_err(|error| sled_error("flush compacted copy", error))?;
    Ok(())
}

/// True for the files and directories sled 0.34 owns in its directory.
fn is_sled_entry(name: &str) -> bool {
    matches!(name, "conf" | "db" | "blobs") || name.starts_with("snap.")
}

fn sled_entries(dir: &Path) -> Result<Vec<String>, CompactionError> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir).map_err(|error| io_error("list directory", dir, error))? {
        let entry = entry.map_err(|error| io_error("list directory", dir, error))?;
        if let Some(name) = entry.file_name().to_str() {
            if is_sled_entry(name) {
                names.push(name.to_string());
            }
        }
    }
    names.sort();
    Ok(names)
}

fn path_size(path: &Path) -> Result<u64, CompactionError> {
    let metadata = fs::metadata(path).map_err(|error| io_error("stat", path, error))?;
    if !metadata.is_dir() {
        return Ok(metadata.len());
    }
    let mut total = 0_u64;
    for entry in fs::read_dir(path).map_err(|error| io_error("list directory", path, error))? {
        let entry = entry.map_err(|error| io_error("list directory", path, error))?;
        total = total.saturating_add(path_size(&entry.path())?);
    }
    Ok(total)
}

/// Bytes taken by sled's own files in `dir`.
pub fn sled_files_size(dir: &Path) -> Result<u64, CompactionError> {
    let mut total = 0_u64;
    for name in sled_entries(dir)? {
        total = total.saturating_add(path_size(&dir.join(name))?);
    }
    Ok(total)
}

fn sync_dir(dir: &Path) -> Result<(), CompactionError> {
    fs::File::open(dir)
        .and_then(|handle| handle.sync_all())
        .map_err(|error| io_error("sync directory", dir, error))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SwapPhase {
    MoveOld,
    MoveNew,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    version: u8,
    staging: String,
    phase: SwapPhase,
    digest: String,
    records: u64,
}

fn write_marker(db_path: &Path, marker: &Marker) -> Result<(), CompactionError> {
    let path = db_path.join(COMPACTION_MARKER);
    let temporary = db_path.join(format!("{COMPACTION_MARKER}.tmp"));
    let encoded = serde_json::to_vec_pretty(marker).map_err(|error| CompactionError::Marker {
        path: path.clone(),
        detail: error.to_string(),
    })?;
    let mut file = fs::File::create(&temporary)
        .map_err(|error| io_error("create marker", &temporary, error))?;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|error| io_error("write marker", &temporary, error))?;
    fs::rename(&temporary, &path).map_err(|error| io_error("install marker", &path, error))?;
    sync_dir(db_path)
}

fn read_marker(db_path: &Path) -> Result<Option<Marker>, CompactionError> {
    let path = db_path.join(COMPACTION_MARKER);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error("read marker", &path, error)),
    };
    let marker: Marker =
        serde_json::from_slice(&bytes).map_err(|error| CompactionError::Marker {
            path: path.clone(),
            detail: error.to_string(),
        })?;
    if marker.version != 1
        || !marker.staging.starts_with(STAGING_PREFIX)
        || marker.staging.contains(['/', '\\'])
    {
        return Err(CompactionError::Marker {
            path,
            detail: format!(
                "unsupported marker (version {}, staging {:?})",
                marker.version, marker.staging
            ),
        });
    }
    Ok(Some(marker))
}

/// Refuses to open a database whose compaction swap was interrupted.
pub fn ensure_no_interrupted_compaction(db_path: &Path) -> Result<(), InfrastructureError> {
    if db_path.join(COMPACTION_MARKER).exists() {
        return Err(InfrastructureError::Database(format!(
            "database at {} has an unfinished compaction ({} present); run `nox db compact` \
             with the same db_path to finish it before starting the node",
            db_path.display(),
            COMPACTION_MARKER
        )));
    }
    Ok(())
}

/// Options for [`compact_database`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CompactionOptions {
    /// Keep the old sled files under `compact-staging-<unix>/old`.
    pub keep_backup: bool,
}

/// What [`compact_database`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionReport {
    pub bytes_before: u64,
    pub bytes_after: u64,
    pub records: u64,
    pub trees: usize,
    /// Where the old files were kept, when they were.
    pub backup: Option<PathBuf>,
    /// An interrupted swap was finished instead of starting a new copy.
    pub resumed: bool,
}

/// Waits until no sled instance holds the lock on `dir/db`.
///
/// Dropping a `sled::Db` does not stop its background work: log writes and
/// snapshots run on sled's thread pool and can create `snap.*` files after
/// the handle is gone. Each of those tasks holds sled's lock file open, so
/// the lock is free only once all of them finished. Moving files before that
/// could leave a snapshot of the old database next to the new one.
pub(crate) fn wait_for_sled_release(dir: &Path, timeout: Duration) -> Result<(), CompactionError> {
    let lock_path = dir.join("db");
    let file = match fs::File::open(&lock_path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_error("open sled lock file", &lock_path, error)),
    };
    let deadline = Instant::now() + timeout;
    loop {
        match file.try_lock() {
            Ok(()) => {
                file.unlock()
                    .map_err(|error| io_error("release sled lock", &lock_path, error))?;
                return Ok(());
            }
            Err(fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(SLED_RELEASE_POLL);
            }
            Err(fs::TryLockError::WouldBlock) => {
                return Err(CompactionError::Open {
                    path: dir.to_path_buf(),
                    detail: format!("the sled lock is still held after {}s", timeout.as_secs()),
                });
            }
            Err(fs::TryLockError::Error(error)) => {
                return Err(io_error("lock sled database", &lock_path, error));
            }
        }
    }
}

fn open(path: &Path) -> Result<sled::Db, CompactionError> {
    sled::open(path).map_err(|error| CompactionError::Open {
        path: path.to_path_buf(),
        detail: error.to_string(),
    })
}

fn move_entries(from: &Path, to: &Path, names: &[String]) -> Result<(), CompactionError> {
    for name in names {
        let source = from.join(name);
        let target = to.join(name);
        if target.exists() {
            return Err(io_error(
                "move would overwrite",
                &target,
                std::io::Error::new(std::io::ErrorKind::AlreadyExists, "target exists"),
            ));
        }
        fs::rename(&source, &target).map_err(|error| io_error("move", &source, error))?;
    }
    sync_dir(from)?;
    sync_dir(to)
}

/// Finishes the swap described by `marker`, verifies the result and removes
/// the marker. Returns where the old files are.
fn finish_swap(
    db_path: &Path,
    mut marker: Marker,
    options: CompactionOptions,
) -> Result<(u64, Option<PathBuf>), CompactionError> {
    let staging = db_path.join(&marker.staging);
    let new_dir = staging.join("new");
    let old_dir = staging.join("old");
    if marker.phase == SwapPhase::MoveOld {
        wait_for_sled_release(db_path, SLED_RELEASE_TIMEOUT)?;
        fs::create_dir_all(&old_dir).map_err(|error| io_error("create backup", &old_dir, error))?;
        move_entries(db_path, &old_dir, &sled_entries(db_path)?)?;
        marker.phase = SwapPhase::MoveNew;
        write_marker(db_path, &marker)?;
    }
    wait_for_sled_release(&new_dir, SLED_RELEASE_TIMEOUT)?;
    move_entries(&new_dir, db_path, &sled_entries(&new_dir)?)?;

    let swapped = open(db_path)?;
    let digest = database_digest(&swapped)?;
    drop(swapped);
    wait_for_sled_release(db_path, SLED_RELEASE_TIMEOUT)?;
    if hex::encode(digest.digest) != marker.digest || digest.records() != marker.records {
        return Err(CompactionError::Verification {
            detail: format!(
                "swapped database digest {} ({} records) differs from the copy {} ({} records); \
                 the original files are in {}, and {} was left in place",
                hex::encode(digest.digest),
                digest.records(),
                marker.digest,
                marker.records,
                old_dir.display(),
                COMPACTION_MARKER
            ),
        });
    }
    let marker_path = db_path.join(COMPACTION_MARKER);
    fs::remove_file(&marker_path)
        .map_err(|error| io_error("remove marker", &marker_path, error))?;
    sync_dir(db_path)?;

    if options.keep_backup {
        if new_dir.exists() {
            fs::remove_dir_all(&new_dir)
                .map_err(|error| io_error("remove staging copy", &new_dir, error))?;
        }
        Ok((digest.records(), Some(old_dir)))
    } else {
        fs::remove_dir_all(&staging)
            .map_err(|error| io_error("remove staging directory", &staging, error))?;
        sync_dir(db_path)?;
        Ok((digest.records(), None))
    }
}

/// Compacts the sled database in `db_path` by copying it into a fresh one.
/// Must run while no node uses `db_path`; sled's lock makes it fail otherwise.
pub fn compact_database(
    db_path: &Path,
    options: CompactionOptions,
) -> Result<CompactionReport, CompactionError> {
    compact_database_with_timeout(db_path, options, SLED_RELEASE_TIMEOUT)
}

/// [`compact_database`] with a custom wait for a busy database lock.
fn compact_database_with_timeout(
    db_path: &Path,
    options: CompactionOptions,
    lock_timeout: Duration,
) -> Result<CompactionReport, CompactionError> {
    if !db_path.is_dir() {
        return Err(CompactionError::Missing(db_path.to_path_buf()));
    }
    if let Some(marker) = read_marker(db_path)? {
        let bytes_before = sled_files_size(db_path)?;
        let (records, backup) = finish_swap(db_path, marker, options)?;
        let trees = open(db_path)?.tree_names().len();
        return Ok(CompactionReport {
            bytes_before,
            bytes_after: sled_files_size(db_path)?,
            records,
            trees,
            backup,
            resumed: true,
        });
    }
    if sled_entries(db_path)?.is_empty() {
        return Err(CompactionError::Missing(db_path.to_path_buf()));
    }
    let bytes_before = sled_files_size(db_path)?;
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default();
    let staging_name = format!("{STAGING_PREFIX}{unix}");
    let staging = db_path.join(&staging_name);
    if staging.exists() {
        return Err(io_error(
            "staging directory already exists",
            &staging,
            std::io::Error::new(std::io::ErrorKind::AlreadyExists, "retry in a second"),
        ));
    }
    let new_dir = staging.join("new");

    wait_for_sled_release(db_path, lock_timeout)?;
    let source = open(db_path)?;
    let copied = (|| {
        fs::create_dir_all(&new_dir)
            .map_err(|error| io_error("create staging", &new_dir, error))?;
        let target = open(&new_dir)?;
        copy_database(&source, &target)?;
        let expected = database_digest(&source)?;
        let actual = database_digest(&target)?;
        if expected != actual {
            return Err(CompactionError::Verification {
                detail: format!(
                    "source {} ({} records) vs copy {} ({} records)",
                    hex::encode(expected.digest),
                    expected.records(),
                    hex::encode(actual.digest),
                    actual.records()
                ),
            });
        }
        Ok(expected)
    })();
    let expected = match copied {
        Ok(expected) => expected,
        Err(error) => {
            drop(source);
            // Nothing outside the staging directory changed yet.
            let _ = fs::remove_dir_all(&staging);
            return Err(error);
        }
    };
    // Written while the source lock is still held, so no node can open the
    // directory between the copy and the swap.
    write_marker(
        db_path,
        &Marker {
            version: 1,
            staging: staging_name,
            phase: SwapPhase::MoveOld,
            digest: hex::encode(expected.digest),
            records: expected.records(),
        },
    )?;
    drop(source);

    let marker = read_marker(db_path)?.ok_or_else(|| CompactionError::Marker {
        path: db_path.join(COMPACTION_MARKER),
        detail: "marker vanished after it was written".to_string(),
    })?;
    let (records, backup) = finish_swap(db_path, marker, options)?;
    Ok(CompactionReport {
        bytes_before,
        bytes_after: sled_files_size(db_path)?,
        records,
        trees: expected.trees.len(),
        backup,
        resumed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn populate(path: &Path) {
        let db = sled::open(path).unwrap();
        db.insert(b"nonce:local", &7_u64.to_le_bytes()).unwrap();
        let outbox = db.open_tree(b"exit_outbox").unwrap();
        for index in 0..300_u32 {
            outbox
                .insert(format!("tx:{index}").as_bytes(), vec![index as u8; 2_000])
                .unwrap();
        }
        db.open_tree(b"empty_tree").unwrap();
        db.flush().unwrap();
        drop(outbox);
        drop(db);
        wait_for_sled_release(path, SLED_RELEASE_TIMEOUT).unwrap();
    }

    fn digest_of(path: &Path) -> DatabaseDigest {
        wait_for_sled_release(path, SLED_RELEASE_TIMEOUT).unwrap();
        let db = sled::open(path).unwrap();
        let digest = database_digest(&db).unwrap();
        drop(db);
        wait_for_sled_release(path, SLED_RELEASE_TIMEOUT).unwrap();
        digest
    }

    #[test]
    fn compaction_preserves_every_record_and_foreign_files() {
        let dir = tempfile::tempdir().unwrap();
        populate(dir.path());
        fs::write(dir.path().join("bloom.bin"), b"bloom").unwrap();
        let before = digest_of(dir.path());

        let report = compact_database(dir.path(), CompactionOptions::default()).unwrap();
        assert!(!report.resumed);
        assert_eq!(report.records, before.records());
        assert!(report.backup.is_none());
        assert_eq!(digest_of(dir.path()), before);
        assert_eq!(fs::read(dir.path().join("bloom.bin")).unwrap(), b"bloom");
        assert!(!dir.path().join(COMPACTION_MARKER).exists());
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(STAGING_PREFIX)
            })
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn keep_backup_leaves_the_old_files() {
        let dir = tempfile::tempdir().unwrap();
        populate(dir.path());
        let before = digest_of(dir.path());
        let report = compact_database(dir.path(), CompactionOptions { keep_backup: true }).unwrap();
        let backup = report.backup.unwrap();
        assert!(backup.join("db").exists() || backup.join("conf").exists());
        assert_eq!(digest_of(&backup), before);
        assert_eq!(digest_of(dir.path()), before);
    }

    #[test]
    fn compaction_refuses_a_database_in_use() {
        let dir = tempfile::tempdir().unwrap();
        populate(dir.path());
        let running = sled::open(dir.path()).unwrap();
        let error = compact_database_with_timeout(
            dir.path(),
            CompactionOptions::default(),
            Duration::from_millis(100),
        )
        .unwrap_err();
        assert!(matches!(error, CompactionError::Open { .. }), "{error}");
        drop(running);
        assert!(!dir.path().join(COMPACTION_MARKER).exists());
    }

    #[test]
    fn missing_database_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            compact_database(dir.path(), CompactionOptions::default()),
            Err(CompactionError::Missing(_))
        ));
        assert!(matches!(
            compact_database(&dir.path().join("absent"), CompactionOptions::default()),
            Err(CompactionError::Missing(_))
        ));
    }

    /// Simulates a crash after the old files moved out but before the new
    /// ones moved in: the marker blocks node startup and a second run
    /// finishes the swap.
    #[test]
    fn interrupted_swap_blocks_startup_and_resumes() {
        let dir = tempfile::tempdir().unwrap();
        populate(dir.path());
        let before = digest_of(dir.path());

        let staging_name = format!("{STAGING_PREFIX}1");
        let staging = dir.path().join(&staging_name);
        let new_dir = staging.join("new");
        let old_dir = staging.join("old");
        {
            let source = sled::open(dir.path()).unwrap();
            fs::create_dir_all(&new_dir).unwrap();
            let target = sled::open(&new_dir).unwrap();
            copy_database(&source, &target).unwrap();
        }
        wait_for_sled_release(dir.path(), SLED_RELEASE_TIMEOUT).unwrap();
        wait_for_sled_release(&new_dir, SLED_RELEASE_TIMEOUT).unwrap();
        write_marker(
            dir.path(),
            &Marker {
                version: 1,
                staging: staging_name,
                phase: SwapPhase::MoveNew,
                digest: hex::encode(before.digest),
                records: before.records(),
            },
        )
        .unwrap();
        fs::create_dir_all(&old_dir).unwrap();
        move_entries(dir.path(), &old_dir, &sled_entries(dir.path()).unwrap()).unwrap();

        let refused = crate::infra::storage::SledRepository::new(dir.path());
        assert!(refused.is_err());
        assert!(
            sled_entries(dir.path()).unwrap().is_empty(),
            "no empty database was created"
        );

        let report = compact_database(dir.path(), CompactionOptions::default()).unwrap();
        assert!(report.resumed);
        assert_eq!(digest_of(dir.path()), before);
        assert!(!dir.path().join(COMPACTION_MARKER).exists());
        assert!(crate::infra::storage::SledRepository::new(dir.path()).is_ok());
    }

    #[test]
    fn malformed_marker_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        populate(dir.path());
        fs::write(
            dir.path().join(COMPACTION_MARKER),
            br#"{"version":1,"staging":"../../etc","phase":"move_new","digest":"","records":0}"#,
        )
        .unwrap();
        assert!(matches!(
            compact_database(dir.path(), CompactionOptions::default()),
            Err(CompactionError::Marker { .. })
        ));
    }

    #[test]
    fn lock_wait_returns_only_after_sled_is_closed() {
        let dir = tempfile::tempdir().unwrap();
        populate(dir.path());
        let running = sled::open(dir.path()).unwrap();
        assert!(matches!(
            wait_for_sled_release(dir.path(), Duration::from_millis(100)),
            Err(CompactionError::Open { .. })
        ));
        drop(running);
        wait_for_sled_release(dir.path(), SLED_RELEASE_TIMEOUT).unwrap();
        assert!(sled::open(dir.path()).is_ok());
        let empty = tempfile::tempdir().unwrap();
        wait_for_sled_release(empty.path(), Duration::from_millis(1)).unwrap();
    }

    /// After a swap, no file written by the old database may land in
    /// `db_path`: every snapshot there must belong to the new log.
    #[test]
    fn no_old_snapshot_reaches_the_swapped_directory() {
        for _ in 0..5 {
            let dir = tempfile::tempdir().unwrap();
            populate(dir.path());
            let before = digest_of(dir.path());
            compact_database(dir.path(), CompactionOptions::default()).unwrap();
            std::thread::sleep(Duration::from_millis(200));
            assert_eq!(digest_of(dir.path()), before);
        }
    }
}
