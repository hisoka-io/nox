//! One-time import of a sled 0.34 database into `nox.redb`.
//!
//! Runs inside [`NodeStore::new`](crate::infra::storage::NodeStore::new) when
//! `db_path` still holds sled files and no `nox.redb`:
//!
//! 1. Open sled (its lock fails if another process uses the directory).
//! 2. Read every record. Default-tree keys go to the `default` table, except
//!    `outbox:*`/`tx:*` which go to `exit_outbox` (rc.3 layout); a key present
//!    in both sled trees keeps the default-tree copy, the newer write (same
//!    rule as the rc.4 outbox migration). `exit_outbox` → `exit_outbox`,
//!    `replay_tags` → `replay_tags`.
//! 3. Write everything into `nox.redb.importing` in one transaction, read it
//!    back and compare record by record.
//! 4. Rename the file to `nox.redb` (atomic), then move the sled files into
//!    `sled-backup-<unix>/` inside `db_path`.
//!
//! A crash before step 4 leaves sled untouched and the import reruns. A crash
//! after the rename leaves `nox.redb` and the sled files with the same
//! records; the next start compares them and moves the sled files into a
//! backup directory. sled files that differ from `nox.redb` (restored for a
//! rollback, or written by an older release since) stop startup instead, so a
//! stale `nox.redb` never replaces newer sled data.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use nox_core::traits::InfrastructureError;
use redb::{Database, ReadableDatabase, ReadableTable};
use tracing::{info, warn};

use crate::infra::compaction::{
    sled_entries, sync_dir, wait_for_sled_release, SLED_RELEASE_TIMEOUT,
};
use crate::infra::storage::{
    database_error, is_outbox_key, write_transaction, BytesTable, WriteError, DATABASE_FILE,
    DEFAULT_TABLE, OUTBOX_TABLE, REPLAY_TABLE,
};

/// Temporary file name while an import is being written.
pub const IMPORT_FILE: &str = "nox.redb.importing";

/// Directory name prefix for the sled files kept after an import.
pub const SLED_BACKUP_PREFIX: &str = "sled-backup-";

const SLED_DEFAULT_TREE: &[u8] = b"__sled__default";
const SLED_OUTBOX_TREE: &[u8] = b"exit_outbox";
const SLED_REPLAY_TREE: &[u8] = b"replay_tags";

type Records = BTreeMap<Vec<u8>, Vec<u8>>;

/// What one import moved.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub default_records: usize,
    pub outbox_records: usize,
    pub replay_records: usize,
    /// sled trees with records that have no destination (left in the backup).
    pub skipped_trees: Vec<String>,
}

fn import_error(context: &str, error: impl std::fmt::Display) -> InfrastructureError {
    InfrastructureError::Database(format!("sled import: {context}: {error}"))
}

/// Reads a sled database into the three destination record sets.
fn read_sled(
    db: &sled::Db,
) -> Result<(Records, Records, Records, Vec<String>), InfrastructureError> {
    let mut default = Records::new();
    let mut outbox = Records::new();
    let mut replay = Records::new();
    let mut skipped = Vec::new();
    let read_tree = |name: &[u8]| -> Result<Records, InfrastructureError> {
        let tree = db
            .open_tree(name)
            .map_err(|error| import_error("open sled tree", error))?;
        let mut records = Records::new();
        for item in &tree {
            let (key, value) = item.map_err(|error| import_error("read sled tree", error))?;
            records.insert(key.to_vec(), value.to_vec());
        }
        Ok(records)
    };
    for (key, value) in read_tree(SLED_OUTBOX_TREE)? {
        outbox.insert(key, value);
    }
    for (key, value) in read_tree(SLED_DEFAULT_TREE)? {
        if is_outbox_key(&key) {
            outbox.insert(key, value);
        } else {
            default.insert(key, value);
        }
    }
    replay.extend(read_tree(SLED_REPLAY_TREE)?);
    for name in db.tree_names() {
        if [SLED_DEFAULT_TREE, SLED_OUTBOX_TREE, SLED_REPLAY_TREE].contains(&name.as_ref()) {
            continue;
        }
        let records = read_tree(&name)?;
        if !records.is_empty() {
            skipped.push(String::from_utf8_lossy(&name).into_owned());
        }
    }
    Ok((default, outbox, replay, skipped))
}

fn read_table(db: &Database, table: BytesTable) -> Result<Records, InfrastructureError> {
    let transaction = db
        .begin_read()
        .map_err(|error| import_error("begin verification read", error))?;
    let table = transaction
        .open_table(table)
        .map_err(|error| import_error("open table for verification", error))?;
    let mut records = Records::new();
    for item in table
        .iter()
        .map_err(|error| import_error("iterate table for verification", error))?
    {
        let (key, value) =
            item.map_err(|error| import_error("read table for verification", error))?;
        records.insert(key.value().to_vec(), value.value().to_vec());
    }
    Ok(records)
}

fn move_to_backup(
    db_path: &Path,
    names: &[String],
) -> Result<std::path::PathBuf, InfrastructureError> {
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default();
    let backup = db_path.join(format!("{SLED_BACKUP_PREFIX}{unix}"));
    fs::create_dir_all(&backup)
        .map_err(|error| import_error(&format!("create {}", backup.display()), error))?;
    for name in names {
        let source = db_path.join(name);
        fs::rename(&source, backup.join(name))
            .map_err(|error| import_error(&format!("move {}", source.display()), error))?;
    }
    sync_dir(db_path).map_err(|error| import_error("sync database directory", error))?;
    Ok(backup)
}

/// Imports a sled database in `db_path` when there is one and no `nox.redb`.
/// Returns what was imported, or `None` when there was nothing to do.
/// Checks that sled files found next to `nox.redb` hold exactly the records
/// of `nox.redb`, which is the state a crash between installing the import and
/// moving the sled files leaves.
fn ensure_leftover_matches(db_path: &Path, target: &Path) -> Result<(), InfrastructureError> {
    let sled = sled::open(db_path).map_err(|error| {
        import_error(
            &format!(
                "open sled at {} (stop any other process using it)",
                db_path.display()
            ),
            error,
        )
    })?;
    let (default, outbox, replay, _) = read_sled(&sled)?;
    drop(sled);
    let imported = Database::open(target)
        .map_err(|error| import_error(&format!("open {}", target.display()), error))?;
    let matches = read_table(&imported, DEFAULT_TABLE)? == default
        && read_table(&imported, OUTBOX_TABLE)? == outbox
        && read_table(&imported, REPLAY_TABLE)? == replay;
    drop(imported);
    if matches {
        return Ok(());
    }
    Err(import_error(
        "leftover sled files",
        format!(
            "{} holds both nox.redb and sled files with different records (sled files restored \
             or written by an older release after the import). Nothing was changed. To import \
             the sled files, move nox.redb out of the directory; to keep nox.redb, move the sled \
             files (conf, db, blobs, snap.*) out of it",
            db_path.display()
        ),
    ))
}

pub fn import_if_present(db_path: &Path) -> Result<Option<ImportReport>, InfrastructureError> {
    import_with_lock_timeout(db_path, SLED_RELEASE_TIMEOUT)
}

/// [`import_if_present`] with a custom wait for a busy sled lock.
fn import_with_lock_timeout(
    db_path: &Path,
    lock_timeout: std::time::Duration,
) -> Result<Option<ImportReport>, InfrastructureError> {
    let sled_files =
        sled_entries(db_path).map_err(|error| import_error("list sled files", error))?;
    let target = db_path.join(DATABASE_FILE);
    let temporary = db_path.join(IMPORT_FILE);
    if sled_files.is_empty() {
        if temporary.exists() {
            fs::remove_file(&temporary)
                .map_err(|error| import_error("remove stale import file", error))?;
        }
        return Ok(None);
    }
    if target.exists() {
        wait_for_sled_release(db_path, lock_timeout)
            .map_err(|error| import_error("wait for the sled lock", error))?;
        ensure_leftover_matches(db_path, &target)?;
        // Opening sled for the comparison can leave new snapshot files; list
        // the files again once its background work released the lock.
        wait_for_sled_release(db_path, SLED_RELEASE_TIMEOUT)
            .map_err(|error| import_error("wait for sled to close", error))?;
        let sled_files =
            sled_entries(db_path).map_err(|error| import_error("list sled files", error))?;
        let backup = move_to_backup(db_path, &sled_files)?;
        warn!(
            backup = %backup.display(),
            "Found sled files next to an imported nox.redb; moved them to a backup directory"
        );
        return Ok(None);
    }
    if temporary.exists() {
        fs::remove_file(&temporary)
            .map_err(|error| import_error("remove interrupted import file", error))?;
    }

    wait_for_sled_release(db_path, lock_timeout)
        .map_err(|error| import_error("wait for the sled lock", error))?;
    let sled = sled::open(db_path).map_err(|error| {
        import_error(
            &format!(
                "open sled at {} (stop any other process using it)",
                db_path.display()
            ),
            error,
        )
    })?;
    let (default, outbox, replay, skipped_trees) = read_sled(&sled)?;

    let imported = Database::create(&temporary)
        .map_err(|error| import_error(&format!("create {}", temporary.display()), error))?;
    write_transaction::<_, String>(&imported, |transaction| {
        for (definition, records) in [
            (DEFAULT_TABLE, &default),
            (OUTBOX_TABLE, &outbox),
            (REPLAY_TABLE, &replay),
        ] {
            let mut table = transaction.open_table(definition)?;
            for (key, value) in records {
                table.insert(key.as_slice(), value.as_slice())?;
            }
        }
        Ok(())
    })
    .map_err(|error| match error {
        WriteError::Abort(reason) => import_error("write", reason),
        WriteError::Storage(error) => database_error("sled import: write", error),
    })?;
    for (definition, expected, name) in [
        (DEFAULT_TABLE, &default, "default"),
        (OUTBOX_TABLE, &outbox, "exit_outbox"),
        (REPLAY_TABLE, &replay, "replay_tags"),
    ] {
        if &read_table(&imported, definition)? != expected {
            drop(imported);
            let _ = fs::remove_file(&temporary);
            return Err(import_error(
                "verification",
                format!("table {name} does not match the sled records; sled was left untouched"),
            ));
        }
    }
    drop(imported);
    fs::File::open(&temporary)
        .and_then(|file| file.sync_all())
        .map_err(|error| import_error("sync imported file", error))?;
    fs::rename(&temporary, &target)
        .map_err(|error| import_error("install imported database", error))?;
    sync_dir(db_path).map_err(|error| import_error("sync database directory", error))?;
    drop(sled);
    // sled's background tasks may still write snapshot files; they hold its
    // lock until they finish.
    wait_for_sled_release(db_path, SLED_RELEASE_TIMEOUT)
        .map_err(|error| import_error("wait for sled to close", error))?;
    let backup = move_to_backup(
        db_path,
        &sled_entries(db_path).map_err(|error| import_error("list sled files", error))?,
    )?;
    let report = ImportReport {
        default_records: default.len(),
        outbox_records: outbox.len(),
        replay_records: replay.len(),
        skipped_trees,
    };
    info!(
        default_records = report.default_records,
        outbox_records = report.outbox_records,
        replay_records = report.replay_records,
        backup = %backup.display(),
        "Imported the sled database into nox.redb; the sled files are kept in the backup directory"
    );
    if !report.skipped_trees.is_empty() {
        warn!(trees = ?report.skipped_trees, "sled trees without a destination were left in the backup");
    }
    Ok(Some(report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::storage::NodeStore;
    use nox_core::traits::IStorageRepository;

    fn sled_fixture(path: &Path) {
        let db = sled::open(path).unwrap();
        db.insert(b"nonce:local", &9_u64.to_le_bytes()).unwrap();
        db.insert(b"chain_observer:last_block", &7_u64.to_be_bytes())
            .unwrap();
        db.insert(b"quote:nonce", &3_u64.to_le_bytes()).unwrap();
        // rc.3 layout: an outbox record still in the default tree, newer than
        // the copy in exit_outbox.
        db.insert(b"tx:1", b"newer".as_slice()).unwrap();
        let outbox = db.open_tree(SLED_OUTBOX_TREE).unwrap();
        outbox.insert(b"tx:1", b"older".as_slice()).unwrap();
        outbox.insert(b"outbox:aa", vec![5_u8; 70_000]).unwrap();
        let replay = db.open_tree(SLED_REPLAY_TREE).unwrap();
        replay.insert(b"tag", &1_u64.to_be_bytes()).unwrap();
        db.flush().unwrap();
    }

    #[tokio::test]
    async fn sled_database_is_imported_once_and_kept_as_backup() {
        let dir = tempfile::tempdir().unwrap();
        sled_fixture(dir.path());
        std::fs::write(dir.path().join("bloom.bin"), b"bloom").unwrap();

        let store = NodeStore::new(dir.path()).unwrap();
        assert_eq!(
            store.get(b"nonce:local").await.unwrap(),
            Some(9_u64.to_le_bytes().to_vec())
        );
        assert_eq!(store.get(b"tx:1").await.unwrap(), Some(b"newer".to_vec()));
        assert_eq!(
            store.get(b"outbox:aa").await.unwrap(),
            Some(vec![5_u8; 70_000])
        );
        assert_eq!(store.scan(b"tx:").await.unwrap().len(), 1);
        assert!(sled_entries(dir.path()).unwrap().is_empty());
        assert_eq!(
            std::fs::read(dir.path().join("bloom.bin")).unwrap(),
            b"bloom"
        );
        let backups: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(SLED_BACKUP_PREFIX)
            })
            .collect();
        assert_eq!(backups.len(), 1);
        assert!(backups[0].path().join("conf").exists() || backups[0].path().join("db").exists());
        drop(store);

        // A second start finds nothing to import.
        assert_eq!(import_if_present(dir.path()).unwrap(), None);
        let reopened = NodeStore::new(dir.path()).unwrap();
        assert_eq!(
            reopened.get(b"quote:nonce").await.unwrap(),
            Some(3_u64.to_le_bytes().to_vec())
        );
    }

    #[test]
    fn an_interrupted_import_is_redone_from_sled() {
        let dir = tempfile::tempdir().unwrap();
        sled_fixture(dir.path());
        std::fs::write(dir.path().join(IMPORT_FILE), b"partial").unwrap();
        let report = import_if_present(dir.path()).unwrap().unwrap();
        assert_eq!(report.outbox_records, 2);
        assert_eq!(report.default_records, 3);
        assert_eq!(report.replay_records, 1);
        assert!(!dir.path().join(IMPORT_FILE).exists());
        assert!(dir.path().join(DATABASE_FILE).exists());
    }

    #[test]
    fn leftover_sled_files_after_an_import_are_moved_aside() {
        let dir = tempfile::tempdir().unwrap();
        sled_fixture(dir.path());
        import_if_present(dir.path()).unwrap();
        // Simulate a crash between the rename and the move: sled files return.
        sled_fixture(dir.path());
        assert_eq!(import_if_present(dir.path()).unwrap(), None);
        assert!(sled_entries(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn sled_files_that_differ_from_nox_redb_stop_startup() {
        let dir = tempfile::tempdir().unwrap();
        sled_fixture(dir.path());
        import_if_present(dir.path()).unwrap();
        // A rollback restored sled and the older release wrote to it, but
        // nox.redb was left in place.
        sled_fixture(dir.path());
        {
            let db = sled::open(dir.path()).unwrap();
            db.insert(b"nonce:local", &10_u64.to_le_bytes()).unwrap();
            db.flush().unwrap();
        }
        let error = import_if_present(dir.path()).unwrap_err().to_string();
        assert!(error.contains("different records"), "{error}");
        assert!(NodeStore::new(dir.path()).is_err());
        // Nothing moved: the sled files and nox.redb are both still there.
        assert!(!sled_entries(dir.path()).unwrap().is_empty());
        assert!(dir.path().join(DATABASE_FILE).exists());
        // Moving nox.redb out imports the newer sled data.
        std::fs::rename(
            dir.path().join(DATABASE_FILE),
            dir.path().join("nox.redb.rolled-back"),
        )
        .unwrap();
        let report = import_if_present(dir.path()).unwrap().unwrap();
        assert_eq!(report.default_records, 3);
    }

    #[test]
    fn a_locked_sled_database_is_not_imported() {
        let dir = tempfile::tempdir().unwrap();
        sled_fixture(dir.path());
        let running = sled::open(dir.path()).unwrap();
        assert!(
            import_with_lock_timeout(dir.path(), std::time::Duration::from_millis(100)).is_err()
        );
        drop(running);
        assert!(!dir.path().join(DATABASE_FILE).exists());
    }
}
