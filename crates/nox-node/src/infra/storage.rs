//! Node database on redb.
//!
//! One file, `<db_path>/nox.redb`, with three tables:
//! - `default`: nonce floor, quotes and quote counters, peers, sessions, chain
//!   observer cursor;
//! - `exit_outbox`: `outbox:*` and `tx:*` exit transaction records;
//! - `replay_tags`: tags written through [`IReplayProtection`].
//!
//! Every commit is durable when it returns (`Durability::Immediate`), and a
//! write transaction is the only writer while it is open, so the quote and
//! outbox read-modify-write sequences are atomic without retry loops. Pages
//! freed by deletes and rewrites are reused by later writes; `nox db compact`
//! (or startup compaction) also returns them to the filesystem.
//!
//! A `db_path` that still holds a sled 0.34 database is imported once at
//! startup (see `infra::sled_import`).

use async_trait::async_trait;
use ethers::types::U256;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::{error, info, warn};

use nox_core::traits::{IReplayProtection, IStorageRepository, InfrastructureError};
use nox_core::{
    DecodedTransaction, ExecutionId, LegacyPendingTransaction, PendingTransactionV2, QuoteStatusV2,
    StoredQuoteV2, StoredTransactionV2,
};

#[derive(Debug, thiserror::Error)]
pub enum QuoteStoreError {
    #[error("quote execution or payment ID already exists")]
    DuplicateIdentity,
    #[error("quote execution ID is unknown")]
    Unknown,
    #[error("quote is expired")]
    Expired,
    #[error("quote is not outstanding")]
    NotOutstanding,
    #[error("outstanding quote limit reached")]
    OutstandingCapacity,
    #[error("pending sponsored gas limit reached")]
    PendingGasCapacity,
    #[error("rolling sponsored loss limit reached")]
    PendingLossLimit,
    #[error(transparent)]
    Storage(#[from] InfrastructureError),
}

/// Snapshot of the quote reservation counters, read outside a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QuoteCounters {
    pub outstanding: u64,
    pub pending_sponsored_gas: u64,
    /// Loss recorded in the current window, as last written.
    pub rolling_loss_native: U256,
    pub loss_window_start: Option<u64>,
}

impl QuoteCounters {
    /// Cheap admission check with the same limits that `create_quote_durably` enforces
    /// atomically. Lets a quote be refused before any RPC, oracle or signing work.
    pub fn admit(
        &self,
        requested_gas: u64,
        maximum_outstanding: u32,
        maximum_pending_gas: u64,
        rolling_loss_limit_native: U256,
        rolling_loss_window_secs: u64,
        now_unix: u64,
    ) -> Result<(), QuoteStoreError> {
        let window_expired = self
            .loss_window_start
            .is_none_or(|start| now_unix.saturating_sub(start) >= rolling_loss_window_secs);
        if !window_expired && self.rolling_loss_native >= rolling_loss_limit_native {
            return Err(QuoteStoreError::PendingLossLimit);
        }
        if self.outstanding >= u64::from(maximum_outstanding) {
            return Err(QuoteStoreError::OutstandingCapacity);
        }
        match self.pending_sponsored_gas.checked_add(requested_gas) {
            Some(next) if next <= maximum_pending_gas => Ok(()),
            _ => Err(QuoteStoreError::PendingGasCapacity),
        }
    }
}

fn decode_u64(bytes: &[u8]) -> Result<u64, String> {
    let encoded: [u8; 8] = bytes
        .try_into()
        .map_err(|_| "stored counter must contain exactly eight bytes".to_string())?;
    Ok(u64::from_le_bytes(encoded))
}

/// Backoff schedule for transient IO errors. A single short retry is not
/// enough to ride out a disk that is briefly full, and escalating delays avoid
/// hot-looping against a filesystem that is genuinely out of space.
const RETRY_BACKOFF_MS: [u64; 3] = [100, 500, 2000];

/// Shared flag describing whether the storage layer is failing writes.
pub type DegradedFlag = Arc<AtomicBool>;

/// File name of the database inside `db_path`.
pub const DATABASE_FILE: &str = "nox.redb";

pub(crate) type BytesTable = TableDefinition<'static, &'static [u8], &'static [u8]>;

/// Everything that is not an outbox record or a replay tag.
pub(crate) const DEFAULT_TABLE: BytesTable = TableDefinition::new("default");
/// `outbox:*` and `tx:*` exit transaction records.
pub(crate) const OUTBOX_TABLE: BytesTable = TableDefinition::new("exit_outbox");
/// Replay tags and their expiry.
pub(crate) const REPLAY_TABLE: BytesTable = TableDefinition::new("replay_tags");

/// Key prefixes stored in the outbox table instead of the default table.
pub const OUTBOX_KEY_PREFIXES: [&[u8]; 2] = [b"outbox:", b"tx:"];

/// True for keys that live in the outbox table.
#[must_use]
pub fn is_outbox_key(key: &[u8]) -> bool {
    OUTBOX_KEY_PREFIXES
        .iter()
        .any(|prefix| key.starts_with(prefix))
}

fn table_for(key: &[u8]) -> BytesTable {
    if is_outbox_key(key) {
        OUTBOX_TABLE
    } else {
        DEFAULT_TABLE
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum CreateOutboxResult {
    Created,
    Existing(PendingTransactionV2),
}

pub fn decode_stored_transaction(bytes: &[u8]) -> Result<DecodedTransaction, InfrastructureError> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        InfrastructureError::Database(format!("transaction record is malformed JSON: {error}"))
    })?;
    if value.get("schema").is_some() {
        let stored: StoredTransactionV2 = serde_json::from_value(value).map_err(|error| {
            InfrastructureError::Database(format!("v2 transaction record is malformed: {error}"))
        })?;
        if stored.schema != 2 {
            return Err(InfrastructureError::Database(format!(
                "unsupported transaction schema {}",
                stored.schema
            )));
        }
        Ok(DecodedTransaction::V2(stored.transaction))
    } else {
        serde_json::from_value(value)
            .map(DecodedTransaction::Legacy)
            .map_err(|error| {
                InfrastructureError::Database(format!(
                    "legacy transaction record is malformed: {error}"
                ))
            })
    }
}

/// Failure inside a write transaction: either a reason to abort it, or a
/// storage error. Aborting discards every change made in the transaction.
#[derive(Debug)]
pub(crate) enum WriteError<E> {
    Abort(E),
    Storage(redb::Error),
}

macro_rules! storage_from {
    ($($error:ty),*) => {$(
        impl<E> From<$error> for WriteError<E> {
            fn from(error: $error) -> Self {
                WriteError::Storage(error.into())
            }
        }
    )*};
}
storage_from!(
    redb::Error,
    redb::StorageError,
    redb::TableError,
    redb::TransactionError,
    redb::CommitError
);

pub(crate) fn database_error(context: &str, error: impl std::fmt::Display) -> InfrastructureError {
    InfrastructureError::Database(format!("{context}: {error}"))
}

/// Runs `body` in one write transaction and commits it. An `Err` aborts.
pub(crate) fn write_transaction<T, E>(
    db: &Database,
    body: impl FnOnce(&WriteTransaction) -> Result<T, WriteError<E>>,
) -> Result<T, WriteError<E>> {
    let transaction = db.begin_write()?;
    match body(&transaction) {
        Ok(value) => {
            transaction.commit()?;
            Ok(value)
        }
        Err(error) => {
            if let Err(abort_error) = transaction.abort() {
                warn!(error = %abort_error, "aborting a write transaction failed");
            }
            Err(error)
        }
    }
}

fn get_bytes(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    key: &[u8],
) -> Result<Option<Vec<u8>>, redb::StorageError> {
    Ok(table.get(key)?.map(|value| value.value().to_vec()))
}

fn read_u64<E: From<String>>(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    key: &[u8],
) -> Result<Option<u64>, WriteError<E>> {
    match get_bytes(table, key)? {
        Some(bytes) => decode_u64(&bytes)
            .map(Some)
            .map_err(|error| WriteError::Abort(E::from(error))),
        None => Ok(None),
    }
}

fn collect_prefix(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    prefix: &[u8],
    results: &mut Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<(), redb::StorageError> {
    for item in table.range::<&[u8]>(prefix..)? {
        let (key, value) = item?;
        if !key.value().starts_with(prefix) {
            break;
        }
        results.push((key.value().to_vec(), value.value().to_vec()));
    }
    Ok(())
}

/// Which tables a prefix scan has to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanScope {
    Default,
    Outbox,
    Both,
}

fn scan_scope(prefix: &[u8]) -> ScanScope {
    if is_outbox_key(prefix) {
        ScanScope::Outbox
    } else if OUTBOX_KEY_PREFIXES
        .iter()
        .any(|outbox_prefix| outbox_prefix.starts_with(prefix))
    {
        ScanScope::Both
    } else {
        ScanScope::Default
    }
}

/// Wraps a domain error from inside a quote transaction.
impl From<String> for QuoteStoreError {
    fn from(error: String) -> Self {
        QuoteStoreError::Storage(InfrastructureError::Database(error))
    }
}

fn quote_write_error(context: &str, error: WriteError<QuoteStoreError>) -> QuoteStoreError {
    match error {
        WriteError::Abort(error) => error,
        WriteError::Storage(error) => QuoteStoreError::Storage(database_error(context, error)),
    }
}

fn string_write_error(context: &str, error: WriteError<String>) -> InfrastructureError {
    match error {
        WriteError::Abort(reason) => InfrastructureError::Database(format!("{context}: {reason}")),
        WriteError::Storage(error) => database_error(context, error),
    }
}

fn is_io(error: &redb::Error) -> bool {
    matches!(error, redb::Error::Io(_)) || matches!(error, redb::Error::PreviousIo)
}

#[derive(Clone)]
pub struct NodeStore {
    db: Arc<Database>,
    /// Directory the database file lives in.
    path: PathBuf,
    /// Set once an IO error survives every retry. redb refuses further writes
    /// after an IO error (`PreviousIo`) until the database is reopened, so the
    /// node needs a restart once storage is healthy again.
    degraded: DegradedFlag,
    outbox_degraded: Arc<AtomicBool>,
    #[cfg(test)]
    durable_flush_calls: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(test)]
    fail_durable_flush_call: Arc<std::sync::atomic::AtomicUsize>,
}

impl NodeStore {
    /// Opens (or creates) `<path>/nox.redb`, importing a sled database found
    /// in `path` first.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, InfrastructureError> {
        let path = path.as_ref();
        crate::infra::compaction::ensure_no_interrupted_compaction(path)?;
        std::fs::create_dir_all(path).map_err(|error| {
            database_error(
                &format!("create database directory {}", path.display()),
                error,
            )
        })?;
        crate::infra::sled_import::import_if_present(path)?;
        let file = path.join(DATABASE_FILE);
        let db = Database::create(&file)
            .map_err(|error| database_error(&format!("open database {}", file.display()), error))?;
        write_transaction::<_, String>(&db, |transaction| {
            for table in [DEFAULT_TABLE, OUTBOX_TABLE, REPLAY_TABLE] {
                transaction.open_table(table)?;
            }
            Ok(())
        })
        .map_err(|error| string_write_error("create database tables", error))?;
        Ok(Self {
            db: Arc::new(db),
            path: path.to_path_buf(),
            degraded: Arc::new(AtomicBool::new(false)),
            outbox_degraded: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            durable_flush_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(test)]
            fail_durable_flush_call: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    pub(crate) fn database(&self) -> &Arc<Database> {
        &self.db
    }

    /// Runs blocking database work off the async runtime.
    async fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce(&Database) -> T + Send + 'static,
    ) -> Result<T, InfrastructureError> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || work(&db))
            .await
            .map_err(|error| database_error("database task failed", error))
    }

    pub async fn next_quote_nonce_durably(&self) -> Result<u64, InfrastructureError> {
        let nonce = self
            .blocking(|db| {
                write_transaction::<_, String>(db, |transaction| {
                    let mut table = transaction.open_table(DEFAULT_TABLE)?;
                    let current = read_u64(&table, b"quote:nonce")?.unwrap_or(0);
                    let next = current
                        .checked_add(1)
                        .ok_or_else(|| WriteError::Abort("quote nonce overflow".to_string()))?;
                    table.insert(b"quote:nonce".as_slice(), next.to_le_bytes().as_slice())?;
                    Ok(next)
                })
                .map_err(|error| string_write_error("quote nonce allocation failed", error))
            })
            .await??;
        self.durable_flush("quote nonce").await?;
        Ok(nonce)
    }

    pub async fn quote_counters(&self) -> Result<QuoteCounters, InfrastructureError> {
        let counter = |bytes: Option<Vec<u8>>| -> Result<Option<u64>, InfrastructureError> {
            bytes
                .map(|value| decode_u64(&value).map_err(InfrastructureError::Database))
                .transpose()
        };
        let outstanding = counter(self.get(b"quote:outstanding").await?)?.unwrap_or(0);
        let pending_sponsored_gas = counter(self.get(b"quote:pending-gas").await?)?.unwrap_or(0);
        let loss_window_start = counter(self.get(b"quote:loss-window-start").await?)?;
        let rolling_loss_native = self
            .get(b"quote:rolling-loss")
            .await?
            .map(|value| U256::from_big_endian(&value))
            .unwrap_or_default();
        Ok(QuoteCounters {
            outstanding,
            pending_sponsored_gas,
            rolling_loss_native,
            loss_window_start,
        })
    }

    pub async fn create_quote_durably(
        &self,
        record: &StoredQuoteV2,
        maximum_outstanding: u32,
        maximum_pending_gas: u64,
        rolling_loss_limit_native: U256,
        rolling_loss_window_secs: u64,
        now_unix: u64,
    ) -> Result<(), QuoteStoreError> {
        let record = record.clone();
        self.blocking(move |db| {
            let execution_key = format!("quote:execution:{}", hex::encode(record.execution_id));
            let payment_key = format!("quote:payment:{}", hex::encode(record.request.payment_id));
            let bytes = serde_json::to_vec(&record).map_err(|error| {
                QuoteStoreError::Storage(database_error("serialize quote record failed", error))
            })?;
            write_transaction(db, |transaction| {
                let mut table = transaction.open_table(DEFAULT_TABLE)?;
                let stored_window_start =
                    read_u64::<QuoteStoreError>(&table, b"quote:loss-window-start")?
                        .unwrap_or(now_unix);
                let window_expired =
                    now_unix.saturating_sub(stored_window_start) >= rolling_loss_window_secs;
                let rolling_loss = if window_expired {
                    U256::zero()
                } else {
                    get_bytes(&table, b"quote:rolling-loss")?
                        .map(|value| U256::from_big_endian(&value))
                        .unwrap_or_default()
                };
                if rolling_loss >= rolling_loss_limit_native {
                    return Err(WriteError::Abort(QuoteStoreError::PendingLossLimit));
                }
                if table.get(execution_key.as_bytes())?.is_some()
                    || table.get(payment_key.as_bytes())?.is_some()
                {
                    return Err(WriteError::Abort(QuoteStoreError::DuplicateIdentity));
                }
                let outstanding = read_u64(&table, b"quote:outstanding")?.unwrap_or(0);
                if outstanding >= u64::from(maximum_outstanding) {
                    return Err(WriteError::Abort(QuoteStoreError::OutstandingCapacity));
                }
                let pending_gas = read_u64(&table, b"quote:pending-gas")?.unwrap_or(0);
                let next_pending = pending_gas
                    .checked_add(record.pending_sponsored_gas)
                    .ok_or_else(|| {
                        WriteError::Abort(QuoteStoreError::from(
                            "pending sponsored gas overflow".to_string(),
                        ))
                    })?;
                if next_pending > maximum_pending_gas {
                    return Err(WriteError::Abort(QuoteStoreError::PendingGasCapacity));
                }
                let next_outstanding = outstanding.checked_add(1).ok_or_else(|| {
                    WriteError::Abort(QuoteStoreError::from(
                        "outstanding quote counter overflow".to_string(),
                    ))
                })?;
                table.insert(execution_key.as_bytes(), bytes.as_slice())?;
                table.insert(payment_key.as_bytes(), record.execution_id.as_slice())?;
                table.insert(
                    b"quote:outstanding".as_slice(),
                    next_outstanding.to_le_bytes().as_slice(),
                )?;
                table.insert(
                    b"quote:pending-gas".as_slice(),
                    next_pending.to_le_bytes().as_slice(),
                )?;
                if window_expired {
                    table.insert(
                        b"quote:loss-window-start".as_slice(),
                        now_unix.to_le_bytes().as_slice(),
                    )?;
                    table.insert(b"quote:rolling-loss".as_slice(), [0_u8; 32].as_slice())?;
                }
                Ok(())
            })
            .map_err(|error| quote_write_error("quote reservation failed", error))
        })
        .await
        .map_err(QuoteStoreError::Storage)??;
        self.durable_flush("quote reservation")
            .await
            .map_err(QuoteStoreError::Storage)
    }

    pub async fn take_quote_durably(
        &self,
        execution_id: ExecutionId,
        now_unix: u64,
    ) -> Result<StoredQuoteV2, QuoteStoreError> {
        let record = self
            .blocking(move |db| {
                let key = format!("quote:execution:{}", hex::encode(execution_id));
                write_transaction(db, |transaction| {
                    let mut table = transaction.open_table(DEFAULT_TABLE)?;
                    let bytes = get_bytes(&table, key.as_bytes())?
                        .ok_or(WriteError::Abort(QuoteStoreError::Unknown))?;
                    let mut record: StoredQuoteV2 =
                        serde_json::from_slice(&bytes).map_err(|error| {
                            WriteError::Abort(QuoteStoreError::Storage(database_error(
                                "stored quote is malformed",
                                error,
                            )))
                        })?;
                    if record.status != QuoteStatusV2::Outstanding {
                        return Err(WriteError::Abort(QuoteStoreError::NotOutstanding));
                    }
                    if record.quote.valid_until_unix <= now_unix {
                        return Err(WriteError::Abort(QuoteStoreError::Expired));
                    }
                    record.status = QuoteStatusV2::Inflight;
                    let updated = serde_json::to_vec(&record).map_err(|error| {
                        WriteError::Abort(QuoteStoreError::Storage(database_error(
                            "serialize inflight quote failed",
                            error,
                        )))
                    })?;
                    table.insert(key.as_bytes(), updated.as_slice())?;
                    Ok(record)
                })
                .map_err(|error| quote_write_error("quote take failed", error))
            })
            .await
            .map_err(QuoteStoreError::Storage)??;
        self.durable_flush("quote take")
            .await
            .map_err(QuoteStoreError::Storage)?;
        Ok(record)
    }

    pub async fn load_quote(
        &self,
        execution_id: ExecutionId,
    ) -> Result<Option<StoredQuoteV2>, InfrastructureError> {
        let key = format!("quote:execution:{}", hex::encode(execution_id));
        self.get(key.as_bytes())
            .await?
            .map(|bytes| {
                serde_json::from_slice(&bytes).map_err(|error| {
                    InfrastructureError::Database(format!("stored quote is malformed: {error}"))
                })
            })
            .transpose()
    }

    pub async fn load_outbox_by_execution(
        &self,
        execution_id: ExecutionId,
    ) -> Result<Option<PendingTransactionV2>, InfrastructureError> {
        let key = format!("outbox:{}", hex::encode(execution_id));
        self.get(key.as_bytes())
            .await?
            .map(|bytes| match decode_stored_transaction(&bytes)? {
                DecodedTransaction::V2(transaction) => Ok(transaction),
                DecodedTransaction::Legacy(_) => Err(InfrastructureError::Database(
                    "execution outbox points to a legacy transaction".to_string(),
                )),
            })
            .transpose()
    }

    pub async fn mark_quote_submitted_durably(
        &self,
        execution_id: ExecutionId,
    ) -> Result<(), InfrastructureError> {
        self.update_quote_status_durably(execution_id, QuoteStatusV2::Submitted, None, 0)
            .await
            .map(|_| ())
    }

    pub async fn finalize_quote_durably(
        &self,
        execution_id: ExecutionId,
        terminal_status: QuoteStatusV2,
        unreimbursed_loss_native: U256,
        now_unix: u64,
    ) -> Result<bool, InfrastructureError> {
        if !matches!(
            terminal_status,
            QuoteStatusV2::Confirmed
                | QuoteStatusV2::Reverted
                | QuoteStatusV2::Expired
                | QuoteStatusV2::Rejected
        ) {
            return Err(InfrastructureError::Database(
                "quote finalization requires a terminal status".to_string(),
            ));
        }
        self.update_quote_status_durably(
            execution_id,
            terminal_status,
            Some(unreimbursed_loss_native),
            now_unix,
        )
        .await
    }

    async fn update_quote_status_durably(
        &self,
        execution_id: ExecutionId,
        next_status: QuoteStatusV2,
        terminal_loss: Option<U256>,
        now_unix: u64,
    ) -> Result<bool, InfrastructureError> {
        let changed = self
            .blocking(move |db| {
                let key = format!("quote:execution:{}", hex::encode(execution_id));
                write_transaction::<_, String>(db, |transaction| {
                    let mut table = transaction.open_table(DEFAULT_TABLE)?;
                    let bytes = get_bytes(&table, key.as_bytes())?.ok_or_else(|| {
                        WriteError::Abort("quote execution ID is unknown".to_string())
                    })?;
                    let mut record: StoredQuoteV2 =
                        serde_json::from_slice(&bytes).map_err(|error| {
                            WriteError::Abort(format!("stored quote is malformed: {error}"))
                        })?;
                    if matches!(
                        record.status,
                        QuoteStatusV2::Confirmed
                            | QuoteStatusV2::Reverted
                            | QuoteStatusV2::Expired
                            | QuoteStatusV2::Rejected
                    ) {
                        return Ok(false);
                    }
                    if let Some(loss) = terminal_loss {
                        let outstanding = read_u64(&table, b"quote:outstanding")?.unwrap_or(0);
                        let pending = read_u64(&table, b"quote:pending-gas")?.unwrap_or(0);
                        let next_outstanding = outstanding.checked_sub(1).ok_or_else(|| {
                            WriteError::Abort("outstanding quote counter underflow".to_string())
                        })?;
                        let next_pending = pending
                            .checked_sub(record.pending_sponsored_gas)
                            .ok_or_else(|| {
                                WriteError::Abort(
                                    "pending sponsored gas counter underflow".to_string(),
                                )
                            })?;
                        table.insert(
                            b"quote:outstanding".as_slice(),
                            next_outstanding.to_le_bytes().as_slice(),
                        )?;
                        table.insert(
                            b"quote:pending-gas".as_slice(),
                            next_pending.to_le_bytes().as_slice(),
                        )?;
                        if !loss.is_zero() {
                            let stored_start =
                                read_u64(&table, b"quote:loss-window-start")?.unwrap_or(now_unix);
                            let window_expired = now_unix.saturating_sub(stored_start)
                                >= record.rolling_loss_window_secs;
                            let current_loss = if window_expired {
                                U256::zero()
                            } else {
                                get_bytes(&table, b"quote:rolling-loss")?
                                    .map(|value| U256::from_big_endian(&value))
                                    .unwrap_or_default()
                            };
                            let next_loss = current_loss.checked_add(loss).ok_or_else(|| {
                                WriteError::Abort("rolling sponsored loss overflow".to_string())
                            })?;
                            let mut encoded_loss = [0_u8; 32];
                            next_loss.to_big_endian(&mut encoded_loss);
                            table.insert(
                                b"quote:rolling-loss".as_slice(),
                                encoded_loss.as_slice(),
                            )?;
                            if window_expired {
                                table.insert(
                                    b"quote:loss-window-start".as_slice(),
                                    now_unix.to_le_bytes().as_slice(),
                                )?;
                            }
                        }
                    } else if record.status != QuoteStatusV2::Inflight {
                        return Err(WriteError::Abort(
                            "only an inflight quote can become submitted".to_string(),
                        ));
                    }
                    record.status = next_status.clone();
                    let updated = serde_json::to_vec(&record).map_err(|error| {
                        WriteError::Abort(format!("serialize quote status failed: {error}"))
                    })?;
                    table.insert(key.as_bytes(), updated.as_slice())?;
                    Ok(true)
                })
                .map_err(|error| string_write_error("quote status update failed", error))
            })
            .await??;
        self.durable_flush("quote status").await?;
        Ok(changed)
    }

    pub async fn prune_expired_quotes_durably(
        &self,
        now_unix: u64,
    ) -> Result<usize, InfrastructureError> {
        let records = self.scan(b"quote:execution:").await?;
        let mut pruned = 0_usize;
        for (_, bytes) in records {
            let record: StoredQuoteV2 = serde_json::from_slice(&bytes).map_err(|error| {
                InfrastructureError::Database(format!("stored quote is malformed: {error}"))
            })?;
            if record.status == QuoteStatusV2::Outstanding
                && record.quote.valid_until_unix <= now_unix
                && self
                    .finalize_quote_durably(
                        record.execution_id,
                        QuoteStatusV2::Expired,
                        U256::zero(),
                        now_unix,
                    )
                    .await?
            {
                pruned = pruned.checked_add(1).ok_or_else(|| {
                    InfrastructureError::Database("expired quote count overflow".to_string())
                })?;
            }
        }
        Ok(pruned)
    }

    /// True when writes are persistently failing and the node needs a restart.
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Relaxed) || self.outbox_degraded.load(Ordering::Relaxed)
    }

    /// Shared handle to the degraded flag, for health reporting.
    #[must_use]
    pub fn degraded_flag(&self) -> DegradedFlag {
        self.degraded.clone()
    }

    #[cfg(test)]
    pub(crate) fn inject_next_durable_flush_failure(&self) {
        self.inject_durable_flush_failure_on_call(1);
    }

    #[cfg(test)]
    pub(crate) fn inject_durable_flush_failure_on_call(&self, call_offset: usize) {
        let current = self.durable_flush_calls.load(Ordering::SeqCst);
        self.fail_durable_flush_call
            .store(current.saturating_add(call_offset), Ordering::SeqCst);
    }

    /// Commits are already durable; this is the hook where a durable write is
    /// confirmed, and where tests inject a failure after the write.
    #[allow(clippy::unused_async)]
    async fn durable_flush(&self, operation: &'static str) -> Result<(), InfrastructureError> {
        #[cfg(test)]
        {
            let call = self.durable_flush_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if self.fail_durable_flush_call.load(Ordering::SeqCst) == call {
                self.fail_durable_flush_call.store(0, Ordering::SeqCst);
                self.outbox_degraded.store(true, Ordering::SeqCst);
                self.degraded.store(true, Ordering::SeqCst);
                return Err(InfrastructureError::Database(format!(
                    "{operation} flush fault injected"
                )));
            }
        }
        let _ = operation;
        Ok(())
    }

    /// Latches both degraded flags when a durable write failed in storage.
    fn latch_outbox_failure<T>(
        &self,
        result: Result<T, InfrastructureError>,
    ) -> Result<T, InfrastructureError> {
        if result.is_err() {
            self.outbox_degraded.store(true, Ordering::SeqCst);
            self.degraded.store(true, Ordering::SeqCst);
        }
        result
    }

    pub async fn create_outbox_durably(
        &self,
        execution_id: ExecutionId,
        record: &PendingTransactionV2,
        next_nonce: u64,
    ) -> Result<CreateOutboxResult, InfrastructureError> {
        if self.outbox_degraded.load(Ordering::SeqCst) {
            return Err(InfrastructureError::Database(
                "durable outbox is degraded; restart after restoring storage".to_string(),
            ));
        }
        let record = record.clone();
        let existing = self
            .blocking(move |db| {
                let outbox_key = format!("outbox:{}", hex::encode(execution_id));
                let tx_key = format!("tx:{}", record.nonce);
                let bytes = serde_json::to_vec(&StoredTransactionV2 {
                    schema: 2,
                    transaction: record,
                })
                .map_err(|error| database_error("serialize v2 outbox record failed", error))?;
                write_transaction::<_, String>(db, |transaction| {
                    let mut outbox = transaction.open_table(OUTBOX_TABLE)?;
                    if let Some(existing) = get_bytes(&outbox, outbox_key.as_bytes())? {
                        return Ok(Some(existing));
                    }
                    outbox.insert(outbox_key.as_bytes(), bytes.as_slice())?;
                    outbox.insert(tx_key.as_bytes(), bytes.as_slice())?;
                    let mut default = transaction.open_table(DEFAULT_TABLE)?;
                    default.insert(
                        b"nonce:local".as_slice(),
                        next_nonce.to_le_bytes().as_slice(),
                    )?;
                    Ok(None)
                })
                .map_err(|error| string_write_error("atomic outbox creation failed", error))
            })
            .await?;
        let existing = self.latch_outbox_failure(existing)?;
        self.durable_flush("durable outbox").await?;
        match existing {
            Some(bytes) => match decode_stored_transaction(&bytes)? {
                DecodedTransaction::V2(transaction) => {
                    Ok(CreateOutboxResult::Existing(transaction))
                }
                DecodedTransaction::Legacy(_) => Err(InfrastructureError::Database(
                    "execution outbox points to a legacy record".to_string(),
                )),
            },
            None => Ok(CreateOutboxResult::Created),
        }
    }

    pub async fn persist_v2_durably(
        &self,
        record: &PendingTransactionV2,
    ) -> Result<(), InfrastructureError> {
        if self.outbox_degraded.load(Ordering::SeqCst) {
            return Err(InfrastructureError::Database(
                "durable outbox is degraded; restart after restoring storage".to_string(),
            ));
        }
        let record = record.clone();
        let written = self
            .blocking(move |db| {
                let outbox_key = format!("outbox:{}", hex::encode(record.execution_id));
                let tx_key = format!("tx:{}", record.nonce);
                let bytes = serde_json::to_vec(&StoredTransactionV2 {
                    schema: 2,
                    transaction: record,
                })
                .map_err(|error| database_error("serialize v2 record failed", error))?;
                write_transaction::<_, String>(db, |transaction| {
                    let mut outbox = transaction.open_table(OUTBOX_TABLE)?;
                    outbox.insert(outbox_key.as_bytes(), bytes.as_slice())?;
                    outbox.insert(tx_key.as_bytes(), bytes.as_slice())?;
                    Ok(())
                })
                .map_err(|error| string_write_error("atomic v2 update failed", error))
            })
            .await?;
        self.latch_outbox_failure(written)?;
        self.durable_flush("durable v2").await
    }

    pub async fn persist_legacy_terminal_durably(
        &self,
        record: &LegacyPendingTransaction,
    ) -> Result<(), InfrastructureError> {
        let key = format!("tx:{}", record.nonce);
        let bytes = serde_json::to_vec(record).map_err(|error| {
            InfrastructureError::Database(format!(
                "serialize legacy terminal record failed: {error}"
            ))
        })?;
        self.put(key.as_bytes(), &bytes).await?;
        self.durable_flush("legacy terminal transaction").await
    }

    /// Runs a database operation, retrying transient IO errors on an
    /// escalating backoff. Other errors fail immediately. If every attempt
    /// fails the store latches into a degraded state and logs once at ERROR.
    fn with_retry<T, F: Fn() -> Result<T, redb::Error>>(
        &self,
        op_name: &str,
        f: F,
    ) -> Result<T, InfrastructureError> {
        let mut last_err = match f() {
            Ok(val) => {
                self.clear_degraded();
                return Ok(val);
            }
            Err(e) => e,
        };

        for (attempt, backoff_ms) in RETRY_BACKOFF_MS.iter().enumerate() {
            if !is_io(&last_err) {
                return Err(InfrastructureError::Database(last_err.to_string()));
            }
            warn!(
                "Database {op_name}: transient IO error (attempt {}/{}), retrying in {backoff_ms}ms: {last_err}",
                attempt + 1,
                RETRY_BACKOFF_MS.len()
            );
            std::thread::sleep(Duration::from_millis(*backoff_ms));
            match f() {
                Ok(val) => {
                    self.clear_degraded();
                    return Ok(val);
                }
                Err(e) => last_err = e,
            }
        }

        if is_io(&last_err) && !self.degraded.swap(true, Ordering::SeqCst) {
            error!(
                "Database {op_name}: IO error persisted through {} retries: {last_err}. \
                 Storage is DEGRADED and writes are being lost. redb refuses writes after an \
                 IO error until the database is reopened, so the node must be restarted once \
                 free space is available.",
                RETRY_BACKOFF_MS.len()
            );
        }

        Err(InfrastructureError::Database(last_err.to_string()))
    }

    /// Clear the degraded latch after a successful operation.
    fn clear_degraded(&self) {
        if self.outbox_degraded.load(Ordering::SeqCst) {
            return;
        }
        if self.degraded.swap(false, Ordering::SeqCst) {
            info!("Database: storage recovered, writes are succeeding again");
        }
    }

    /// Kept for the maintenance pass. Commits are durable when they return,
    /// so there is nothing to flush; this logs the database's page usage at
    /// DEBUG.
    pub async fn compact(&self) -> Result<(), InfrastructureError> {
        let stats = self.stats().await?;
        tracing::debug!(
            stored_bytes = stats.stored_bytes,
            fragmented_bytes = stats.fragmented_bytes,
            "Database maintenance check complete"
        );
        Ok(())
    }

    /// Page usage of the database file.
    pub async fn stats(&self) -> Result<StoreStats, InfrastructureError> {
        self.blocking(|db| {
            let transaction = db
                .begin_write()
                .map_err(|error| database_error("begin stats transaction", error))?;
            let stats = transaction
                .stats()
                .map_err(|error| database_error("read database stats", error))?;
            transaction
                .abort()
                .map_err(|error| database_error("end stats transaction", error))?;
            Ok(StoreStats {
                stored_bytes: stats.stored_bytes(),
                metadata_bytes: stats.metadata_bytes(),
                fragmented_bytes: stats.fragmented_bytes(),
            })
        })
        .await?
    }

    /// Bytes the database file occupies on disk.
    pub async fn size_on_disk(&self) -> Result<u64, InfrastructureError> {
        let file = self.path.join(DATABASE_FILE);
        tokio::task::spawn_blocking(move || {
            std::fs::metadata(&file)
                .map(|metadata| metadata.len())
                .map_err(|error| database_error(&format!("stat {}", file.display()), error))
        })
        .await
        .map_err(|e| InfrastructureError::Database(format!("spawn_blocking join error: {e}")))?
    }

    /// Directory the database lives in.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// True once a durable outbox write failed; maintenance leaves the outbox
    /// alone until the node is restarted.
    pub(crate) fn is_outbox_degraded(&self) -> bool {
        self.outbox_degraded.load(Ordering::SeqCst)
    }

    /// Confirms a maintenance write; commits are already durable.
    pub(crate) async fn flush_durably(
        &self,
        operation: &'static str,
    ) -> Result<(), InfrastructureError> {
        self.durable_flush(operation).await
    }
}

/// Page usage reported by [`NodeStore::stats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreStats {
    pub stored_bytes: u64,
    pub metadata_bytes: u64,
    pub fragmented_bytes: u64,
}

#[async_trait]
impl IStorageRepository for NodeStore {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, InfrastructureError> {
        let repo = self.clone();
        let key = key.to_vec();
        tokio::task::spawn_blocking(move || {
            repo.with_retry("get", || {
                let transaction = repo.db.begin_read()?;
                let table = transaction.open_table(table_for(&key))?;
                Ok(get_bytes(&table, &key)?)
            })
        })
        .await
        .map_err(|e| InfrastructureError::Database(format!("spawn_blocking join error: {e}")))?
    }

    async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), InfrastructureError> {
        let repo = self.clone();
        let key = key.to_vec();
        let value = value.to_vec();
        tokio::task::spawn_blocking(move || {
            repo.with_retry("put", || {
                let transaction = repo.db.begin_write()?;
                {
                    let mut table = transaction.open_table(table_for(&key))?;
                    table.insert(key.as_slice(), value.as_slice())?;
                }
                transaction.commit()?;
                Ok(())
            })
        })
        .await
        .map_err(|e| InfrastructureError::Database(format!("spawn_blocking join error: {e}")))?
    }

    async fn exists(&self, key: &[u8]) -> Result<bool, InfrastructureError> {
        Ok(self.get(key).await?.is_some())
    }

    async fn delete(&self, key: &[u8]) -> Result<(), InfrastructureError> {
        let repo = self.clone();
        let key = key.to_vec();
        tokio::task::spawn_blocking(move || {
            repo.with_retry("delete", || {
                let transaction = repo.db.begin_write()?;
                {
                    let mut table = transaction.open_table(table_for(&key))?;
                    table.remove(key.as_slice())?;
                }
                transaction.commit()?;
                Ok(())
            })
        })
        .await
        .map_err(|e| InfrastructureError::Database(format!("spawn_blocking join error: {e}")))?
    }

    async fn scan(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, InfrastructureError> {
        let prefix = prefix.to_vec();
        self.blocking(move |db| {
            let read = || -> Result<Vec<(Vec<u8>, Vec<u8>)>, redb::Error> {
                let transaction = db.begin_read()?;
                let mut results = Vec::new();
                match scan_scope(&prefix) {
                    ScanScope::Default => {
                        collect_prefix(
                            &transaction.open_table(DEFAULT_TABLE)?,
                            &prefix,
                            &mut results,
                        )?;
                    }
                    ScanScope::Outbox => {
                        collect_prefix(
                            &transaction.open_table(OUTBOX_TABLE)?,
                            &prefix,
                            &mut results,
                        )?;
                    }
                    ScanScope::Both => {
                        collect_prefix(
                            &transaction.open_table(DEFAULT_TABLE)?,
                            &prefix,
                            &mut results,
                        )?;
                        collect_prefix(
                            &transaction.open_table(OUTBOX_TABLE)?,
                            &prefix,
                            &mut results,
                        )?;
                        results.sort_by(|left, right| left.0.cmp(&right.0));
                    }
                }
                Ok(results)
            };
            read().map_err(|error| database_error("prefix scan", error))
        })
        .await?
    }
}

#[async_trait]
impl IReplayProtection for NodeStore {
    async fn check_and_tag(
        &self,
        tag: &[u8],
        ttl_seconds: u64,
    ) -> Result<bool, InfrastructureError> {
        let tag = tag.to_vec();
        self.blocking(move |db| {
            // Expiry stored in milliseconds to avoid rounding issues.
            let now = unix_millis();
            let expiry = now.saturating_add(ttl_seconds.saturating_mul(1000));
            write_transaction::<_, String>(db, |transaction| {
                let mut table = transaction.open_table(REPLAY_TABLE)?;
                if let Some(existing) = get_bytes(&table, &tag)? {
                    let live = <[u8; 8]>::try_from(existing.as_slice())
                        .map_or(true, |bytes| u64::from_be_bytes(bytes) >= now);
                    if live {
                        return Ok(true);
                    }
                }
                table.insert(tag.as_slice(), expiry.to_be_bytes().as_slice())?;
                Ok(false)
            })
            .map_err(|error| string_write_error("replay tag", error))
        })
        .await?
    }

    /// Removes expired replay tags. Only the replay table is scanned.
    async fn prune_expired(&self) -> Result<usize, InfrastructureError> {
        self.blocking(|db| {
            let now = unix_millis();
            write_transaction::<_, String>(db, |transaction| {
                let mut table = transaction.open_table(REPLAY_TABLE)?;
                let mut removed = 0_usize;
                table.retain(|_, value| {
                    let expired = <[u8; 8]>::try_from(value)
                        .is_ok_and(|bytes| u64::from_be_bytes(bytes) < now);
                    if expired {
                        removed += 1;
                    }
                    !expired
                })?;
                Ok(removed)
            })
            .map_err(|error| string_write_error("replay prune", error))
        })
        .await?
    }
}

fn unix_millis() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

/// Number of entries in a table, for tests.
#[cfg(test)]
pub(crate) fn table_len(db: &Database, table: BytesTable) -> Result<u64, InfrastructureError> {
    use redb::ReadableTableMetadata;
    let transaction = db
        .begin_read()
        .map_err(|error| database_error("begin read", error))?;
    let table = transaction
        .open_table(table)
        .map_err(|error| database_error("open table", error))?;
    table
        .len()
        .map_err(|error| database_error("table length", error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::time::sleep;

    fn test_repo() -> (tempfile::TempDir, NodeStore) {
        let dir = tempdir().expect("tempdir");
        let repo = NodeStore::new(dir.path()).expect("open store");
        (dir, repo)
    }

    fn raw_get(repo: &NodeStore, table: BytesTable, key: &[u8]) -> Option<Vec<u8>> {
        let transaction = repo.db.begin_read().unwrap();
        let table = transaction.open_table(table).unwrap();
        get_bytes(&table, key).unwrap()
    }

    const CURSOR_KEY: &[u8] = b"chain_observer:last_block";

    #[tokio::test]
    async fn crud_and_prefix_scan() {
        let (_dir, repo) = test_repo();
        repo.put(b"key1", b"val1").await.unwrap();
        assert!(repo.exists(b"key1").await.unwrap());
        assert_eq!(repo.get(b"key1").await.unwrap(), Some(b"val1".to_vec()));
        repo.delete(b"key1").await.unwrap();
        assert!(!repo.exists(b"key1").await.unwrap());
        assert_eq!(repo.get(b"missing").await.unwrap(), None);

        repo.put(b"peer:A", b"infoA").await.unwrap();
        repo.put(b"peer:B", b"infoB").await.unwrap();
        repo.put(b"other:C", b"infoC").await.unwrap();
        let peers = repo.scan(b"peer:").await.unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].0, b"peer:A");
        assert_eq!(peers[1].0, b"peer:B");
    }

    #[tokio::test]
    async fn values_survive_reopen() {
        let dir = tempdir().unwrap();
        {
            let repo = NodeStore::new(dir.path()).unwrap();
            repo.put(b"nonce:local", &5_u64.to_le_bytes())
                .await
                .unwrap();
        }
        let repo = NodeStore::new(dir.path()).unwrap();
        assert_eq!(
            repo.get(b"nonce:local").await.unwrap(),
            Some(5_u64.to_le_bytes().to_vec())
        );
    }

    #[test]
    fn a_second_open_of_the_same_directory_is_refused() {
        let dir = tempdir().unwrap();
        let _first = NodeStore::new(dir.path()).unwrap();
        assert!(NodeStore::new(dir.path()).is_err());
    }

    #[tokio::test]
    async fn replay_protection_and_pruning() {
        let (_dir, repo) = test_repo();
        assert!(!repo.check_and_tag(b"tag", 2).await.unwrap());
        assert!(repo.check_and_tag(b"tag", 2).await.unwrap());
        repo.check_and_tag(b"old", 0).await.unwrap();
        repo.put(CURSOR_KEY, &315_000_000_u64.to_be_bytes())
            .await
            .unwrap();
        repo.put(b"nonce:local", &0_u64.to_le_bytes())
            .await
            .unwrap();
        sleep(Duration::from_millis(1_100)).await;
        assert_eq!(repo.prune_expired().await.unwrap(), 1);
        assert!(raw_get(&repo, REPLAY_TABLE, b"old").is_none());
        assert!(raw_get(&repo, REPLAY_TABLE, b"tag").is_some());
        for key in [CURSOR_KEY, b"nonce:local".as_slice()] {
            assert!(repo.exists(key).await.unwrap());
        }
        sleep(Duration::from_secs(2)).await;
        assert!(!repo.check_and_tag(b"tag", 2).await.unwrap());
    }

    #[tokio::test]
    async fn store_routes_outbox_keys_to_their_table() {
        let (_dir, repo) = test_repo();
        repo.put(b"tx:4", b"record").await.unwrap();
        repo.put(b"outbox:cc", b"record").await.unwrap();
        repo.put(b"peer:a", b"node").await.unwrap();
        assert!(raw_get(&repo, DEFAULT_TABLE, b"tx:4").is_none());
        assert!(raw_get(&repo, OUTBOX_TABLE, b"tx:4").is_some());
        assert!(raw_get(&repo, OUTBOX_TABLE, b"peer:a").is_none());
        let everything: Vec<Vec<u8>> = repo
            .scan(b"")
            .await
            .unwrap()
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        assert_eq!(
            everything,
            vec![b"outbox:cc".to_vec(), b"peer:a".to_vec(), b"tx:4".to_vec()]
        );
        assert_eq!(repo.scan(b"t").await.unwrap().len(), 1);
    }

    #[test]
    fn retry_latches_degraded_on_persistent_io_errors() {
        let (_dir, repo) = test_repo();
        let calls = std::sync::atomic::AtomicU32::new(0);
        let result: Result<(), _> = repo.with_retry("test", || {
            calls.fetch_add(1, Ordering::Relaxed);
            Err(redb::Error::Io(std::io::Error::other(
                "no space left on device",
            )))
        });
        assert!(result.is_err());
        assert_eq!(
            calls.load(Ordering::Relaxed) as usize,
            RETRY_BACKOFF_MS.len() + 1
        );
        assert!(repo.is_degraded());
        assert_eq!(
            repo.with_retry("test", || Ok::<_, redb::Error>(1)).unwrap(),
            1
        );
        assert!(!repo.is_degraded());
        let logic: Result<(), _> =
            repo.with_retry("test", || Err(redb::Error::Corrupted("x".to_string())));
        assert!(logic.is_err());
        assert!(!repo.is_degraded());
    }

    fn counters(outstanding: u64, pending: u64, loss: u64, start: Option<u64>) -> QuoteCounters {
        QuoteCounters {
            outstanding,
            pending_sponsored_gas: pending,
            rolling_loss_native: U256::from(loss),
            loss_window_start: start,
        }
    }

    #[test]
    fn quote_admission_mirrors_reservation_limits() {
        let limit = U256::from(100);
        assert!(counters(0, 0, 0, None)
            .admit(10, 2, 20, limit, 60, 1_000)
            .is_ok());
        assert!(matches!(
            counters(2, 0, 0, None).admit(10, 2, 20, limit, 60, 1_000),
            Err(QuoteStoreError::OutstandingCapacity)
        ));
        assert!(matches!(
            counters(1, 15, 0, None).admit(10, 2, 20, limit, 60, 1_000),
            Err(QuoteStoreError::PendingGasCapacity)
        ));
        assert!(matches!(
            counters(0, 0, 100, Some(990)).admit(10, 2, 20, limit, 60, 1_000),
            Err(QuoteStoreError::PendingLossLimit)
        ));
        assert!(counters(0, 0, 100, Some(900))
            .admit(10, 2, 20, limit, 60, 1_000)
            .is_ok());
    }

    #[tokio::test]
    async fn quote_counters_default_to_zero_and_read_stored_values() {
        let (_dir, repo) = test_repo();
        assert_eq!(
            repo.quote_counters().await.unwrap(),
            QuoteCounters::default()
        );
        repo.put(b"quote:outstanding", &3_u64.to_le_bytes())
            .await
            .unwrap();
        repo.put(b"quote:pending-gas", &4_000_u64.to_le_bytes())
            .await
            .unwrap();
        repo.put(b"quote:loss-window-start", &50_u64.to_le_bytes())
            .await
            .unwrap();
        let mut loss = [0_u8; 32];
        U256::from(7).to_big_endian(&mut loss);
        repo.put(b"quote:rolling-loss", &loss).await.unwrap();
        assert_eq!(
            repo.quote_counters().await.unwrap(),
            counters(3, 4_000, 7, Some(50))
        );
    }

    fn v2_record(seed: u8, nonce: u64) -> PendingTransactionV2 {
        PendingTransactionV2 {
            execution_id: [seed; 32],
            to: "0x1111111111111111111111111111111111111111".to_string(),
            data_hash: [seed; 32],
            nonce,
            gas_limit: "21000".to_string(),
            gas_price: "1".to_string(),
            maximum_fee_per_gas: "1".to_string(),
            raw_signed_tx: vec![200_u8; 16_500],
            tx_hash: format!("0x{}", hex::encode([seed; 32])),
            prior_transaction_hashes: Vec::new(),
            replacement_attempts: 0,
            first_sent_at: 1,
            last_update_at: 1,
            status: nox_core::TxStatusV2::Mined,
        }
    }

    #[tokio::test]
    async fn durable_outbox_writes_are_atomic_and_idempotent() {
        let (_dir, repo) = test_repo();
        let first = v2_record(0x01, 0);
        let second = v2_record(0x02, 1);
        assert!(matches!(
            repo.create_outbox_durably(first.execution_id, &first, 1)
                .await
                .unwrap(),
            CreateOutboxResult::Created
        ));
        assert!(matches!(
            repo.create_outbox_durably(second.execution_id, &second, 2)
                .await
                .unwrap(),
            CreateOutboxResult::Created
        ));
        repo.persist_v2_durably(&second).await.unwrap();
        assert_eq!(table_len(&repo.db, OUTBOX_TABLE).unwrap(), 4);
        assert_eq!(
            raw_get(&repo, DEFAULT_TABLE, b"nonce:local").unwrap(),
            2_u64.to_le_bytes().to_vec()
        );
        assert!(matches!(
            repo.create_outbox_durably(first.execution_id, &first, 3)
                .await
                .unwrap(),
            CreateOutboxResult::Existing(_)
        ));
        // An existing record leaves the nonce floor alone.
        assert_eq!(
            raw_get(&repo, DEFAULT_TABLE, b"nonce:local").unwrap(),
            2_u64.to_le_bytes().to_vec()
        );
        assert_eq!(
            repo.load_outbox_by_execution(second.execution_id)
                .await
                .unwrap()
                .unwrap()
                .nonce,
            1
        );
    }

    /// The failure mode that made sled grow on nox-7: a small key rewritten
    /// next to large records. redb reuses freed pages, so the file stays put.
    #[tokio::test]
    async fn hot_key_rewrites_next_to_large_records_do_not_grow_the_file() {
        let (dir, repo) = test_repo();
        for record in [v2_record(0x01, 0), v2_record(0x02, 1)] {
            repo.create_outbox_durably(record.execution_id, &record, record.nonce + 1)
                .await
                .unwrap();
        }
        for block in 0..200_u64 {
            repo.put(CURSOR_KEY, &block.to_be_bytes()).await.unwrap();
        }
        let settled = std::fs::metadata(dir.path().join(DATABASE_FILE))
            .unwrap()
            .len();
        for block in 200..2_000_u64 {
            repo.put(CURSOR_KEY, &block.to_be_bytes()).await.unwrap();
        }
        let after = std::fs::metadata(dir.path().join(DATABASE_FILE))
            .unwrap()
            .len();
        assert!(after <= settled, "file grew from {settled} to {after}");
    }
}
