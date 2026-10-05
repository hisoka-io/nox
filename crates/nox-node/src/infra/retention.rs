//! Retention for records that are finished: mined or failed exit transactions
//! and quotes that can no longer be used.
//!
//! What is never touched:
//! - transactions that are not `Mined`/`Failed` (legacy: not `Mined`/`Failed`),
//!   because the monitor may still rebroadcast, replace or reconcile them;
//! - quotes that are `Outstanding`, `Inflight` or `Submitted`, because the
//!   reservation counters still include them;
//! - `nonce:local` and the quote counters, which nonce and capacity recovery
//!   read on every start.
//!
//! A terminal transaction record is never read again by the node: startup
//! hydration skips it and the nonce floor comes from `nonce:local` and the
//! chain. Slimming drops its signed bytes (recoverable from the chain by hash);
//! pruning deletes it. A terminal quote is pruned only after its
//! `valid_until`, when the request validation and the entry point both refuse
//! it anyway.
//!
//! Every change is a compare-and-swap against the bytes that were read, so a
//! record that changes during the sweep is left for the next pass.

use std::path::Path;

use nox_core::traits::InfrastructureError;
use nox_core::{
    DecodedTransaction, LegacyTxStatus, QuoteStatusV2, StoredQuoteV2, StoredTransactionV2,
    TxStatusV2,
};
use sled::transaction::{ConflictableTransactionError, TransactionError};
use sled::Tree;
use tracing::warn;

use crate::config::StorageConfig;
use crate::infra::storage::{decode_stored_transaction, SledRepository};

/// Thresholds for one retention sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Delete terminal records once old enough. `false` keeps them forever
    /// (they are still slimmed).
    pub prune_terminal_records: bool,
    pub slim_terminal_transactions_after_secs: u64,
    pub terminal_transaction_retention_secs: u64,
    pub expired_quote_retention_secs: u64,
    pub terminal_quote_retention_secs: u64,
    /// Most records changed by one sweep.
    pub batch_limit: usize,
}

impl RetentionPolicy {
    #[must_use]
    pub fn from_config(config: &StorageConfig) -> Self {
        Self {
            prune_terminal_records: config.prune_terminal_records,
            slim_terminal_transactions_after_secs: config.slim_terminal_transactions_after_secs,
            terminal_transaction_retention_secs: config.terminal_transaction_retention_secs,
            expired_quote_retention_secs: config.expired_quote_retention_secs,
            terminal_quote_retention_secs: config.terminal_quote_retention_secs,
            batch_limit: config.maintenance_batch_limit,
        }
    }
}

/// What one sweep changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RetentionReport {
    pub outbox_slimmed: usize,
    pub transactions_slimmed: usize,
    pub outbox_pruned: usize,
    pub transactions_pruned: usize,
    pub quotes_pruned: usize,
    pub payment_indexes_pruned: usize,
    /// Records skipped because they did not decode. Startup hydration fails
    /// closed on the same records, so they need an operator either way.
    pub undecodable: usize,
    /// The batch limit stopped the sweep before it saw every record.
    pub budget_exhausted: bool,
}

impl RetentionReport {
    #[must_use]
    pub fn changed(&self) -> usize {
        self.outbox_slimmed
            + self.transactions_slimmed
            + self.outbox_pruned
            + self.transactions_pruned
            + self.quotes_pruned
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RecordAction {
    Keep,
    Slim(Vec<u8>),
    Prune,
}

fn database_error(context: &str, error: impl std::fmt::Display) -> InfrastructureError {
    InfrastructureError::Database(format!("{context}: {error}"))
}

/// Decides what happens to one `outbox:*` or `tx:*` record.
fn transaction_action(
    bytes: &[u8],
    policy: &RetentionPolicy,
    now_unix: u64,
) -> Result<RecordAction, InfrastructureError> {
    let decoded = decode_stored_transaction(bytes)?;
    let (terminal, last_update_at, has_payload) = match &decoded {
        DecodedTransaction::V2(transaction) => (
            matches!(transaction.status, TxStatusV2::Mined | TxStatusV2::Failed),
            transaction.last_update_at,
            !transaction.raw_signed_tx.is_empty(),
        ),
        DecodedTransaction::Legacy(transaction) => (
            matches!(
                transaction.status,
                LegacyTxStatus::Mined | LegacyTxStatus::Failed
            ),
            transaction.last_update_at,
            !transaction.data.is_empty(),
        ),
    };
    if !terminal {
        return Ok(RecordAction::Keep);
    }
    let age = now_unix.saturating_sub(last_update_at);
    if policy.prune_terminal_records && age >= policy.terminal_transaction_retention_secs {
        return Ok(RecordAction::Prune);
    }
    if age < policy.slim_terminal_transactions_after_secs || !has_payload {
        return Ok(RecordAction::Keep);
    }
    let encoded = match decoded {
        DecodedTransaction::V2(mut transaction) => {
            transaction.raw_signed_tx = Vec::new();
            serde_json::to_vec(&StoredTransactionV2 {
                schema: 2,
                transaction,
            })
        }
        DecodedTransaction::Legacy(mut transaction) => {
            transaction.data = Vec::new();
            serde_json::to_vec(&transaction)
        }
    }
    .map_err(|error| database_error("encode slimmed transaction record", error))?;
    Ok(RecordAction::Slim(encoded))
}

/// Remaining changes this sweep may make.
struct Budget(usize);

impl Budget {
    fn take(&mut self) -> bool {
        if self.0 == 0 {
            return false;
        }
        self.0 -= 1;
        true
    }
}

fn prefix_keys(tree: &Tree, prefix: &[u8]) -> Result<Vec<sled::IVec>, InfrastructureError> {
    tree.scan_prefix(prefix)
        .keys()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            database_error(
                &format!("retention scan of {} keys", String::from_utf8_lossy(prefix)),
                error,
            )
        })
}

/// Applies [`transaction_action`] to every record under `prefix` in the outbox
/// tree. Returns `(slimmed, pruned)`.
fn sweep_transactions(
    tree: &Tree,
    prefix: &[u8],
    policy: &RetentionPolicy,
    now_unix: u64,
    budget: &mut Budget,
    report: &mut RetentionReport,
) -> Result<(usize, usize), InfrastructureError> {
    let mut slimmed = 0_usize;
    let mut pruned = 0_usize;
    for key in prefix_keys(tree, prefix)? {
        let Some(current) = tree
            .get(&key)
            .map_err(|error| database_error("retention read", error))?
        else {
            continue;
        };
        let action = match transaction_action(&current, policy, now_unix) {
            Ok(action) => action,
            Err(error) => {
                report.undecodable += 1;
                warn!(
                    key = %String::from_utf8_lossy(&key),
                    error = %error,
                    "Retention skipped a transaction record that does not decode"
                );
                continue;
            }
        };
        let new_value = match action {
            RecordAction::Keep => continue,
            RecordAction::Slim(bytes) => Some(bytes),
            RecordAction::Prune => None,
        };
        if !budget.take() {
            report.budget_exhausted = true;
            break;
        }
        let is_prune = new_value.is_none();
        let swapped = tree
            .compare_and_swap(&key, Some(current.as_ref()), new_value)
            .map_err(|error| database_error("retention compare-and-swap", error))?;
        if swapped.is_ok() {
            if is_prune {
                pruned += 1;
            } else {
                slimmed += 1;
            }
        }
    }
    Ok((slimmed, pruned))
}

fn quote_is_prunable(record: &StoredQuoteV2, policy: &RetentionPolicy, now_unix: u64) -> bool {
    let retention = match record.status {
        QuoteStatusV2::Expired => policy.expired_quote_retention_secs,
        QuoteStatusV2::Confirmed | QuoteStatusV2::Reverted | QuoteStatusV2::Rejected => {
            policy.terminal_quote_retention_secs
        }
        QuoteStatusV2::Outstanding | QuoteStatusV2::Inflight | QuoteStatusV2::Submitted => {
            return false;
        }
    };
    now_unix.saturating_sub(record.quote.valid_until_unix) >= retention
        && record.quote.valid_until_unix <= now_unix
}

/// Deletes one terminal quote and its payment index, if both are unchanged.
/// Returns `Some(payment_index_removed)` when the quote was deleted.
fn prune_quote(
    tree: &Tree,
    execution_key: &[u8],
    expected: &[u8],
    record: &StoredQuoteV2,
) -> Result<Option<bool>, InfrastructureError> {
    let payment_key = format!("quote:payment:{}", hex::encode(record.request.payment_id));
    let execution_id = record.execution_id;
    tree.transaction(|tx| {
        match tx.get(execution_key)? {
            Some(current) if current.as_ref() == expected => {}
            _ => return Ok(None),
        }
        tx.remove(execution_key)?;
        let index_matches = tx
            .get(payment_key.as_bytes())?
            .is_some_and(|value| value.as_ref() == execution_id.as_slice());
        if index_matches {
            tx.remove(payment_key.as_bytes())?;
        }
        Ok::<_, ConflictableTransactionError<()>>(Some(index_matches))
    })
    .map_err(|error: TransactionError<()>| {
        database_error("retention quote prune", format!("{error:?}"))
    })
}

fn sweep_quotes(
    tree: &Tree,
    policy: &RetentionPolicy,
    now_unix: u64,
    budget: &mut Budget,
    report: &mut RetentionReport,
) -> Result<(), InfrastructureError> {
    if !policy.prune_terminal_records {
        return Ok(());
    }
    for key in prefix_keys(tree, b"quote:execution:")? {
        let Some(current) = tree
            .get(&key)
            .map_err(|error| database_error("retention quote read", error))?
        else {
            continue;
        };
        let record: StoredQuoteV2 = match serde_json::from_slice(&current) {
            Ok(record) => record,
            Err(error) => {
                report.undecodable += 1;
                warn!(
                    key = %String::from_utf8_lossy(&key),
                    error = %error,
                    "Retention skipped a quote record that does not decode"
                );
                continue;
            }
        };
        if !quote_is_prunable(&record, policy, now_unix) {
            continue;
        }
        if !budget.take() {
            report.budget_exhausted = true;
            break;
        }
        if let Some(index_removed) = prune_quote(tree, &key, &current, &record)? {
            report.quotes_pruned += 1;
            if index_removed {
                report.payment_indexes_pruned += 1;
            }
        }
    }
    Ok(())
}

/// One synchronous sweep over the outbox tree and the quote records.
fn sweep(
    default_tree: &Tree,
    outbox: Option<&Tree>,
    policy: &RetentionPolicy,
    now_unix: u64,
) -> Result<RetentionReport, InfrastructureError> {
    let mut report = RetentionReport::default();
    let mut budget = Budget(policy.batch_limit);
    if let Some(outbox) = outbox {
        let (slimmed, pruned) = sweep_transactions(
            outbox,
            b"outbox:",
            policy,
            now_unix,
            &mut budget,
            &mut report,
        )?;
        report.outbox_slimmed = slimmed;
        report.outbox_pruned = pruned;
        if !report.budget_exhausted {
            let (slimmed, pruned) =
                sweep_transactions(outbox, b"tx:", policy, now_unix, &mut budget, &mut report)?;
            report.transactions_slimmed = slimmed;
            report.transactions_pruned = pruned;
        }
    }
    if !report.budget_exhausted {
        sweep_quotes(default_tree, policy, now_unix, &mut budget, &mut report)?;
    }
    Ok(report)
}

impl SledRepository {
    /// Slims and prunes terminal transaction and quote records, then flushes.
    ///
    /// When a durable outbox write has failed the outbox tree is left alone
    /// until restart; quote records are still swept.
    pub async fn apply_retention(
        &self,
        policy: RetentionPolicy,
        now_unix: u64,
    ) -> Result<RetentionReport, InfrastructureError> {
        let default_tree = self.default_tree().clone();
        let outbox = (!self.is_outbox_degraded()).then(|| self.outbox_tree().clone());
        let report = tokio::task::spawn_blocking(move || {
            sweep(&default_tree, outbox.as_ref(), &policy, now_unix)
        })
        .await
        .map_err(|error| database_error("retention task failed", error))??;
        if report.changed() > 0 {
            self.flush_durably("retention sweep").await?;
        }
        Ok(report)
    }

    /// Number of records per tree and key kind. Every known kind is listed,
    /// with zero when absent, so a gauge that drops to zero is reported.
    pub async fn record_counts(&self) -> Result<Vec<RecordCount>, InfrastructureError> {
        let default_tree = self.default_tree().clone();
        let outbox = self.outbox_tree().clone();
        let replay = self.replay_tree().clone();
        tokio::task::spawn_blocking(move || {
            let mut counts: Vec<RecordCount> = Vec::new();
            for (tree_name, tree) in [
                (TREE_LABEL_DEFAULT, &default_tree),
                (TREE_LABEL_OUTBOX, &outbox),
                (TREE_LABEL_REPLAY, &replay),
            ] {
                let mut per_kind = [0_u64; RECORD_KINDS.len()];
                for key in tree.iter().keys() {
                    let key = key.map_err(|error| database_error("record count scan", error))?;
                    let kind = if tree_name == TREE_LABEL_REPLAY {
                        RECORD_KIND_REPLAY_TAG
                    } else {
                        record_kind(&key)
                    };
                    if let Some(index) = RECORD_KINDS.iter().position(|known| *known == kind) {
                        per_kind[index] = per_kind[index].saturating_add(1);
                    }
                }
                counts.extend(
                    RECORD_KINDS
                        .iter()
                        .zip(per_kind)
                        .filter(|(kind, count)| *count > 0 || kind_lives_in(kind, tree_name))
                        .map(|(kind, count)| RecordCount {
                            tree: tree_name,
                            kind,
                            count,
                        }),
                );
            }
            Ok(counts)
        })
        .await
        .map_err(|error| database_error("record count task failed", error))?
    }
}

pub const TREE_LABEL_DEFAULT: &str = "default";
pub const TREE_LABEL_OUTBOX: &str = "exit_outbox";
pub const TREE_LABEL_REPLAY: &str = "replay_tags";

const RECORD_KIND_REPLAY_TAG: &str = "replay_tag";

/// Key kinds reported by [`SledRepository::record_counts`].
pub const RECORD_KINDS: [&str; 11] = [
    "outbox",
    "transaction",
    "quote",
    "quote_payment_index",
    "quote_counter",
    "nonce",
    "session",
    "peer",
    "chain_observer",
    RECORD_KIND_REPLAY_TAG,
    "other",
];

fn record_kind(key: &[u8]) -> &'static str {
    const PREFIXES: [(&[u8], &str); 9] = [
        (b"outbox:", "outbox"),
        (b"tx:", "transaction"),
        (b"quote:execution:", "quote"),
        (b"quote:payment:", "quote_payment_index"),
        (b"quote:", "quote_counter"),
        (b"nonce:", "nonce"),
        (b"session:", "session"),
        (b"peer:", "peer"),
        (b"chain_observer:", "chain_observer"),
    ];
    PREFIXES
        .iter()
        .find(|(prefix, _)| key.starts_with(prefix))
        .map_or("other", |(_, kind)| kind)
}

/// Kinds that are always reported for a tree, even at zero.
fn kind_lives_in(kind: &str, tree: &str) -> bool {
    match tree {
        TREE_LABEL_OUTBOX => matches!(kind, "outbox" | "transaction"),
        TREE_LABEL_REPLAY => kind == RECORD_KIND_REPLAY_TAG,
        _ => matches!(
            kind,
            "quote"
                | "quote_payment_index"
                | "quote_counter"
                | "nonce"
                | "session"
                | "peer"
                | "chain_observer"
                | "other"
        ),
    }
}

/// One `nox_storage_records` sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordCount {
    pub tree: &'static str,
    pub kind: &'static str,
    pub count: u64,
}

/// Number and total size of sled's blob files under `db_path/blobs`.
pub fn blob_usage(db_path: &Path) -> Result<(u64, u64), InfrastructureError> {
    let entries = match std::fs::read_dir(db_path.join("blobs")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0)),
        Err(error) => {
            return Err(database_error(
                &format!("read blob directory under {}", db_path.display()),
                error,
            ))
        }
    };
    let mut files = 0_u64;
    let mut bytes = 0_u64;
    for entry in entries {
        let entry = entry.map_err(|error| database_error("read blob directory entry", error))?;
        let metadata = entry
            .metadata()
            .map_err(|error| database_error("read blob file metadata", error))?;
        if metadata.is_file() {
            files = files.saturating_add(1);
            bytes = bytes.saturating_add(metadata.len());
        }
    }
    Ok((files, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nox_core::{LegacyPendingTransaction, PendingTransactionV2};

    fn policy() -> RetentionPolicy {
        RetentionPolicy {
            prune_terminal_records: true,
            slim_terminal_transactions_after_secs: 100,
            terminal_transaction_retention_secs: 1_000,
            expired_quote_retention_secs: 50,
            terminal_quote_retention_secs: 500,
            batch_limit: 100,
        }
    }

    fn v2(status: TxStatusV2, last_update_at: u64) -> PendingTransactionV2 {
        PendingTransactionV2 {
            execution_id: [1; 32],
            to: "0x1111111111111111111111111111111111111111".to_string(),
            data_hash: [2; 32],
            nonce: 3,
            gas_limit: "21000".to_string(),
            gas_price: "1".to_string(),
            maximum_fee_per_gas: "1".to_string(),
            raw_signed_tx: vec![7; 64],
            tx_hash: format!("0x{}", "ab".repeat(32)),
            prior_transaction_hashes: Vec::new(),
            replacement_attempts: 0,
            first_sent_at: last_update_at,
            last_update_at,
            status,
        }
    }

    fn encode(transaction: &PendingTransactionV2) -> Vec<u8> {
        serde_json::to_vec(&StoredTransactionV2 {
            schema: 2,
            transaction: transaction.clone(),
        })
        .unwrap()
    }

    #[test]
    fn non_terminal_transactions_are_always_kept() {
        for status in [
            TxStatusV2::Prepared,
            TxStatusV2::Submitted,
            TxStatusV2::ReplacementPrepared,
            TxStatusV2::Replaced,
        ] {
            let bytes = encode(&v2(status.clone(), 0));
            assert_eq!(
                transaction_action(&bytes, &policy(), u64::MAX).unwrap(),
                RecordAction::Keep,
                "{status:?}"
            );
        }
    }

    #[test]
    fn terminal_transactions_are_slimmed_then_pruned() {
        for status in [TxStatusV2::Mined, TxStatusV2::Failed] {
            let bytes = encode(&v2(status.clone(), 1_000));
            assert_eq!(
                transaction_action(&bytes, &policy(), 1_099).unwrap(),
                RecordAction::Keep
            );
            let RecordAction::Slim(slim) = transaction_action(&bytes, &policy(), 1_100).unwrap()
            else {
                panic!("expected a slimmed record");
            };
            let DecodedTransaction::V2(decoded) = decode_stored_transaction(&slim).unwrap() else {
                panic!("slimmed record must stay v2");
            };
            assert!(decoded.raw_signed_tx.is_empty());
            assert_eq!(decoded.tx_hash, v2(status.clone(), 1_000).tx_hash);
            assert_eq!(decoded.status, status);
            // An already slim record is not rewritten.
            assert_eq!(
                transaction_action(&slim, &policy(), 1_500).unwrap(),
                RecordAction::Keep
            );
            assert_eq!(
                transaction_action(&bytes, &policy(), 2_000).unwrap(),
                RecordAction::Prune
            );
        }
    }

    #[test]
    fn disabled_pruning_still_slims() {
        let keep_forever = RetentionPolicy {
            prune_terminal_records: false,
            ..policy()
        };
        let bytes = encode(&v2(TxStatusV2::Mined, 0));
        assert!(matches!(
            transaction_action(&bytes, &keep_forever, u64::MAX).unwrap(),
            RecordAction::Slim(_)
        ));
    }

    #[test]
    fn legacy_terminal_records_follow_the_same_rules() {
        let legacy = |status: LegacyTxStatus| LegacyPendingTransaction {
            id: "legacy".to_string(),
            to: "0x1111111111111111111111111111111111111111".to_string(),
            data: vec![9; 32],
            nonce: 1,
            gas_limit: "21000".to_string(),
            gas_price: "1".to_string(),
            tx_hash: format!("0x{}", "cd".repeat(32)),
            first_sent_at: 0,
            last_update_at: 0,
            status,
        };
        for status in [LegacyTxStatus::Pending, LegacyTxStatus::Replaced] {
            let bytes = serde_json::to_vec(&legacy(status)).unwrap();
            assert_eq!(
                transaction_action(&bytes, &policy(), u64::MAX).unwrap(),
                RecordAction::Keep
            );
        }
        let bytes = serde_json::to_vec(&legacy(LegacyTxStatus::Mined)).unwrap();
        assert!(matches!(
            transaction_action(&bytes, &policy(), 500).unwrap(),
            RecordAction::Slim(_)
        ));
        assert_eq!(
            transaction_action(&bytes, &policy(), 1_000).unwrap(),
            RecordAction::Prune
        );
    }

    #[test]
    fn record_kinds_cover_every_prefix() {
        assert_eq!(record_kind(b"outbox:aa"), "outbox");
        assert_eq!(record_kind(b"tx:1"), "transaction");
        assert_eq!(record_kind(b"quote:execution:aa"), "quote");
        assert_eq!(record_kind(b"quote:payment:aa"), "quote_payment_index");
        assert_eq!(record_kind(b"quote:nonce"), "quote_counter");
        assert_eq!(record_kind(b"nonce:local"), "nonce");
        assert_eq!(record_kind(b"session:x"), "session");
        assert_eq!(record_kind(b"peer:0x1"), "peer");
        assert_eq!(record_kind(b"chain_observer:last_block"), "chain_observer");
        assert_eq!(record_kind(b"unexpected"), "other");
    }

    #[test]
    fn blob_usage_of_a_missing_directory_is_zero() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(blob_usage(dir.path()).unwrap(), (0, 0));
        std::fs::create_dir(dir.path().join("blobs")).unwrap();
        std::fs::write(dir.path().join("blobs").join("12"), [0_u8; 10]).unwrap();
        assert_eq!(blob_usage(dir.path()).unwrap(), (1, 10));
    }

    fn quote(
        execution_id: [u8; 32],
        status: QuoteStatusV2,
        valid_until_unix: u64,
    ) -> StoredQuoteV2 {
        StoredQuoteV2 {
            schema: 1,
            request: nox_core::PaidQuoteRequestV2 {
                chain_id: 31_337,
                entry_point: [1; 20],
                client_intent_id: [2; 32],
                payment_adapter: [3; 20],
                payment_id: execution_id,
                fee_asset: [4; 20],
                payment_gas_limit: 21_000,
                action_target: [5; 20],
                action_calldata_hash: [6; 32],
                action_gas_limit: 21_000,
                tracked_assets_hash: [7; 32],
                maximum_transaction_gas: 100_000,
                return_data_limit: 0,
                valid_until_unix,
            },
            quote: nox_core::ExecutionQuoteV1 {
                quote_version: 1,
                chain_id: [0; 32],
                entry_point: [1; 20],
                exit_address: [2; 20],
                client_intent_id: [2; 32],
                payment_adapter: [3; 20],
                payment_id: execution_id,
                fee_asset: [4; 20],
                exit_fee: [0; 32],
                network_fee: [0; 32],
                payment_gas_limit: [0; 32],
                action_target: [5; 20],
                action_calldata_hash: [6; 32],
                action_gas_limit: [0; 32],
                tracked_assets_hash: [7; 32],
                maximum_transaction_gas: [0; 32],
                maximum_fee_per_gas: [0; 32],
                return_data_limit: [0; 32],
                valid_after_unix: 0,
                valid_until_unix,
                quote_nonce: [0; 32],
            },
            execution_id,
            exit_signature: vec![0; 65],
            pending_sponsored_gas: 100_000,
            rolling_loss_window_secs: 3_600,
            status,
        }
    }

    fn put_quote(repo: &SledRepository, record: &StoredQuoteV2) {
        let tree = repo.default_tree();
        tree.insert(
            format!("quote:execution:{}", hex::encode(record.execution_id)).as_bytes(),
            serde_json::to_vec(record).unwrap(),
        )
        .unwrap();
        tree.insert(
            format!("quote:payment:{}", hex::encode(record.request.payment_id)).as_bytes(),
            record.execution_id.as_slice(),
        )
        .unwrap();
    }

    fn has_quote(repo: &SledRepository, execution_id: [u8; 32]) -> bool {
        repo.default_tree()
            .contains_key(format!("quote:execution:{}", hex::encode(execution_id)).as_bytes())
            .unwrap()
    }

    fn has_payment_index(repo: &SledRepository, payment_id: [u8; 32]) -> bool {
        repo.default_tree()
            .contains_key(format!("quote:payment:{}", hex::encode(payment_id)).as_bytes())
            .unwrap()
    }

    fn outbox_record(
        repo: &SledRepository,
        execution_id: [u8; 32],
    ) -> Option<PendingTransactionV2> {
        let bytes = repo
            .outbox_tree()
            .get(format!("outbox:{}", hex::encode(execution_id)).as_bytes())
            .unwrap()?;
        match decode_stored_transaction(&bytes).unwrap() {
            DecodedTransaction::V2(transaction) => Some(transaction),
            DecodedTransaction::Legacy(_) => None,
        }
    }

    async fn store_transaction(
        repo: &SledRepository,
        seed: u8,
        nonce: u64,
        status: TxStatusV2,
        last_update_at: u64,
    ) {
        let mut record = v2(TxStatusV2::Prepared, last_update_at);
        record.execution_id = [seed; 32];
        record.nonce = nonce;
        repo.create_outbox_durably(record.execution_id, &record, nonce + 1)
            .await
            .unwrap();
        record.status = status;
        repo.persist_v2_durably(&record).await.unwrap();
    }

    const NOW: u64 = 10_000;

    #[tokio::test]
    async fn sweep_removes_only_finished_transactions_and_keeps_the_nonce_floor() {
        let dir = tempfile::tempdir().unwrap();
        let repo = SledRepository::new(dir.path()).unwrap();
        store_transaction(&repo, 1, 0, TxStatusV2::Mined, 0).await;
        store_transaction(&repo, 2, 1, TxStatusV2::Failed, 0).await;
        store_transaction(&repo, 3, 2, TxStatusV2::Mined, NOW - 200).await;
        store_transaction(&repo, 4, 3, TxStatusV2::Prepared, 0).await;
        store_transaction(&repo, 5, 4, TxStatusV2::Submitted, 0).await;
        store_transaction(&repo, 6, 5, TxStatusV2::ReplacementPrepared, 0).await;
        store_transaction(&repo, 7, 6, TxStatusV2::Replaced, 0).await;

        let report = repo.apply_retention(policy(), NOW).await.unwrap();
        assert_eq!(report.outbox_pruned, 2);
        assert_eq!(report.transactions_pruned, 2);
        assert_eq!(report.outbox_slimmed, 1);
        assert_eq!(report.transactions_slimmed, 1);
        assert!(!report.budget_exhausted);

        for seed in [1, 2] {
            assert!(outbox_record(&repo, [seed; 32]).is_none());
        }
        for nonce in [0, 1] {
            assert!(!repo
                .outbox_tree()
                .contains_key(format!("tx:{nonce}"))
                .unwrap());
        }
        let slim = outbox_record(&repo, [3; 32]).unwrap();
        assert!(slim.raw_signed_tx.is_empty());
        assert_eq!(slim.status, TxStatusV2::Mined);
        for seed in 4..=7 {
            let kept = outbox_record(&repo, [seed; 32]).unwrap();
            assert_eq!(kept.raw_signed_tx, vec![7; 64], "seed {seed}");
        }
        assert_eq!(
            repo.default_tree().get(b"nonce:local").unwrap().unwrap(),
            7_u64.to_le_bytes().as_slice()
        );

        // A second pass has nothing left to do until the slim record ages out.
        assert_eq!(
            repo.apply_retention(policy(), NOW).await.unwrap().changed(),
            0
        );
        let later = repo.apply_retention(policy(), NOW + 1_000).await.unwrap();
        assert_eq!(later.outbox_pruned, 1);
        assert_eq!(later.transactions_pruned, 1);
    }

    #[tokio::test]
    async fn sweep_prunes_finished_quotes_after_valid_until_only() {
        let dir = tempfile::tempdir().unwrap();
        let repo = SledRepository::new(dir.path()).unwrap();
        let cases = [
            ([1; 32], QuoteStatusV2::Expired, NOW - 50, false),
            ([2; 32], QuoteStatusV2::Expired, NOW - 49, true),
            ([3; 32], QuoteStatusV2::Confirmed, NOW - 500, false),
            ([4; 32], QuoteStatusV2::Reverted, NOW - 499, true),
            ([5; 32], QuoteStatusV2::Rejected, NOW - 500, false),
            ([6; 32], QuoteStatusV2::Outstanding, 0, true),
            ([7; 32], QuoteStatusV2::Inflight, 0, true),
            ([8; 32], QuoteStatusV2::Submitted, 0, true),
            ([9; 32], QuoteStatusV2::Confirmed, NOW + 1_000, true),
        ];
        for (id, status, valid_until, _) in &cases {
            put_quote(&repo, &quote(*id, status.clone(), *valid_until));
        }
        // A payment index that points at another execution stays.
        repo.default_tree()
            .insert(
                format!("quote:payment:{}", hex::encode([1_u8; 32])).as_bytes(),
                [42_u8; 32].as_slice(),
            )
            .unwrap();

        let report = repo.apply_retention(policy(), NOW).await.unwrap();
        assert_eq!(report.quotes_pruned, 3);
        assert_eq!(report.payment_indexes_pruned, 2);
        for (id, status, _, kept) in &cases {
            assert_eq!(has_quote(&repo, *id), *kept, "{status:?} {id:?}");
        }
        assert!(has_payment_index(&repo, [1; 32]));
        assert!(!has_payment_index(&repo, [3; 32]));
        assert!(has_payment_index(&repo, [6; 32]));
    }

    #[tokio::test]
    async fn disabled_pruning_keeps_quotes_and_records() {
        let dir = tempfile::tempdir().unwrap();
        let repo = SledRepository::new(dir.path()).unwrap();
        store_transaction(&repo, 1, 0, TxStatusV2::Mined, 0).await;
        put_quote(&repo, &quote([2; 32], QuoteStatusV2::Expired, 0));
        let keep = RetentionPolicy {
            prune_terminal_records: false,
            ..policy()
        };
        let report = repo.apply_retention(keep, NOW).await.unwrap();
        assert_eq!(report.outbox_pruned + report.quotes_pruned, 0);
        assert_eq!(report.outbox_slimmed, 1);
        assert!(has_quote(&repo, [2; 32]));
        assert!(outbox_record(&repo, [1; 32]).is_some());
    }

    #[tokio::test]
    async fn batch_limit_spreads_work_over_passes() {
        let dir = tempfile::tempdir().unwrap();
        let repo = SledRepository::new(dir.path()).unwrap();
        for seed in 0..5_u8 {
            store_transaction(&repo, seed + 1, u64::from(seed), TxStatusV2::Mined, 0).await;
        }
        let limited = RetentionPolicy {
            batch_limit: 3,
            ..policy()
        };
        let first = repo.apply_retention(limited, NOW).await.unwrap();
        assert_eq!(first.changed(), 3);
        assert!(first.budget_exhausted);
        let mut passes = 1;
        while !repo.outbox_tree().is_empty() {
            repo.apply_retention(limited, NOW).await.unwrap();
            passes += 1;
            assert!(passes < 10);
        }
        assert_eq!(passes, 4);
    }

    #[tokio::test]
    async fn undecodable_records_are_left_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let repo = SledRepository::new(dir.path()).unwrap();
        repo.outbox_tree()
            .insert(b"tx:3", b"not json".as_slice())
            .unwrap();
        repo.default_tree()
            .insert(b"quote:execution:aa", b"{}".as_slice())
            .unwrap();
        let report = repo.apply_retention(policy(), NOW).await.unwrap();
        assert_eq!(report.undecodable, 2);
        assert!(repo.outbox_tree().contains_key(b"tx:3").unwrap());
    }

    #[tokio::test]
    async fn record_counts_report_every_kind() {
        let dir = tempfile::tempdir().unwrap();
        let repo = SledRepository::new(dir.path()).unwrap();
        store_transaction(&repo, 1, 0, TxStatusV2::Submitted, 0).await;
        put_quote(&repo, &quote([2; 32], QuoteStatusV2::Outstanding, 0));
        repo.default_tree()
            .insert(b"peer:0xabc", b"{}".as_slice())
            .unwrap();
        let counts = repo.record_counts().await.unwrap();
        let count = |tree: &str, kind: &str| {
            counts
                .iter()
                .find(|entry| entry.tree == tree && entry.kind == kind)
                .map(|entry| entry.count)
        };
        assert_eq!(count(TREE_LABEL_OUTBOX, "outbox"), Some(1));
        assert_eq!(count(TREE_LABEL_OUTBOX, "transaction"), Some(1));
        assert_eq!(count(TREE_LABEL_DEFAULT, "quote"), Some(1));
        assert_eq!(count(TREE_LABEL_DEFAULT, "quote_payment_index"), Some(1));
        assert_eq!(count(TREE_LABEL_DEFAULT, "nonce"), Some(1));
        assert_eq!(count(TREE_LABEL_DEFAULT, "peer"), Some(1));
        assert_eq!(count(TREE_LABEL_DEFAULT, "session"), Some(0));
        assert_eq!(count(TREE_LABEL_REPLAY, RECORD_KIND_REPLAY_TAG), Some(0));
    }
}
