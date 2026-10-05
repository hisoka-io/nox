//! Long-run simulation of the exit outbox lifecycle: thousands of paid
//! executions, each with a quote, an outbox record that moves from Prepared to
//! Mined, and spam quotes that expire unused. Storage maintenance runs on a
//! simulated clock and the node restarts every few hundred executions.
//!
//! Without retention the database grows by roughly two 40 KB records per
//! execution (about 240 MB for 3,000). The test asserts that record counts
//! and bytes on disk stay bounded across restarts instead.
//!
//! Retention alone does not bound bytes on sled 0.34: every restart forgets
//! the blob files that were pending deletion. With a restart every 100
//! executions and no compaction, blob bytes grew from 12 MB to 78 MB over
//! this run while the record counts stayed flat. The restart step therefore
//! applies the startup compaction (`storage.compact_on_start_blob_bytes`).

use std::path::Path;

use ethers::types::U256;
use nox_core::{
    ExecutionQuoteV1, PaidQuoteRequestV2, PendingTransactionV2, QuoteStatusV2, StoredQuoteV2,
    TxStatusV2,
};
use nox_node::infra::compaction::{compact_database, sled_files_size, CompactionOptions};
use nox_node::infra::retention::{
    blob_usage, RetentionPolicy, TREE_LABEL_DEFAULT, TREE_LABEL_OUTBOX,
};
use nox_node::infra::storage::{CreateOutboxResult, SledRepository};

const EXECUTIONS: u64 = 3_000;
/// Simulated seconds between executions.
const STEP_SECS: u64 = 60;
/// Unused quotes issued per execution.
const SPAM_QUOTES_PER_EXECUTION: u64 = 2;
const QUOTE_TTL_SECS: u64 = 30;
/// Executions between maintenance passes (one pass per 100 simulated minutes).
const MAINTENANCE_EVERY: u64 = 100;
/// Executions between restarts.
const RESTART_EVERY: u64 = 500;
/// Signed transaction size seen on the live fleet (66 KB as a number array).
const RAW_TX_BYTES: usize = 19_000;
/// Startup compaction threshold used by the restart step.
const COMPACT_ON_START_BLOB_BYTES: u64 = 8 * 1024 * 1024;

fn policy() -> RetentionPolicy {
    RetentionPolicy {
        prune_terminal_records: true,
        slim_terminal_transactions_after_secs: 0,
        terminal_transaction_retention_secs: 3_600,
        expired_quote_retention_secs: 300,
        terminal_quote_retention_secs: 3_600,
        batch_limit: 100_000,
    }
}

fn id(kind: u8, index: u64) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes[0] = kind;
    bytes[24..].copy_from_slice(&index.to_be_bytes());
    bytes
}

fn quote(execution_id: [u8; 32], valid_until_unix: u64) -> StoredQuoteV2 {
    StoredQuoteV2 {
        schema: 1,
        request: PaidQuoteRequestV2 {
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
        quote: ExecutionQuoteV1 {
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
        status: QuoteStatusV2::Outstanding,
    }
}

/// Pseudo-random signed bytes, so nothing compresses them away.
fn raw_transaction(index: u64) -> Vec<u8> {
    let mut state = index.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..RAW_TX_BYTES)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

async fn reserve(repo: &SledRepository, record: &StoredQuoteV2, now: u64) {
    repo.create_quote_durably(
        record,
        10_000,
        u64::MAX / 2,
        U256::from(u128::MAX),
        3_600,
        now,
    )
    .await
    .expect("quote reservation");
}

/// One paid execution through the full outbox lifecycle.
async fn execute(repo: &SledRepository, index: u64, now: u64) {
    let execution_id = id(1, index);
    reserve(repo, &quote(execution_id, now + QUOTE_TTL_SECS), now).await;
    repo.take_quote_durably(execution_id, now)
        .await
        .expect("quote take");

    let mut record = PendingTransactionV2 {
        execution_id,
        to: "0x1111111111111111111111111111111111111111".to_string(),
        data_hash: [9; 32],
        nonce: index,
        gas_limit: "900000".to_string(),
        gas_price: "100000000".to_string(),
        maximum_fee_per_gas: "200000000".to_string(),
        raw_signed_tx: raw_transaction(index),
        tx_hash: format!("0x{}", hex::encode(id(2, index))),
        prior_transaction_hashes: Vec::new(),
        replacement_attempts: 0,
        first_sent_at: now,
        last_update_at: now,
        status: TxStatusV2::Prepared,
    };
    assert!(matches!(
        repo.create_outbox_durably(execution_id, &record, index + 1)
            .await
            .expect("outbox creation"),
        CreateOutboxResult::Created
    ));
    repo.mark_quote_submitted_durably(execution_id)
        .await
        .expect("quote submitted");
    record.status = TxStatusV2::Submitted;
    repo.persist_v2_durably(&record).await.expect("submitted");
    record.status = TxStatusV2::Mined;
    record.last_update_at = now + STEP_SECS / 2;
    repo.persist_v2_durably(&record).await.expect("mined");
    repo.finalize_quote_durably(execution_id, QuoteStatusV2::Confirmed, U256::zero(), now)
        .await
        .expect("quote confirmed");

    for spam in 0..SPAM_QUOTES_PER_EXECUTION {
        let spam_id = id(3, index * SPAM_QUOTES_PER_EXECUTION + spam);
        reserve(repo, &quote(spam_id, now + QUOTE_TTL_SECS), now).await;
    }
}

struct Sample {
    executions: u64,
    sled_bytes: u64,
    blob_bytes: u64,
    outbox_keys: u64,
    quote_keys: u64,
}

async fn sample(repo: &SledRepository, path: &Path, executions: u64) -> Sample {
    let counts = repo.record_counts().await.expect("record counts");
    let count = |tree: &str, kind: &str| {
        counts
            .iter()
            .filter(|entry| entry.tree == tree && entry.kind == kind)
            .map(|entry| entry.count)
            .sum::<u64>()
    };
    Sample {
        executions,
        sled_bytes: sled_files_size(path).expect("sled size"),
        blob_bytes: blob_usage(path).expect("blob usage").1,
        outbox_keys: count(TREE_LABEL_OUTBOX, "outbox") + count(TREE_LABEL_OUTBOX, "transaction"),
        quote_keys: count(TREE_LABEL_DEFAULT, "quote")
            + count(TREE_LABEL_DEFAULT, "quote_payment_index"),
    }
}

/// Restart: drop every handle, compact when blobs pass the startup threshold
/// (what `storage.compact_on_start_blob_bytes` does), reopen.
fn restart(repo: SledRepository, path: &Path) -> (SledRepository, bool) {
    drop(repo);
    let compacted = blob_usage(path).expect("blob usage").1 > COMPACT_ON_START_BLOB_BYTES;
    if compacted {
        compact_database(path, CompactionOptions { keep_backup: false }).expect("compaction");
    }
    (SledRepository::new(path).expect("reopen"), compacted)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exit_storage_stays_bounded_over_thousands_of_paid_executions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("nox_db");
    let mut repo = SledRepository::new(&path).expect("open");
    let mut now = 1_800_000_000_u64;
    let mut samples = Vec::new();
    let mut compactions = 0_u32;

    for index in 0..EXECUTIONS {
        execute(&repo, index, now).await;
        now += STEP_SECS;
        if (index + 1) % MAINTENANCE_EVERY == 0 {
            repo.prune_expired_quotes_durably(now)
                .await
                .expect("expire quotes");
            repo.apply_retention(policy(), now)
                .await
                .expect("retention");
            samples.push(sample(&repo, &path, index + 1).await);
        }
        if (index + 1) % RESTART_EVERY == 0 {
            let (reopened, compacted) = restart(repo, &path);
            repo = reopened;
            compactions += u32::from(compacted);
        }
    }

    println!("executions  sled_bytes  blob_bytes  outbox_keys  quote_keys");
    for s in &samples {
        println!(
            "{:>10}  {:>10}  {:>10}  {:>11}  {:>10}",
            s.executions, s.sled_bytes, s.blob_bytes, s.outbox_keys, s.quote_keys
        );
    }
    println!("startup compactions: {compactions}");

    // Records: everything newer than the retention window plus one
    // maintenance interval, for both keys of each record.
    let window = policy().terminal_transaction_retention_secs / STEP_SECS + MAINTENANCE_EVERY;
    let quote_window = window * (1 + SPAM_QUOTES_PER_EXECUTION);
    for s in &samples {
        assert!(
            s.outbox_keys <= 2 * window,
            "outbox keys {} at {}",
            s.outbox_keys,
            s.executions
        );
        assert!(
            s.quote_keys <= 2 * quote_window,
            "quote keys {} at {}",
            s.quote_keys,
            s.executions
        );
    }

    // Bytes: the last third of the run must not exceed the peak of the first
    // third by more than sled's own slack, and stays far below the ~240 MB
    // an unpruned outbox would hold.
    let third = samples.len() / 3;
    let early_peak = samples[..third]
        .iter()
        .map(|s| s.sled_bytes)
        .max()
        .unwrap_or(0);
    let late_peak = samples[2 * third..]
        .iter()
        .map(|s| s.sled_bytes)
        .max()
        .unwrap_or(0);
    assert!(
        late_peak <= early_peak.saturating_mul(2).max(16 * 1024 * 1024),
        "database kept growing: early peak {early_peak}, late peak {late_peak}"
    );
    assert!(late_peak < 64 * 1024 * 1024, "late peak {late_peak} bytes");

    // Nonce recovery state survives every restart and prune.
    let floor = nox_core::traits::IStorageRepository::get(&repo, b"nonce:local")
        .await
        .expect("nonce floor")
        .expect("nonce floor present");
    assert_eq!(floor, EXECUTIONS.to_le_bytes().to_vec());
    let counters = repo.quote_counters().await.expect("counters");
    assert_eq!(counters.pending_sponsored_gas, 0);
    assert_eq!(counters.outstanding, 0);
}
