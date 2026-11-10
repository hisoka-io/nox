//! Upgrade from an rc.11 sled data directory to `nox.redb`, and the rollback.
//!
//! The fixture is written with sled 0.34 in the rc.11 layout: peers,
//! sessions, the observer cursor, the nonce floor, quotes with their payment
//! index and counters in the default tree; outbox and per-nonce transaction
//! records in `exit_outbox`; replay tags in `replay_tags`. Values use the
//! same `nox_core` encodings rc.11 writes.

use std::collections::BTreeMap;
use std::path::Path;

use nox_core::traits::{IReplayProtection, IStorageRepository};
use nox_core::{
    ExecutionQuoteV1, PaidQuoteRequestV2, PendingTransactionV2, QuoteStatusV2, RelayerNode,
    StoredQuoteV2, StoredTransactionV2, TxStatusV2,
};
use nox_node::infra::sled_import::{import_if_present, SLED_BACKUP_PREFIX};
use nox_node::infra::storage::{NodeStore, DATABASE_FILE};

type Tree = BTreeMap<Vec<u8>, Vec<u8>>;

/// Records of one rc.11 data directory, per sled tree.
struct Fixture {
    default: Tree,
    outbox: Tree,
    replay: Tree,
}

fn quote(execution_id: [u8; 32], status: QuoteStatusV2) -> StoredQuoteV2 {
    StoredQuoteV2 {
        schema: 1,
        request: PaidQuoteRequestV2 {
            chain_id: 421_614,
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
            valid_until_unix: 4_000_000_000,
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
            valid_until_unix: 4_000_000_000,
            quote_nonce: [0; 32],
        },
        execution_id,
        exit_signature: vec![0x1b; 65],
        pending_sponsored_gas: 100_000,
        rolling_loss_window_secs: 3_600,
        status,
    }
}

fn transaction(seed: u8, nonce: u64, status: TxStatusV2) -> PendingTransactionV2 {
    PendingTransactionV2 {
        execution_id: [seed; 32],
        to: "0xad911ca217c6dc779fce6a6538bdda3071c38e7e".to_string(),
        data_hash: [seed.wrapping_add(1); 32],
        nonce,
        gas_limit: "144000".to_string(),
        gas_price: "115000000".to_string(),
        maximum_fee_per_gas: "138000000".to_string(),
        raw_signed_tx: vec![seed; 19_000],
        tx_hash: format!("0x{}", hex::encode([seed.wrapping_add(2); 32])),
        prior_transaction_hashes: Vec::new(),
        replacement_attempts: 0,
        first_sent_at: 1_800_000_000,
        last_update_at: 1_800_000_060,
        status,
    }
}

fn fixture() -> Fixture {
    let mut default = Tree::new();
    let mut outbox = Tree::new();
    let mut replay = Tree::new();
    let put = |tree: &mut Tree, key: &str, value: Vec<u8>| {
        tree.insert(key.as_bytes().to_vec(), value);
    };

    put(&mut default, "nonce:local", 3_u64.to_le_bytes().to_vec());
    put(
        &mut default,
        "chain_observer:last_block",
        1_234_567_u64.to_le_bytes().to_vec(),
    );
    put(
        &mut default,
        "chain_observer:registry_scope",
        b"421614:0xf7bff88a1412054a001dc4b8acbddad6f9b26cb6".to_vec(),
    );
    for (index, layer) in [(1_u8, 0_u8), (2, 1), (3, 2)] {
        let address = format!("0x{}", hex::encode([index; 20]));
        let node = RelayerNode {
            address: address.clone(),
            sphinx_key: hex::encode([index; 32]),
            url: format!("/ip4/127.0.0.1/tcp/{}", 9_000 + u16::from(index)),
            stake: "1000000000000000000".to_string(),
            last_seen: 1_800_000_000,
            is_privileged: true,
            layer,
            role: if layer == 2 { 2 } else { 1 },
            ingress_url: None,
            metadata_url: None,
        };
        put(
            &mut default,
            &format!("peer:{address}"),
            serde_json::to_vec(&node).expect("encode peer"),
        );
    }
    put(
        &mut default,
        "session:12D3KooWMigrationFixture",
        b"{\"registry_verified\":true}".to_vec(),
    );

    for (seed, status) in [
        (0x10_u8, QuoteStatusV2::Outstanding),
        (0x11, QuoteStatusV2::Submitted),
        (0x12, QuoteStatusV2::Confirmed),
    ] {
        let record = quote([seed; 32], status);
        put(
            &mut default,
            &format!("quote:execution:{}", hex::encode(record.execution_id)),
            serde_json::to_vec(&record).expect("encode quote"),
        );
        put(
            &mut default,
            &format!("quote:payment:{}", hex::encode(record.request.payment_id)),
            record.execution_id.to_vec(),
        );
    }
    put(
        &mut default,
        "quote:outstanding",
        2_u64.to_le_bytes().to_vec(),
    );
    put(
        &mut default,
        "quote:pending-gas",
        200_000_u64.to_le_bytes().to_vec(),
    );
    put(&mut default, "quote:nonce", 3_u64.to_le_bytes().to_vec());
    let mut loss = [0_u8; 32];
    loss[31] = 7;
    put(&mut default, "quote:rolling-loss", loss.to_vec());
    put(
        &mut default,
        "quote:loss-window-start",
        1_800_000_000_u64.to_le_bytes().to_vec(),
    );

    for (seed, nonce, status) in [
        (0x20_u8, 0_u64, TxStatusV2::Mined),
        (0x21, 1, TxStatusV2::Submitted),
        (0x22, 2, TxStatusV2::Prepared),
    ] {
        let bytes = serde_json::to_vec(&StoredTransactionV2 {
            schema: 2,
            transaction: transaction(seed, nonce, status),
        })
        .expect("encode transaction");
        put(
            &mut outbox,
            &format!("outbox:{}", hex::encode([seed; 32])),
            bytes.clone(),
        );
        put(&mut outbox, &format!("tx:{nonce}"), bytes);
    }

    for index in 0..64_u8 {
        replay.insert(vec![index; 32], u64::MAX.to_be_bytes().to_vec());
    }

    Fixture {
        default,
        outbox,
        replay,
    }
}

/// Writes the fixture as rc.11 does: sled 0.34, three trees, flushed.
fn write_sled(path: &Path, fixture: &Fixture) {
    let db = sled::open(path).expect("open sled");
    for (key, value) in &fixture.default {
        db.insert(key.as_slice(), value.as_slice())
            .expect("default tree");
    }
    let outbox = db.open_tree(b"exit_outbox").expect("outbox tree");
    for (key, value) in &fixture.outbox {
        outbox
            .insert(key.as_slice(), value.as_slice())
            .expect("outbox tree");
    }
    let replay = db.open_tree(b"replay_tags").expect("replay tree");
    for (key, value) in &fixture.replay {
        replay
            .insert(key.as_slice(), value.as_slice())
            .expect("replay tree");
    }
    db.flush().expect("flush sled");
}

/// Reads a sled directory as rc.11 would open it.
fn read_sled(path: &Path) -> (Tree, Tree, Tree) {
    let db = sled::open(path).expect("open sled");
    let collect = |tree: &sled::Tree| -> Tree {
        tree.iter()
            .map(|item| {
                let (key, value) = item.expect("sled record");
                (key.to_vec(), value.to_vec())
            })
            .collect()
    };
    let default = collect(&db);
    let outbox = collect(&db.open_tree(b"exit_outbox").expect("outbox tree"));
    let replay = collect(&db.open_tree(b"replay_tags").expect("replay tree"));
    (default, outbox, replay)
}

fn backups(path: &Path) -> Vec<std::path::PathBuf> {
    let mut found: Vec<_> = std::fs::read_dir(path)
        .expect("list db_path")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(SLED_BACKUP_PREFIX)
        })
        .map(|entry| entry.path())
        .collect();
    found.sort();
    found
}

fn has_sled_files(path: &Path) -> bool {
    path.join("conf").exists() || path.join("db").exists()
}

/// Every fixture record reads back byte for byte, and the typed readers the
/// node uses at startup decode them.
async fn assert_store_holds(store: &NodeStore, fixture: &Fixture) {
    for (key, value) in fixture.default.iter().chain(&fixture.outbox) {
        assert_eq!(
            store.get(key).await.expect("get").as_deref(),
            Some(value.as_slice()),
            "record {}",
            String::from_utf8_lossy(key)
        );
    }
    for (prefix, expected) in [
        ("peer:", 3),
        ("session:", 1),
        ("quote:execution:", 3),
        ("quote:payment:", 3),
        ("outbox:", 3),
        ("tx:", 3),
    ] {
        assert_eq!(
            store.scan(prefix.as_bytes()).await.expect("scan").len(),
            expected,
            "prefix {prefix}"
        );
    }
    for (seed, nonce, status) in [
        (0x20_u8, 0_u64, TxStatusV2::Mined),
        (0x21, 1, TxStatusV2::Submitted),
        (0x22, 2, TxStatusV2::Prepared),
    ] {
        let loaded = store
            .load_outbox_by_execution([seed; 32])
            .await
            .expect("outbox read")
            .expect("outbox record");
        assert_eq!(
            serde_json::to_value(&loaded).expect("encode loaded"),
            serde_json::to_value(transaction(seed, nonce, status)).expect("encode expected")
        );
    }
    let loaded = store
        .load_quote([0x10; 32])
        .await
        .expect("quote read")
        .expect("quote record");
    assert_eq!(
        serde_json::to_value(&loaded).expect("encode loaded"),
        serde_json::to_value(quote([0x10; 32], QuoteStatusV2::Outstanding))
            .expect("encode expected")
    );
    let counters = store.quote_counters().await.expect("counters");
    assert_eq!(counters.outstanding, 2);
    assert_eq!(counters.pending_sponsored_gas, 200_000);
    for tag in fixture.replay.keys() {
        assert!(
            store.check_and_tag(tag, 60).await.expect("replay check"),
            "replay tag was not imported"
        );
    }
}

#[tokio::test]
async fn rc11_sled_directory_imports_once_and_restarts_on_redb() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("nox_db");
    let fixture = fixture();
    write_sled(&path, &fixture);
    std::fs::write(path.join("bloom.bin"), b"bloom").expect("bloom file");

    let store = NodeStore::new(&path).expect("first start imports");
    assert!(path.join(DATABASE_FILE).is_file());
    assert!(!has_sled_files(&path));
    let kept = backups(&path);
    assert_eq!(kept.len(), 1);
    assert_store_holds(&store, &fixture).await;
    assert_eq!(
        std::fs::read(path.join("bloom.bin")).expect("bloom file"),
        b"bloom"
    );
    store
        .put(b"nonce:local", &4_u64.to_le_bytes())
        .await
        .expect("write after upgrade");
    drop(store);

    // The sled files kept aside are the rc.11 database, unchanged.
    let (default, outbox, replay) = read_sled(&kept[0]);
    assert_eq!(default, fixture.default);
    assert_eq!(outbox, fixture.outbox);
    assert_eq!(replay, fixture.replay);

    // Restart: nothing left to import, redb is read, the backup is not touched.
    assert_eq!(import_if_present(&path).expect("second import"), None);
    let reopened = NodeStore::new(&path).expect("restart");
    assert_eq!(backups(&path), kept);
    assert_eq!(
        reopened.get(b"nonce:local").await.expect("nonce"),
        Some(4_u64.to_le_bytes().to_vec())
    );
    let mut upgraded = fixture;
    upgraded
        .default
        .insert(b"nonce:local".to_vec(), 4_u64.to_le_bytes().to_vec());
    assert_store_holds(&reopened, &upgraded).await;
    drop(reopened);

    // A third start is the same again.
    let third = NodeStore::new(&path).expect("third start");
    assert_eq!(backups(&path), kept);
    assert_store_holds(&third, &upgraded).await;
}

/// Rollback as the CHANGELOG upgrade notes describe it: stop the node, move
/// `nox.redb` aside, move the sled files back, start the previous release.
/// A later upgrade imports the sled database again, including what the
/// previous release wrote in between.
#[tokio::test]
async fn rollback_restores_the_sled_files_and_a_second_upgrade_imports_again() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("nox_db");
    let mut fixture = fixture();
    write_sled(&path, &fixture);

    drop(NodeStore::new(&path).expect("upgrade"));
    let kept = backups(&path);
    assert_eq!(kept.len(), 1);

    std::fs::rename(
        path.join(DATABASE_FILE),
        dir.path().join("nox.redb.rolled-back"),
    )
    .expect("move nox.redb aside");
    for entry in std::fs::read_dir(&kept[0]).expect("list backup") {
        let entry = entry.expect("backup entry");
        std::fs::rename(entry.path(), path.join(entry.file_name())).expect("restore sled file");
    }
    std::fs::remove_dir(&kept[0]).expect("remove empty backup");

    // The previous release opens its database and keeps writing to it.
    let (default, outbox, replay) = read_sled(&path);
    assert_eq!(default, fixture.default);
    assert_eq!(outbox, fixture.outbox);
    assert_eq!(replay, fixture.replay);
    {
        let db = sled::open(&path).expect("previous release");
        db.insert(b"nonce:local", &5_u64.to_le_bytes())
            .expect("write");
        db.flush().expect("flush");
    }
    fixture
        .default
        .insert(b"nonce:local".to_vec(), 5_u64.to_le_bytes().to_vec());

    let store = NodeStore::new(&path).expect("second upgrade");
    assert_eq!(backups(&path).len(), 1);
    assert_store_holds(&store, &fixture).await;
}
