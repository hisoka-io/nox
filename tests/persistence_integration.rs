//! Wallet state persistence: save/load/restore roundtrip.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use darkpool_client::{
    load_wallet_state, save_wallet_state, LocalMerkleTree, NotePlaintext, OwnedNote, UtxoStore,
};
use ethers::types::{Address, U256};
use tempfile::tempdir;

fn make_note(value: u64, commitment: u64) -> (OwnedNote, U256) {
    let commitment_u256 = U256::from(commitment);
    let note = OwnedNote {
        plaintext: NotePlaintext {
            value: U256::from(value),
            asset_id: U256::zero(),
            secret: U256::from(0x1111u64),
            nullifier: U256::from(0x2222u64),
            timelock: U256::zero(),
            hashlock: U256::zero(),
        },
        commitment: commitment_u256,
        leaf_index: commitment,
        spending_secret: U256::from(0x3333u64),
        is_transfer: false,
        received_block: 10,
    };
    (note, commitment_u256)
}

fn wallet_path(dir: &tempfile::TempDir, name: &str) -> PathBuf {
    dir.path().join(name)
}

#[test]
fn test_persistence_empty_wallet_roundtrip() {
    let dir = tempdir().expect("tempdir");
    let path = wallet_path(&dir, "empty.json");

    let utxos = UtxoStore::new();
    let tree = LocalMerkleTree::new();
    let last_block = 0u64;

    save_wallet_state(&path, &utxos, &tree, last_block).expect("save");

    let result = load_wallet_state(&path).expect("load");
    let (restored_utxos, restored_tree, restored_block) = result.expect("state exists");

    assert_eq!(restored_block, 0);
    assert_eq!(restored_utxos.count(), 0);
    assert_eq!(restored_tree.leaves().len(), 0);
}

#[test]
fn test_persistence_wallet_with_notes_roundtrip() {
    let dir = tempdir().expect("tempdir");
    let path = wallet_path(&dir, "notes.json");

    let mut utxos = UtxoStore::new();
    let mut tree = LocalMerkleTree::new();

    let (note1, c1) = make_note(1_000, 1);
    let (note2, c2) = make_note(2_500, 2);
    let nullifier1 = U256::from(0xAAAAu64);
    let nullifier2 = U256::from(0xBBBBu64);

    utxos.add_note(note1, nullifier1);
    utxos.add_note(note2, nullifier2);
    tree.insert(c1);
    tree.insert(c2);

    let last_block = 150u64;
    save_wallet_state(&path, &utxos, &tree, last_block).expect("save");

    let result = load_wallet_state(&path).expect("load");
    let (restored_utxos, restored_tree, restored_block) = result.expect("state exists");

    assert_eq!(restored_block, 150);
    assert_eq!(restored_utxos.count(), 2);
    assert_eq!(restored_tree.leaves().len(), 2);

    let r1 = restored_utxos.get_by_commitment(&c1).expect("note 1 found");
    assert_eq!(r1.value(), U256::from(1_000u64));

    let r2 = restored_utxos.get_by_commitment(&c2).expect("note 2 found");
    assert_eq!(r2.value(), U256::from(2_500u64));
}

#[test]
fn test_persistence_spent_nullifiers_preserved() {
    let dir = tempdir().expect("tempdir");
    let path = wallet_path(&dir, "spent.json");

    let mut utxos = UtxoStore::new();
    let tree = LocalMerkleTree::new();

    let (note, commitment) = make_note(500, 99);
    let nullifier = U256::from(0xDEADu64);
    utxos.add_note(note, nullifier);
    utxos.mark_spent(nullifier); // mark as spent

    save_wallet_state(&path, &utxos, &tree, 20).expect("save");

    let result = load_wallet_state(&path).expect("load");
    let (restored_utxos, _tree, _block) = result.expect("state exists");

    assert!(restored_utxos.is_spent(&nullifier));
    assert!(restored_utxos.get_by_commitment(&commitment).is_none());
}

#[test]
fn test_persistence_merkle_root_deterministic_after_restore() {
    let dir = tempdir().expect("tempdir");
    let path = wallet_path(&dir, "root.json");

    let utxos = UtxoStore::new();
    let mut tree = LocalMerkleTree::new();

    for i in 0u64..10 {
        tree.insert(U256::from(i * 0x1000 + 1));
    }
    let original_root = tree.root();

    save_wallet_state(&path, &utxos, &tree, 99).expect("save");

    let result = load_wallet_state(&path).expect("load");
    let (_, restored_tree, _) = result.expect("state exists");

    assert_eq!(restored_tree.root(), original_root);
    assert_eq!(restored_tree.leaves().len(), 10);
}

#[test]
fn test_persistence_load_missing_file_returns_none() {
    let dir = tempdir().expect("tempdir");
    let path = wallet_path(&dir, "does_not_exist.json");

    let result = load_wallet_state(&path).expect("load should not error for missing file");
    assert!(result.is_none());
}

#[test]
fn test_persistence_overwrite_produces_new_state() {
    let dir = tempdir().expect("tempdir");
    let path = wallet_path(&dir, "overwrite.json");

    // First save: 1 note, block 50
    let mut utxos1 = UtxoStore::new();
    let tree1 = LocalMerkleTree::new();
    let (note1, _c1) = make_note(100, 1);
    utxos1.add_note(note1, U256::from(0x11u64));
    save_wallet_state(&path, &utxos1, &tree1, 50).expect("first save");

    // Second save: 3 notes, block 200 (overwrites)
    let mut utxos2 = UtxoStore::new();
    let tree2 = LocalMerkleTree::new();
    for i in 1u64..=3 {
        let (note, _c) = make_note(i * 100, i);
        utxos2.add_note(note, U256::from(i * 0x100));
    }
    save_wallet_state(&path, &utxos2, &tree2, 200).expect("second save");

    let result = load_wallet_state(&path).expect("load after overwrite");
    let (restored, _tree, block) = result.expect("state exists");

    assert_eq!(block, 200);
    assert_eq!(restored.count(), 3);
}

#[test]
fn test_persistence_large_tree_roundtrip() {
    let dir = tempdir().expect("tempdir");
    let path = wallet_path(&dir, "large.json");

    let utxos = UtxoStore::new();
    let mut tree = LocalMerkleTree::new();
    for i in 0u64..100 {
        tree.insert(U256::from(i + 1));
    }
    let original_root = tree.root();

    save_wallet_state(&path, &utxos, &tree, 1000).expect("save");

    let result = load_wallet_state(&path).expect("load");
    let (_, restored_tree, block) = result.expect("state exists");

    assert_eq!(block, 1000);
    assert_eq!(restored_tree.leaves().len(), 100);
    assert_eq!(restored_tree.root(), original_root);
}

#[test]
fn test_persistence_partial_sync_resume() {
    let dir = tempdir().expect("tempdir");
    let path = wallet_path(&dir, "partial.json");

    let mut utxos = UtxoStore::new();
    let mut tree = LocalMerkleTree::new();

    // Simulate scanning blocks 1-50: found 2 notes
    for i in 1u64..=2 {
        let (note, c) = make_note(i * 1000, i);
        utxos.add_note(note, U256::from(i * 0x10));
        tree.insert(c);
    }
    save_wallet_state(&path, &utxos, &tree, 50).expect("save at block 50");

    // Restore and continue scanning blocks 51-100 (simulate finding 1 more note)
    let result = load_wallet_state(&path).expect("load");
    let (mut resumed_utxos, mut resumed_tree, last_block) = result.expect("state exists");

    assert_eq!(last_block, 50);
    assert_eq!(resumed_utxos.count(), 2);

    let (note3, c3) = make_note(5_000, 3);
    resumed_utxos.add_note(note3, U256::from(0x30u64));
    resumed_tree.insert(c3);
    save_wallet_state(&path, &resumed_utxos, &resumed_tree, 100).expect("save at block 100");

    let result2 = load_wallet_state(&path).expect("load final");
    let (final_utxos, _final_tree, final_block) = result2.expect("state exists");

    assert_eq!(final_block, 100);
    assert_eq!(final_utxos.count(), 3);

    let total = final_utxos.get_balance(Address::zero());
    assert_eq!(total, U256::from(8_000u64));
}
