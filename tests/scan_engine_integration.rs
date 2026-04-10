//! ScanEngine integration tests using `MockProvider` (no real Ethereum node).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use darkpool_client::{
    DarkAccount, KeyRepository, LocalMerkleTree, NotePlaintext, OwnedNote, ScanEngine, UtxoStore,
};
use ethers::providers::{MockProvider, Provider};
use ethers::types::{Address, Bytes, Log, H160, H256, U256, U64};

const DARKPOOL_ADDR: H160 = H160([
    0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);

fn make_engine(mock: MockProvider) -> ScanEngine<Provider<MockProvider>> {
    let provider = Arc::new(Provider::new(mock));
    let address = Address::from(DARKPOOL_ADDR);
    let account = DarkAccount::from_seed(b"scan_engine_integration_test");
    let compliance_pk = (U256::from(0x1234u64), U256::from(0x5678u64));
    let repo = KeyRepository::new(account, compliance_pk);
    ScanEngine::new(provider, address, repo, compliance_pk)
}

fn make_engine_with_utxos(
    mock: MockProvider,
    utxos: UtxoStore,
) -> ScanEngine<Provider<MockProvider>> {
    let provider = Arc::new(Provider::new(mock));
    let address = Address::from(DARKPOOL_ADDR);
    let account = DarkAccount::from_seed(b"scan_engine_integration_test");
    let compliance_pk = (U256::from(0x1234u64), U256::from(0x5678u64));
    let repo = KeyRepository::new(account, compliance_pk);
    ScanEngine::with_state(
        provider,
        address,
        repo,
        utxos,
        LocalMerkleTree::new(),
        compliance_pk,
        0,
    )
}

fn keccak_sig(sig: &str) -> H256 {
    let mut hasher = tiny_keccak::Keccak::v256();
    tiny_keccak::Hasher::update(&mut hasher, sig.as_bytes());
    let mut out = [0u8; 32];
    tiny_keccak::Hasher::finalize(hasher, &mut out);
    H256::from(out)
}

fn nullifier_spent_log(nullifier_hash: H256) -> Log {
    let sig = keccak_sig("NullifierSpent(bytes32)");
    Log {
        address: Address::zero(),
        topics: vec![sig, nullifier_hash],
        data: Bytes::new(),
        block_number: Some(U64::from(10u64)),
        transaction_hash: Some(H256::zero()),
        transaction_index: Some(U64::from(0u64)),
        block_hash: Some(H256::zero()),
        log_index: Some(U256::zero()),
        removed: Some(false),
        ..Default::default()
    }
}

fn unknown_event_log() -> Log {
    let unknown_sig = keccak_sig("SomeRandomEvent(uint256,address)");
    Log {
        address: Address::zero(),
        topics: vec![unknown_sig],
        data: Bytes::from(vec![0u8; 32]),
        block_number: Some(U64::from(5u64)),
        ..Default::default()
    }
}

fn make_owned_note(value: u64, nullifier_hash: U256) -> (OwnedNote, U256) {
    let commitment = nullifier_hash + U256::from(1u64); // distinct from nullifier hash
    let note = OwnedNote {
        plaintext: NotePlaintext {
            value: U256::from(value),
            asset_id: U256::zero(),
            secret: U256::from(0xDEADu64),
            nullifier: U256::from(0xBEEFu64),
            timelock: U256::zero(),
            hashlock: U256::zero(),
        },
        commitment,
        leaf_index: 0,
        spending_secret: U256::zero(),
        is_transfer: false,
        received_block: 1,
    };
    (note, commitment)
}

#[tokio::test]
async fn test_scan_empty_block_range_no_events() {
    let mock = MockProvider::new();
    mock.push::<Vec<Log>, _>(vec![]).expect("push");
    let mut engine = make_engine(mock);

    let result = engine.scan_blocks(100, 200).await.expect("scan_blocks");

    assert_eq!(result.new_notes.len(), 0, "no new notes");
    assert_eq!(result.spent_nullifiers.len(), 0, "no spent nullifiers");
    assert_eq!(result.new_commitments.len(), 0, "no new commitments");
    assert_eq!(result.blocks_processed, 101, "101 blocks (200-100+1)");
}

#[tokio::test]
async fn test_scan_nullifier_spent_for_owned_note() {
    let nullifier_hash = H256::from_low_u64_be(0xABCD_1234);
    let nullifier_u256 = U256::from_big_endian(nullifier_hash.as_bytes());

    let mut utxos = UtxoStore::new();
    let (note, _commitment) = make_owned_note(1_000, nullifier_u256);
    utxos.add_note(note, nullifier_u256);

    let mock = MockProvider::new();
    mock.push::<Vec<Log>, _>(vec![nullifier_spent_log(nullifier_hash)])
        .expect("push");
    let mut engine = make_engine_with_utxos(mock, utxos);

    let result = engine.scan_blocks(1, 10).await.expect("scan_blocks");

    assert_eq!(
        result.spent_nullifiers.len(),
        1,
        "one nullifier marked spent"
    );
    assert_eq!(
        result.spent_nullifiers[0], nullifier_u256,
        "nullifier value matches"
    );
    assert_eq!(result.new_notes.len(), 0);
}

#[tokio::test]
async fn test_scan_nullifier_spent_foreign_note_ignored() {
    let mock = MockProvider::new();
    let foreign_nullifier = H256::from_low_u64_be(0xFFFF_0000);
    mock.push::<Vec<Log>, _>(vec![nullifier_spent_log(foreign_nullifier)])
        .expect("push");
    let mut engine = make_engine(mock);

    let result = engine.scan_blocks(1, 10).await.expect("scan_blocks");

    assert_eq!(
        result.spent_nullifiers.len(),
        0,
        "foreign nullifier ignored"
    );
}

#[tokio::test]
async fn test_scan_multiple_nullifiers_spent_for_owned_notes() {
    let hashes: Vec<H256> = (0u64..3).map(H256::from_low_u64_be).collect();

    let mut utxos = UtxoStore::new();
    for h in &hashes {
        let nul = U256::from_big_endian(h.as_bytes());
        let (note, _c) = make_owned_note(100, nul);
        utxos.add_note(note, nul);
    }

    let mock = MockProvider::new();
    mock.push::<Vec<Log>, _>(
        hashes
            .iter()
            .map(|h| nullifier_spent_log(*h))
            .collect::<Vec<_>>(),
    )
    .expect("push");
    let mut engine = make_engine_with_utxos(mock, utxos);

    let result = engine.scan_blocks(1, 50).await.expect("scan_blocks");

    assert_eq!(
        result.spent_nullifiers.len(),
        3,
        "all 3 owned nullifiers reported"
    );
}

#[tokio::test]
async fn test_scan_unknown_event_ignored() {
    let mock = MockProvider::new();
    mock.push::<Vec<Log>, _>(vec![unknown_event_log()])
        .expect("push");
    let mut engine = make_engine(mock);

    let result = engine.scan_blocks(1, 5).await.expect("scan_blocks");

    assert_eq!(result.new_notes.len(), 0);
    assert_eq!(result.spent_nullifiers.len(), 0);
}

#[tokio::test]
async fn test_scan_mixed_known_and_unknown_events() {
    let nullifier_hash = H256::from_low_u64_be(0xBEEF);
    let nullifier_u256 = U256::from_big_endian(nullifier_hash.as_bytes());

    let mut utxos = UtxoStore::new();
    let (note, _c) = make_owned_note(500, nullifier_u256);
    utxos.add_note(note, nullifier_u256);

    let mock = MockProvider::new();
    mock.push::<Vec<Log>, _>(vec![
        nullifier_spent_log(nullifier_hash),
        unknown_event_log(),
    ])
    .expect("push");
    let mut engine = make_engine_with_utxos(mock, utxos);

    let result = engine.scan_blocks(1, 20).await.expect("scan_blocks");

    assert_eq!(result.spent_nullifiers.len(), 1);
    assert_eq!(result.new_notes.len(), 0);
}

#[tokio::test]
async fn test_scan_log_with_no_topics_ignored() {
    let mock = MockProvider::new();
    let empty_log = Log {
        address: Address::zero(),
        topics: vec![],
        data: Bytes::from(vec![0u8; 64]),
        block_number: Some(U64::from(1u64)),
        ..Default::default()
    };
    mock.push::<Vec<Log>, _>(vec![empty_log]).expect("push");
    let mut engine = make_engine(mock);

    let result = engine.scan_blocks(1, 1).await.expect("scan_blocks");

    assert_eq!(result.new_notes.len(), 0);
    assert_eq!(result.spent_nullifiers.len(), 0);
}

#[tokio::test]
async fn test_scan_provider_error_propagates() {
    let mock = MockProvider::new();
    // Push nothing -- MockProvider returns `EmptyResponses` on the first call
    let mut engine = make_engine(mock);

    let result = engine.scan_blocks(1, 10).await;

    assert!(result.is_err(), "provider error should propagate");
}

#[tokio::test]
async fn test_scan_single_block_range() {
    let mock = MockProvider::new();
    mock.push::<Vec<Log>, _>(vec![]).expect("push");
    let mut engine = make_engine(mock);

    let result = engine.scan_blocks(42, 42).await.expect("scan_blocks");

    assert_eq!(result.blocks_processed, 1);
}

#[tokio::test]
async fn test_scan_sequential_ranges() {
    let nullifier_hash = H256::from_low_u64_be(0xAAAA);
    let nullifier_u256 = U256::from_big_endian(nullifier_hash.as_bytes());

    let mut utxos = UtxoStore::new();
    let (note, _c) = make_owned_note(200, nullifier_u256);
    utxos.add_note(note, nullifier_u256);

    let mock = MockProvider::new();
    // MockProvider pops from back -- push in reverse order
    mock.push::<Vec<Log>, _>(vec![nullifier_spent_log(nullifier_hash)])
        .expect("push second response");
    mock.push::<Vec<Log>, _>(vec![])
        .expect("push first response");
    let mut engine = make_engine_with_utxos(mock, utxos);

    let r1 = engine.scan_blocks(1, 50).await.expect("first scan");
    assert_eq!(r1.spent_nullifiers.len(), 0, "first range: no nullifiers");

    let r2 = engine.scan_blocks(51, 100).await.expect("second scan");
    assert_eq!(r2.spent_nullifiers.len(), 1, "second range: one nullifier");
}
