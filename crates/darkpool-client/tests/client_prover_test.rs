//! # Client Prover Integration Tests
//!
//! Tests for the Prover Bridge (Phase 3B).
//! These tests verify that Rust input structs are correctly formatted
//! for the Noir prover without running actual proof generation.

use darkpool_client::{
    circuits, DLEQProof, DepositInputs, GasPaymentInputs, JoinInputs, NotePlaintext, ProverInput,
    PublicClaimInputs, SplitInputs, TransferInputs, WithdrawInputs,
};
use ethers::types::{Address, U256};

// TEST HELPERS

fn create_test_note(value: u64) -> NotePlaintext {
    NotePlaintext {
        value: U256::from(value),
        asset_id: U256::from_dec_str(
            "103508305839049902321661647408748286489328944596736343597450696309701510356112",
        )
        .unwrap(), // 0x1234...7890
        secret: U256::from(12345),
        nullifier: U256::from(67890),
        timelock: U256::zero(),
        hashlock: U256::zero(),
    }
}

fn create_compliance_pk() -> (U256, U256) {
    // Real compliance PK from test vectors
    (
        U256::from_dec_str(
            "3782039688895273922067030825065528598190946456505481755793010724346869899025",
        )
        .unwrap(),
        U256::from_dec_str(
            "16450024509161567336498250209673691876881689675122281721289782564946017219816",
        )
        .unwrap(),
    )
}

fn create_merkle_path() -> Vec<U256> {
    vec![U256::zero(); 32]
}

fn create_dleq_proof() -> DLEQProof {
    DLEQProof {
        u: (
            U256::from_dec_str(
                "16143559696366421990440424938839399920310310932693398413753667428935268211390",
            )
            .unwrap(),
            U256::from_dec_str(
                "17819099115591099831166234567174697234891764631093629700499188541632651500866",
            )
            .unwrap(),
        ),
        v: (
            U256::from_dec_str(
                "20362989706261619034949380227591168456666831912915019584566200665685631792430",
            )
            .unwrap(),
            U256::from_dec_str(
                "18007648505403091632649287497877655063591096108614498456764069932251091129806",
            )
            .unwrap(),
        ),
        z: U256::from_dec_str(
            "695632992682927447668621648704168069403166254619168626629795086923586140011",
        )
        .unwrap(),
    }
}

// DEPOSIT TESTS

#[test]
fn test_deposit_inputs_complete_map() {
    let note = create_test_note(100);
    let inputs = DepositInputs::new(note, U256::from(888), create_compliance_pk());

    let map = inputs.to_prover_map();

    // Verify all required keys exist
    let required_keys = [
        "ephemeral_sk",
        "note_plaintext.value",
        "note_plaintext.asset_id",
        "note_plaintext.secret",
        "note_plaintext.nullifier",
        "note_plaintext.timelock",
        "note_plaintext.hashlock",
        "compliance_pubkey_x",
        "compliance_pubkey_y",
    ];

    for key in &required_keys {
        assert!(map.contains_key(*key), "missing key: {key}");
    }

    // Verify hex formatting
    assert_eq!(map.len(), 9);
    for (key, value) in &map {
        assert!(value.starts_with("0x"), "{key} not hex-prefixed: {value}");
        assert_eq!(value.len(), 66, "{key} not 66 chars: {value}");
    }
}

#[test]
fn test_deposit_inputs_value_encoding() {
    let note = NotePlaintext {
        value: U256::from(100), // 0x64
        asset_id: U256::from(1),
        secret: U256::from(2),
        nullifier: U256::from(3),
        timelock: U256::zero(),
        hashlock: U256::zero(),
    };
    let inputs = DepositInputs::new(note, U256::from(999), (U256::from(1), U256::from(2)));

    let map = inputs.to_prover_map();

    let value = map.get("note_plaintext.value").unwrap();
    // Should be 0x padded to 64 chars, ending with 64 (100 in hex)
    assert!(
        value.ends_with("64"),
        "value hex doesn't end with 64: {value}"
    );
}

// WITHDRAW TESTS

#[test]
fn test_withdraw_inputs_complete_map() {
    let inputs = WithdrawInputs {
        withdraw_value: U256::from(50),
        recipient: Address::random(),
        merkle_root: U256::from(1111),
        current_timestamp: 1700000000,
        intent_hash: U256::from(9999),
        compliance_pk: create_compliance_pk(),
        old_note: create_test_note(100),
        old_shared_secret: U256::from(2222),
        old_note_index: 5,
        old_note_path: create_merkle_path(),
        hashlock_preimage: U256::zero(),
        change_note: create_test_note(50),
        change_ephemeral_sk: U256::from(3333),
    };

    let map = inputs.to_prover_map();

    // Verify all required keys
    let required_keys = [
        "withdraw_value",
        "_recipient",
        "merkle_root",
        "current_timestamp",
        "_intent_hash",
        "compliance_pubkey_x",
        "compliance_pubkey_y",
        "old_note.value",
        "old_note.asset_id",
        "old_note.secret",
        "old_note.nullifier",
        "old_shared_secret",
        "old_note_index",
        "old_note_path",
        "hashlock_preimage",
        "change_note.value",
        "change_ephemeral_sk",
    ];

    for key in &required_keys {
        assert!(map.contains_key(*key), "missing key: {key}");
    }
}

#[test]
fn test_withdraw_merkle_path_formatting() {
    let mut path = vec![U256::zero(); 32];
    path[0] = U256::from(123);
    path[1] = U256::from(456);

    let inputs = WithdrawInputs {
        withdraw_value: U256::from(50),
        recipient: Address::zero(),
        merkle_root: U256::from(1111),
        current_timestamp: 0,
        intent_hash: U256::zero(),
        compliance_pk: create_compliance_pk(),
        old_note: create_test_note(100),
        old_shared_secret: U256::from(2222),
        old_note_index: 0,
        old_note_path: path,
        hashlock_preimage: U256::zero(),
        change_note: create_test_note(50),
        change_ephemeral_sk: U256::from(3333),
    };

    let map = inputs.to_prover_map();
    let path_str = map.get("old_note_path").unwrap();

    // Should be TOML array format
    assert!(path_str.starts_with("[\"0x"));
    assert!(path_str.ends_with("\"]"));
    assert!(path_str.contains(", "));

    let count = path_str.matches("0x").count();
    assert_eq!(count, 32);
}

// TRANSFER TESTS

#[test]
fn test_transfer_inputs_complete_map() {
    let inputs = TransferInputs {
        merkle_root: U256::from(1111),
        current_timestamp: 0,
        compliance_pk: create_compliance_pk(),
        recipient_b: (U256::from(100), U256::from(200)),
        recipient_p: (U256::from(300), U256::from(400)),
        recipient_proof: create_dleq_proof(),
        old_note: create_test_note(100),
        old_shared_secret: U256::from(2222),
        old_note_index: 0,
        old_note_path: create_merkle_path(),
        hashlock_preimage: U256::zero(),
        memo_note: create_test_note(40),
        memo_ephemeral_sk: U256::from(4444),
        change_note: create_test_note(60),
        change_ephemeral_sk: U256::from(5555),
    };

    let map = inputs.to_prover_map();

    // Verify DLEQ proof keys (Noir format: U, V, z)
    let dleq_keys = [
        "recipient_proof.U.x",
        "recipient_proof.U.y",
        "recipient_proof.V.x",
        "recipient_proof.V.y",
        "recipient_proof.z",
    ];

    for key in &dleq_keys {
        assert!(map.contains_key(*key), "missing DLEQ key: {key}");
    }

    // Verify recipient point keys
    assert!(map.contains_key("recipient_B.x"));
    assert!(map.contains_key("recipient_B.y"));
    assert!(map.contains_key("recipient_P.x"));
    assert!(map.contains_key("recipient_P.y"));

    // Verify memo and change notes
    assert!(map.contains_key("memo_note.value"));
    assert!(map.contains_key("memo_ephemeral_sk"));
    assert!(map.contains_key("change_note.value"));
    assert!(map.contains_key("change_ephemeral_sk"));
}

#[test]
fn test_transfer_value_conservation() {
    // old_note.value = memo_note.value + change_note.value
    let old_value = 100u64;
    let memo_value = 40u64;
    let change_value = 60u64;

    let inputs = TransferInputs {
        merkle_root: U256::from(1111),
        current_timestamp: 0,
        compliance_pk: create_compliance_pk(),
        recipient_b: (U256::from(100), U256::from(200)),
        recipient_p: (U256::from(300), U256::from(400)),
        recipient_proof: create_dleq_proof(),
        old_note: create_test_note(old_value),
        old_shared_secret: U256::from(2222),
        old_note_index: 0,
        old_note_path: create_merkle_path(),
        hashlock_preimage: U256::zero(),
        memo_note: create_test_note(memo_value),
        memo_ephemeral_sk: U256::from(4444),
        change_note: create_test_note(change_value),
        change_ephemeral_sk: U256::from(5555),
    };

    let map = inputs.to_prover_map();

    // Verify values are correctly encoded
    let old_val = map.get("old_note.value").unwrap();
    let memo_val = map.get("memo_note.value").unwrap();
    let change_val = map.get("change_note.value").unwrap();

    assert!(old_val.ends_with("64")); // 100 = 0x64
    assert!(memo_val.ends_with("28")); // 40 = 0x28
    assert!(change_val.ends_with("3c")); // 60 = 0x3c
}

// GAS PAYMENT TESTS

#[test]
fn test_gas_payment_inputs_complete_map() {
    let inputs = GasPaymentInputs {
        merkle_root: U256::from(1111),
        current_timestamp: 1700000000,
        payment_value: U256::from(10),
        payment_asset_id: U256::from(1),
        relayer_address: Address::random(),
        execution_hash: U256::from(9999),
        compliance_pk: create_compliance_pk(),
        old_note: create_test_note(100),
        old_shared_secret: U256::from(2222),
        old_note_index: 0,
        old_note_path: create_merkle_path(),
        hashlock_preimage: U256::zero(),
        change_note: create_test_note(90),
        change_ephemeral_sk: U256::from(3333),
    };

    let map = inputs.to_prover_map();

    // Verify all required keys (matching Noir circuit)
    let required_keys = [
        "merkle_root",
        "current_timestamp",
        "payment_value",
        "payment_asset_id",
        "_relayer_address",
        "_execution_hash",
        "compliance_pubkey_x",
        "compliance_pubkey_y",
        "old_note.value",
        "old_shared_secret",
        "old_note_index",
        "old_note_path",
        "hashlock_preimage",
        "change_note.value",
        "change_ephemeral_sk",
    ];

    for key in &required_keys {
        assert!(map.contains_key(*key), "missing key: {key}");
    }
}

// JOIN TESTS

#[test]
fn test_join_inputs_complete_map() {
    let inputs = JoinInputs {
        merkle_root: U256::from(1111),
        current_timestamp: 0,
        compliance_pk: create_compliance_pk(),
        note_a: create_test_note(50),
        secret_a: U256::from(111),
        index_a: 0,
        path_a: create_merkle_path(),
        preimage_a: U256::zero(),
        note_b: create_test_note(50),
        secret_b: U256::from(222),
        index_b: 1,
        path_b: create_merkle_path(),
        preimage_b: U256::zero(),
        note_out: create_test_note(100),
        sk_out: U256::from(333),
    };

    let map = inputs.to_prover_map();

    // Verify all note_a keys
    assert!(map.contains_key("note_a.value"));
    assert!(map.contains_key("secret_a"));
    assert!(map.contains_key("index_a"));
    assert!(map.contains_key("path_a"));
    assert!(map.contains_key("preimage_a"));

    // Verify all note_b keys
    assert!(map.contains_key("note_b.value"));
    assert!(map.contains_key("secret_b"));
    assert!(map.contains_key("index_b"));
    assert!(map.contains_key("path_b"));
    assert!(map.contains_key("preimage_b"));

    // Verify output note keys
    assert!(map.contains_key("note_out.value"));
    assert!(map.contains_key("sk_out"));
}

// SPLIT TESTS

#[test]
fn test_split_inputs_complete_map() {
    let inputs = SplitInputs {
        merkle_root: U256::from(1111),
        current_timestamp: 0,
        compliance_pk: create_compliance_pk(),
        note_in: create_test_note(100),
        secret_in: U256::from(111),
        index_in: 0,
        path_in: create_merkle_path(),
        preimage_in: U256::zero(),
        note_out_1: create_test_note(60),
        sk_out_1: U256::from(222),
        note_out_2: create_test_note(40),
        sk_out_2: U256::from(333),
    };

    let map = inputs.to_prover_map();

    // Verify input note keys
    assert!(map.contains_key("note_in.value"));
    assert!(map.contains_key("secret_in"));
    assert!(map.contains_key("index_in"));
    assert!(map.contains_key("path_in"));
    assert!(map.contains_key("preimage_in"));

    // Verify output notes use underscore format (Noir convention)
    assert!(map.contains_key("note_out_1.value"));
    assert!(map.contains_key("sk_out_1"));
    assert!(map.contains_key("note_out_2.value"));
    assert!(map.contains_key("sk_out_2"));
}

// PUBLIC CLAIM TESTS

#[test]
fn test_public_claim_inputs_complete_map() {
    let inputs = PublicClaimInputs {
        memo_id: U256::from(12345),
        compliance_pk: create_compliance_pk(),
        val: U256::from(100),
        asset_id: U256::from(1),
        timelock: U256::zero(),
        owner_x: U256::from(111),
        owner_y: U256::from(222),
        salt: U256::from(333),
        recipient_sk: U256::from(444),
        note_out: create_test_note(100),
        sk_out: U256::from(555),
    };

    let map = inputs.to_prover_map();

    let required_keys = [
        "memo_id",
        "compliance_pubkey_x",
        "compliance_pubkey_y",
        "val",
        "asset_id",
        "timelock",
        "owner_x",
        "owner_y",
        "salt",
        "recipient_sk",
        "note_out.value",
        "sk_out",
    ];

    for key in &required_keys {
        assert!(map.contains_key(*key), "missing key: {key}");
    }
}

// CIRCUIT CONSTANTS TESTS

#[test]
fn test_circuit_names_match_noir() {
    // Verify circuit name constants match expected Noir circuit names
    assert_eq!(circuits::DEPOSIT, "deposit");
    assert_eq!(circuits::WITHDRAW, "withdraw");
    assert_eq!(circuits::TRANSFER, "transfer");
    assert_eq!(circuits::GAS_PAYMENT, "gas_payment");
    assert_eq!(circuits::JOIN, "join");
    assert_eq!(circuits::SPLIT, "split");
    assert_eq!(circuits::PUBLIC_CLAIM, "public_claim");
}

// HEX ENCODING TESTS

#[test]
fn test_large_value_hex_encoding() {
    // Test with a value near BN254 field max
    let large_value = U256::from_dec_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495616",
    )
    .unwrap();

    let note = NotePlaintext {
        value: large_value,
        asset_id: U256::from(1),
        secret: U256::from(2),
        nullifier: U256::from(3),
        timelock: U256::zero(),
        hashlock: U256::zero(),
    };
    let inputs = DepositInputs::new(note, U256::from(1), (U256::from(1), U256::from(2)));

    let map = inputs.to_prover_map();
    let value = map.get("note_plaintext.value").unwrap();

    // Should be valid 66-char hex
    assert_eq!(value.len(), 66);
    assert!(value.starts_with("0x"));
}

#[test]
fn test_zero_value_hex_encoding() {
    let note = NotePlaintext {
        value: U256::zero(),
        asset_id: U256::zero(),
        secret: U256::zero(),
        nullifier: U256::zero(),
        timelock: U256::zero(),
        hashlock: U256::zero(),
    };
    let inputs = DepositInputs::new(note, U256::zero(), (U256::zero(), U256::zero()));

    let map = inputs.to_prover_map();

    // All values should be 0x followed by 64 zeros
    for value in map.values() {
        assert_eq!(value.len(), 66);
        assert!(value.starts_with("0x"));
    }

    let value = map.get("note_plaintext.value").unwrap();
    assert_eq!(
        value,
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
}
