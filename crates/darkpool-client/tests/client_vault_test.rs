//! # Client Vault Integration Tests
//!
//! Integration tests for Phase 3A: The Vault implementation.
//! Tests the full key derivation, note encryption, and decryption flows.

use darkpool_client::{
    aes128_decrypt, aes128_encrypt, derive_nullifier_path_a, derive_nullifier_path_b,
    encrypt_note_for_deposit_aes, fr_to_u256, kdf_to_aes_key_iv, pack_ciphertext_to_fields,
    pack_note_plaintext, poseidon_hash, u256_to_fr, unpack_ciphertext_from_fields,
    unpack_note_plaintext, DarkAccount, EventType, KeyRepository, NotePlaintext, NoteProcessor,
    UnprocessedEvent,
};
use darkpool_crypto::bjj::BASE8;
use darkpool_crypto::kdf::Kdf;
use ethers::types::U256;
use num_bigint::BigUint;

// BJJ Subgroup Order - used for key reduction
const SUBGROUP_ORDER: &str =
    "2736030358979909402780800718157159386076813972158567259200215660948447373041";

/// Helper to reduce U256 mod subgroup order
fn reduce_mod_subgroup(value: U256) -> U256 {
    let mut bytes = [0u8; 32];
    value.to_big_endian(&mut bytes);
    let bigint = BigUint::from_bytes_be(&bytes);
    let order = BigUint::parse_bytes(SUBGROUP_ORDER.as_bytes(), 10).expect("valid subgroup order");
    let reduced = bigint % order;
    let mut result_bytes = reduced.to_bytes_be();
    while result_bytes.len() < 32 {
        result_bytes.insert(0, 0);
    }
    U256::from_big_endian(&result_bytes)
}

/// Helper to create a compliance keypair
fn create_compliance_keypair() -> (U256, (U256, U256)) {
    let compliance_sk_bytes = [0x42u8; 32];
    let compliance_pk_point = BASE8
        .mul_scalar(&compliance_sk_bytes)
        .expect("valid test key");
    let compliance_pk = (
        fr_to_u256(compliance_pk_point.x()),
        fr_to_u256(compliance_pk_point.y()),
    );
    (U256::from_big_endian(&compliance_sk_bytes), compliance_pk)
}

/// Helper to create a random note plaintext
fn create_test_note() -> NotePlaintext {
    use darkpool_client::crypto_helpers::random_field;
    NotePlaintext {
        asset_id: U256::from(1),
        value: U256::from(1_000_000_000_000_000_000u64), // 1 ETH
        secret: random_field(),
        nullifier: random_field(),
        timelock: U256::zero(),
        hashlock: U256::zero(),
    }
}

// Test 1: KDF Consistency

#[test]
fn test_kdf_deterministic_derivation() {
    let master = U256::from(12345u64);

    // Same inputs should produce same outputs
    let key1 = Kdf::derive("hisoka.spend", master, None);
    let key2 = Kdf::derive("hisoka.spend", master, None);
    assert_eq!(key1, key2);

    // Different purposes should produce different keys
    let spend_key = Kdf::derive("hisoka.spend", master, None);
    let view_key = Kdf::derive("hisoka.view", master, None);
    assert_ne!(spend_key, view_key);

    // Nonce should change output
    let key_n0 = Kdf::derive_indexed("hisoka.eskTweak", master, 0);
    let key_n1 = Kdf::derive_indexed("hisoka.eskTweak", master, 1);
    assert_ne!(key_n0, key_n1);
}

// Test 2: Key Hierarchy

#[test]
fn test_dark_account_key_hierarchy() {
    let mut account = DarkAccount::from_seed(b"test_hierarchy_seed");

    // Derive keys in order - each should depend on previous
    let spend = account.get_spend_key();
    let view = account.get_view_key();

    // Keys should be different (different domain separation)
    assert_ne!(spend, view);

    // Per-index keys should be derivable
    let esk_0 = account.get_ephemeral_outgoing_key(0);
    let esk_1 = account.get_ephemeral_outgoing_key(1);
    assert_ne!(esk_0, esk_1);

    let ivk_0 = account.get_incoming_viewing_key(0);
    let ivk_1 = account.get_incoming_viewing_key(1);
    assert_ne!(ivk_0, ivk_1);

    // Ephemeral and incoming keys should be different
    assert_ne!(esk_0, ivk_0);
}

#[test]
fn test_dark_account_deterministic_from_seed() {
    // Same seed should produce same account
    let account1 = DarkAccount::from_seed(b"reproducible_seed");
    let account2 = DarkAccount::from_seed(b"reproducible_seed");

    let mut account1 = account1;
    let mut account2 = account2;

    assert_eq!(
        account1.get_spend_key(),
        account2.get_spend_key(),
        "Same seed must produce same keys"
    );
    assert_eq!(
        account1.get_ephemeral_outgoing_key(5),
        account2.get_ephemeral_outgoing_key(5),
        "Same seed must produce same per-index keys"
    );
}

// Test 3: AES Round-Trip

#[test]
fn test_aes_encryption_roundtrip() {
    let key = [0x12u8; 16];
    let iv = [0x34u8; 16];

    // Create a note plaintext
    let note = NotePlaintext {
        asset_id: U256::from(0xDEADBEEFu64),
        value: U256::from(1000000u64),
        secret: U256::from(12345u64),
        nullifier: U256::from(67890u64),
        timelock: U256::zero(),
        hashlock: U256::zero(),
    };

    // Pack, encrypt, decrypt, unpack
    let packed = pack_note_plaintext(&note);
    let ciphertext = aes128_encrypt(&packed, &key, &iv);
    let decrypted = aes128_decrypt(&ciphertext, &key, &iv).expect("decryption should succeed");
    let recovered = unpack_note_plaintext(&decrypted);

    assert_eq!(recovered.asset_id, note.asset_id);
    assert_eq!(recovered.value, note.value);
    assert_eq!(recovered.secret, note.secret);
    assert_eq!(recovered.nullifier, note.nullifier);
}

#[test]
fn test_ciphertext_field_packing_roundtrip() {
    // Create random ciphertext
    let mut ciphertext = [0u8; 208];
    for (i, byte) in ciphertext.iter_mut().enumerate() {
        *byte = (i * 17 % 256) as u8;
    }

    // Pack to fields and unpack
    let fields = pack_ciphertext_to_fields(&ciphertext);
    let unpacked = unpack_ciphertext_from_fields(&fields);

    assert_eq!(
        ciphertext, unpacked,
        "Ciphertext field packing must roundtrip"
    );
}

// Test 4: KeyRepository Matching

#[test]
fn test_key_repository_ephemeral_key_matching() {
    let account = DarkAccount::from_seed(b"key_repo_test");
    let (_, compliance_pk) = create_compliance_keypair();
    let mut key_repo = KeyRepository::new(account.clone(), compliance_pk);

    // Get ephemeral params (this also registers the key)
    let (eph_sk, _nonce) = key_repo.next_ephemeral_params();

    // Compute the expected public key
    let mut sk_bytes = [0u8; 32];
    eph_sk.to_big_endian(&mut sk_bytes);
    sk_bytes.reverse();
    let epk = BASE8.mul_scalar(&sk_bytes).expect("valid test key");
    let epk_x = fr_to_u256(epk.x());
    let epk_y = fr_to_u256(epk.y());

    // Should match
    let result = key_repo.try_match_deposit(epk_x, epk_y);
    assert!(result.is_some());
    let (matched_sk, index) = result.unwrap();
    assert_eq!(matched_sk, eph_sk);
    assert_eq!(index, 0);
}

#[test]
fn test_key_repository_incoming_key_matching() {
    let mut account = DarkAccount::from_seed(b"incoming_key_test");
    let (_, compliance_pk) = create_compliance_keypair();
    let mut key_repo = KeyRepository::new(account.clone(), compliance_pk);

    // Advance incoming keys
    key_repo.advance_incoming_keys(3);

    // Compute the tag for index 0 (same as KeyRepository does internally)
    let ivk = account.get_incoming_viewing_key(0);
    let ivk_mod = reduce_mod_subgroup(ivk);

    let mut ivk_bytes = [0u8; 32];
    ivk_mod.to_big_endian(&mut ivk_bytes);
    ivk_bytes.reverse();

    use darkpool_crypto::bjj::PublicKey;
    let compliance_pk_point =
        PublicKey::new_unchecked(u256_to_fr(compliance_pk.0), u256_to_fr(compliance_pk.1));
    let tag_point = compliance_pk_point
        .mul_scalar(&ivk_bytes)
        .expect("valid test key");
    let tag = fr_to_u256(tag_point.x());

    // Should match
    let result = key_repo.try_match_transfer(tag);
    assert!(result.is_some());
    let (matched_sk, index) = result.unwrap();
    assert_eq!(matched_sk, ivk_mod);
    assert_eq!(index, 0);
}

// Test 5: NoteProcessor Path A (Deposits)

#[test]
fn test_note_processor_path_a_deposit() {
    let account = DarkAccount::from_seed(b"path_a_test");
    let (_, compliance_pk) = create_compliance_keypair();
    let mut key_repo = KeyRepository::new(account, compliance_pk);

    // Create deposit
    let (ephemeral_sk, _nonce) = key_repo.next_ephemeral_params();
    let note = create_test_note();

    // Encrypt
    let (packed_ciphertext, epk) = encrypt_note_for_deposit_aes(ephemeral_sk, compliance_pk, &note)
        .expect("encryption should succeed");

    let commitment = poseidon_hash(&packed_ciphertext);

    // Create event
    let event = UnprocessedEvent {
        event_type: EventType::NewNote,
        block_number: 100,
        tx_hash: "0x1234".to_string(),
        leaf_index: 0,
        commitment,
        epk_x: epk.0,
        epk_y: epk.1,
        packed_ciphertext,
        tag: None,
        intermediate_bob_x: None,
        intermediate_bob_y: None,
    };

    // Process
    let processor = NoteProcessor::new(&key_repo, compliance_pk);
    let result = processor.process(&event);

    assert!(result.is_some());
    let wallet_note = result.unwrap();
    assert_eq!(wallet_note.note.value, note.value);
    assert_eq!(wallet_note.note.asset_id, note.asset_id);
    assert!(!wallet_note.is_transfer);
    assert!(!wallet_note.spent);

    // Verify nullifier derivation
    let expected_nullifier = derive_nullifier_path_a(note.nullifier);
    assert_eq!(wallet_note.nullifier, expected_nullifier);
}

// Test 6: NoteProcessor Path B (Transfers)

#[test]
fn test_note_processor_path_b_transfer() {
    let mut recipient_account = DarkAccount::from_seed(b"path_b_recipient");
    let (_, compliance_pk) = create_compliance_keypair();
    let mut key_repo = KeyRepository::new(recipient_account.clone(), compliance_pk);

    // Register incoming keys
    key_repo.advance_incoming_keys(5);

    // Get ivk for index 0 and reduce it
    let recipient_ivk = recipient_account.get_incoming_viewing_key(0);
    let recipient_ivk_mod = reduce_mod_subgroup(recipient_ivk);

    // Compute recipient's public key from reduced ivk
    let mut ivk_mod_bytes = [0u8; 32];
    recipient_ivk_mod.to_big_endian(&mut ivk_mod_bytes);
    ivk_mod_bytes.reverse();
    let recipient_pk = BASE8.mul_scalar(&ivk_mod_bytes).expect("valid test key");

    // Sender picks random r
    let sender_r = U256::from(98765u64);
    let mut r_bytes = [0u8; 32];
    sender_r.to_big_endian(&mut r_bytes);
    r_bytes.reverse();

    // Compute intermediate_bob = [r] * G
    let intermediate_bob = BASE8.mul_scalar(&r_bytes).expect("valid test key");

    // Compute shared secret: [r] * recipient_pk
    let sender_shared = recipient_pk.mul_scalar(&r_bytes).expect("valid test key");
    let sender_shared_secret = fr_to_u256(sender_shared.x());

    // Encrypt note
    let note = create_test_note();
    let (key, iv) = kdf_to_aes_key_iv(sender_shared_secret);
    let plaintext = pack_note_plaintext(&note);
    let ciphertext = aes128_encrypt(&plaintext, &key, &iv);
    let packed_ciphertext = pack_ciphertext_to_fields(&ciphertext);

    // Compute tag: [ivk_mod] * compliance_pk
    use darkpool_crypto::bjj::PublicKey;
    let compliance_pk_point =
        PublicKey::new_unchecked(u256_to_fr(compliance_pk.0), u256_to_fr(compliance_pk.1));
    let tag_point = compliance_pk_point
        .mul_scalar(&ivk_mod_bytes)
        .expect("valid test key");
    let tag = fr_to_u256(tag_point.x());

    let commitment = poseidon_hash(&packed_ciphertext);

    // Create memo event
    let event = UnprocessedEvent {
        event_type: EventType::NewMemo,
        block_number: 200,
        tx_hash: "0x5678".to_string(),
        leaf_index: 10,
        commitment,
        epk_x: U256::zero(),
        epk_y: U256::zero(),
        packed_ciphertext,
        tag: Some(tag),
        intermediate_bob_x: Some(fr_to_u256(intermediate_bob.x())),
        intermediate_bob_y: Some(fr_to_u256(intermediate_bob.y())),
    };

    // Process
    let processor = NoteProcessor::new(&key_repo, compliance_pk);
    let result = processor.process(&event);

    assert!(result.is_some());
    let wallet_note = result.unwrap();
    assert_eq!(wallet_note.note.value, note.value);
    assert_eq!(wallet_note.note.asset_id, note.asset_id);
    assert!(wallet_note.is_transfer);
    assert!(!wallet_note.spent);

    // Verify nullifier derivation (Path B uses shared secret)
    let expected_nullifier = derive_nullifier_path_b(wallet_note.spending_secret, commitment, 10);
    assert_eq!(wallet_note.nullifier, expected_nullifier);
}

// Test 7: Full Deposit-to-Spend Flow

#[test]
fn test_full_deposit_flow() {
    // Alice creates a wallet
    let alice_account = DarkAccount::from_seed(b"alice_wallet");
    let (_, compliance_pk) = create_compliance_keypair();
    let mut alice_key_repo = KeyRepository::new(alice_account, compliance_pk);

    // Alice deposits 100 tokens
    let deposit_value = U256::from(100_000_000_000_000_000_000u128); // 100 tokens
    let deposit_note = NotePlaintext {
        asset_id: U256::from(1), // Token ID
        value: deposit_value,
        secret: U256::from(111111u64),
        nullifier: U256::from(222222u64),
        timelock: U256::zero(),
        hashlock: U256::zero(),
    };

    // Get ephemeral key and encrypt
    let (eph_sk, _) = alice_key_repo.next_ephemeral_params();
    let (packed_ct, epk) =
        encrypt_note_for_deposit_aes(eph_sk, compliance_pk, &deposit_note).unwrap();
    let commitment = poseidon_hash(&packed_ct);

    // Simulate blockchain event
    let deposit_event = UnprocessedEvent {
        event_type: EventType::NewNote,
        block_number: 1000,
        tx_hash: "0xdeposit".to_string(),
        leaf_index: 42,
        commitment,
        epk_x: epk.0,
        epk_y: epk.1,
        packed_ciphertext: packed_ct,
        tag: None,
        intermediate_bob_x: None,
        intermediate_bob_y: None,
    };

    // Alice processes the event and recovers her note
    let processor = NoteProcessor::new(&alice_key_repo, compliance_pk);
    let recovered = processor
        .process(&deposit_event)
        .expect("Should recover deposit");

    // Verify Alice can spend this note
    assert_eq!(recovered.note.value, deposit_value);
    assert_eq!(recovered.leaf_index, 42);
    assert!(!recovered.is_transfer);
    assert!(!recovered.nullifier.is_zero());

    // The spending secret should allow deriving the same nullifier
    // (This is what the ZK circuit would verify)
    let computed_nullifier = derive_nullifier_path_a(recovered.note.nullifier);
    assert_eq!(recovered.nullifier, computed_nullifier);
}

// Test 8: Edge Cases

#[test]
fn test_unmatched_ephemeral_key_returns_none() {
    let account = DarkAccount::from_seed(b"unmatched_test");
    let (_, compliance_pk) = create_compliance_keypair();
    let key_repo = KeyRepository::new(account, compliance_pk);

    // Create event with unknown ephemeral key
    let event = UnprocessedEvent {
        event_type: EventType::NewNote,
        block_number: 100,
        tx_hash: "0xtest".to_string(),
        leaf_index: 0,
        commitment: U256::from(12345),
        epk_x: U256::from(999999), // Unknown
        epk_y: U256::from(888888),
        packed_ciphertext: [U256::zero(); 7],
        tag: None,
        intermediate_bob_x: None,
        intermediate_bob_y: None,
    };

    let processor = NoteProcessor::new(&key_repo, compliance_pk);
    assert!(
        processor.process(&event).is_none(),
        "Should not match unknown key"
    );
}

#[test]
fn test_unmatched_transfer_tag_returns_none() {
    let account = DarkAccount::from_seed(b"unmatched_tag_test");
    let (_, compliance_pk) = create_compliance_keypair();
    let key_repo = KeyRepository::new(account, compliance_pk);

    // Create memo event with unknown tag
    let event = UnprocessedEvent {
        event_type: EventType::NewMemo,
        block_number: 200,
        tx_hash: "0xtest".to_string(),
        leaf_index: 0,
        commitment: U256::from(12345),
        epk_x: U256::zero(),
        epk_y: U256::zero(),
        packed_ciphertext: [U256::zero(); 7],
        tag: Some(U256::from(99999)), // Unknown
        intermediate_bob_x: Some(U256::from(111)),
        intermediate_bob_y: Some(U256::from(222)),
    };

    let processor = NoteProcessor::new(&key_repo, compliance_pk);
    assert!(
        processor.process(&event).is_none(),
        "Should not match unknown tag"
    );
}
