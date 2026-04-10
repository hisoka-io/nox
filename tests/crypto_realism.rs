//! Crypto realism: note serialization, deposit pipeline, nullifier derivation.

use darkpool_client::crypto_helpers::poseidon_hash;
use ethers::types::U256;
use std::str::FromStr;

/// Golden vector from TypeScript: WETH note with 1 ETH value.
const GOLDEN_NOTE_PACKED: &str = "000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000000000006f00000000000000000000000000000000000000000000000000000000000000de00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

#[test]
fn test_note_serialization_parity() {
    use darkpool_client::crypto_helpers::u256_to_fr;
    use nox_core::Note;

    let weth_address = U256::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
    let note = Note {
        asset_id: u256_to_fr(weth_address),
        value: u256_to_fr(U256::from(1000000000000000000u64)), // 1 ETH
        secret: u256_to_fr(U256::from(111u64)),                // 0x6f
        nullifier: u256_to_fr(U256::from(222u64)),             // 0xde
        timelock: u256_to_fr(U256::from(0u64)),
        hashlock: u256_to_fr(U256::from(0u64)),
    };

    let serialized = note.serialize_to_bytes();
    let serialized_hex = hex::encode(&serialized);

    assert_eq!(
        serialized.len(),
        192,
        "Note serialization must be 192 bytes (6 * 32)"
    );

    assert_eq!(
        serialized_hex.to_lowercase(),
        GOLDEN_NOTE_PACKED.to_lowercase(),
        "\n\nNOTE SERIALIZATION MISMATCH\n\
         Rust serialization does not match TypeScript!\n\
         \n\
         Expected (TypeScript): {}\n\
         Got (Rust):            {}\n\
         \n\
         Check: Field order, Endianness (Big Endian expected)\n\n",
        GOLDEN_NOTE_PACKED,
        serialized_hex
    );
}

/// Full deposit pipeline parity with circuit test vectors.
#[test]
fn test_deposit_pipeline_matches_circuit() {
    use darkpool_client::crypto_helpers::encrypt_note_for_deposit_aes;
    use darkpool_client::proof_inputs::NotePlaintext;

    let compliance_pk = (
        U256::from_str("0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111")
            .unwrap(),
        U256::from_str("0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8")
            .unwrap(),
    );
    let ephemeral_sk =
        U256::from_str("0x0fe883a6de68afab75b8d20bba38c90511bd969d66df3bed303a3e9d293d9550")
            .unwrap();

    let note = NotePlaintext {
        asset_id: U256::from_str(
            "0x0000000000000000000000000d500b1d8e8ef31e21c99d1db9a6444d3adf1270",
        )
        .unwrap(),
        value: U256::from(100u64),
        secret: U256::from(123u64),
        nullifier: U256::from(456u64),
        timelock: U256::zero(),
        hashlock: U256::zero(),
    };

    let exp_epk_x =
        U256::from_str("0x05aeddf5c49db2aa0a16ca23af6cc1c5f11faa4408177c276c042c7a917c9688")
            .unwrap();
    let exp_epk_y =
        U256::from_str("0x24fff8909e635b0fd91a935ef6dc0b0b91c283395fcc6c67d5e8bbad57166b6a")
            .unwrap();
    let exp_ct: [U256; 7] = [
        U256::from_str("0x00c45e1a1b67b5fb3545c3328e77d83a0afff829713bd7d675a32857c48d3ad1")
            .unwrap(),
        U256::from_str("0x0086bcb787b6fc2a30a98a9ae9b12ada6e7106c4287549635f187a70d7d5a1bb")
            .unwrap(),
        U256::from_str("0x00242ff45c3b74efb8f8fc482e403f7430ab28e27adaa2ae8de35dc510eeac4c")
            .unwrap(),
        U256::from_str("0x002df0ebc2ea5a3e0775020598190bacae76a5d75ba04874d75c1a92844adf9a")
            .unwrap(),
        U256::from_str("0x008cf25bea8386af1c3c1db8888c48e6c15d7c123ba852692077fcdcb4b33e2b")
            .unwrap(),
        U256::from_str("0x00868afe85c908d27ecc257a9ed85a1b249b7b16d2d0d66c7aa3e598b2fd73bf")
            .unwrap(),
        U256::from_str("0x00000000000000000000f14176119f1657470cef170d7734e0693fa2f1310477")
            .unwrap(),
    ];

    let (packed_ct, epk) = encrypt_note_for_deposit_aes(ephemeral_sk, compliance_pk, &note)
        .expect("Encryption should succeed");

    assert_eq!(
        epk.0, exp_epk_x,
        "\n\nEPK.x mismatch with circuit\nExpected: 0x{:064x}\nGot:      0x{:064x}\n",
        exp_epk_x, epk.0
    );
    assert_eq!(
        epk.1, exp_epk_y,
        "\n\nEPK.y mismatch with circuit\nExpected: 0x{:064x}\nGot:      0x{:064x}\n",
        exp_epk_y, epk.1
    );

    for i in 0..7 {
        assert_eq!(
            packed_ct[i], exp_ct[i],
            "\n\nPacked ciphertext field {} mismatch with circuit\nExpected: 0x{:064x}\nGot:      0x{:064x}\n",
            i, exp_ct[i], packed_ct[i]
        );
    }

    let commitment = poseidon_hash(&packed_ct);
    assert!(!commitment.is_zero());
}

/// Nullifier Path A: `Poseidon([note.nullifier])` for non-zero nullifier.
#[test]
fn test_nullifier_path_a_matches_circuit() {
    use darkpool_client::crypto_helpers::derive_nullifier_path_a;

    // From transfer circuit test: old_note.nullifier = 0xc8 (200)
    let nullifier_secret = U256::from(200u64);
    // Expected output from circuit: exp_nf
    let expected =
        U256::from_str("0x1330149830bb507a82c893814415ac88d36a2f8263dffffdb1956b3635a04fae")
            .unwrap();

    let computed = derive_nullifier_path_a(nullifier_secret);

    assert_eq!(
        computed, expected,
        "\n\nNullifier Path A mismatch with circuit\nExpected: 0x{:064x}\nGot:      0x{:064x}\n",
        expected, computed
    );
}
