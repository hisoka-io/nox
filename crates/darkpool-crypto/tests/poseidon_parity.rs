//! Poseidon2 parity tests against known TypeScript/Noir vectors.

use darkpool_crypto::{fr_to_u256, poseidon_hash, u256_to_fr};
use ethers_core::types::U256;

const KNOWN_VECTOR_INPUT: u64 = 456;
const KNOWN_VECTOR_OUTPUT: &str =
    "0x2b5e2e032c8c028717d5c04dbc403bad8e40126798465625f58460fcd3e9d418";

#[test]
fn test_poseidon_known_vector() {
    let input = U256::from(KNOWN_VECTOR_INPUT);
    let result = poseidon_hash(&[input]);
    let result_hex = format!("0x{:064x}", result);

    assert_eq!(
        result_hex.to_lowercase(),
        KNOWN_VECTOR_OUTPUT.to_lowercase(),
        "Poseidon vector mismatch!\nInput: {}\nExpected: {}\nGot: {}",
        KNOWN_VECTOR_INPUT,
        KNOWN_VECTOR_OUTPUT,
        result_hex
    );
}

#[test]
fn test_poseidon_deterministic() {
    let inputs = [U256::from(42), U256::from(123), U256::from(456)];

    let hash1 = poseidon_hash(&inputs);
    let hash2 = poseidon_hash(&inputs);

    assert_eq!(hash1, hash2, "Poseidon must be deterministic");
}

#[test]
fn test_poseidon_different_inputs_different_outputs() {
    let hash1 = poseidon_hash(&[U256::from(1)]);
    let hash2 = poseidon_hash(&[U256::from(2)]);

    assert_ne!(
        hash1, hash2,
        "Different inputs must produce different outputs"
    );
}

#[test]
fn test_u256_fr_conversion_roundtrip() {
    let test_values = [
        U256::from(0u64),
        U256::from(1u64),
        U256::from(456u64),
        U256::from(12345678901234567890u128),
    ];

    for original in test_values {
        let fr = u256_to_fr(original);
        let back = fr_to_u256(fr);
        assert_eq!(
            original, back,
            "U256 -> Fr -> U256 roundtrip failed for {}",
            original
        );
    }
}

#[test]
fn test_poseidon_empty_input() {
    let _result = poseidon_hash(&[]);
}

#[test]
fn test_poseidon_multi_input() {
    let inputs = [
        U256::from(100u64),
        U256::from(1u64),
        U256::from(123u64),
        U256::from(456u64),
        U256::from(0u64),
        U256::from(0u64),
    ];

    let result = poseidon_hash(&inputs);
    assert!(
        !result.is_zero(),
        "Hash of multiple inputs should be non-zero"
    );
}

#[test]
fn test_poseidon_7_input_commitment_parity() {
    let inputs: Vec<_> = (1..=7).map(U256::from).collect();
    let result = poseidon_hash(&inputs);

    let expected = U256::from_str_radix(
        "16f929bc0d216df4b05bdc44222463edf2b9791bd949ab926eebda06a502d238",
        16,
    )
    .unwrap();

    assert_eq!(
        result, expected,
        "Poseidon2([1..7]) mismatch!\n  Rust: 0x{:064x}\n  TS:   0x{:064x}",
        result, expected
    );
}

#[test]
fn test_poseidon_2_input_parity_with_typescript() {
    let result = poseidon_hash(&[U256::from(1), U256::from(2)]);
    let expected = U256::from_str_radix(
        "038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383",
        16,
    )
    .unwrap();

    assert_eq!(
        result, expected,
        "Poseidon2([1, 2]) mismatch!\n  Rust:       0x{:064x}\n  TypeScript: 0x{:064x}",
        result, expected
    );
}
