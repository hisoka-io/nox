use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use darkpool_crypto::NoxHasher;
use nox_core::{HisokaKdf, IPoseidonHasher};
use std::sync::Arc;

#[test]
fn test_kdf_parity_with_typescript() {
    let hasher = Arc::new(NoxHasher::new());
    let kdf = HisokaKdf::new(hasher.clone());

    let master_key = Fr::from_be_bytes_mod_order(
        &hex::decode("00000000000000000000000000000000000000000000000000000000075bcd15").unwrap(),
    );
    let nonce = Fr::from(1u64);

    let s_ephemeral = hasher
        .string_to_fr("hisoka.ephemeral")
        .expect("domain string fits in field");

    let result_hex = format!("0x{}", hex::encode(s_ephemeral.into_bigint().to_bytes_be()));
    println!("Rust string_to_fr(ephemeral): {}", result_hex);

    assert_eq!(
        result_hex, "0x1e7216c94a814cdf66bcfcc1c85c5da2470acd24a9d19b7f9649bd3781317356",
        "StringToFr (ephemeral) mismatch - Sponge initialization likely wrong"
    );

    let derived_sk = kdf
        .derive("hisoka.ephemeral", master_key, Some(nonce))
        .expect("purpose string fits in field");
    let derived_sk_hex = format!("0x{}", hex::encode(derived_sk.into_bigint().to_bytes_be()));

    println!("Rust final_ephemeral_sk:      {}", derived_sk_hex);

    assert_eq!(
        derived_sk_hex, "0x28741fe9b4d2c147f37df64a46be1aec404091d5318fc00709075cae81277707",
        "Final KDF derivation mismatch"
    );
}
