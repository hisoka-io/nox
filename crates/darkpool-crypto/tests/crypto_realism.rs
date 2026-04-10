//! Cryptographic parity tests against TypeScript/Noir known vectors.

use ark_bn254::Fr;
use ark_ff::Zero;
use darkpool_crypto::{
    aes128_decrypt, aes128_encrypt, fr_to_u256, kdf_to_aes_key_iv, poseidon_hash, string_to_fr,
    u256_to_fr, SecretKey, BASE8,
};
use ethers_core::types::U256;
use std::str::FromStr;

const POSEIDON_1_2: &str = "0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383";
const POSEIDON_456: &str = "0x2b5e2e032c8c028717d5c04dbc403bad8e40126798465625f58460fcd3e9d418";

const BASE8_X_STR: &str =
    "5299619240641551281634865583518297030282874472190772894086521144482721001553";
const BASE8_Y_STR: &str =
    "16950150798460657717958625567821834550301663161624707787222815936182638968203";

const STRING_TO_FR_ENC_KEY: &str =
    "0x0281a8425bea84c419aa615997d24dd06616356a715c72dc95be25985fd32e8d";
const STRING_TO_FR_ENC_IV: &str =
    "0x240f81dbabe617f804ce036eb97fb79d25005a52b2128ac6364b872889b4a48f";

const KDF_12345_KEY: &str = "3d5aa6a5078824942613bba749e41bd7";
const KDF_12345_IV: &str = "3e4deaaad459d176d8fe8ebae6f6f3a9";

const AES_NOTE_PLAINTEXT: &str = "0000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000000000000000000111000000000000000000000000000000000000000000000000000000000000022200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const AES_NOTE_CIPHERTEXT: &str = "fd6b26da8c94d80edaccf419a0a0e6b7515b1ae95b9cab57b7c4daea75a0e2152f214cf9811983895c523af78c6ce08c7f24316124f4d4fccadaa4a147df130a055be80dde4ca81fb6f9b9b1ba9ce4af44913469c39d3a423de439e3c7bd252d146f771fdb35f2d9f559056c454ed14af29669c88d7ceb5deaf17e583533d81f227133071ec377ee09cbf12594ee7c8732c981a3ad01b5a47a81d1acc5556da97b178a74c344594d7bd326a798d5c2030c09d89db5d67c3ba213108e7c7f34e416939edc5b05a95b03bd54eddff6fe91";

#[test]
fn test_poseidon_1_2_exact_match() {
    let inputs = [U256::from(1), U256::from(2)];
    let result = poseidon_hash(&inputs);
    let result_hex = format!("0x{:064x}", result);

    assert_eq!(
        result_hex.to_lowercase(),
        POSEIDON_1_2.to_lowercase(),
        "Poseidon([1, 2]) does not match TypeScript!\nExpected: {}\nGot:      {}",
        POSEIDON_1_2,
        result_hex
    );
}

#[test]
fn test_poseidon_456_exact_match() {
    let inputs = [U256::from(456u64)];
    let result = poseidon_hash(&inputs);
    let result_hex = format!("0x{:064x}", result);

    assert_eq!(
        result_hex.to_lowercase(),
        POSEIDON_456.to_lowercase(),
        "Poseidon([456]) mismatch!\nExpected: {}\nGot:      {}",
        POSEIDON_456,
        result_hex
    );
}

#[test]
fn test_poseidon_empty_is_defined() {
    let _result = poseidon_hash(&[]);
}

#[test]
fn test_poseidon_7_elements() {
    let inputs = [
        U256::from(100u64),
        U256::from(1u64),
        U256::from(123u64),
        U256::from(456u64),
        U256::from(0u64),
        U256::from(0u64),
        U256::from(789u64),
    ];

    let result = poseidon_hash(&inputs);
    assert!(!result.is_zero());
}

#[test]
fn test_bjj_base8_coordinates() {
    let expected_x = Fr::from_str(BASE8_X_STR).expect("BASE8_X is valid");
    let expected_y = Fr::from_str(BASE8_Y_STR).expect("BASE8_Y is valid");

    assert_eq!(
        BASE8.x(),
        expected_x,
        "BASE8.x does not match zk-kit canonical value"
    );
    assert_eq!(
        BASE8.y(),
        expected_y,
        "BASE8.y does not match zk-kit canonical value"
    );
}

#[test]
fn test_bjj_point_doubling() {
    let two_g_via_add = BASE8.add(&BASE8).expect("Point addition should work");

    let scalar_2 = 2u64.to_le_bytes();
    let two_g_via_mul = BASE8
        .mul_scalar(&scalar_2)
        .expect("mul_scalar should succeed");

    assert_eq!(two_g_via_add.x(), two_g_via_mul.x(), "2G.x mismatch");
    assert_eq!(two_g_via_add.y(), two_g_via_mul.y(), "2G.y mismatch");
}

#[test]
fn test_bjj_scalar_mul_identity() {
    let scalar_1 = 1u64.to_le_bytes();
    let result = BASE8
        .mul_scalar(&scalar_1)
        .expect("mul_scalar should succeed");

    assert_eq!(result.x(), BASE8.x(), "1*G.x should equal G.x");
    assert_eq!(result.y(), BASE8.y(), "1*G.y should equal G.y");
}

#[test]
fn test_bjj_keypair_derivation() {
    let sk_bytes = hex::decode(format!("{:064x}", 42u64)).unwrap();
    let sk = SecretKey::from_hex(&hex::encode(&sk_bytes)).expect("SK parse should work");
    let pk = sk.public_key().expect("public_key should succeed");

    assert!(!Zero::is_zero(&pk.x()));
    assert!(!Zero::is_zero(&pk.y()));
}

#[test]
fn test_bjj_ecdh_symmetry() {
    let alice_sk_hex = format!("{:064x}", 12345u64);
    let bob_sk_hex = format!("{:064x}", 67890u64);

    let alice_sk = SecretKey::from_hex(&alice_sk_hex).unwrap();
    let bob_sk = SecretKey::from_hex(&bob_sk_hex).unwrap();

    let alice_pk = alice_sk.public_key().expect("alice pk");
    let bob_pk = bob_sk.public_key().expect("bob pk");

    let ss_alice = alice_sk.derive_shared_secret(&bob_pk).expect("alice ECDH");
    let ss_bob = bob_sk.derive_shared_secret(&alice_pk).expect("bob ECDH");

    assert_eq!(ss_alice.x(), ss_bob.x(), "ECDH shared secret X mismatch");
    assert_eq!(ss_alice.y(), ss_bob.y(), "ECDH shared secret Y mismatch");
}

#[test]
fn test_u256_fr_roundtrip_small() {
    let test_values = [0u64, 1, 42, 456, 12345678901234567890];

    for val in test_values {
        let original = U256::from(val);
        let fr = u256_to_fr(original);
        let back = fr_to_u256(fr);

        assert_eq!(
            original, back,
            "U256 -> Fr -> U256 roundtrip failed for {}",
            val
        );
    }
}

#[test]
fn test_u256_fr_modular_reduction() {
    let large_value = U256::MAX;
    let fr = u256_to_fr(large_value);
    let back = fr_to_u256(fr);

    assert!(back < large_value);
}

#[test]
fn test_endianness_consistency() {
    let test_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let bytes = hex::decode(test_hex).unwrap();

    let u256 = U256::from_big_endian(&bytes);
    let fr = u256_to_fr(u256);
    let back = fr_to_u256(fr);

    let mut back_bytes = [0u8; 32];
    back.to_big_endian(&mut back_bytes);

    assert_eq!(bytes, back_bytes);
}

#[test]
fn test_string_to_fr_enc_key_exact_match() {
    let result = string_to_fr("hisoka.enc_key").unwrap();
    let result_hex = format!("0x{:064x}", result);

    assert_eq!(
        result_hex.to_lowercase(),
        STRING_TO_FR_ENC_KEY.to_lowercase(),
        "stringToFr(\"hisoka.enc_key\") mismatch!\nExpected: {}\nGot:      {}",
        STRING_TO_FR_ENC_KEY,
        result_hex
    );
}

#[test]
fn test_string_to_fr_enc_iv_exact_match() {
    let result = string_to_fr("hisoka.enc_iv").unwrap();
    let result_hex = format!("0x{:064x}", result);

    assert_eq!(
        result_hex.to_lowercase(),
        STRING_TO_FR_ENC_IV.to_lowercase(),
        "stringToFr(\"hisoka.enc_iv\") mismatch!\nExpected: {}\nGot:      {}",
        STRING_TO_FR_ENC_IV,
        result_hex
    );
}

#[test]
fn test_kdf_12345_exact_match() {
    let shared_secret = U256::from(12345u64);
    let (key, iv) = kdf_to_aes_key_iv(shared_secret);

    let key_hex = hex::encode(key);
    let iv_hex = hex::encode(iv);

    assert_eq!(
        key_hex.to_lowercase(),
        KDF_12345_KEY.to_lowercase(),
        "KDF key for shared_secret=12345 mismatch!\nExpected: {}\nGot:      {}",
        KDF_12345_KEY,
        key_hex
    );

    assert_eq!(
        iv_hex.to_lowercase(),
        KDF_12345_IV.to_lowercase(),
        "KDF IV for shared_secret=12345 mismatch!\nExpected: {}\nGot:      {}",
        KDF_12345_IV,
        iv_hex
    );
}

#[test]
fn test_aes_encryption_note_parity() {
    let key: [u8; 16] = hex::decode(KDF_12345_KEY)
        .unwrap()
        .try_into()
        .expect("Key must be 16 bytes");
    let iv: [u8; 16] = hex::decode(KDF_12345_IV)
        .unwrap()
        .try_into()
        .expect("IV must be 16 bytes");
    let plaintext_vec = hex::decode(AES_NOTE_PLAINTEXT).unwrap();
    let expected_ct = hex::decode(AES_NOTE_CIPHERTEXT).unwrap();

    assert_eq!(plaintext_vec.len(), 192, "Plaintext must be 192 bytes");

    let plaintext: [u8; 192] = plaintext_vec.try_into().unwrap();
    let ciphertext = aes128_encrypt(&plaintext, &key, &iv);

    assert_eq!(
        ciphertext.as_slice(),
        expected_ct.as_slice(),
        "AES ciphertext mismatch with TypeScript!\nExpected: {}\nGot:      {}",
        AES_NOTE_CIPHERTEXT,
        hex::encode(ciphertext)
    );
}

#[test]
fn test_aes_decryption_note_parity() {
    let key: [u8; 16] = hex::decode(KDF_12345_KEY)
        .unwrap()
        .try_into()
        .expect("Key must be 16 bytes");
    let iv: [u8; 16] = hex::decode(KDF_12345_IV)
        .unwrap()
        .try_into()
        .expect("IV must be 16 bytes");
    let ciphertext_vec = hex::decode(AES_NOTE_CIPHERTEXT).unwrap();
    let expected_plaintext = hex::decode(AES_NOTE_PLAINTEXT).unwrap();

    assert_eq!(ciphertext_vec.len(), 208, "Ciphertext must be 208 bytes");

    let ciphertext: [u8; 208] = ciphertext_vec.try_into().unwrap();
    let plaintext = aes128_decrypt(&ciphertext, &key, &iv).expect("Decryption should succeed");

    assert_eq!(
        plaintext.len(),
        192,
        "Decrypted plaintext must be 192 bytes"
    );
    assert_eq!(
        plaintext.as_slice(),
        expected_plaintext.as_slice(),
        "Decrypted plaintext does not match original"
    );
}
