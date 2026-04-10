//! Cryptographic primitives for the `DarkPool` protocol (BJJ, Poseidon2, AES, ECDH, KDF, DLEQ).
//!
//! All implementations maintain cross-language byte-identical parity with TypeScript, Noir, and Solidity.

pub mod aes;
pub mod bjj;
pub mod dleq;
pub mod ecdh;
pub mod error;
pub mod field;
pub mod kdf;
pub mod poseidon;

pub use aes::{aes128_decrypt, aes128_encrypt, kdf_to_aes_key_iv};
pub use bjj::{
    u256_to_le_bytes, PublicKey, SecretKey, SharedSecret, BASE8, BASE8_X, BASE8_Y, SUBGROUP_ORDER,
};
pub use dleq::{generate_dleq_proof, RawDleqProof};
pub use ecdh::{
    bjj_is_on_curve, bjj_scalar_mul, derive_public_key_from_sk, derive_shared_secret_bjj,
};
pub use error::CryptoError;
pub use field::{
    address_to_field, deserialize_fr, field_to_address, fr_to_u256, from_noir_hex, poseidon_hash,
    poseidon_hash_fr, random_bjj_scalar, random_field, serialize_fr, string_to_fr, to_noir_decimal,
    to_noir_hex, u256_to_fr,
};
pub use kdf::Kdf;
pub use poseidon::{IPoseidonHasher, NoxHasher};
