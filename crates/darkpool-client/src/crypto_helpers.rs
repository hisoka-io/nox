//! Note-specific crypto: packing, encryption, nullifier derivation.
//! Re-exports pure primitives from `darkpool_crypto`.

use ethers::types::U256;

// Re-export all pure crypto functions from darkpool-crypto for backward compatibility
pub use darkpool_crypto::{
    address_to_field, aes128_decrypt, aes128_encrypt, bjj_is_on_curve, bjj_scalar_mul,
    derive_public_key_from_sk, derive_shared_secret_bjj, field_to_address, fr_to_u256,
    from_noir_hex, kdf_to_aes_key_iv, poseidon_hash, random_bjj_scalar, random_field, string_to_fr,
    to_noir_decimal, to_noir_hex, u256_to_fr, CryptoError,
};

use crate::proof_inputs::NotePlaintext;

/// `NullifierHash` = Poseidon(`noteNullifier`)
#[must_use]
pub fn derive_nullifier_path_a(note_nullifier: U256) -> U256 {
    poseidon_hash(&[note_nullifier])
}

/// `NullifierHash` = Poseidon(`sharedSecret`, commitment, `leafIndex`)
#[must_use]
pub fn derive_nullifier_path_b(shared_secret: U256, commitment: U256, leaf_index: u64) -> U256 {
    poseidon_hash(&[shared_secret, commitment, U256::from(leaf_index)])
}

#[must_use]
pub fn calculate_public_memo_id(
    value: U256,
    asset_id: U256,
    timelock: U256,
    owner_x: U256,
    owner_y: U256,
    salt: U256,
) -> U256 {
    poseidon_hash(&[value, asset_id, timelock, owner_x, owner_y, salt])
}

/// Pack a `NotePlaintext` into 192 bytes (6 × 32-byte BE fields).
#[must_use]
pub fn pack_note_plaintext(note: &NotePlaintext) -> [u8; 192] {
    let mut buf = [0u8; 192];
    let mut offset = 0;

    for field in [
        note.asset_id,
        note.value,
        note.secret,
        note.nullifier,
        note.timelock,
        note.hashlock,
    ] {
        field.to_big_endian(&mut buf[offset..offset + 32]);
        offset += 32;
    }

    buf
}

#[must_use]
pub fn unpack_note_plaintext(bytes: &[u8; 192]) -> NotePlaintext {
    let asset_id = U256::from_big_endian(&bytes[0..32]);
    let value = U256::from_big_endian(&bytes[32..64]);
    let secret = U256::from_big_endian(&bytes[64..96]);
    let nullifier = U256::from_big_endian(&bytes[96..128]);
    let timelock = U256::from_big_endian(&bytes[128..160]);
    let hashlock = U256::from_big_endian(&bytes[160..192]);

    NotePlaintext {
        value,
        asset_id,
        secret,
        nullifier,
        timelock,
        hashlock,
    }
}

/// Pack 208-byte ciphertext into 7 field elements (LE, 31+31+31+31+31+31+22).
#[must_use]
pub fn pack_ciphertext_to_fields(ciphertext: &[u8; 208]) -> [U256; 7] {
    let mut fields = [U256::zero(); 7];
    let mut idx = 0;

    for (p, field) in fields.iter_mut().enumerate() {
        let bytes_in_this = if p < 6 { 31 } else { 22 };
        let mut val = U256::zero();

        for i in (0..bytes_in_this).rev() {
            val <<= 8;
            val += U256::from(ciphertext[idx + i]);
        }

        *field = val;
        idx += bytes_in_this;
    }

    fields
}

#[must_use]
pub fn unpack_ciphertext_from_fields(packed: &[U256; 7]) -> [u8; 208] {
    let mut ciphertext = [0u8; 208];
    let mut idx = 0;

    for (p, &val) in packed.iter().enumerate() {
        let mut val = val;
        let bytes_in_this = if p < 6 { 31 } else { 22 };

        for _ in 0..bytes_in_this {
            ciphertext[idx] = (val % U256::from(256)).as_u32() as u8;
            val /= U256::from(256);
            idx += 1;
        }
    }

    ciphertext
}

/// Encrypt a note for deposit. Returns (`packed_fields`, `ephemeral_pk`).
pub fn encrypt_note_for_deposit_aes(
    ephemeral_sk: U256,
    compliance_pk: (U256, U256),
    note: &NotePlaintext,
) -> Result<([U256; 7], (U256, U256)), CryptoError> {
    let shared_x = derive_shared_secret_bjj(ephemeral_sk, compliance_pk)?;
    let (key, iv) = kdf_to_aes_key_iv(shared_x);
    let plaintext = pack_note_plaintext(note);
    let ciphertext = aes128_encrypt(&plaintext, &key, &iv);
    let fields = pack_ciphertext_to_fields(&ciphertext);
    let epk = derive_public_key_from_sk(ephemeral_sk)?;
    Ok((fields, epk))
}

pub struct MemoEncryptionResult {
    pub packed_ciphertext: [U256; 7],
    pub ephemeral_pk: (U256, U256),
    /// a * `compliance_pk` -- Bob uses `b * int_bob` to decrypt
    pub int_bob: (U256, U256),
    /// a * `recipient_b` -- Carol uses `c * int_carol` to decrypt
    pub int_carol: (U256, U256),
}

/// 3-party ECDH memo encryption: S = a * b * c * G shared between
/// sender (a), recipient (b/ivk), and compliance (c).
pub fn encrypt_memo_note_3party(
    ephemeral_sk: U256,
    recipient_p: (U256, U256),   // P = ivk * compliance_pk = b * c * G
    recipient_b: (U256, U256),   // B = ivk * G = b * G
    compliance_pk: (U256, U256), // C = c * G
    note: &NotePlaintext,
) -> Result<MemoEncryptionResult, CryptoError> {
    let s_point = bjj_scalar_mul(ephemeral_sk, recipient_p)?;
    let shared_secret = s_point.0;

    let (key, iv) = kdf_to_aes_key_iv(shared_secret);
    let plaintext = pack_note_plaintext(note);
    let ciphertext = aes128_encrypt(&plaintext, &key, &iv);
    let packed = pack_ciphertext_to_fields(&ciphertext);

    let epk = derive_public_key_from_sk(ephemeral_sk)?;
    let int_bob = bjj_scalar_mul(ephemeral_sk, compliance_pk)?;
    let int_carol = bjj_scalar_mul(ephemeral_sk, recipient_b)?;

    Ok(MemoEncryptionResult {
        packed_ciphertext: packed,
        ephemeral_pk: epk,
        int_bob,
        int_carol,
    })
}

pub fn decrypt_note_from_fields(
    packed: &[U256; 7],
    ephemeral_sk: U256,
    compliance_pk: (U256, U256),
) -> Result<NotePlaintext, CryptoError> {
    let ciphertext = unpack_ciphertext_from_fields(packed);
    let shared_x = derive_shared_secret_bjj(ephemeral_sk, compliance_pk)?;
    let (key, iv) = kdf_to_aes_key_iv(shared_x);
    let plaintext = aes128_decrypt(&ciphertext, &key, &iv)?;
    Ok(unpack_note_plaintext(&plaintext))
}

pub struct DleqResult {
    pub recipient_b: (U256, U256),
    pub recipient_p: (U256, U256),
    pub proof: crate::proof_inputs::DLEQProof,
}

pub fn generate_dleq_proof(
    recipient_sk: U256,
    compliance_pk: (U256, U256),
) -> Result<DleqResult, CryptoError> {
    let raw = darkpool_crypto::generate_dleq_proof(recipient_sk, compliance_pk)?;
    Ok(DleqResult {
        recipient_b: raw.recipient_b,
        recipient_p: raw.recipient_p,
        proof: crate::proof_inputs::DLEQProof {
            u: raw.u,
            v: raw.v,
            z: raw.z,
        },
    })
}

/// Returns (note, `shared_secret`) -- `shared_secret` is needed for Path B nullifier derivation.
pub fn recipient_decrypt_3party(
    recipient_sk: U256,
    intermediate_point: (U256, U256),
    packed_ciphertext: &[U256; 7],
) -> Result<(NotePlaintext, U256), CryptoError> {
    let shared_point = bjj_scalar_mul(recipient_sk, intermediate_point)?;
    let shared_secret = shared_point.0;
    let (key, iv) = kdf_to_aes_key_iv(shared_secret);
    let ciphertext = unpack_ciphertext_from_fields(packed_ciphertext);
    let plaintext = aes128_decrypt(&ciphertext, &key, &iv)?;
    Ok((unpack_note_plaintext(&plaintext), shared_secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullifier_derivation() {
        let nullifier = U256::from(12345);
        let hash_a = derive_nullifier_path_a(nullifier);
        assert!(!hash_a.is_zero());

        let shared = U256::from(111);
        let commitment = U256::from(222);
        let hash_b = derive_nullifier_path_b(shared, commitment, 5);
        assert!(!hash_b.is_zero());
        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn test_note_plaintext_packing_roundtrip() {
        let note = NotePlaintext {
            asset_id: U256::from(1),
            value: U256::from(1000),
            secret: U256::from(12345),
            nullifier: U256::from(67890),
            timelock: U256::from(0),
            hashlock: U256::from(0),
        };

        let packed = pack_note_plaintext(&note);
        assert_eq!(packed.len(), 192);

        let unpacked = unpack_note_plaintext(&packed);
        assert_eq!(unpacked.asset_id, note.asset_id);
        assert_eq!(unpacked.value, note.value);
        assert_eq!(unpacked.secret, note.secret);
        assert_eq!(unpacked.nullifier, note.nullifier);
        assert_eq!(unpacked.timelock, note.timelock);
        assert_eq!(unpacked.hashlock, note.hashlock);
    }

    #[test]
    fn test_ciphertext_field_packing_roundtrip() {
        // Create a 208-byte ciphertext with known pattern
        let mut ciphertext = [0u8; 208];
        for (i, byte) in ciphertext.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        let fields = pack_ciphertext_to_fields(&ciphertext);
        assert_eq!(fields.len(), 7);

        let unpacked = unpack_ciphertext_from_fields(&fields);
        assert_eq!(unpacked, ciphertext);
    }

    #[test]
    fn test_ciphertext_field_sizes() {
        let ciphertext = [0xffu8; 208];
        let fields = pack_ciphertext_to_fields(&ciphertext);

        // Fields 0-5 should hold 31 bytes each (max value < 2^248)
        // Field 6 should hold 22 bytes (max value < 2^176)
        for (i, field) in fields[..6].iter().enumerate() {
            assert!(
                !field.is_zero(),
                "Field {} should not be zero for 0xff input",
                i
            );
        }
        assert!(!fields[6].is_zero());
    }

    #[test]
    fn test_full_note_encryption_decryption() {
        use darkpool_crypto::BASE8;

        // Create a compliance keypair
        let compliance_sk = U256::from(987654321u64);
        let mut sk_bytes = [0u8; 32];
        compliance_sk.to_big_endian(&mut sk_bytes);
        sk_bytes.reverse();
        let compliance_pk_point = BASE8.mul_scalar(&sk_bytes).expect("valid test key");
        let compliance_pk = (
            fr_to_u256(compliance_pk_point.x()),
            fr_to_u256(compliance_pk_point.y()),
        );

        // Create a note
        let note = NotePlaintext {
            asset_id: U256::from(0x123456789abcdef0u64),
            value: U256::from(1_000_000_000_000_000_000u64), // 1 ETH
            secret: random_field(),
            nullifier: random_field(),
            timelock: U256::zero(),
            hashlock: U256::zero(),
        };

        // Ephemeral key
        let ephemeral_sk = U256::from(12345678u64);

        // Encrypt
        let (packed_fields, epk) = encrypt_note_for_deposit_aes(ephemeral_sk, compliance_pk, &note)
            .expect("encryption should succeed");

        assert_eq!(packed_fields.len(), 7);
        assert!(!epk.0.is_zero() || !epk.1.is_zero());

        // Decrypt
        let decrypted = decrypt_note_from_fields(&packed_fields, ephemeral_sk, compliance_pk)
            .expect("decryption should succeed");

        assert_eq!(decrypted.asset_id, note.asset_id);
        assert_eq!(decrypted.value, note.value);
        assert_eq!(decrypted.secret, note.secret);
        assert_eq!(decrypted.nullifier, note.nullifier);
        assert_eq!(decrypted.timelock, note.timelock);
        assert_eq!(decrypted.hashlock, note.hashlock);
    }
}
