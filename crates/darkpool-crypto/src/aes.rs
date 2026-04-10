use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::Aes128;
use ethers_core::types::U256;

use crate::error::CryptoError;
use crate::field::{poseidon_hash, string_to_fr};

type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;

/// Cached KDF domain separation strings -- avoids repeated Poseidon2 permutations.
#[allow(clippy::expect_used)]
static KDF_KEY_PURPOSE: std::sync::LazyLock<U256> = std::sync::LazyLock::new(|| {
    string_to_fr("hisoka.enc_key")
        .expect("domain string 'hisoka.enc_key' is 14 bytes, always valid")
});

#[allow(clippy::expect_used)]
static KDF_IV_PURPOSE: std::sync::LazyLock<U256> = std::sync::LazyLock::new(|| {
    string_to_fr("hisoka.enc_iv").expect("domain string 'hisoka.enc_iv' is 13 bytes, always valid")
});

/// Derive AES key (last 16 bytes of Poseidon) and IV from shared secret.
#[must_use]
pub fn kdf_to_aes_key_iv(shared_secret: U256) -> ([u8; 16], [u8; 16]) {
    let key_purpose = *KDF_KEY_PURPOSE;
    let iv_purpose = *KDF_IV_PURPOSE;

    let key_fr = poseidon_hash(&[shared_secret, key_purpose]);
    let iv_fr = poseidon_hash(&[shared_secret, iv_purpose]);

    let mut key_bytes = [0u8; 32];
    let mut iv_bytes = [0u8; 32];
    key_fr.to_big_endian(&mut key_bytes);
    iv_fr.to_big_endian(&mut iv_bytes);

    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&key_bytes[16..]);
    iv.copy_from_slice(&iv_bytes[16..]);

    (key, iv)
}

/// Encrypt 192-byte plaintext using AES-128-CBC with PKCS#7 padding. Returns 208 bytes.
#[must_use]
#[allow(clippy::expect_used)]
pub fn aes128_encrypt(plaintext: &[u8; 192], key: &[u8; 16], iv: &[u8; 16]) -> [u8; 208] {
    let mut buf = [0u8; 208];
    buf[..192].copy_from_slice(plaintext);

    let cipher = Aes128CbcEnc::new(key.into(), iv.into());
    // SAFETY: 208-byte buffer always fits 192 bytes + PKCS#7 padding block
    let ciphertext = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buf, 192)
        .expect("buffer is correct size");

    let mut result = [0u8; 208];
    result.copy_from_slice(ciphertext);
    result
}

/// Decrypt 208-byte AES-128-CBC ciphertext, returning 192 bytes on success.
pub fn aes128_decrypt(
    ciphertext: &[u8; 208],
    key: &[u8; 16],
    iv: &[u8; 16],
) -> Result<[u8; 192], CryptoError> {
    let mut buf = [0u8; 208];
    buf.copy_from_slice(ciphertext);

    let cipher = Aes128CbcDec::new(key.into(), iv.into());
    let plaintext = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| CryptoError::DecryptionFailed("invalid PKCS#7 padding".to_string()))?;

    if plaintext.len() != 192 {
        return Err(CryptoError::DecryptionFailed(format!(
            "expected 192 bytes plaintext, got {}",
            plaintext.len()
        )));
    }

    let mut result = [0u8; 192];
    result.copy_from_slice(plaintext);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_produces_valid_lengths() {
        let shared_secret = U256::from(12345u64);
        let (key, iv) = kdf_to_aes_key_iv(shared_secret);

        assert_eq!(key.len(), 16);
        assert_eq!(iv.len(), 16);
    }

    #[test]
    fn test_kdf_deterministic() {
        let shared_secret = U256::from(987654321u64);
        let (key1, iv1) = kdf_to_aes_key_iv(shared_secret);
        let (key2, iv2) = kdf_to_aes_key_iv(shared_secret);

        assert_eq!(key1, key2);
        assert_eq!(iv1, iv2);
    }

    #[test]
    fn test_kdf_key_iv_different() {
        let shared_secret = U256::from(123456789u64);
        let (key, iv) = kdf_to_aes_key_iv(shared_secret);

        assert_ne!(key, iv);
    }

    #[test]
    fn test_aes_encrypt_decrypt_roundtrip() {
        let key = [0x12u8; 16];
        let iv = [0x34u8; 16];
        let plaintext = [0x42u8; 192];

        let ciphertext = aes128_encrypt(&plaintext, &key, &iv);
        assert_eq!(ciphertext.len(), 208);
        assert_ne!(&ciphertext[..192], &plaintext[..]);

        let decrypted = aes128_decrypt(&ciphertext, &key, &iv).expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_different_keys_different_ciphertext() {
        let key1 = [0x11u8; 16];
        let key2 = [0x22u8; 16];
        let iv = [0x00u8; 16];
        let plaintext = [0x55u8; 192];

        let ct1 = aes128_encrypt(&plaintext, &key1, &iv);
        let ct2 = aes128_encrypt(&plaintext, &key2, &iv);

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_aes_wrong_key_fails() {
        let key = [0x12u8; 16];
        let wrong_key = [0x99u8; 16];
        let iv = [0x34u8; 16];
        let plaintext = [0x42u8; 192];

        let ciphertext = aes128_encrypt(&plaintext, &key, &iv);
        let result = aes128_decrypt(&ciphertext, &wrong_key, &iv);

        assert!(result.is_err());
    }

    #[test]
    fn test_aes_wrong_iv_fails() {
        let key = [0x12u8; 16];
        let iv = [0x34u8; 16];
        let wrong_iv = [0x99u8; 16];
        let plaintext = [0x42u8; 192];

        let ciphertext = aes128_encrypt(&plaintext, &key, &iv);
        let result = aes128_decrypt(&ciphertext, &key, &wrong_iv);

        if let Ok(decrypted) = result {
            assert_ne!(decrypted, plaintext);
        }
    }

    #[test]
    fn test_aes_tampered_ciphertext() {
        let key = [0x12u8; 16];
        let iv = [0x34u8; 16];
        let plaintext = [0x42u8; 192];

        let mut ciphertext = aes128_encrypt(&plaintext, &key, &iv);

        ciphertext[207] ^= 0x01;

        let result = aes128_decrypt(&ciphertext, &key, &iv);
        assert!(result.is_err());
    }

    #[test]
    fn test_kdf_different_secrets() {
        let (key1, iv1) = kdf_to_aes_key_iv(U256::from(1u64));
        let (key2, iv2) = kdf_to_aes_key_iv(U256::from(2u64));

        assert_ne!(key1, key2);
        assert_ne!(iv1, iv2);
    }

    #[test]
    fn test_full_kdf_encrypt_decrypt_roundtrip() {
        let shared_secret = U256::from(0xDEADBEEFu64);
        let (key, iv) = kdf_to_aes_key_iv(shared_secret);

        let mut plaintext = [0u8; 192];
        for (i, byte) in plaintext.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        let ciphertext = aes128_encrypt(&plaintext, &key, &iv);
        let decrypted = aes128_decrypt(&ciphertext, &key, &iv).expect("should decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_ciphertext_length() {
        let key = [0xAAu8; 16];
        let iv = [0xBBu8; 16];
        let plaintext = [0u8; 192];

        let ct = aes128_encrypt(&plaintext, &key, &iv);
        assert_eq!(ct.len(), 208);
    }

    #[test]
    fn test_decrypt_error_variant() {
        let key = [0x12u8; 16];
        let wrong_key = [0x99u8; 16];
        let iv = [0x34u8; 16];
        let plaintext = [0x42u8; 192];

        let ciphertext = aes128_encrypt(&plaintext, &key, &iv);
        let result = aes128_decrypt(&ciphertext, &wrong_key, &iv);

        if let Err(e) = result {
            match e {
                CryptoError::DecryptionFailed(_) => {} // correct
                other => panic!("Expected DecryptionFailed, got: {other:?}"),
            }
        }
    }

    #[test]
    fn test_aes128_parity_with_typescript() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let plaintext = [1u8; 192];

        let ct = aes128_encrypt(&plaintext, &key, &iv);
        let ct_hex = hex::encode(ct);

        let expected_hex = "e14d5d0ee27715df08b4152ba23da8e066224f25d2578c169989600e70029eac0f990cdc49f2d1fbeca95ad327def624092611708a75d10f1476b8ed6499538208f47f32921f2f184cd4323eb9d24935ea8316bc08ad5e26b76f839e93cf1e26217f8c3755e8345a5d3fc257235b7c5728814627e7c922096920484cefc7dc83a9d39bfc7abb06c8576c247a650edd007ed65ff16cd8ea38a80d8b055f3ded1748499828bcc7c0baf772b5c08f4b7dc0deead18cab10f6904fea5e4ffb8b9fdd1e83330fd492c872204b49b8105231a4";

        assert_eq!(
            ct_hex, expected_hex,
            "AES-128-CBC ciphertext mismatch!\n  Rust: {ct_hex}\n  TS:   {expected_hex}"
        );
    }
}
