//! Lioness wide-block cipher (4-round Luby-Rackoff SPRP) for non-malleable Sphinx body encryption.
//! Prevents tagging attacks: flipping any ciphertext bit garbles the entire plaintext.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{ChaCha20, Key, Nonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

const HASH_SIZE: usize = 32; // SHA-256 output = R block size

pub const MIN_BODY_SIZE: usize = HASH_SIZE + 1;

/// Four 32-byte sub-keys for the Lioness cipher, derived from a single `pi` key via HKDF.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct LionessKeys {
    pub k1: [u8; 32],
    pub k2: [u8; 32],
    pub k3: [u8; 32],
    pub k4: [u8; 32],
}

impl LionessKeys {
    /// Derive 4 sub-keys from `pi` via HKDF-SHA256-Expand with distinct info strings.
    ///
    /// Expects are safe: `pi` is 32 bytes (>= SHA-256 PRK minimum) and we
    /// request 32 bytes per expansion (<< 255 * `hash_len` limit).
    #[inline]
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn from_pi(pi: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::from_prk(pi).expect("valid PRK length");

        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        let mut k3 = [0u8; 32];
        let mut k4 = [0u8; 32];

        hk.expand(b"lioness_k1", &mut k1)
            .expect("valid expansion length");
        hk.expand(b"lioness_k2", &mut k2)
            .expect("valid expansion length");
        hk.expand(b"lioness_k3", &mut k3)
            .expect("valid expansion length");
        hk.expand(b"lioness_k4", &mut k4)
            .expect("valid expansion length");

        Self { k1, k2, k3, k4 }
    }
}

/// Encrypt a body in-place. Panics if `data.len() < MIN_BODY_SIZE` (33 bytes).
#[inline]
pub fn lioness_encrypt(keys: &LionessKeys, data: &mut [u8]) {
    assert!(
        data.len() >= MIN_BODY_SIZE,
        "Lioness body must be at least {} bytes, got {}",
        MIN_BODY_SIZE,
        data.len()
    );

    let (right, left) = data.split_at_mut(HASH_SIZE);

    // Round 1: L ^= S(k2, R)
    xor_with_stream(&keys.k2, right, left);

    // Round 2: R ^= H(k1, L)
    xor_with_hash(&keys.k1, left, right);

    // Round 3: L ^= S(k4, R)
    xor_with_stream(&keys.k4, right, left);

    // Round 4: R ^= H(k3, L)
    xor_with_hash(&keys.k3, left, right);
}

/// Decrypt a body in-place. Panics if `data.len() < MIN_BODY_SIZE` (33 bytes).
#[inline]
pub fn lioness_decrypt(keys: &LionessKeys, data: &mut [u8]) {
    assert!(
        data.len() >= MIN_BODY_SIZE,
        "Lioness body must be at least {} bytes, got {}",
        MIN_BODY_SIZE,
        data.len()
    );

    let (right, left) = data.split_at_mut(HASH_SIZE);

    // Round 4 inverse: R ^= H(k3, L)
    xor_with_hash(&keys.k3, left, right);

    // Round 3 inverse: L ^= S(k4, R)
    xor_with_stream(&keys.k4, right, left);

    // Round 2 inverse: R ^= H(k1, L)
    xor_with_hash(&keys.k1, left, right);

    // Round 1 inverse: L ^= S(k2, R)
    xor_with_stream(&keys.k2, right, left);
}

/// `target ^= SHA256(key || input)` for Lioness hash rounds.
#[inline]
fn xor_with_hash(key: &[u8; 32], input: &[u8], target: &mut [u8]) {
    debug_assert_eq!(target.len(), HASH_SIZE);

    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(input);
    let hash: [u8; 32] = hasher.finalize().into();

    for (t, h) in target.iter_mut().zip(hash.iter()) {
        *t ^= h;
    }
}

/// `target ^= ChaCha20(SHA256(key || nonce_source), nonce_source[..12])` for Lioness stream rounds.
#[inline]
fn xor_with_stream(key: &[u8; 32], nonce_source: &[u8], target: &mut [u8]) {
    debug_assert!(nonce_source.len() >= 12);

    let derived: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(nonce_source);
        hasher.finalize().into()
    };

    let cipher_key = Key::from_slice(&derived);
    let nonce = Nonce::from_slice(&nonce_source[..12]);
    let mut cipher = ChaCha20::new(cipher_key, nonce);
    cipher.apply_keystream(target);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let pi = [42u8; 32];
        let keys = LionessKeys::from_pi(&pi);

        let original = vec![0xABu8; 1024];
        let mut data = original.clone();

        lioness_encrypt(&keys, &mut data);
        assert_ne!(data, original);

        lioness_decrypt(&keys, &mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_encrypt_decrypt_large_body() {
        // Sphinx body size: ~32296 bytes
        let pi = [0x5A; 32];
        let keys = LionessKeys::from_pi(&pi);

        let original: Vec<u8> = (0..32296u32).map(|i| (i % 256) as u8).collect();
        let mut data = original.clone();

        lioness_encrypt(&keys, &mut data);
        assert_ne!(data, original);

        lioness_decrypt(&keys, &mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_bit_flip_garbles_all() {
        let pi = [0x7F; 32];
        let keys = LionessKeys::from_pi(&pi);

        let original = vec![0u8; 512];
        let mut encrypted = original.clone();
        lioness_encrypt(&keys, &mut encrypted);

        // Flip one bit in the middle of the ciphertext
        encrypted[256] ^= 0x01;

        // Decrypt the tampered ciphertext
        let mut decrypted = encrypted;
        lioness_decrypt(&keys, &mut decrypted);

        // The plaintext should be completely garbled (not just one bit different)
        let matching_bytes = decrypted
            .iter()
            .zip(original.iter())
            .filter(|(a, b)| a == b)
            .count();

        // With SPRP, flipping one ciphertext bit should affect ~50% of plaintext bytes
        // Allow some statistical tolerance: fewer than 80% should match
        assert!(
            matching_bytes < (original.len() * 80 / 100),
            "{matching_bytes}/{} bytes survived bit flip -- SPRP garbling insufficient",
            original.len()
        );
    }

    #[test]
    fn test_different_keys_produce_different_ciphertext() {
        let keys1 = LionessKeys::from_pi(&[1u8; 32]);
        let keys2 = LionessKeys::from_pi(&[2u8; 32]);

        let plaintext = vec![0x42u8; 256];
        let mut ct1 = plaintext.clone();
        let mut ct2 = plaintext.clone();

        lioness_encrypt(&keys1, &mut ct1);
        lioness_encrypt(&keys2, &mut ct2);

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_min_body_size() {
        let keys = LionessKeys::from_pi(&[0u8; 32]);
        let mut data = vec![0u8; MIN_BODY_SIZE];
        // Should not panic
        lioness_encrypt(&keys, &mut data);
        lioness_decrypt(&keys, &mut data);
        assert_eq!(data, vec![0u8; MIN_BODY_SIZE]);
    }

    #[test]
    #[should_panic(expected = "Lioness body must be at least")]
    fn test_too_small_body_panics() {
        let keys = LionessKeys::from_pi(&[0u8; 32]);
        let mut data = vec![0u8; HASH_SIZE]; // Only 32 bytes, need 33
        lioness_encrypt(&keys, &mut data);
    }

    #[test]
    fn test_multi_layer_onion() {
        // Simulate 3-hop onion: encrypt with 3 different keys, decrypt in reverse
        let keys: Vec<LionessKeys> = (0..3u8)
            .map(|i| LionessKeys::from_pi(&[i + 10; 32]))
            .collect();

        let original = vec![0xCC; 2048];
        let mut data = original.clone();

        // Encrypt layers (innermost first, like Sphinx packet construction)
        for k in keys.iter().rev() {
            lioness_encrypt(k, &mut data);
        }

        // Decrypt layers (outermost first, like relay processing)
        for k in &keys {
            lioness_decrypt(k, &mut data);
        }

        assert_eq!(data, original);
    }

    #[test]
    fn test_keys_from_pi_deterministic() {
        let pi = [0xFE; 32];
        let keys1 = LionessKeys::from_pi(&pi);
        let keys2 = LionessKeys::from_pi(&pi);
        assert_eq!(keys1.k1, keys2.k1);
        assert_eq!(keys1.k2, keys2.k2);
        assert_eq!(keys1.k3, keys2.k3);
        assert_eq!(keys1.k4, keys2.k4);
    }

    #[test]
    fn test_keys_from_pi_distinct_subkeys() {
        let keys = LionessKeys::from_pi(&[0xAA; 32]);
        // All 4 sub-keys should be different
        assert_ne!(keys.k1, keys.k2);
        assert_ne!(keys.k1, keys.k3);
        assert_ne!(keys.k1, keys.k4);
        assert_ne!(keys.k2, keys.k3);
        assert_ne!(keys.k2, keys.k4);
        assert_ne!(keys.k3, keys.k4);
    }

    #[test]
    fn test_lioness_serde_roundtrip() {
        let keys = LionessKeys::from_pi(&[0xBB; 32]);
        let json = serde_json::to_string(&keys).expect("serialize");
        let keys2: LionessKeys = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(keys.k1, keys2.k1);
        assert_eq!(keys.k2, keys2.k2);
        assert_eq!(keys.k3, keys2.k3);
        assert_eq!(keys.k4, keys2.k4);
    }
}
