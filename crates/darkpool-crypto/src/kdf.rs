//! Domain-separated key derivation for the Hisoka protocol.

use ethers_core::types::U256;

use crate::error::CryptoError;
use crate::field::{poseidon_hash, string_to_fr};

pub struct Kdf;

impl Kdf {
    /// Derive a child key: `Poseidon([master, stringToFr(purpose), nonce?])`.
    /// Nonce is only included if non-zero. `purpose` must be <= 32 bytes.
    pub fn derive(purpose: &str, master: U256, nonce: Option<U256>) -> Result<U256, CryptoError> {
        let purpose_fr = string_to_fr(purpose)?;

        Ok(match nonce {
            Some(n) if !n.is_zero() => poseidon_hash(&[master, purpose_fr, n]),
            _ => poseidon_hash(&[master, purpose_fr]),
        })
    }

    /// Convenience wrapper: derive with a u64 index as nonce.
    pub fn derive_indexed(purpose: &str, master: U256, index: u64) -> Result<U256, CryptoError> {
        Self::derive(purpose, master, Some(U256::from(index)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_deterministic() {
        let master = U256::from(12345u64);
        let result1 = Kdf::derive("hisoka.spend", master, None).unwrap();
        let result2 = Kdf::derive("hisoka.spend", master, None).unwrap();

        assert_eq!(result1, result2);
        assert!(!result1.is_zero());
    }

    #[test]
    fn test_kdf_different_purposes() {
        let master = U256::from(12345u64);
        let spend = Kdf::derive("hisoka.spend", master, None).unwrap();
        let view = Kdf::derive("hisoka.view", master, None).unwrap();

        assert_ne!(spend, view);
    }

    #[test]
    fn test_kdf_with_nonce() {
        let master = U256::from(12345u64);
        let without_nonce = Kdf::derive("hisoka.eskTweak", master, None).unwrap();
        let with_zero_nonce = Kdf::derive("hisoka.eskTweak", master, Some(U256::zero())).unwrap();
        let with_nonce_1 = Kdf::derive("hisoka.eskTweak", master, Some(U256::from(1))).unwrap();
        let with_nonce_2 = Kdf::derive("hisoka.eskTweak", master, Some(U256::from(2))).unwrap();

        assert_eq!(without_nonce, with_zero_nonce);

        assert_ne!(with_nonce_1, with_nonce_2);
        assert_ne!(with_nonce_1, without_nonce);
    }

    #[test]
    fn test_kdf_derive_indexed() {
        let master = U256::from(12345u64);
        let key_0 = Kdf::derive_indexed("hisoka.eskTweak", master, 0).unwrap();
        let key_1 = Kdf::derive_indexed("hisoka.eskTweak", master, 1).unwrap();
        let key_2 = Kdf::derive_indexed("hisoka.eskTweak", master, 2).unwrap();

        let without_nonce = Kdf::derive("hisoka.eskTweak", master, None).unwrap();
        assert_eq!(key_0, without_nonce);

        assert_ne!(key_1, key_0);
        assert_ne!(key_2, key_1);
    }

    #[test]
    fn test_kdf_protocol_purposes() {
        let master = U256::from(999999u64);

        let purposes = [
            "hisoka.spend",
            "hisoka.view",
            "hisoka.ivkMaster",
            "hisoka.eskTweak",
            "hisoka.ivkTweak",
        ];

        let mut results = Vec::new();
        for purpose in purposes {
            let result = Kdf::derive(purpose, master, None).unwrap();
            assert!(!result.is_zero(), "{purpose} produced zero");
            results.push(result);
        }

        for i in 0..results.len() {
            for j in (i + 1)..results.len() {
                assert_ne!(
                    results[i], results[j],
                    "{} and {} collided",
                    purposes[i], purposes[j]
                );
            }
        }
    }

    #[test]
    fn test_kdf_rejects_oversized_purpose() {
        let master = U256::from(12345u64);
        let long_purpose = "a]".repeat(17);
        let result = Kdf::derive(&long_purpose, master, None);
        assert!(result.is_err());
    }
}
