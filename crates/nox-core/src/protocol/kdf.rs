use ark_bn254::Fr;
use ark_std::Zero;
use darkpool_crypto::error::CryptoError;
use darkpool_crypto::IPoseidonHasher;
use std::sync::Arc;

pub struct HisokaKdf {
    hasher: Arc<dyn IPoseidonHasher>,
}

impl HisokaKdf {
    pub fn new(hasher: Arc<dyn IPoseidonHasher>) -> Self {
        Self { hasher }
    }

    /// Derive a child key from a master key, purpose string, and optional nonce.
    ///
    /// Returns `Err` if `purpose` exceeds 32 bytes.
    ///
    /// **Collision note (M-04):** When `nonce` is `None` or `Some(Fr::zero())`,
    /// the hash input is identical: `[master, purpose_fr]`. This is intentional --
    /// the nonce-less derivation is used only once per purpose (e.g., `"hisoka.ephemeral"`).
    /// Callers that re-derive with different nonces MUST use nonce >= 1.
    pub fn derive(&self, purpose: &str, master: Fr, nonce: Option<Fr>) -> Result<Fr, CryptoError> {
        let purpose_fr = self.hasher.string_to_fr(purpose)?;

        let mut inputs = vec![master, purpose_fr];

        if let Some(n) = nonce {
            if !n.is_zero() {
                inputs.push(n);
            }
        }

        Ok(self.hasher.hash(&inputs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::One;
    use darkpool_crypto::poseidon::NoxHasher;

    fn kdf() -> HisokaKdf {
        HisokaKdf::new(Arc::new(NoxHasher))
    }

    #[test]
    fn derive_is_deterministic() {
        let master = Fr::one();
        let k = kdf();
        let a = k.derive("test.purpose", master, None).unwrap();
        let b = k.derive("test.purpose", master, None).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_purposes_yield_different_keys() {
        let master = Fr::one();
        let k = kdf();
        let a = k.derive("purpose.alpha", master, None).unwrap();
        let b = k.derive("purpose.beta", master, None).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_nonces_yield_different_keys() {
        let master = Fr::one();
        let k = kdf();
        let a = k.derive("same", master, Some(Fr::from(1u64))).unwrap();
        let b = k.derive("same", master, Some(Fr::from(2u64))).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn none_and_zero_nonce_are_equivalent() {
        let master = Fr::one();
        let k = kdf();
        let a = k.derive("same", master, None).unwrap();
        let b = k.derive("same", master, Some(Fr::zero())).unwrap();
        assert_eq!(
            a, b,
            "None and Some(Fr::zero()) must produce the same key (M-04 collision)"
        );
    }

    #[test]
    fn nonzero_nonce_differs_from_none() {
        let master = Fr::one();
        let k = kdf();
        let a = k.derive("same", master, None).unwrap();
        let b = k.derive("same", master, Some(Fr::from(1u64))).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_masters_yield_different_keys() {
        let k = kdf();
        let a = k.derive("same", Fr::from(100u64), None).unwrap();
        let b = k.derive("same", Fr::from(200u64), None).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn output_is_nonzero() {
        let k = kdf();
        let result = k.derive("test", Fr::one(), None).unwrap();
        assert!(!result.is_zero());
    }
}
