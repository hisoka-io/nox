use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};

use crate::error::CryptoError;

const RATE: usize = 3;
const TWO_POW_64: u128 = 18_446_744_073_709_551_616;

pub trait IPoseidonHasher: Send + Sync {
    fn hash(&self, inputs: &[Fr]) -> Fr;
    fn string_to_fr(&self, text: &str) -> Result<Fr, CryptoError>;
}

#[derive(Default)]
pub struct NoxHasher;

impl NoxHasher {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Noir/Aztec Poseidon2 sponge (matches noir-lang/poseidon/src/poseidon2.nr).
    fn hash_internal(&self, inputs: &[Fr]) -> Fr {
        let in_len = inputs.len();
        let iv = Fr::from(in_len as u128 * TWO_POW_64);

        let mut state: [Fr; 4] = [Fr::zero(); 4];
        state[RATE] = iv;

        let mut cache = [Fr::zero(); RATE];
        let mut cache_size = 0;

        for &input in inputs {
            if cache_size == RATE {
                for i in 0..RATE {
                    state[i] += cache[i];
                }
                state = taceo_poseidon2::bn254::t4::permutation(&state);

                cache[0] = input;
                cache_size = 1;
            } else {
                cache[cache_size] = input;
                cache_size += 1;
            }
        }

        for i in 0..RATE {
            if i < cache_size {
                state[i] += cache[i];
            }
        }
        let final_state = taceo_poseidon2::bn254::t4::permutation(&state);
        final_state[0]
    }
}

impl IPoseidonHasher for NoxHasher {
    fn hash(&self, inputs: &[Fr]) -> Fr {
        self.hash_internal(inputs)
    }

    fn string_to_fr(&self, text: &str) -> Result<Fr, CryptoError> {
        let bytes = text.as_bytes();
        let len = bytes.len();
        if len > 32 {
            return Err(CryptoError::InputTooLong { max: 32, got: len });
        }
        let mut buffer = [0u8; 32];
        buffer[32 - len..].copy_from_slice(bytes);
        let field_element = Fr::from_be_bytes_mod_order(&buffer);
        Ok(self.hash(&[field_element]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    #[test]
    fn test_nox_hasher_direct_matches_wrapper() {
        let hasher = NoxHasher::new();
        let inputs = [
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(42u64),
        ];

        let via_trait = hasher.hash(&inputs);
        let via_internal = hasher.hash_internal(&inputs);

        assert_eq!(
            via_trait, via_internal,
            "hash() and hash_internal() must produce identical results"
        );
        assert!(!via_trait.is_zero(), "Hash output must not be zero");
    }

    #[test]
    fn test_nox_hasher_empty_input() {
        let hasher = NoxHasher::new();
        let via_trait = hasher.hash(&[]);
        let via_internal = hasher.hash_internal(&[]);
        assert_eq!(via_trait, via_internal);
    }

    #[test]
    fn test_nox_hasher_deterministic() {
        let hasher = NoxHasher::new();
        let inputs = [Fr::from(7u64)];
        let h1 = hasher.hash(&inputs);
        let h2 = hasher.hash(&inputs);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_nox_hasher_different_inputs_differ() {
        let hasher = NoxHasher::new();
        let h1 = hasher.hash(&[Fr::from(1u64)]);
        let h2 = hasher.hash(&[Fr::from(2u64)]);
        assert_ne!(h1, h2);
    }
}
