use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ethers_core::types::{Address, U256};

use crate::error::CryptoError;
use crate::poseidon::{IPoseidonHasher, NoxHasher};

/// Convert ethers U256 to `ark_bn254::Fr`. Values >= modulus are silently reduced.
#[allow(clippy::must_use_candidate)]
pub fn u256_to_fr(value: U256) -> Fr {
    let mut bytes = [0u8; 32];
    value.to_big_endian(&mut bytes);
    Fr::from_be_bytes_mod_order(&bytes)
}

/// Convert `ark_bn254::Fr` to ethers U256.
#[allow(clippy::must_use_candidate)]
pub fn fr_to_u256(fr: Fr) -> U256 {
    let bigint = fr.into_bigint();
    let bytes = bigint.to_bytes_be();
    U256::from_big_endian(&bytes)
}

/// Convert U256 to Noir-compatible hex string (0x-prefixed, 64 chars, lowercase).
#[allow(clippy::must_use_candidate)]
pub fn to_noir_hex(value: U256) -> String {
    format!("0x{value:064x}")
}

/// Convert U256 to Noir decimal string.
#[allow(clippy::must_use_candidate)]
pub fn to_noir_decimal(value: U256) -> String {
    value.to_string()
}

/// Parse a Noir hex string (0x-prefixed or raw) back to U256.
pub fn from_noir_hex(hex_str: &str) -> Result<U256, CryptoError> {
    let clean = hex_str.trim().trim_start_matches("0x");
    let padded = format!("{clean:0>64}");
    let bytes = hex::decode(&padded).map_err(|_| CryptoError::FieldConversion)?;
    Ok(U256::from_big_endian(&bytes))
}

/// Poseidon2 hash over U256 values. Output matches `std::hash::poseidon2` in Noir.
#[must_use]
pub fn poseidon_hash(inputs: &[U256]) -> U256 {
    let hasher = NoxHasher::new();

    let fr_inputs: Vec<_> = inputs.iter().map(|u| u256_to_fr(*u)).collect();
    let result_fr = hasher.hash(&fr_inputs);
    fr_to_u256(result_fr)
}

/// Poseidon hash on `Fr` directly, avoiding U256 roundtrips.
#[must_use]
pub fn poseidon_hash_fr(inputs: &[Fr]) -> Fr {
    let hasher = NoxHasher::new();
    hasher.hash(inputs)
}

/// Convert string to field element: left-pad to 32 bytes, interpret as Fr, then Poseidon hash.
///
/// Must match TypeScript `stringToFr` exactly for KDF domain separation.
pub fn string_to_fr(text: &str) -> Result<U256, CryptoError> {
    let bytes = text.as_bytes();
    if bytes.len() > 32 {
        return Err(CryptoError::InputTooLong {
            max: 32,
            got: bytes.len(),
        });
    }

    // Left-pad to 32 bytes
    let mut padded = [0u8; 32];
    let start = 32 - bytes.len();
    padded[start..].copy_from_slice(bytes);

    let fr = Fr::from_be_bytes_mod_order(&padded);
    let field_from_bytes = fr_to_u256(fr);
    Ok(poseidon_hash(&[field_from_bytes]))
}

/// Convert an Ethereum address to a field element.
#[allow(clippy::must_use_candidate)]
pub fn address_to_field(addr: Address) -> U256 {
    U256::from_big_endian(addr.as_bytes())
}

/// Convert a field element back to an Ethereum address (last 20 bytes).
#[allow(clippy::must_use_candidate)]
pub fn field_to_address(field: U256) -> Address {
    let mut bytes = [0u8; 32];
    field.to_big_endian(&mut bytes);
    Address::from_slice(&bytes[12..32])
}

/// Generate a random BN254 scalar field element.
#[must_use]
pub fn random_field() -> U256 {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);

    let fr = Fr::from_be_bytes_mod_order(&bytes);
    fr_to_u256(fr)
}

/// Random BJJ scalar (mod subgroup order L, ~2^251). Required for Noir circuits
/// where `ScalarField::<63>` needs values < 2^252; `random_field()` would fail ~67% of the time.
#[must_use]
pub fn random_bjj_scalar() -> U256 {
    use num_bigint::BigUint;
    use rand::RngCore;

    #[allow(clippy::expect_used)]
    static SUBGROUP_ORDER_BIGINT: std::sync::LazyLock<BigUint> = std::sync::LazyLock::new(|| {
        BigUint::parse_bytes(crate::SUBGROUP_ORDER.as_bytes(), 10)
            .expect("SUBGROUP_ORDER is a compile-time decimal constant")
    });

    let mut rng = rand::rngs::OsRng;
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);

    let val = BigUint::from_bytes_be(&bytes);
    let reduced = val % &*SUBGROUP_ORDER_BIGINT;
    let be_bytes = reduced.to_bytes_be();
    let mut padded = [0u8; 32];
    let start = 32_usize.saturating_sub(be_bytes.len());
    let copy_len = be_bytes.len().min(32);
    padded[start..start + copy_len].copy_from_slice(&be_bytes[..copy_len]);
    U256::from_big_endian(&padded)
}

/// Serialize `Fr` as `"0x"` + 64 lowercase hex chars (big-endian).
pub fn serialize_fr<S>(field: &ark_bn254::Fr, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let bytes = field.into_bigint().to_bytes_be();
    serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
}

/// Deserialize `Fr` from hex string. Rejects over-modulus values via round-trip check.
pub fn deserialize_fr<'de, D>(deserializer: D) -> Result<ark_bn254::Fr, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    let s = String::deserialize(deserializer)?;
    let clean_s = s.trim_start_matches("0x");
    let bytes = hex::decode(clean_s).map_err(serde::de::Error::custom)?;

    if bytes.len() > 32 {
        return Err(serde::de::Error::custom("Field element exceeds 32 bytes"));
    }

    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(&bytes);

    let val = ark_bn254::Fr::from_be_bytes_mod_order(&padded);

    let round_trip = val.into_bigint().to_bytes_be();
    if round_trip != padded {
        return Err(serde::de::Error::custom("Value exceeds field modulus"));
    }

    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u256_fr_roundtrip() {
        let original = U256::from(12345u64);
        let fr = u256_to_fr(original);
        let back = fr_to_u256(fr);
        assert_eq!(original, back);
    }

    #[test]
    fn test_u256_fr_large_value() {
        let bytes = [0xffu8; 32];
        let original = U256::from_big_endian(&bytes);
        let fr = u256_to_fr(original);
        let back = fr_to_u256(fr);
        assert!(back < original);
    }

    #[test]
    fn test_poseidon_hash_deterministic() {
        let inputs = [U256::from(1), U256::from(2), U256::from(3)];
        let hash1 = poseidon_hash(&inputs);
        let hash2 = poseidon_hash(&inputs);
        assert_eq!(hash1, hash2);
        assert!(!hash1.is_zero());
    }

    #[test]
    fn test_random_field_valid() {
        let a = random_field();
        let b = random_field();
        assert_ne!(a, b);

        let fr = u256_to_fr(a);
        let back = fr_to_u256(fr);
        assert_eq!(a, back);
    }

    #[test]
    fn test_string_to_fr_deterministic() {
        let result1 = string_to_fr("hisoka.enc_key").unwrap();
        let result2 = string_to_fr("hisoka.enc_key").unwrap();
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_string_to_fr_different_inputs() {
        let key = string_to_fr("hisoka.enc_key").unwrap();
        let iv = string_to_fr("hisoka.enc_iv").unwrap();
        assert_ne!(key, iv);
    }

    #[test]
    fn test_string_to_fr_too_long() {
        let long = "a".repeat(33);
        let result = string_to_fr(&long);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            CryptoError::InputTooLong { max: 32, got: 33 }
        );
    }

    #[test]
    fn test_string_to_fr_exactly_32() {
        let exact = "a".repeat(32);
        let result = string_to_fr(&exact);
        assert!(result.is_ok());
    }

    #[test]
    fn test_string_to_fr_empty() {
        let result = string_to_fr("");
        assert!(result.is_ok());
        assert!(!result.unwrap().is_zero());
    }

    #[test]
    fn test_to_noir_hex_format() {
        let val = U256::from(255u64);
        let hex = to_noir_hex(val);
        assert!(hex.starts_with("0x"));
        assert_eq!(hex.len(), 66);
        assert!(hex.ends_with("ff"));
    }

    #[test]
    fn test_to_noir_hex_zero() {
        let hex = to_noir_hex(U256::zero());
        assert_eq!(hex, format!("0x{}", "0".repeat(64)));
    }

    #[test]
    fn test_noir_hex_roundtrip() {
        let values = [
            U256::zero(),
            U256::from(1u64),
            U256::from(u64::MAX),
            U256::from(42u64),
        ];
        for val in values {
            let hex = to_noir_hex(val);
            let recovered = from_noir_hex(&hex).expect("roundtrip");
            assert_eq!(val, recovered, "roundtrip mismatch for {val}");
        }
    }

    #[test]
    fn test_from_noir_hex_no_prefix() {
        let result = from_noir_hex("ff");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), U256::from(255u64));
    }

    #[test]
    fn test_from_noir_hex_invalid() {
        let result = from_noir_hex("0xZZZZ");
        assert!(result.is_err());
    }

    #[test]
    fn test_to_noir_decimal() {
        assert_eq!(to_noir_decimal(U256::from(42u64)), "42");
        assert_eq!(to_noir_decimal(U256::zero()), "0");
    }

    #[test]
    fn test_address_roundtrip() {
        let addr = Address::from_slice(&[0xABu8; 20]);
        let field = address_to_field(addr);
        let recovered = field_to_address(field);
        assert_eq!(addr, recovered);
    }

    #[test]
    fn test_address_zero() {
        let addr = Address::zero();
        let field = address_to_field(addr);
        assert!(field.is_zero());
        let recovered = field_to_address(field);
        assert_eq!(addr, recovered);
    }

    #[test]
    fn test_address_known_value() {
        let addr_bytes = hex::decode("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045").unwrap();
        let addr = Address::from_slice(&addr_bytes);
        let field = address_to_field(addr);
        let recovered = field_to_address(field);
        assert_eq!(addr, recovered);
    }

    #[test]
    fn test_serialize_deserialize_fr_roundtrip() {
        use ark_ff::BigInteger;

        let values = [
            U256::zero(),
            U256::from(1u64),
            U256::from(999999u64),
            U256::from(u64::MAX),
        ];
        for val in values {
            let fr = u256_to_fr(val);

            let bytes = fr.into_bigint().to_bytes_be();
            let hex_str = format!("0x{}", hex::encode(&bytes));
            assert!(hex_str.starts_with("0x"));
            assert_eq!(hex_str.len(), 66);

            let clean = hex_str.trim_start_matches("0x");
            let decoded = hex::decode(clean).expect("valid hex");
            let mut padded = [0u8; 32];
            padded[32 - decoded.len()..].copy_from_slice(&decoded);
            let recovered = ark_bn254::Fr::from_be_bytes_mod_order(&padded);

            let round_trip = recovered.into_bigint().to_bytes_be();
            assert_eq!(round_trip, padded, "unexpected reduction for U256={val}");
            assert_eq!(fr, recovered, "Fr roundtrip mismatch for U256={val}");
        }
    }

    #[test]
    fn test_deserialize_fr_over_modulus() {
        use ark_ff::BigInteger;

        let bytes = [0xFFu8; 32];
        let val = ark_bn254::Fr::from_be_bytes_mod_order(&bytes);

        let round_trip = val.into_bigint().to_bytes_be();
        assert_ne!(round_trip.as_slice(), &bytes[..]);
    }

    #[test]
    fn test_u256_to_fr_zero() {
        let fr = u256_to_fr(U256::zero());
        let back = fr_to_u256(fr);
        assert!(back.is_zero());
    }

    #[test]
    fn test_u256_to_fr_max_valid() {
        let modulus_minus_one = U256::from_dec_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495616",
        )
        .unwrap();
        let fr = u256_to_fr(modulus_minus_one);
        let back = fr_to_u256(fr);
        assert_eq!(modulus_minus_one, back);
    }

    #[test]
    fn test_poseidon_hash_single_input() {
        let hash = poseidon_hash(&[U256::from(42)]);
        assert!(!hash.is_zero());
    }

    #[test]
    fn test_poseidon_hash_collision_resistance() {
        let h1 = poseidon_hash(&[U256::from(1)]);
        let h2 = poseidon_hash(&[U256::from(2)]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_poseidon_hash_multi_block() {
        let inputs: Vec<_> = (0..10).map(U256::from).collect();
        let hash = poseidon_hash(&inputs);
        assert!(!hash.is_zero());

        let mut reversed = inputs.clone();
        reversed.reverse();
        let hash2 = poseidon_hash(&reversed);
        assert_ne!(hash, hash2);
    }

    #[test]
    fn test_random_bjj_scalar_in_subgroup_order() {
        use num_bigint::BigUint;

        let subgroup_order = BigUint::parse_bytes(
            b"2736030358979909402780800718157159386076813972158567259200215660948447373041",
            10,
        )
        .expect("valid decimal constant");

        for _ in 0..1000 {
            let scalar = random_bjj_scalar();
            let mut bytes = [0u8; 32];
            scalar.to_big_endian(&mut bytes);
            let val = BigUint::from_bytes_be(&bytes);
            assert!(val < subgroup_order, "got {val} >= subgroup order");
        }
    }

    #[test]
    fn test_random_field_valid_multiple() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..20 {
            let val = random_field();
            let fr = u256_to_fr(val);
            let back = fr_to_u256(fr);
            assert_eq!(val, back);
            seen.insert(val);
        }
        assert!(
            seen.len() >= 15,
            "only {} unique values in 20 draws",
            seen.len()
        );
    }
}
