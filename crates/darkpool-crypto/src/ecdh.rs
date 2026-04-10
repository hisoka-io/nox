use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField};
use ethers_core::types::U256;

use crate::bjj::{u256_to_le_bytes, PublicKey, BASE8, BJJ_A, BJJ_D};
use crate::error::CryptoError;
use crate::field::{fr_to_u256, u256_to_fr};

/// `PK = sk * Base8`
pub fn derive_public_key_from_sk(sk: U256) -> Result<(U256, U256), CryptoError> {
    let sk_bytes = u256_to_le_bytes(sk);
    let result = BASE8.mul_scalar(&sk_bytes)?;

    let x_bytes = result.x().into_bigint().to_bytes_be();
    let y_bytes = result.y().into_bigint().to_bytes_be();

    Ok((
        U256::from_big_endian(&x_bytes),
        U256::from_big_endian(&y_bytes),
    ))
}

/// ECDH shared secret derivation. Returns X coordinate of `sk * pk`.
///
/// Uses `mul_scalar` directly (not `SecretKey::from_hex`) because the scalar
/// may exceed the BJJ subgroup order when sourced from KDF values.
pub fn derive_shared_secret_bjj(
    ephemeral_sk: U256,
    compliance_pk: (U256, U256),
) -> Result<U256, CryptoError> {
    let pk = PublicKey::from_coordinates(u256_to_fr(compliance_pk.0), u256_to_fr(compliance_pk.1))?;

    let sk_bytes = u256_to_le_bytes(ephemeral_sk);
    let shared_point = pk.mul_scalar(&sk_bytes)?;

    Ok(fr_to_u256(shared_point.x()))
}

/// Check `a*x^2 + y^2 == 1 + d*x^2*y^2`
#[must_use]
pub fn bjj_is_on_curve(x: Fr, y: Fr) -> bool {
    let a = *BJJ_A;
    let d = *BJJ_D;

    let x2 = x.square();
    let y2 = y.square();

    let lhs = a * x2 + y2;
    let rhs = Fr::from(1u64) + d * x2 * y2;

    lhs == rhs
}

/// `scalar * point` with full validation (on-curve + subgroup check).
pub fn bjj_scalar_mul(scalar: U256, point: (U256, U256)) -> Result<(U256, U256), CryptoError> {
    let x = u256_to_fr(point.0);
    let y = u256_to_fr(point.1);

    let pk = PublicKey::from_coordinates(x, y)?;

    let scalar_bytes = u256_to_le_bytes(scalar);
    let result = pk.mul_scalar(&scalar_bytes)?;

    let x_bytes = result.x().into_bigint().to_bytes_be();
    let y_bytes = result.y().into_bigint().to_bytes_be();

    Ok((
        U256::from_big_endian(&x_bytes),
        U256::from_big_endian(&y_bytes),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bjj::SecretKey;

    #[test]
    fn test_derive_shared_secret_bjj_symmetry() {
        let alice_sk = U256::from(12345u64);
        let bob_sk = U256::from(67890u64);

        let alice_sk_bytes = u256_to_le_bytes(alice_sk);
        let bob_sk_bytes = u256_to_le_bytes(bob_sk);

        let alice_pk = BASE8.mul_scalar(&alice_sk_bytes).expect("valid test key");
        let bob_pk = BASE8.mul_scalar(&bob_sk_bytes).expect("valid test key");

        let alice_pk_tuple = (fr_to_u256(alice_pk.x()), fr_to_u256(alice_pk.y()));
        let bob_pk_tuple = (fr_to_u256(bob_pk.x()), fr_to_u256(bob_pk.y()));

        let ss_from_alice = derive_shared_secret_bjj(alice_sk, bob_pk_tuple).unwrap();
        let ss_from_bob = derive_shared_secret_bjj(bob_sk, alice_pk_tuple).unwrap();

        assert_eq!(ss_from_alice, ss_from_bob);
    }

    #[test]
    fn test_derive_pk_from_zero_sk() {
        let (x, y) = derive_public_key_from_sk(U256::zero()).expect("zero sk");
        assert!(x.is_zero());
        assert_eq!(y, U256::from(1));
    }

    #[test]
    fn test_derive_pk_from_one() {
        let (x, y) = derive_public_key_from_sk(U256::from(1)).expect("sk=1");
        let base8_x = fr_to_u256(BASE8.x());
        let base8_y = fr_to_u256(BASE8.y());
        assert_eq!(x, base8_x);
        assert_eq!(y, base8_y);
    }

    #[test]
    fn test_derive_pk_matches_secret_key() {
        let mut rng = rand::thread_rng();
        let sk = SecretKey::generate(&mut rng);
        let pk = sk.public_key().expect("pk");

        let sk_bytes = sk.0.into_bigint().to_bytes_be();
        let sk_u256 = U256::from_big_endian(&sk_bytes);

        let (x, y) = derive_public_key_from_sk(sk_u256).expect("derive pk");
        assert_eq!(x, fr_to_u256(pk.x()));
        assert_eq!(y, fr_to_u256(pk.y()));
    }

    #[test]
    fn test_bjj_is_on_curve_base8() {
        assert!(bjj_is_on_curve(BASE8.x(), BASE8.y()));
    }

    #[test]
    fn test_bjj_is_on_curve_identity() {
        assert!(bjj_is_on_curve(Fr::from(0), Fr::from(1)));
    }

    #[test]
    fn test_bjj_is_on_curve_random_point() {
        assert!(!bjj_is_on_curve(Fr::from(42), Fr::from(99)));
    }

    #[test]
    fn test_bjj_is_on_curve_derived() {
        let mut rng = rand::thread_rng();
        let sk = SecretKey::generate(&mut rng);
        let pk = sk.public_key().expect("pk");
        assert!(bjj_is_on_curve(pk.x(), pk.y()));
    }

    #[test]
    fn test_bjj_scalar_mul_identity() {
        let base = (fr_to_u256(BASE8.x()), fr_to_u256(BASE8.y()));
        let result = bjj_scalar_mul(U256::from(1), base).expect("scalar mul");
        assert_eq!(result, base);
    }

    #[test]
    fn test_bjj_scalar_mul_zero() {
        let base = (fr_to_u256(BASE8.x()), fr_to_u256(BASE8.y()));
        let (x, y) = bjj_scalar_mul(U256::zero(), base).expect("scalar mul 0");
        assert!(x.is_zero());
        assert_eq!(y, U256::from(1));
    }

    #[test]
    fn test_bjj_scalar_mul_off_curve() {
        let bad_point = (U256::from(1), U256::from(2));
        let result = bjj_scalar_mul(U256::from(5), bad_point);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_shared_secret_rejects_off_curve() {
        let result = derive_shared_secret_bjj(U256::from(42), (U256::from(1), U256::from(2)));
        assert!(result.is_err());
    }
}
