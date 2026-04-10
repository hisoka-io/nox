use crate::error::CryptoError;
use crate::field::{deserialize_fr, serialize_fr};
use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use zeroize::Zeroize;

/// `BabyJubJub` twisted Edwards parameter A = 168700.
#[allow(clippy::expect_used)]
pub(crate) static BJJ_A: std::sync::LazyLock<Fr> =
    std::sync::LazyLock::new(|| Fr::from_str("168700").expect("BJJ parameter A is valid"));

/// `BabyJubJub` twisted Edwards parameter D = 168696 (non-square, addition law is complete).
#[allow(clippy::expect_used)]
pub(crate) static BJJ_D: std::sync::LazyLock<Fr> =
    std::sync::LazyLock::new(|| Fr::from_str("168696").expect("BJJ parameter D is valid"));

pub const BASE8_X: &str =
    "5299619240641551281634865583518297030282874472190772894086521144482721001553";
pub const BASE8_Y: &str =
    "16950150798460657717958625567821834550301663161624707787222815936182638968203";

/// `BabyJubJub` subgroup order (decimal). Canonical source for all crates.
pub const SUBGROUP_ORDER: &str =
    "2736030358979909402780800718157159386076813972158567259200215660948447373041";

#[allow(clippy::expect_used)]
pub static BASE8: std::sync::LazyLock<PublicKey> = std::sync::LazyLock::new(|| PublicKey {
    x: Fr::from_str(BASE8_X).expect("BASE8_X is valid"),
    y: Fr::from_str(BASE8_Y).expect("BASE8_Y is valid"),
});

#[allow(clippy::expect_used)]
static SUBGROUP_ORDER_LE: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {
    let order = Fr::from_str(SUBGROUP_ORDER).expect("BJJ subgroup order is valid");
    order.into_bigint().to_bytes_le()
});

#[allow(clippy::expect_used)]
static HALF_MODULUS: std::sync::LazyLock<Fr> = std::sync::LazyLock::new(|| {
    Fr::from_bigint(<Fr as PrimeField>::MODULUS_MINUS_ONE_DIV_TWO)
        .expect("MODULUS_MINUS_ONE_DIV_TWO is valid")
});

/// Convert a U256 value to 32-byte little-endian representation for `mul_scalar`.
#[must_use]
pub fn u256_to_le_bytes(value: ethers_core::types::U256) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    value.to_little_endian(&mut bytes);
    bytes
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize)]
pub struct PublicKey {
    #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
    x: Fr,
    #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
    y: Fr,
}

impl PublicKey {
    #[inline]
    #[must_use]
    pub fn x(&self) -> Fr {
        self.x
    }

    #[inline]
    #[must_use]
    pub fn y(&self) -> Fr {
        self.y
    }

    /// Caller must ensure the point is on the BJJ curve and in the prime-order subgroup.
    #[inline]
    #[must_use]
    pub fn new_unchecked(x: Fr, y: Fr) -> Self {
        Self { x, y }
    }
}

/// `BabyJubJub` secret key. Zeroized on drop; no `Copy` to prevent silent duplication.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey(pub ark_ed_on_bn254::Fr);

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SecretKey").field(&"[REDACTED]").finish()
    }
}

impl SecretKey {
    pub fn generate<R: CryptoRng + Rng>(rng: &mut R) -> Self {
        use ark_std::UniformRand;
        Self(ark_ed_on_bn254::Fr::rand(rng))
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(hex_str).map_err(|_| CryptoError::InvalidKey)?;
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKey);
        }
        let val = ark_ed_on_bn254::Fr::from_be_bytes_mod_order(&bytes);

        // Reject over-modulus values that get silently reduced
        let round_trip = val.into_bigint().to_bytes_be();
        let mut padded = [0u8; 32];
        padded.copy_from_slice(&bytes);
        if round_trip != padded {
            return Err(CryptoError::InvalidKey);
        }

        Ok(Self(val))
    }

    pub fn public_key(&self) -> Result<PublicKey, CryptoError> {
        BASE8.mul_scalar(&self.0.into_bigint().to_bytes_le())
    }

    pub fn derive_shared_secret(&self, peer_pk: &PublicKey) -> Result<SharedSecret, CryptoError> {
        let point = peer_pk.mul_scalar(&self.0.into_bigint().to_bytes_le())?;
        Ok(SharedSecret {
            x: point.x,
            y: point.y,
        })
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        let bytes = self.0.into_bigint().to_bytes_be();
        hex::encode(bytes)
    }
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone)]
pub struct SharedSecret {
    x: Fr,
    y: Fr,
}

impl SharedSecret {
    #[inline]
    #[must_use]
    pub fn x(&self) -> Fr {
        self.x
    }

    #[inline]
    #[must_use]
    pub fn y(&self) -> Fr {
        self.y
    }
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedSecret")
            .field("x", &"[REDACTED]")
            .field("y", &"[REDACTED]")
            .finish()
    }
}

impl SharedSecret {
    #[must_use]
    pub fn to_symmetric_key(&self) -> [u8; 32] {
        let packed = PublicKey {
            x: self.x,
            y: self.y,
        }
        .to_bytes();
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(packed);
        hasher.finalize().into()
    }
}

impl Zeroize for SharedSecret {
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl PublicKey {
    /// Construct from coordinates with on-curve and subgroup membership validation.
    pub fn from_coordinates(x: Fr, y: Fr) -> Result<Self, CryptoError> {
        let point = Self { x, y };

        if !point.is_on_curve() {
            return Err(CryptoError::InvalidPoint);
        }

        let check = point.mul_scalar(&SUBGROUP_ORDER_LE)?;
        if !check.x.is_zero() || !check.y.is_one() {
            return Err(CryptoError::SubgroupCheckFailed);
        }

        Ok(point)
    }

    /// Check: `A*x^2 + y^2 == 1 + D*x^2*y^2`
    #[must_use]
    pub fn is_on_curve(&self) -> bool {
        let a = *BJJ_A;
        let d = *BJJ_D;
        let x2 = self.x.square();
        let y2 = self.y.square();
        let lhs = a * x2 + y2;
        let rhs = Fr::one() + d * x2 * y2;
        lhs == rhs
    }

    /// Twisted Edwards point addition (complete -- no exceptional cases).
    pub fn add(&self, other: &Self) -> Result<Self, CryptoError> {
        let a = *BJJ_A;
        let d = *BJJ_D;

        let beta = self.x * other.y;
        let gamma = self.y * other.x;
        let tau = beta * gamma;
        let dtau = d * tau;

        let x3_denom_inv = (Fr::one() + dtau)
            .inverse()
            .ok_or(CryptoError::InvalidOperation)?;
        let x3 = (beta + gamma) * x3_denom_inv;

        let delta = (self.y - (a * self.x)) * (other.x + other.y);
        let y3_denom_inv = (Fr::one() - dtau)
            .inverse()
            .ok_or(CryptoError::InvalidOperation)?;
        let y3 = (delta + (a * beta) - gamma) * y3_denom_inv;

        Ok(Self { x: x3, y: y3 })
    }

    /// Constant-time double-and-add scalar multiplication. Scalar is little-endian bytes.
    pub fn mul_scalar(&self, scalar_le_bytes: &[u8]) -> Result<Self, CryptoError> {
        use subtle::Choice;

        let mut res = Self {
            x: Fr::zero(),
            y: Fr::one(),
        };
        let mut temp = *self;

        for byte in scalar_le_bytes {
            let mut b = *byte;
            for _ in 0..8 {
                let candidate = res.add(&temp)?;
                let bit = Choice::from(b & 1);
                res = Self::ct_select(&res, &candidate, bit);
                temp = temp.add(&temp)?;
                b >>= 1;
            }
        }
        Ok(res)
    }

    /// Constant-time point selection using u64 limbs (4 per coordinate).
    fn ct_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        use subtle::ConditionallySelectable;

        let a_x_limbs = a.x.into_bigint().0;
        let b_x_limbs = b.x.into_bigint().0;
        let a_y_limbs = a.y.into_bigint().0;
        let b_y_limbs = b.y.into_bigint().0;

        let mut x_bytes = [0u8; 32];
        let mut y_bytes = [0u8; 32];

        for i in 0..4 {
            let x_limb = u64::conditional_select(&a_x_limbs[i], &b_x_limbs[i], choice);
            let y_limb = u64::conditional_select(&a_y_limbs[i], &b_y_limbs[i], choice);
            x_bytes[i * 8..(i + 1) * 8].copy_from_slice(&x_limb.to_le_bytes());
            y_bytes[i * 8..(i + 1) * 8].copy_from_slice(&y_limb.to_le_bytes());
        }

        Self {
            x: Fr::from_le_bytes_mod_order(&x_bytes),
            y: Fr::from_le_bytes_mod_order(&y_bytes),
        }
    }

    /// Compressed encoding: LE y-coordinate with sign bit in MSB.
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut y_bytes = self.y.into_bigint().to_bytes_le();
        if self.x > *HALF_MODULUS {
            y_bytes[31] |= 0x80;
        }
        // SAFETY: BN254 field elements are always 32 bytes in LE representation
        y_bytes.try_into().expect("y_bytes is 32 bytes")
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Decompress from hex with full validation (curve check + subgroup membership).
    pub fn from_hex(hex_str: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(hex_str).map_err(|_| CryptoError::InvalidKey)?;
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKey);
        }

        let mut y_bytes = bytes.clone();
        let sign = (y_bytes[31] & 0x80) != 0;
        y_bytes[31] &= 0x7F;

        let y = Fr::from_le_bytes_mod_order(&y_bytes);
        let a = *BJJ_A;
        let d = *BJJ_D;
        let y2 = y.square();

        let x2 = (Fr::one() - y2) * (a - (d * y2)).inverse().ok_or(CryptoError::InvalidPoint)?;
        let mut x = x2.sqrt().ok_or(CryptoError::InvalidPoint)?;

        if (x > *HALF_MODULUS) != sign {
            x = -x;
        }

        let point = Self { x, y };

        let check = point.mul_scalar(&SUBGROUP_ORDER_LE)?;
        if !check.x.is_zero() || !check.y.is_one() {
            return Err(CryptoError::SubgroupCheckFailed);
        }

        Ok(point)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_element() {
        let scalar_zero = [0u8; 32];
        let result = BASE8
            .mul_scalar(&scalar_zero)
            .expect("mul by zero should succeed");
        assert_eq!(result.x, Fr::from(0));
        assert_eq!(result.y, Fr::from(1));
    }

    #[test]
    fn test_generator_mul_one() {
        let mut scalar_one = [0u8; 32];
        scalar_one[0] = 1;
        let result = BASE8
            .mul_scalar(&scalar_one)
            .expect("mul by one should succeed");
        assert_eq!(result.x, BASE8.x);
        assert_eq!(result.y, BASE8.y);
    }

    #[test]
    fn test_public_key_generation() {
        let mut rng = rand::thread_rng();
        let sk = SecretKey::generate(&mut rng);
        let pk = sk
            .public_key()
            .expect("public key derivation should succeed");
        // Public key should not be the identity element
        assert!(pk.x != Fr::from(0) || pk.y != Fr::from(1));
    }

    #[test]
    fn test_public_key_serialization_roundtrip() {
        let mut rng = rand::thread_rng();
        let sk = SecretKey::generate(&mut rng);
        let pk = sk
            .public_key()
            .expect("public key derivation should succeed");
        let hex_str = pk.to_hex();
        let pk2 = PublicKey::from_hex(&hex_str).expect("from_hex should succeed");
        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_secret_key_roundtrip() {
        let mut rng = rand::thread_rng();
        let sk = SecretKey::generate(&mut rng);
        let hex_str = sk.to_hex();
        let sk2 = SecretKey::from_hex(&hex_str).expect("from_hex should succeed");
        assert_eq!(sk, sk2);
    }

    #[test]
    fn test_shared_secret_commutativity() {
        let mut rng = rand::thread_rng();
        let alice_sk = SecretKey::generate(&mut rng);
        let bob_sk = SecretKey::generate(&mut rng);

        let alice_pk = alice_sk.public_key().expect("alice pk");
        let bob_pk = bob_sk.public_key().expect("bob pk");

        let ss_alice = alice_sk.derive_shared_secret(&bob_pk).expect("alice ECDH");
        let ss_bob = bob_sk.derive_shared_secret(&alice_pk).expect("bob ECDH");

        assert_eq!(ss_alice.x, ss_bob.x);
        assert_eq!(ss_alice.y, ss_bob.y);
    }

    #[test]
    fn test_mul_scalar_returns_result() {
        let scalar = [0x42u8; 32];
        let result = BASE8.mul_scalar(&scalar);
        assert!(result.is_ok());
    }

    #[test]
    fn test_from_hex_rejects_over_modulus() {
        let over_modulus = "060c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f2";
        let result = SecretKey::from_hex(over_modulus);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_hex_rejects_wrong_length() {
        let short = "00".repeat(31);
        assert!(SecretKey::from_hex(&short).is_err());

        let long = "00".repeat(33);
        assert!(SecretKey::from_hex(&long).is_err());
    }

    #[test]
    fn test_point_addition_identity() {
        let identity = PublicKey {
            x: Fr::from(0),
            y: Fr::from(1),
        };
        let result = BASE8
            .add(&identity)
            .expect("adding identity should succeed");
        assert_eq!(result.x, BASE8.x);
        assert_eq!(result.y, BASE8.y);
    }

    #[test]
    fn test_from_coordinates_valid_point() {
        let pk = PublicKey::from_coordinates(BASE8.x, BASE8.y);
        assert!(pk.is_ok());
        assert_eq!(pk.unwrap(), *BASE8);
    }

    #[test]
    fn test_from_coordinates_off_curve() {
        let result = PublicKey::from_coordinates(Fr::from(1), Fr::from(2));
        assert_eq!(result, Err(CryptoError::InvalidPoint));
    }

    #[test]
    fn test_from_coordinates_zero_zero() {
        let result = PublicKey::from_coordinates(Fr::from(0), Fr::from(0));
        assert_eq!(result, Err(CryptoError::InvalidPoint));
    }

    #[test]
    fn test_from_coordinates_identity() {
        let result = PublicKey::from_coordinates(Fr::from(0), Fr::from(1));
        assert!(result.is_ok());
    }

    #[test]
    fn test_is_on_curve_base8() {
        assert!(BASE8.is_on_curve());
    }

    #[test]
    fn test_is_on_curve_identity() {
        let id = PublicKey {
            x: Fr::from(0),
            y: Fr::from(1),
        };
        assert!(id.is_on_curve());
    }

    #[test]
    fn test_is_on_curve_invalid() {
        let bad = PublicKey {
            x: Fr::from(42),
            y: Fr::from(99),
        };
        assert!(!bad.is_on_curve());
    }

    #[test]
    fn test_derived_pk_is_on_curve() {
        let mut rng = rand::thread_rng();
        let sk = SecretKey::generate(&mut rng);
        let pk = sk.public_key().expect("pk derivation");
        assert!(pk.is_on_curve());
    }

    #[test]
    fn test_point_negation() {
        let neg_base8 = PublicKey {
            x: -BASE8.x,
            y: BASE8.y,
        };
        let result = BASE8.add(&neg_base8).expect("P + (-P) should succeed");
        assert_eq!(result.x, Fr::from(0));
        assert_eq!(result.y, Fr::from(1));
    }

    #[test]
    fn test_mul_by_subgroup_order() {
        let result = BASE8
            .mul_scalar(&SUBGROUP_ORDER_LE)
            .expect("mul by subgroup order should succeed");
        assert_eq!(result.x, Fr::from(0));
        assert_eq!(result.y, Fr::from(1));
    }

    #[test]
    fn test_point_addition_commutative() {
        let mut rng = rand::thread_rng();
        let sk1 = SecretKey::generate(&mut rng);
        let sk2 = SecretKey::generate(&mut rng);
        let p = sk1.public_key().expect("pk1");
        let q = sk2.public_key().expect("pk2");

        let pq = p.add(&q).expect("P + Q");
        let qp = q.add(&p).expect("Q + P");
        assert_eq!(pq, qp);
    }

    #[test]
    fn test_scalar_mul_double() {
        let mut scalar_two = [0u8; 32];
        scalar_two[0] = 2;
        let doubled = BASE8.mul_scalar(&scalar_two).expect("[2]*G");
        let added = BASE8.add(&*BASE8).expect("G + G");
        assert_eq!(doubled, added);
    }

    #[test]
    fn test_from_hex_empty() {
        let result = PublicKey::from_hex("");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_hex_wrong_length() {
        let result = PublicKey::from_hex("aabb");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_hex_invalid_chars() {
        let result = PublicKey::from_hex(&"zz".repeat(32));
        assert!(result.is_err());
    }

    #[test]
    fn test_from_hex_all_zeros() {
        let result = PublicKey::from_hex(&"00".repeat(32));
        assert!(result.is_err());
    }

    #[test]
    fn test_from_hex_all_ff() {
        let result = PublicKey::from_hex(&"ff".repeat(32));
        assert!(result.is_err());
    }

    #[test]
    fn test_public_key_roundtrip_stress() {
        let mut rng = rand::thread_rng();
        for _ in 0..10 {
            let sk = SecretKey::generate(&mut rng);
            let pk = sk.public_key().expect("pk");
            let hex = pk.to_hex();
            let recovered = PublicKey::from_hex(&hex).expect("roundtrip");
            assert_eq!(pk, recovered);
        }
    }

    #[test]
    fn test_secret_key_zero() {
        let zero = "00".repeat(32);
        let sk = SecretKey::from_hex(&zero);
        assert!(sk.is_ok());
    }

    #[test]
    fn test_secret_key_one() {
        let mut hex = "00".repeat(31);
        hex.push_str("01");
        let sk = SecretKey::from_hex(&hex).expect("one should be valid");
        let pk = sk.public_key().expect("pk from sk=1");
        assert_eq!(pk, *BASE8);
    }

    #[test]
    fn test_secret_key_invalid_hex() {
        let result = SecretKey::from_hex("not_valid_hex_at_all_!");
        assert!(result.is_err());
    }

    #[test]
    fn test_shared_secret_to_symmetric_key() {
        let mut rng = rand::thread_rng();
        let alice = SecretKey::generate(&mut rng);
        let bob = SecretKey::generate(&mut rng);
        let bob_pk = bob.public_key().expect("bob pk");

        let ss = alice.derive_shared_secret(&bob_pk).expect("ECDH");
        let key1 = ss.to_symmetric_key();
        let key2 = ss.to_symmetric_key();

        assert_eq!(key1.len(), 32);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_shared_secret_different_keys() {
        let mut rng = rand::thread_rng();
        let alice = SecretKey::generate(&mut rng);
        let bob = SecretKey::generate(&mut rng);
        let carol = SecretKey::generate(&mut rng);

        let bob_pk = bob.public_key().expect("bob pk");
        let carol_pk = carol.public_key().expect("carol pk");

        let ss_bob = alice.derive_shared_secret(&bob_pk).expect("ECDH bob");
        let ss_carol = alice.derive_shared_secret(&carol_pk).expect("ECDH carol");

        assert_ne!(ss_bob.to_symmetric_key(), ss_carol.to_symmetric_key());
    }

    #[test]
    fn test_u256_to_le_bytes_small() {
        let val = ethers_core::types::U256::from(0x0102u64);
        let le = u256_to_le_bytes(val);
        assert_eq!(le[0], 0x02);
        assert_eq!(le[1], 0x01);
        assert!(le[2..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_u256_to_le_bytes_length() {
        let val = ethers_core::types::U256::MAX;
        let le = u256_to_le_bytes(val);
        assert_eq!(le.len(), 32);
        assert!(le.iter().all(|&b| b == 0xff));
    }
}
