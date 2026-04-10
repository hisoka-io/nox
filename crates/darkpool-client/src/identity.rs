//! Cryptographic identity management: BJJ keypairs (note ownership), X25519 keypairs
//! (mixnet routing), and hierarchical `DarkAccount` key derivation.

use ark_ff::{BigInteger, PrimeField};
use curve25519_dalek::constants::X25519_BASEPOINT;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use ethers::types::U256;
use num_bigint::BigUint;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use darkpool_crypto::Kdf;
use darkpool_crypto::{
    CryptoError as BjjCryptoError, PublicKey as BjjPublicKey, SecretKey as BjjSecretKey,
    SharedSecret, BASE8, SUBGROUP_ORDER,
};

pub type X25519SecretKey = [u8; 32];
pub type X25519PublicKey = [u8; 32];

#[allow(clippy::expect_used)]
static SUBGROUP_ORDER_BIGINT: std::sync::LazyLock<BigUint> = std::sync::LazyLock::new(|| {
    BigUint::parse_bytes(SUBGROUP_ORDER.as_bytes(), 10).expect("valid constant")
});

/// BJJ keypair (Baby Jubjub curve). Note: `BjjSecretKey` (`ark_ed_on_bn254::Fr`)
/// does not implement `Zeroize` -- keypairs are short-lived and never persisted.
#[derive(Debug, Clone)]
pub struct BjjKeypair {
    sk: BjjSecretKey,
    pk: BjjPublicKey,
}

impl Serialize for BjjKeypair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("BjjKeypair", 3)?;
        state.serialize_field("sk", &self.sk.to_hex())?;
        state.serialize_field("pk", &self.pk.to_hex())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for BjjKeypair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct BjjKeypairData {
            sk: String,
            pk: String,
        }

        let data = BjjKeypairData::deserialize(deserializer)?;
        let sk = BjjSecretKey::from_hex(&data.sk).map_err(serde::de::Error::custom)?;
        let pk = BjjPublicKey::from_hex(&data.pk).map_err(serde::de::Error::custom)?;

        Ok(Self { sk, pk })
    }
}

impl BjjKeypair {
    #[must_use]
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        let sk = BjjSecretKey::generate(&mut rng);
        let pk = sk.public_key().unwrap_or_else(|_| {
            unreachable!("public key derivation cannot fail for random scalar")
        });
        Self { sk, pk }
    }

    /// Deterministic derivation with `SUBGROUP_ORDER` reduction (matches TS circomlibjs).
    pub fn from_seed(seed: &[u8]) -> Result<Self, BjjCryptoError> {
        let mut hasher = Sha256::new();
        hasher.update(b"hisoka.bjj.keypair");
        hasher.update(seed);
        let hash_bytes = hasher.finalize();

        let hash_bigint = BigUint::from_bytes_be(&hash_bytes);
        let reduced = hash_bigint % &*SUBGROUP_ORDER_BIGINT;

        let mut sk_bytes = reduced.to_bytes_be();
        while sk_bytes.len() < 32 {
            sk_bytes.insert(0, 0);
        }

        let sk = BjjSecretKey::from_hex(&hex::encode(&sk_bytes))?;
        let pk = sk.public_key()?;
        Ok(Self { sk, pk })
    }

    #[allow(clippy::must_use_candidate)]
    pub fn public_key(&self) -> &BjjPublicKey {
        &self.pk
    }

    #[allow(clippy::must_use_candidate)]
    pub fn pk_x(&self) -> U256 {
        let bytes = self.pk.x().into_bigint().to_bytes_be();
        U256::from_big_endian(&bytes)
    }

    #[allow(clippy::must_use_candidate)]
    pub fn pk_y(&self) -> U256 {
        let bytes = self.pk.y().into_bigint().to_bytes_be();
        U256::from_big_endian(&bytes)
    }

    #[allow(clippy::must_use_candidate)]
    pub fn pk_tuple(&self) -> (U256, U256) {
        (self.pk_x(), self.pk_y())
    }

    #[allow(clippy::must_use_candidate)]
    pub fn sk_as_u256(&self) -> U256 {
        let bytes = self.sk.0.into_bigint().to_bytes_be();
        U256::from_big_endian(&bytes)
    }

    pub fn derive_shared_secret(
        &self,
        peer_pk: &BjjPublicKey,
    ) -> Result<SharedSecret, BjjCryptoError> {
        self.sk.derive_shared_secret(peer_pk)
    }

    pub fn derive_shared_secret_x(&self, peer_pk: &BjjPublicKey) -> Result<U256, BjjCryptoError> {
        let ss = self.derive_shared_secret(peer_pk)?;
        let bytes = ss.x().into_bigint().to_bytes_be();
        Ok(U256::from_big_endian(&bytes))
    }

    #[allow(clippy::must_use_candidate)]
    pub fn sk_hex(&self) -> String {
        self.sk.to_hex()
    }

    #[allow(clippy::must_use_candidate)]
    pub fn pk_hex(&self) -> String {
        self.pk.to_hex()
    }
}

/// X25519 keypair for mixnet routing.
#[derive(Debug, Clone)]
pub struct X25519Keypair {
    pub sk: X25519SecretKey,
    pub pk: X25519PublicKey,
}

impl X25519Keypair {
    #[must_use]
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);

        // Clamp per X25519 spec
        sk[0] &= 0xF8;
        sk[31] &= 0x7F;
        sk[31] |= 0x40;

        let scalar = Scalar::from_bytes_mod_order(sk);
        let pk_point = X25519_BASEPOINT * scalar;

        Self {
            sk,
            pk: pk_point.to_bytes(),
        }
    }

    #[must_use]
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"hisoka.x25519.keypair");
        hasher.update(seed);
        let mut sk: [u8; 32] = hasher.finalize().into();

        sk[0] &= 0xF8;
        sk[31] &= 0x7F;
        sk[31] |= 0x40;

        let scalar = Scalar::from_bytes_mod_order(sk);
        let pk_point = X25519_BASEPOINT * scalar;

        Self {
            sk,
            pk: pk_point.to_bytes(),
        }
    }

    #[must_use]
    pub fn ecdh(&self, other_pk: &X25519PublicKey) -> [u8; 32] {
        let other_point = MontgomeryPoint(*other_pk);
        let scalar = Scalar::from_bytes_mod_order(self.sk);
        (other_point * scalar).to_bytes()
    }
}

impl Drop for X25519Keypair {
    fn drop(&mut self) {
        self.sk.zeroize();
    }
}

#[derive(Debug, Clone)]
pub struct ClientIdentity {
    pub bjj: BjjKeypair,
    pub x25519: X25519Keypair,
    pub name: String,
}

impl ClientIdentity {
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            bjj: BjjKeypair::generate(),
            x25519: X25519Keypair::generate(),
            name: name.to_string(),
        }
    }

    pub fn from_seed(name: &str, seed: &[u8]) -> Result<Self, BjjCryptoError> {
        Ok(Self {
            bjj: BjjKeypair::from_seed(seed)?,
            x25519: X25519Keypair::from_seed(seed),
            name: name.to_string(),
        })
    }

    pub fn from_signature(name: &str, signature: &[u8]) -> Result<Self, BjjCryptoError> {
        Self::from_seed(name, signature)
    }
}

const BN254_FR_MODULUS: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

#[allow(clippy::expect_used)]
static BN254_MODULUS_BIGINT: std::sync::LazyLock<BigUint> = std::sync::LazyLock::new(|| {
    BigUint::parse_bytes(BN254_FR_MODULUS.as_bytes(), 10).expect("valid constant")
});

/// Hierarchical key derivation (mirrors TypeScript `DarkAccount`):
///
/// ```text
/// sk_root
///    ├── sk_spend = Kdf("hisoka.spend", sk_root)
///    └── sk_view  = Kdf("hisoka.view", sk_root)
///           └── vk_master = Kdf("hisoka.ivkMaster", sk_view)
///                  ├── ivk_j = vk_master + Kdf("hisoka.ivkTweak", vk_master, j)
///                  └── esk_j = vk_master + Kdf("hisoka.eskTweak", vk_master, j)
/// ```
#[derive(Debug, Clone)]
pub struct DarkAccount {
    sk_root: U256,
    sk_spend: Option<U256>,
    sk_view: Option<U256>,
    vk_master: Option<U256>,
}

/// U256 doesn't implement Zeroize, so we use volatile writes.
impl Drop for DarkAccount {
    fn drop(&mut self) {
        zeroize_u256(&mut self.sk_root);
        if let Some(ref mut v) = self.sk_spend {
            zeroize_u256(v);
        }
        if let Some(ref mut v) = self.sk_view {
            zeroize_u256(v);
        }
        if let Some(ref mut v) = self.vk_master {
            zeroize_u256(v);
        }
    }
}

fn zeroize_u256(val: &mut U256) {
    let ptr = std::ptr::from_mut::<U256>(val);
    // volatile_write prevents dead-store elimination
    unsafe { std::ptr::write_volatile(ptr, U256::zero()) };
}

impl DarkAccount {
    #[must_use]
    pub fn new(sk_root: U256) -> Self {
        Self {
            sk_root,
            sk_spend: None,
            sk_view: None,
            vk_master: None,
        }
    }

    /// Reduce signature mod BN254 Fr, then derive root key via KDF.
    #[must_use]
    pub fn from_signature(signature: &[u8]) -> Self {
        let sig_bigint = BigUint::from_bytes_be(signature);
        let reduced = sig_bigint % &*BN254_MODULUS_BIGINT;

        let mut sig_bytes = reduced.to_bytes_be();
        while sig_bytes.len() < 32 {
            sig_bytes.insert(0, 0);
        }
        let sig_fr = U256::from_big_endian(&sig_bytes[..32.min(sig_bytes.len())]);

        #[allow(clippy::expect_used)]
        let sk_root = Kdf::derive("hisoka.root", sig_fr, None).expect("valid purpose string");
        Self::new(sk_root)
    }

    /// Deterministic derivation from seed (for testing; production uses `from_signature`).
    #[must_use]
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"hisoka.seed");
        hasher.update(seed);
        let hash = hasher.finalize();

        let hash_bigint = BigUint::from_bytes_be(&hash);
        let reduced = hash_bigint % &*BN254_MODULUS_BIGINT;

        let mut bytes = reduced.to_bytes_be();
        while bytes.len() < 32 {
            bytes.insert(0, 0);
        }
        let seed_fr = U256::from_big_endian(&bytes);

        #[allow(clippy::expect_used)]
        let sk_root = Kdf::derive("hisoka.root", seed_fr, None).expect("valid purpose string");
        Self::new(sk_root)
    }

    #[allow(clippy::must_use_candidate)]
    pub fn sk_root(&self) -> U256 {
        self.sk_root
    }

    #[allow(clippy::expect_used)]
    pub fn get_spend_key(&mut self) -> U256 {
        *self.sk_spend.get_or_insert_with(|| {
            Kdf::derive("hisoka.spend", self.sk_root, None).expect("valid purpose string")
        })
    }

    #[allow(clippy::expect_used)]
    pub fn get_view_key(&mut self) -> U256 {
        *self.sk_view.get_or_insert_with(|| {
            Kdf::derive("hisoka.view", self.sk_root, None).expect("valid purpose string")
        })
    }

    #[allow(clippy::expect_used)]
    fn get_vk_master(&mut self) -> U256 {
        if self.vk_master.is_none() {
            let sk_view = self.get_view_key();
            self.vk_master =
                Some(Kdf::derive("hisoka.ivkMaster", sk_view, None).expect("valid purpose string"));
        }
        *self.vk_master.as_ref().unwrap_or_else(|| unreachable!())
    }

    /// Reduced mod BJJ subgroup order (not BN254 Fr) so the scalar fits in
    /// Noir's `ScalarField::<63>` (max 2^252).
    #[allow(clippy::expect_used)]
    pub fn get_ephemeral_outgoing_key(&mut self, index: u64) -> U256 {
        let vk_master = self.get_vk_master();
        let tweak =
            Kdf::derive_indexed("hisoka.eskTweak", vk_master, index).expect("valid purpose string");
        Self::add_mod_subgroup_order(vk_master, tweak)
    }

    #[allow(clippy::expect_used)]
    pub fn get_incoming_viewing_key(&mut self, index: u64) -> U256 {
        let vk_master = self.get_vk_master();
        let tweak =
            Kdf::derive_indexed("hisoka.ivkTweak", vk_master, index).expect("valid purpose string");
        Self::add_mod_subgroup_order(vk_master, tweak)
    }

    pub fn get_public_ephemeral_key(&mut self, index: u64) -> Result<(U256, U256), BjjCryptoError> {
        let esk = self.get_ephemeral_outgoing_key(index);
        Self::scalar_mul_base8(esk)
    }

    pub fn get_public_incoming_key(&mut self, index: u64) -> Result<(U256, U256), BjjCryptoError> {
        let ivk = self.get_incoming_viewing_key(index);
        Self::scalar_mul_base8(ivk)
    }

    /// Uses BJJ subgroup order (~2^251) instead of BN254 Fr (~2^254) to avoid
    /// overflowing Noir's nibble decomposition in `noir-edwards`.
    fn add_mod_subgroup_order(a: U256, b: U256) -> U256 {
        let a_bigint = BigUint::from_bytes_be(&{
            let mut bytes = [0u8; 32];
            a.to_big_endian(&mut bytes);
            bytes
        });
        let b_bigint = BigUint::from_bytes_be(&{
            let mut bytes = [0u8; 32];
            b.to_big_endian(&mut bytes);
            bytes
        });

        let sum = (a_bigint + b_bigint) % &*SUBGROUP_ORDER_BIGINT;
        let mut sum_bytes = sum.to_bytes_be();
        while sum_bytes.len() < 32 {
            sum_bytes.insert(0, 0);
        }
        U256::from_big_endian(&sum_bytes)
    }

    fn scalar_mul_base8(scalar: U256) -> Result<(U256, U256), BjjCryptoError> {
        use ark_ff::BigInteger;

        let mut scalar_bytes = [0u8; 32];
        scalar.to_big_endian(&mut scalar_bytes);
        scalar_bytes.reverse(); // mul_scalar expects little-endian

        let result = BASE8.mul_scalar(&scalar_bytes)?;
        let x_bytes = result.x().into_bigint().to_bytes_be();
        let y_bytes = result.y().into_bigint().to_bytes_be();

        Ok((
            U256::from_big_endian(&x_bytes),
            U256::from_big_endian(&y_bytes),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bjj_keypair_generation() {
        let kp1 = BjjKeypair::generate();
        let kp2 = BjjKeypair::generate();
        assert_ne!(kp1.sk_hex(), kp2.sk_hex());
        assert_ne!(kp1.pk_hex(), kp2.pk_hex());
    }

    #[test]
    fn test_bjj_from_seed_deterministic() {
        let seed = b"alice_secret_seed";
        let kp1 = BjjKeypair::from_seed(seed).unwrap();
        let kp2 = BjjKeypair::from_seed(seed).unwrap();
        assert_eq!(kp1.sk_hex(), kp2.sk_hex());
        assert_eq!(kp1.pk_hex(), kp2.pk_hex());
    }

    #[test]
    fn test_bjj_subgroup_reduction() {
        let seed = [0xffu8; 64];
        let kp = BjjKeypair::from_seed(&seed).unwrap();
        let sk_u256 = kp.sk_as_u256();
        let subgroup_order = U256::from_dec_str(SUBGROUP_ORDER).unwrap();
        assert!(sk_u256 < subgroup_order);
    }

    #[test]
    fn test_bjj_ecdh() {
        let alice = BjjKeypair::generate();
        let bob = BjjKeypair::generate();
        let ss_alice = alice.derive_shared_secret_x(bob.public_key()).unwrap();
        let ss_bob = bob.derive_shared_secret_x(alice.public_key()).unwrap();
        assert_eq!(ss_alice, ss_bob);
    }

    #[test]
    fn test_x25519_ecdh() {
        let alice = X25519Keypair::generate();
        let bob = X25519Keypair::generate();
        assert_eq!(alice.ecdh(&bob.pk), bob.ecdh(&alice.pk));
    }

    #[test]
    fn test_bjj_serialization_roundtrip() {
        let kp = BjjKeypair::generate();
        let json = serde_json::to_string(&kp).unwrap();
        let kp2: BjjKeypair = serde_json::from_str(&json).unwrap();
        assert_eq!(kp.sk_hex(), kp2.sk_hex());
        assert_eq!(kp.pk_hex(), kp2.pk_hex());
    }

    #[test]
    fn test_dark_account_from_seed_deterministic() {
        let seed = b"alice_secret_seed_for_dark_account";
        let mut account1 = DarkAccount::from_seed(seed);
        let mut account2 = DarkAccount::from_seed(seed);
        assert_eq!(account1.sk_root(), account2.sk_root());
        assert_eq!(account1.get_spend_key(), account2.get_spend_key());
        assert_eq!(account1.get_view_key(), account2.get_view_key());
    }

    #[test]
    fn test_dark_account_key_hierarchy() {
        let mut account = DarkAccount::from_seed(b"test_hierarchy");
        let sk_root = account.sk_root();
        let sk_spend = account.get_spend_key();
        let sk_view = account.get_view_key();

        assert!(!sk_root.is_zero());
        assert!(!sk_spend.is_zero());
        assert!(!sk_view.is_zero());
        assert_ne!(sk_root, sk_spend);
        assert_ne!(sk_root, sk_view);
        assert_ne!(sk_spend, sk_view);
    }

    #[test]
    fn test_dark_account_per_index_keys() {
        let mut account = DarkAccount::from_seed(b"test_per_index");

        let esk_0 = account.get_ephemeral_outgoing_key(0);
        let esk_1 = account.get_ephemeral_outgoing_key(1);
        let esk_2 = account.get_ephemeral_outgoing_key(2);
        assert_ne!(esk_0, esk_1);
        assert_ne!(esk_1, esk_2);

        let ivk_0 = account.get_incoming_viewing_key(0);
        let ivk_1 = account.get_incoming_viewing_key(1);
        assert_ne!(ivk_0, ivk_1);
        assert_ne!(esk_0, ivk_0);
    }

    #[test]
    fn test_dark_account_public_keys() {
        let mut account = DarkAccount::from_seed(b"test_public_keys");

        let (epk_x, epk_y) = account.get_public_ephemeral_key(0).unwrap();
        let (ivk_x, ivk_y) = account.get_public_incoming_key(0).unwrap();
        assert!(!epk_x.is_zero() || !epk_y.is_zero());
        assert!(!ivk_x.is_zero() || !ivk_y.is_zero());

        let (epk1_x, epk1_y) = account.get_public_ephemeral_key(1).unwrap();
        assert!(epk_x != epk1_x || epk_y != epk1_y);
    }

    #[test]
    fn test_dark_account_from_signature() {
        let signature = hex::decode(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\
             0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
        )
        .unwrap();

        let mut account = DarkAccount::from_signature(&signature);
        assert!(!account.sk_root().is_zero());
        assert!(!account.get_spend_key().is_zero());
    }

    #[test]
    fn test_dark_account_caching() {
        let mut account = DarkAccount::from_seed(b"test_caching");
        let sk_spend_1 = account.get_spend_key();
        let sk_spend_2 = account.get_spend_key();
        assert_eq!(sk_spend_1, sk_spend_2);

        let sk_view_1 = account.get_view_key();
        let sk_view_2 = account.get_view_key();
        assert_eq!(sk_view_1, sk_view_2);
    }
}
