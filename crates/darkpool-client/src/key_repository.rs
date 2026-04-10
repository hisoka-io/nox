//! Ephemeral and incoming key management for blockchain event scanning.
//! Registers lookahead keys to detect deposits (ephemeral PK match) and
//! transfers (tag match) belonging to this wallet.

use std::collections::HashMap;

use ethers::types::U256;
use num_bigint::BigUint;
use tracing::warn;

use darkpool_crypto::SUBGROUP_ORDER;

use crate::identity::DarkAccount;

#[allow(clippy::expect_used)]
static SUBGROUP_ORDER_BIGINT: std::sync::LazyLock<BigUint> = std::sync::LazyLock::new(|| {
    BigUint::parse_bytes(SUBGROUP_ORDER.as_bytes(), 10)
        .expect("SUBGROUP_ORDER is a compile-time constant")
});

pub const DEFAULT_LOOKAHEAD: u64 = 20;

#[derive(Debug, Clone)]
pub struct KeyRepository {
    account: DarkAccount,
    compliance_pk: (U256, U256),
    ephemeral_index: u64,
    incoming_index: u64,
    next_ephemeral_nonce: u64,
    /// `"pkX_pkY"` -> `(ephemeral_sk, derivation_index)`
    ephemeral_key_map: HashMap<String, (U256, u64)>,
    /// `"tag"` -> `(recipient_sk_mod, derivation_index)`
    recipient_key_map: HashMap<String, (U256, u64)>,
}

impl KeyRepository {
    #[must_use]
    pub fn new(account: DarkAccount, compliance_pk: (U256, U256)) -> Self {
        Self {
            account,
            compliance_pk,
            ephemeral_index: 0,
            incoming_index: 0,
            next_ephemeral_nonce: 0,
            ephemeral_key_map: HashMap::new(),
            recipient_key_map: HashMap::new(),
        }
    }

    #[must_use]
    pub fn ephemeral_index(&self) -> u64 {
        self.ephemeral_index
    }

    #[must_use]
    pub fn incoming_index(&self) -> u64 {
        self.incoming_index
    }

    pub fn get_public_incoming_key(
        &mut self,
    ) -> Result<(U256, U256), darkpool_crypto::CryptoError> {
        self.account.get_public_incoming_key(self.incoming_index)
    }

    /// Vend next `(ephemeral_sk, nonce)` and register the key for scanning.
    pub fn next_ephemeral_params(&mut self) -> (U256, U256) {
        let idx = self.next_ephemeral_nonce;
        self.next_ephemeral_nonce += 1;

        let nonce = U256::from(idx);
        let sk = self.account.get_ephemeral_outgoing_key(idx);
        self.register_ephemeral_key(idx);
        (sk, nonce)
    }

    pub fn advance_ephemeral_keys(&mut self, count: u64) {
        for _ in 0..count {
            self.register_ephemeral_key(self.ephemeral_index);
            self.ephemeral_index += 1;
        }
    }

    pub fn advance_incoming_keys(&mut self, count: u64) {
        for _ in 0..count {
            self.register_incoming_key(self.incoming_index);
            self.incoming_index += 1;
        }
    }

    #[must_use]
    pub fn try_match_deposit(&self, epk_x: U256, epk_y: U256) -> Option<(U256, u64)> {
        let key = Self::format_point_key(epk_x, epk_y);
        self.ephemeral_key_map.get(&key).copied()
    }

    #[must_use]
    pub fn try_match_transfer(&self, tag_px: U256) -> Option<(U256, u64)> {
        let key = tag_px.to_string();
        self.recipient_key_map.get(&key).copied()
    }

    #[must_use]
    pub fn get_all_tags(&self) -> Vec<String> {
        self.recipient_key_map.keys().cloned().collect()
    }

    fn register_ephemeral_key(&mut self, index: u64) -> bool {
        let (epk_x, epk_y) = match self.account.get_public_ephemeral_key(index) {
            Ok(pk) => pk,
            Err(e) => {
                warn!(index, "Failed to derive ephemeral public key: {}", e);
                return false;
            }
        };
        let lookup_key = Self::format_point_key(epk_x, epk_y);

        if !self.ephemeral_key_map.contains_key(&lookup_key) {
            let eph_sk = self.account.get_ephemeral_outgoing_key(index);
            self.ephemeral_key_map.insert(lookup_key, (eph_sk, index));
        }
        true
    }

    fn register_incoming_key(&mut self, index: u64) -> bool {
        let recipient_sk = self.account.get_incoming_viewing_key(index);
        let recipient_sk_mod = Self::reduce_mod_subgroup(recipient_sk);
        let p = match Self::scalar_mul_point(recipient_sk_mod, self.compliance_pk) {
            Ok(point) => point,
            Err(e) => {
                warn!(
                    index,
                    "Failed to compute transfer tag for incoming key: {}", e
                );
                return false;
            }
        };

        let tag_key = p.0.to_string();

        self.recipient_key_map
            .entry(tag_key)
            .or_insert((recipient_sk_mod, index));
        true
    }

    fn format_point_key(x: U256, y: U256) -> String {
        format!("{x}_{y}")
    }

    fn reduce_mod_subgroup(value: U256) -> U256 {
        let mut bytes = [0u8; 32];
        value.to_big_endian(&mut bytes);
        let bigint = BigUint::from_bytes_be(&bytes);
        let reduced = bigint % &*SUBGROUP_ORDER_BIGINT;
        let mut result_bytes = reduced.to_bytes_be();
        while result_bytes.len() < 32 {
            result_bytes.insert(0, 0);
        }

        U256::from_big_endian(&result_bytes)
    }

    fn scalar_mul_point(
        scalar: U256,
        point: (U256, U256),
    ) -> Result<(U256, U256), darkpool_crypto::CryptoError> {
        use ark_ff::{BigInteger, PrimeField};
        use darkpool_crypto::PublicKey;

        use crate::crypto_helpers::u256_to_fr;

        let pk = PublicKey::from_coordinates(u256_to_fr(point.0), u256_to_fr(point.1))?;

        let mut scalar_bytes = [0u8; 32];
        scalar.to_big_endian(&mut scalar_bytes);
        scalar_bytes.reverse(); // mul_scalar expects little-endian

        let result = pk.mul_scalar(&scalar_bytes)?;
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

    fn create_test_repo() -> KeyRepository {
        use crate::crypto_helpers::fr_to_u256;
        use darkpool_crypto::BASE8;

        let account = DarkAccount::from_seed(b"test_key_repository_seed");
        let compliance_sk_bytes = [0x42u8; 32];
        let compliance_pk_point = BASE8
            .mul_scalar(&compliance_sk_bytes)
            .expect("valid test key");
        let compliance_pk = (
            fr_to_u256(compliance_pk_point.x()),
            fr_to_u256(compliance_pk_point.y()),
        );
        KeyRepository::new(account, compliance_pk)
    }

    #[test]
    fn test_key_repository_creation() {
        let repo = create_test_repo();
        assert_eq!(repo.ephemeral_index(), 0);
        assert_eq!(repo.incoming_index(), 0);
    }

    #[test]
    fn test_next_ephemeral_params() {
        let mut repo = create_test_repo();

        let (sk1, nonce1) = repo.next_ephemeral_params();
        let (sk2, nonce2) = repo.next_ephemeral_params();
        let (sk3, nonce3) = repo.next_ephemeral_params();

        assert_eq!(nonce1, U256::from(0));
        assert_eq!(nonce2, U256::from(1));
        assert_eq!(nonce3, U256::from(2));
        assert_ne!(sk1, sk2);
        assert_ne!(sk2, sk3);
    }

    #[test]
    fn test_advance_ephemeral_keys() {
        let mut repo = create_test_repo();

        repo.advance_ephemeral_keys(5);
        assert_eq!(repo.ephemeral_index(), 5);

        repo.advance_ephemeral_keys(3);
        assert_eq!(repo.ephemeral_index(), 8);
    }

    #[test]
    fn test_advance_incoming_keys() {
        let mut repo = create_test_repo();

        repo.advance_incoming_keys(5);
        assert_eq!(repo.incoming_index(), 5);

        repo.advance_incoming_keys(3);
        assert_eq!(repo.incoming_index(), 8);
    }

    #[test]
    fn test_try_match_deposit() {
        let mut repo = create_test_repo();

        repo.advance_ephemeral_keys(3);
        let (epk_x, epk_y) = {
            let mut account = DarkAccount::from_seed(b"test_key_repository_seed");
            account.get_public_ephemeral_key(0).unwrap()
        };

        let (sk, idx) = repo.try_match_deposit(epk_x, epk_y).unwrap();
        assert_eq!(idx, 0);
        assert!(!sk.is_zero());
        assert!(repo
            .try_match_deposit(U256::from(999), U256::from(888))
            .is_none());
    }

    #[test]
    fn test_try_match_transfer() {
        let mut repo = create_test_repo();

        repo.advance_incoming_keys(3);
        let tags = repo.get_all_tags();
        assert_eq!(tags.len(), 3);

        for tag in &tags {
            let tag_u256 = U256::from_dec_str(tag).unwrap();
            let result = repo.try_match_transfer(tag_u256);
            assert!(result.is_some(), "Tag {} should be matchable", tag);
        }

        assert!(repo.try_match_transfer(U256::from(12345)).is_none());
    }

    #[test]
    fn test_deterministic_key_registration() {
        let mut repo1 = create_test_repo();
        let mut repo2 = create_test_repo();
        repo1.advance_ephemeral_keys(5);
        repo2.advance_ephemeral_keys(5);

        let (epk_x, epk_y) = {
            let mut account = DarkAccount::from_seed(b"test_key_repository_seed");
            account.get_public_ephemeral_key(2).unwrap()
        };

        assert_eq!(
            repo1.try_match_deposit(epk_x, epk_y),
            repo2.try_match_deposit(epk_x, epk_y)
        );
    }
}
