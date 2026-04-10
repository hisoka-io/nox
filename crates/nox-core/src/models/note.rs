use crate::protocol::serialization::{deserialize_fr, serialize_fr};

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct Note {
    #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
    pub asset_id: Fr,
    #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
    pub value: Fr,
    #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
    pub secret: Fr,
    #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
    pub nullifier: Fr,
    #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
    pub timelock: Fr,
    #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
    pub hashlock: Fr,
}

impl std::fmt::Debug for Note {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Note")
            .field("asset_id", &self.asset_id)
            .field("value", &self.value)
            .field("secret", &"[REDACTED]")
            .field("nullifier", &"[REDACTED]")
            .field("timelock", &self.timelock)
            .field("hashlock", &self.hashlock)
            .finish()
    }
}

impl Note {
    #[must_use]
    pub fn serialize_to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(192);
        bytes.extend_from_slice(&self.asset_id.into_bigint().to_bytes_be());
        bytes.extend_from_slice(&self.value.into_bigint().to_bytes_be());
        bytes.extend_from_slice(&self.secret.into_bigint().to_bytes_be());
        bytes.extend_from_slice(&self.nullifier.into_bigint().to_bytes_be());
        bytes.extend_from_slice(&self.timelock.into_bigint().to_bytes_be());
        bytes.extend_from_slice(&self.hashlock.into_bigint().to_bytes_be());
        bytes
    }

    /// Deserialize from a 192-byte big-endian representation. Returns `None` if length != 192.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 192 {
            return None;
        }
        Some(Self {
            asset_id: Fr::from_be_bytes_mod_order(&bytes[0..32]),
            value: Fr::from_be_bytes_mod_order(&bytes[32..64]),
            secret: Fr::from_be_bytes_mod_order(&bytes[64..96]),
            nullifier: Fr::from_be_bytes_mod_order(&bytes[96..128]),
            timelock: Fr::from_be_bytes_mod_order(&bytes[128..160]),
            hashlock: Fr::from_be_bytes_mod_order(&bytes[160..192]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::One;
    use ark_std::Zero;

    fn sample_note() -> Note {
        Note {
            asset_id: Fr::from(42u64),
            value: Fr::from(1000u64),
            secret: Fr::from(999u64),
            nullifier: Fr::from(777u64),
            timelock: Fr::zero(),
            hashlock: Fr::zero(),
        }
    }

    #[test]
    fn roundtrip_serialize_deserialize() {
        let note = sample_note();
        let bytes = note.serialize_to_bytes();
        assert_eq!(bytes.len(), 192);
        let decoded = Note::from_bytes(&bytes).expect("should decode");
        assert_eq!(note, decoded);
    }

    #[test]
    fn from_bytes_wrong_length() {
        assert!(Note::from_bytes(&[0u8; 191]).is_none());
        assert!(Note::from_bytes(&[0u8; 193]).is_none());
        assert!(Note::from_bytes(&[]).is_none());
    }

    #[test]
    fn roundtrip_with_one_values() {
        let note = Note {
            asset_id: Fr::one(),
            value: Fr::one(),
            secret: Fr::one(),
            nullifier: Fr::one(),
            timelock: Fr::one(),
            hashlock: Fr::one(),
        };
        let bytes = note.serialize_to_bytes();
        let decoded = Note::from_bytes(&bytes).expect("should decode");
        assert_eq!(note, decoded);
    }

    #[test]
    fn roundtrip_with_zero_values() {
        let note = Note {
            asset_id: Fr::zero(),
            value: Fr::zero(),
            secret: Fr::zero(),
            nullifier: Fr::zero(),
            timelock: Fr::zero(),
            hashlock: Fr::zero(),
        };
        let bytes = note.serialize_to_bytes();
        let decoded = Note::from_bytes(&bytes).expect("should decode");
        assert_eq!(note, decoded);
    }
}
