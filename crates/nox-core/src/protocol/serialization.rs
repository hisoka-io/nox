use ark_ff::{BigInteger, PrimeField};
use serde::{self, Deserialize, Deserializer, Serializer};

pub use darkpool_crypto::field::{deserialize_fr, serialize_fr};

pub fn serialize_scalar<S>(field: &ark_ed_on_bn254::Fr, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let bytes = field.into_bigint().to_bytes_be();
    serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
}

pub fn deserialize_scalar<'de, D>(deserializer: D) -> Result<ark_ed_on_bn254::Fr, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let clean_s = s.trim_start_matches("0x");
    let bytes = hex::decode(clean_s).map_err(serde::de::Error::custom)?;

    if bytes.len() > 32 {
        return Err(serde::de::Error::custom(
            "Scalar field element exceeds 32 bytes",
        ));
    }

    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(&bytes);

    let val = ark_ed_on_bn254::Fr::from_be_bytes_mod_order(&padded);

    let round_trip = val.into_bigint().to_bytes_be();
    if round_trip != padded {
        return Err(serde::de::Error::custom(
            "Scalar value exceeds field modulus",
        ));
    }

    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct FrWrapper {
        #[serde(serialize_with = "serialize_fr", deserialize_with = "deserialize_fr")]
        val: ark_bn254::Fr,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct ScalarWrapper {
        #[serde(
            serialize_with = "serialize_scalar",
            deserialize_with = "deserialize_scalar"
        )]
        val: ark_ed_on_bn254::Fr,
    }

    #[test]
    fn test_fr_round_trip_zero() {
        let original = FrWrapper {
            val: ark_bn254::Fr::from(0u64),
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: FrWrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_fr_round_trip_one() {
        let original = FrWrapper {
            val: ark_bn254::Fr::from(1u64),
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: FrWrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_fr_round_trip_large_value() {
        let original = FrWrapper {
            val: ark_bn254::Fr::from(u64::MAX),
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: FrWrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_fr_round_trip_max_valid() {
        let original = FrWrapper {
            val: -ark_bn254::Fr::from(1u64),
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: FrWrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_fr_rejects_over_modulus() {
        let over_modulus =
            r#"{"val":"0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000002"}"#;
        let result: Result<FrWrapper, _> = serde_json::from_str(over_modulus);
        assert!(result.is_err(), "Should reject over-modulus value");
    }

    #[test]
    fn test_fr_rejects_too_long() {
        let too_long =
            r#"{"val":"0x0030644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"}"#;
        let result: Result<FrWrapper, _> = serde_json::from_str(too_long);
        assert!(result.is_err(), "Should reject >32 byte value");
    }

    #[test]
    fn test_fr_accepts_with_0x_prefix() {
        let with_prefix = r#"{"val":"0x01"}"#;
        let parsed: FrWrapper = serde_json::from_str(with_prefix).unwrap();
        assert_eq!(parsed.val, ark_bn254::Fr::from(1u64));
    }

    #[test]
    fn test_fr_accepts_without_0x_prefix() {
        let without_prefix = r#"{"val":"01"}"#;
        let parsed: FrWrapper = serde_json::from_str(without_prefix).unwrap();
        assert_eq!(parsed.val, ark_bn254::Fr::from(1u64));
    }

    #[test]
    fn test_scalar_round_trip_zero() {
        let original = ScalarWrapper {
            val: ark_ed_on_bn254::Fr::from(0u64),
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: ScalarWrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_scalar_round_trip_large_value() {
        let original = ScalarWrapper {
            val: ark_ed_on_bn254::Fr::from(u64::MAX),
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: ScalarWrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_scalar_rejects_over_modulus() {
        let over_modulus =
            r#"{"val":"0x060c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f2"}"#;
        let result: Result<ScalarWrapper, _> = serde_json::from_str(over_modulus);
        assert!(result.is_err(), "Should reject over-modulus scalar value");
    }
}
