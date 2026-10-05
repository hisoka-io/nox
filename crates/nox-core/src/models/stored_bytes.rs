//! Serde encoding for large byte fields in stored records.
//!
//! Records written before v0.4.0-rc.6 encode `Vec<u8>` fields with serde's
//! default, which in JSON is an array of numbers: about 3.4 bytes per byte of
//! data. A signed exit transaction of 19 KB became a 66 KB record. New records
//! store these fields as a `0x`-prefixed hex string (2 bytes per byte).
//!
//! Reads accept both forms, so records written by older nodes stay readable.
//! Deserialising needs a self-describing format (JSON); these fields are never
//! sent over bincode.

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserializer, Serializer};
use std::fmt;

/// Writes `bytes` as a `0x`-prefixed lowercase hex string.
pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    let mut encoded = String::with_capacity(2 + bytes.len() * 2);
    encoded.push_str("0x");
    encoded.push_str(&hex::encode(bytes));
    serializer.serialize_str(&encoded)
}

/// Reads a hex string (with or without `0x`) or the legacy array of numbers.
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    deserializer.deserialize_any(StoredBytesVisitor)
}

struct StoredBytesVisitor;

impl<'de> Visitor<'de> for StoredBytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a hex string or an array of byte values")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        let digits = value.strip_prefix("0x").unwrap_or(value);
        hex::decode(digits).map_err(|error| {
            E::custom(format!(
                "stored byte field is not valid hex ({} characters): {error}",
                value.len()
            ))
        })
    }

    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
        Ok(value.to_vec())
    }

    fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
        Ok(value)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut bytes = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(byte) = seq.next_element::<u8>()? {
            bytes.push(byte);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Holder {
        #[serde(with = "super")]
        bytes: Vec<u8>,
    }

    #[test]
    fn writes_prefixed_hex() {
        let encoded = serde_json::to_string(&Holder {
            bytes: vec![0x00, 0xab, 0xff],
        })
        .unwrap();
        assert_eq!(encoded, r#"{"bytes":"0x00abff"}"#);
    }

    #[test]
    fn reads_hex_with_and_without_prefix() {
        for text in [r#"{"bytes":"0x00abff"}"#, r#"{"bytes":"00ABff"}"#] {
            let holder: Holder = serde_json::from_str(text).unwrap();
            assert_eq!(holder.bytes, vec![0x00, 0xab, 0xff]);
        }
        let empty: Holder = serde_json::from_str(r#"{"bytes":"0x"}"#).unwrap();
        assert!(empty.bytes.is_empty());
    }

    #[test]
    fn reads_legacy_number_arrays() {
        let holder: Holder = serde_json::from_str(r#"{"bytes":[0,171,255]}"#).unwrap();
        assert_eq!(holder.bytes, vec![0x00, 0xab, 0xff]);
        let empty: Holder = serde_json::from_str(r#"{"bytes":[]}"#).unwrap();
        assert!(empty.bytes.is_empty());
    }

    #[test]
    fn rejects_malformed_values() {
        for text in [
            r#"{"bytes":"0xabc"}"#,
            r#"{"bytes":"0xzz"}"#,
            r#"{"bytes":[256]}"#,
            r#"{"bytes":[-1]}"#,
            r#"{"bytes":7}"#,
        ] {
            assert!(serde_json::from_str::<Holder>(text).is_err(), "{text}");
        }
    }

    #[test]
    fn hex_is_smaller_than_the_legacy_array() {
        let bytes: Vec<u8> = (0..=255).cycle().take(19_000).collect();
        let legacy = serde_json::to_vec(&bytes).unwrap().len();
        let compact = serde_json::to_vec(&Holder {
            bytes: bytes.clone(),
        })
        .unwrap()
        .len();
        assert!(
            compact * 10 < legacy * 6,
            "compact {compact}, legacy {legacy}"
        );
    }
}
