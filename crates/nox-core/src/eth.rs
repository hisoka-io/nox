//! Text forms of Ethereum values in operator config, storage and RPC params.
//!
//! The accepted forms are fixed: these parsers define what existing config
//! files and stored records may contain, independent of library defaults.

use alloy::primitives::{Address, FixedBytes, B256, U256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EthTextError {
    #[error("invalid character in decimal integer")]
    InvalidDecimalCharacter,
    #[error("decimal integer exceeds 256 bits")]
    DecimalOverflow,
    #[error("invalid hex character")]
    InvalidHex,
    #[error("invalid length: {actual} hex digits (expected {expected})")]
    InvalidLength { expected: usize, actual: usize },
}

/// Parses an unsigned decimal integer: ASCII digits only, leading zeros
/// allowed, the empty string is zero. No sign, prefix, separators or spaces.
pub fn parse_decimal_u256(text: &str) -> Result<U256, EthTextError> {
    let ten = U256::from(10_u8);
    text.bytes().try_fold(U256::ZERO, |value, byte| {
        let digit = byte.wrapping_sub(b'0');
        if digit > 9 {
            return Err(EthTextError::InvalidDecimalCharacter);
        }
        value
            .checked_mul(ten)
            .and_then(|value| value.checked_add(U256::from(digit)))
            .ok_or(EthTextError::DecimalOverflow)
    })
}

/// Parses `N` bytes of hex with an optional lowercase `0x` prefix, digits in
/// either case and no checksum check.
pub fn parse_fixed_hex<const N: usize>(text: &str) -> Result<FixedBytes<N>, EthTextError> {
    let digits = text.strip_prefix("0x").unwrap_or(text);
    if digits.len() != N * 2 {
        return Err(EthTextError::InvalidLength {
            expected: N * 2,
            actual: digits.len(),
        });
    }
    let mut out = [0_u8; N];
    hex::decode_to_slice(digits, &mut out).map_err(|_| EthTextError::InvalidHex)?;
    Ok(FixedBytes(out))
}

/// Parses a 20-byte address (see [`parse_fixed_hex`]).
pub fn parse_address(text: &str) -> Result<Address, EthTextError> {
    parse_fixed_hex::<20>(text).map(Address::from)
}

/// Lowercase `0x`-prefixed hex of an address, the form used for node
/// identities, topology keys and stored records.
#[must_use]
pub fn address_hex(address: &Address) -> String {
    format!("{address:?}")
}

/// `0x`-prefixed hex quantity of a block number.
#[must_use]
pub fn block_quantity(number: u64) -> String {
    format!("0x{number:x}")
}

/// One position of an `eth_getLogs` topic filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopicFilter {
    /// Match this topic.
    One(B256),
    /// Match any of these topics.
    Any(Vec<B256>),
}

/// `eth_getLogs` filter object. Blocks are `latest`-style tags or
/// [`block_quantity`] strings; `topics` lists positions 0 to 3. Trailing
/// unset topic positions are left out and inner ones are `null`; `topics` is
/// always present.
#[must_use]
pub fn logs_filter(
    from_block: Option<&str>,
    to_block: Option<&str>,
    addresses: &[Address],
    topics: &[Option<TopicFilter>; 4],
) -> serde_json::Value {
    let mut filter = serde_json::Map::new();
    if let Some(from_block) = from_block {
        filter.insert("fromBlock".into(), from_block.into());
    }
    if let Some(to_block) = to_block {
        filter.insert("toBlock".into(), to_block.into());
    }
    match addresses {
        [] => {}
        [address] => {
            filter.insert("address".into(), address_hex(address).into());
        }
        many => {
            filter.insert(
                "address".into(),
                many.iter().map(address_hex).collect::<Vec<_>>().into(),
            );
        }
    }
    let used = topics
        .iter()
        .rposition(Option::is_some)
        .map_or(0, |last| last + 1);
    let topics: Vec<serde_json::Value> = topics[..used]
        .iter()
        .map(|topic| match topic {
            None => serde_json::Value::Null,
            Some(TopicFilter::One(topic)) => format!("{topic:?}").into(),
            Some(TopicFilter::Any(topics)) => topics
                .iter()
                .map(|topic| format!("{topic:?}"))
                .collect::<Vec<_>>()
                .into(),
        })
        .collect();
    filter.insert("topics".into(), topics.into());
    serde_json::Value::Object(filter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_accepts_digits_only() {
        assert_eq!(parse_decimal_u256(""), Ok(U256::ZERO));
        assert_eq!(parse_decimal_u256("00012"), Ok(U256::from(12)));
        assert_eq!(parse_decimal_u256(&U256::MAX.to_string()), Ok(U256::MAX));
        for bad in ["1_0", "0x10", " 1", "1 ", "-1", "+1", "abc"] {
            assert_eq!(
                parse_decimal_u256(bad),
                Err(EthTextError::InvalidDecimalCharacter),
                "{bad}"
            );
        }
        assert_eq!(
            parse_decimal_u256(
                "115792089237316195423570985008687907853269984665640564039457584007913129639936"
            ),
            Err(EthTextError::DecimalOverflow)
        );
    }

    #[test]
    fn address_accepts_lowercase_prefix_and_any_case_digits() {
        let lower = "0x74486dc1ac551e5cd3f4eef80727cc9d50d3abe9";
        let expected = parse_address(lower).unwrap();
        assert_eq!(address_hex(&expected), lower);
        assert_eq!(parse_address(&lower[2..]), Ok(expected));
        assert_eq!(
            parse_address(&lower.to_uppercase().replace("0X", "0x")),
            Ok(expected)
        );
        assert!(parse_address(&lower.replace("0x", "0X")).is_err());
        assert!(parse_address("0x").is_err());
        assert!(parse_address(&lower[..41]).is_err());
    }
}
