//! Proptest-based invariant tests for the fixed-size packet container.

use nox_crypto::sphinx::packet::{PacketError, SphinxPacket, HEADER_SIZE, PACKET_SIZE};
use proptest::prelude::*;

#[test]
fn prop_exact_size_bytes_roundtrip() {
    proptest!(|(fill in any::<u8>(), marker in any::<u8>(), position in 0usize..PACKET_SIZE)| {
        let mut bytes = vec![fill; PACKET_SIZE];
        bytes[position] = marker;

        let packet = SphinxPacket::from_bytes(bytes.clone())
            .expect("an exact-size buffer is a valid packet");

        prop_assert_eq!(packet.as_bytes(), bytes.as_slice());
        prop_assert_eq!(packet.header(), &bytes[..HEADER_SIZE]);
        prop_assert_eq!(packet.into_bytes(), bytes);
    });
}

#[test]
fn prop_wrong_size_is_rejected() {
    proptest!(|(size in 0usize..(2 * PACKET_SIZE))| {
        prop_assume!(size != PACKET_SIZE);
        let result = SphinxPacket::from_bytes(vec![0; size]);
        let is_size_error = matches!(
            result,
            Err(PacketError::InvalidSize { expected: PACKET_SIZE, actual }) if actual == size
        );
        prop_assert!(is_size_error);
    });
}
