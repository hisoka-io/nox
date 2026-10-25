//! Fixed-size (32KB) Sphinx packet container.
//!
//! Packet encryption is done by the Sphinx layer (`sphinx` for forward packets,
//! `surb` for replies); this type only enforces the fixed size. A packet is the
//! 472-byte Sphinx header followed by the 32,296-byte onion-encrypted body.

use thiserror::Error;

pub const PACKET_SIZE: usize = 32_768;

/// Sphinx header: ephemeral key, routing info, MAC and proof-of-work nonce
/// (the same value as [`crate::sphinx::HEADER_SIZE`], 472 bytes).
pub const HEADER_SIZE: usize = super::HEADER_SIZE;

/// Onion-encrypted body that follows the header (32,296 bytes). Forward bodies
/// are zero-padded to this size before Lioness encryption, and a SURB reply is
/// buffered at the entry as this many bytes of ciphertext.
pub const BODY_SIZE: usize = PACKET_SIZE - HEADER_SIZE;

/// Forward payload budget: the largest encoded payload a client puts in one
/// forward packet (31,716 bytes), 580 bytes below [`BODY_SIZE`]. Clients size
/// single packets and forward fragments by it (the TypeScript SDK mirrors it in
/// `client.ts`), so it is part of the wire contract and stays fixed.
pub const MAX_PAYLOAD_SIZE: usize = 31_716;

#[derive(Debug, Error)]
pub enum PacketError {
    #[error("Invalid packet size: expected {expected} bytes, got {actual} bytes")]
    InvalidSize { expected: usize, actual: usize },
}

/// Fixed-size (32KB) packet buffer: `[Header: 472][Body: 32,296]`.
#[derive(Debug, Clone)]
pub struct SphinxPacket(Vec<u8>);

impl SphinxPacket {
    /// Returns the raw packet bytes (always exactly `PACKET_SIZE`).
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the packet, returning the underlying buffer.
    #[inline]
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Creates a `SphinxPacket` from raw bytes. Fails if not exactly `PACKET_SIZE`.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, PacketError> {
        if bytes.len() != PACKET_SIZE {
            return Err(PacketError::InvalidSize {
                expected: PACKET_SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    /// Mutable access to the header section for Sphinx routing info.
    #[inline]
    pub fn header_mut(&mut self) -> &mut [u8] {
        &mut self.0[..HEADER_SIZE]
    }

    /// Read access to the header section.
    #[inline]
    #[must_use]
    pub fn header(&self) -> &[u8] {
        &self.0[..HEADER_SIZE]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_bytes_requires_exact_size() {
        let packet = SphinxPacket::from_bytes(vec![0x5A; PACKET_SIZE]).expect("exact size");
        assert_eq!(packet.as_bytes().len(), PACKET_SIZE);
        assert_eq!(packet.header().len(), HEADER_SIZE);

        for size in [0, PACKET_SIZE - 1, PACKET_SIZE + 1] {
            assert!(matches!(
                SphinxPacket::from_bytes(vec![0; size]),
                Err(PacketError::InvalidSize { expected: PACKET_SIZE, actual }) if actual == size
            ));
        }
    }

    #[test]
    fn test_constants() {
        assert_eq!(PACKET_SIZE, 32_768);
        assert_eq!(HEADER_SIZE, 472);
        assert_eq!(BODY_SIZE, 32_296);
        assert_eq!(HEADER_SIZE + BODY_SIZE, PACKET_SIZE);
        assert_eq!(MAX_PAYLOAD_SIZE, 31_716);
        assert_eq!(BODY_SIZE - MAX_PAYLOAD_SIZE, 580);
    }

    #[test]
    fn header_is_the_sphinx_header() {
        let header = crate::sphinx::SphinxHeader {
            ephemeral_key: x25519_dalek::PublicKey::from([9u8; 32]),
            routing_info: [0u8; crate::sphinx::ROUTING_INFO_SIZE],
            mac: [0u8; crate::sphinx::MAC_SIZE],
            nonce: 0,
        };
        let bytes = header.to_bytes(&vec![0u8; BODY_SIZE]);
        assert_eq!(bytes.len(), PACKET_SIZE);
        let packet = SphinxPacket::from_bytes(bytes).expect("exact size");
        assert_eq!(packet.header().len(), HEADER_SIZE);
    }
}
