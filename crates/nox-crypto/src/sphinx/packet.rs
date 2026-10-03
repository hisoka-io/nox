//! Fixed-size (32KB) Sphinx packet container.
//!
//! Packet encryption is done by the Sphinx layer (`sphinx` for forward packets,
//! `surb` for replies); this type only enforces the fixed size.
//! The size constants below still budget a 12-byte nonce and a 16-byte tag per
//! packet; `MAX_PAYLOAD_SIZE` is part of the wire format and must not change.

use thiserror::Error;

pub const PACKET_SIZE: usize = 32_768;

/// Reserved for Sphinx header (1KB). Accommodates ephemeral key + routing info + MAC + nonce + extensions.
pub const HEADER_SIZE: usize = 1024;

pub const POLY1305_TAG_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 12;
pub const PAYLOAD_OVERHEAD: usize = POLY1305_TAG_SIZE + NONCE_SIZE;
pub const MAX_PAYLOAD_SIZE: usize = PACKET_SIZE - HEADER_SIZE - PAYLOAD_OVERHEAD;

#[derive(Debug, Error)]
pub enum PacketError {
    #[error("Invalid packet size: expected {expected} bytes, got {actual} bytes")]
    InvalidSize { expected: usize, actual: usize },
}

/// Fixed-size (32KB) packet buffer: `[Header: 1024][Body]`.
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
        assert_eq!(HEADER_SIZE, 1024);
        assert_eq!(POLY1305_TAG_SIZE, 16);
        assert_eq!(NONCE_SIZE, 12);
        assert_eq!(PAYLOAD_OVERHEAD, 28);
        assert_eq!(MAX_PAYLOAD_SIZE, 31_716);

        assert_eq!(
            HEADER_SIZE + NONCE_SIZE + MAX_PAYLOAD_SIZE + POLY1305_TAG_SIZE,
            PACKET_SIZE
        );
    }
}
