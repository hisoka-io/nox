//! Fixed-size (32KB) `ChaCha20Poly1305` AEAD packet encapsulation with ISO/IEC 7816-4 padding.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
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
    #[error("Payload too large: {size} bytes exceeds maximum of {max} bytes")]
    PayloadTooLarge { size: usize, max: usize },

    #[error("Decryption failed: packet integrity check failed")]
    DecryptionFailed,

    #[error("Invalid padding: could not find 0x80 padding marker")]
    InvalidPadding,

    #[error("Invalid packet size: expected {expected} bytes, got {actual} bytes")]
    InvalidSize { expected: usize, actual: usize },
}

/// Fixed-size (32KB) encrypted packet: `[Header: 1024][Nonce: 12][Ciphertext + Tag]`.
#[derive(Debug, Clone)]
pub struct SphinxPacket(Vec<u8>);

impl SphinxPacket {
    /// Encrypts a variable-length payload into a fixed-size 32KB packet.
    pub fn new(payload: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Self, PacketError> {
        if payload.len() + 1 > MAX_PAYLOAD_SIZE {
            return Err(PacketError::PayloadTooLarge {
                size: payload.len(),
                max: MAX_PAYLOAD_SIZE - 1,
            });
        }

        let padded = pad_iso7816(payload);
        debug_assert_eq!(padded.len(), MAX_PAYLOAD_SIZE);

        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce_obj = Nonce::from_slice(nonce);
        let ciphertext = cipher
            .encrypt(nonce_obj, padded.as_slice())
            .map_err(|_| PacketError::DecryptionFailed)?;

        debug_assert_eq!(ciphertext.len(), MAX_PAYLOAD_SIZE + POLY1305_TAG_SIZE);

        let mut packet = vec![0u8; PACKET_SIZE];

        // Header area left as zeros -- filled by Sphinx layer
        let nonce_start = HEADER_SIZE;
        let nonce_end = nonce_start + NONCE_SIZE;
        packet[nonce_start..nonce_end].copy_from_slice(nonce);

        let ciphertext_start = nonce_end;
        packet[ciphertext_start..ciphertext_start + ciphertext.len()].copy_from_slice(&ciphertext);

        debug_assert_eq!(packet.len(), PACKET_SIZE);

        Ok(Self(packet))
    }

    /// Decrypts and unpads the packet to recover the original payload.
    pub fn unwrap(&self, key: &[u8; 32]) -> Result<Vec<u8>, PacketError> {
        if self.0.len() != PACKET_SIZE {
            return Err(PacketError::InvalidSize {
                expected: PACKET_SIZE,
                actual: self.0.len(),
            });
        }

        let nonce_start = HEADER_SIZE;
        let nonce_end = nonce_start + NONCE_SIZE;
        let nonce = Nonce::from_slice(&self.0[nonce_start..nonce_end]);

        let ciphertext_start = nonce_end;
        let ciphertext = &self.0[ciphertext_start..];

        let cipher = ChaCha20Poly1305::new(key.into());
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| PacketError::DecryptionFailed)?;

        unpad_iso7816(&plaintext)
    }

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

/// Applies ISO/IEC 7816-4 padding: append `0x80` then fill with `0x00`.
fn pad_iso7816(payload: &[u8]) -> Vec<u8> {
    let mut padded = Vec::with_capacity(MAX_PAYLOAD_SIZE);
    padded.extend_from_slice(payload);
    padded.push(0x80);
    padded.resize(MAX_PAYLOAD_SIZE, 0x00);

    padded
}

/// Removes ISO/IEC 7816-4 padding (constant-time to prevent padding oracle attacks).
fn unpad_iso7816(padded: &[u8]) -> Result<Vec<u8>, PacketError> {
    super::unpad_iso7816_inner(padded).ok_or(PacketError::InvalidPadding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn test_encrypt_decrypt_short_payload() {
        let payload = b"Hello World";
        let key = [0x42u8; 32];
        let nonce = [0x13u8; 12];

        let packet = SphinxPacket::new(payload, &key, &nonce).expect("Encryption failed");
        let decrypted = packet.unwrap(&key).expect("Decryption failed");

        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_encrypt_decrypt_max_payload() {
        let mut rng = rand::thread_rng();

        // Max payload is MAX_PAYLOAD_SIZE - 1 (need 1 byte for 0x80 marker)
        let payload_len = MAX_PAYLOAD_SIZE - 1;
        let payload: Vec<u8> = (0..payload_len).map(|_| rng.gen()).collect();

        let key: [u8; 32] = rng.gen();
        let nonce: [u8; 12] = rng.gen();

        let packet = SphinxPacket::new(&payload, &key, &nonce).expect("Encryption failed");
        let decrypted = packet.unwrap(&key).expect("Decryption failed");

        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_payload_too_large() {
        let payload = vec![0xAA; MAX_PAYLOAD_SIZE];
        let key = [0x00u8; 32];
        let nonce = [0x00u8; 12];

        let result = SphinxPacket::new(&payload, &key, &nonce);

        assert!(matches!(result, Err(PacketError::PayloadTooLarge { .. })));
    }

    #[test]
    fn test_tampered_packet() {
        let payload = b"Sensitive Data";
        let key = [0x55u8; 32];
        let nonce = [0xAAu8; 12];

        let mut packet = SphinxPacket::new(payload, &key, &nonce).expect("Encryption failed");

        let tamper_pos = HEADER_SIZE + NONCE_SIZE + 10;
        packet.0[tamper_pos] ^= 0xFF;

        let result = packet.unwrap(&key);

        assert!(matches!(result, Err(PacketError::DecryptionFailed)));
    }

    #[test]
    fn test_packet_size_exactly_32kb() {
        let payload = b"Any payload";
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];

        let packet = SphinxPacket::new(payload, &key, &nonce).expect("Encryption failed");

        assert_eq!(
            packet.as_bytes().len(),
            PACKET_SIZE,
            "Packet must be exactly {} bytes",
            PACKET_SIZE
        );
        assert_eq!(packet.as_bytes().len(), 32_768);
    }

    #[test]
    fn test_empty_payload() {
        let payload = b"";
        let key = [0x33u8; 32];
        let nonce = [0x44u8; 12];

        let packet = SphinxPacket::new(payload, &key, &nonce).expect("Encryption failed");
        let decrypted = packet.unwrap(&key).expect("Decryption failed");

        assert_eq!(decrypted, payload);
        assert_eq!(packet.as_bytes().len(), PACKET_SIZE);
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
