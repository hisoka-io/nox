//! Single Use Reply Blocks (SURBs) for anonymous bidirectional mixnet communication.

use super::lioness::{lioness_decrypt, lioness_encrypt, LionessKeys};
use super::packet::{PacketError, SphinxPacket};
use super::{
    apply_stream_cipher, compute_mac, derive_keys, PathHop, SphinxError, SphinxHeader,
    ROUTING_INFO_SIZE, SHIFT_SIZE,
};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use x25519_dalek::PublicKey as X25519PublicKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Removes ISO/IEC 7816-4 padding. Validation prevents cover traffic from consuming SURBs.
fn unpad_iso7816(data: &[u8]) -> Result<Vec<u8>, SurbError> {
    super::unpad_iso7816_inner(data).ok_or(SurbError::InvalidPadding)
}

pub const DEFAULT_POW_DIFFICULTY: u32 = 0;

#[derive(Debug, Error)]
pub enum SurbError {
    #[error("Return path is empty")]
    EmptyPath,

    #[error("Sphinx error: {0}")]
    Sphinx(#[from] SphinxError),

    #[error("Packet error: {0}")]
    Packet(#[from] PacketError),

    #[error("Message too large: {size} bytes")]
    MessageTooLarge { size: usize },

    #[error("Invalid ISO 7816-4 padding in decrypted body")]
    InvalidPadding,

    #[error("Invalid address at hop {index}: {reason}")]
    InvalidAddress { index: usize, reason: String },
}

/// A Single Use Reply Block. Contains a pre-computed return-path header and payload encryption keys.
/// Each SURB must be used at most once.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Surb {
    pub id: [u8; 16],
    pub header: SphinxHeader,
    pub first_hop: String,
    pub payload_keys: LionessKeys,
}

impl Surb {
    /// Creates a new SURB for the given return path. Returns `(Surb, SurbRecovery)`.
    pub fn new(
        path: &[PathHop],
        id: [u8; 16],
        pow_difficulty: u32,
    ) -> Result<(Self, SurbRecovery), SurbError> {
        if path.is_empty() {
            return Err(SurbError::EmptyPath);
        }

        for (i, hop) in path.iter().enumerate() {
            if hop.address.is_empty() {
                return Err(SurbError::InvalidAddress {
                    index: i,
                    reason: "address is empty".into(),
                });
            }
            if hop.address.len() > 255 {
                return Err(SurbError::InvalidAddress {
                    index: i,
                    reason: format!("address too long ({} bytes, max 255)", hop.address.len()),
                });
            }
        }

        let mut rng = rand::rngs::OsRng;

        // Raw Scalar multiplication (not X25519SecretKey::diffie_hellman) to avoid clamping mismatch
        let mut ephemeral_public_keys = Vec::with_capacity(path.len());
        let mut shared_secrets = Vec::with_capacity(path.len());
        let mut blinding_factors = Vec::with_capacity(path.len());

        let mut current_secret_scalar = Scalar::random(&mut rng);
        let initial_pk_point =
            curve25519_dalek::constants::X25519_BASEPOINT * current_secret_scalar;
        let mut accumulated_blinding = Scalar::ONE;

        for hop in path {
            let hop_pk_point = MontgomeryPoint(hop.public_key.to_bytes());
            let shared_point = hop_pk_point * current_secret_scalar;
            let shared_bytes = shared_point.to_bytes();

            shared_secrets.push(shared_bytes);

            let (_, _, _, blinding) = derive_keys(&shared_bytes);
            blinding_factors.push(blinding);

            let blinded_point = initial_pk_point * accumulated_blinding;
            let hop_pk = X25519PublicKey::from(blinded_point.to_bytes());
            ephemeral_public_keys.push(hop_pk);

            accumulated_blinding *= blinding;
            current_secret_scalar *= blinding;
        }

        let mut filler = Vec::new();
        for secret in shared_secrets.iter().take(path.len().saturating_sub(1)) {
            let (rho, _, _, _) = derive_keys(secret);
            let mut keystream = [0u8; ROUTING_INFO_SIZE + SHIFT_SIZE];
            apply_stream_cipher(&rho, &[0u8; 12], &mut keystream);

            let filler_start_in_keystream = ROUTING_INFO_SIZE - filler.len();
            for (j, byte) in filler.iter_mut().enumerate() {
                *byte ^= keystream[filler_start_in_keystream + j];
            }
            filler.extend_from_slice(&keystream[ROUTING_INFO_SIZE..ROUTING_INFO_SIZE + SHIFT_SIZE]);
        }

        if !filler.is_empty() && !path.is_empty() {
            let (rho, _, _, _) = derive_keys(&shared_secrets[path.len() - 1]);
            let mut keystream = [0u8; ROUTING_INFO_SIZE];
            apply_stream_cipher(&rho, &[0u8; 12], &mut keystream);
            let filler_start = ROUTING_INFO_SIZE - filler.len();
            for (j, byte) in filler.iter_mut().enumerate() {
                *byte ^= keystream[filler_start + j];
            }
        }

        let mut routing_info = [0u8; ROUTING_INFO_SIZE];
        let mut next_mac = [0u8; 32];
        let mut layer_keys: Vec<LionessKeys> = Vec::with_capacity(path.len());

        for i in (0..path.len()).rev() {
            let shared = shared_secrets[i];
            let (rho, mu, pi, _) = derive_keys(&shared);

            layer_keys.push(LionessKeys::from_pi(&pi));

            let mut current_routing = [0u8; ROUTING_INFO_SIZE];

            if i == path.len() - 1 {
                // Final hop (deliver to user)
                current_routing[0] = 0x01; // Exit flag
                if !filler.is_empty() {
                    let filler_start = ROUTING_INFO_SIZE - filler.len();
                    current_routing[filler_start..].copy_from_slice(&filler);
                }
            } else {
                // Forward hop
                current_routing[0] = 0x00;
                let next_addr_bytes = path[i + 1].address.as_bytes();
                current_routing[1] = next_addr_bytes.len() as u8;
                current_routing[2..34].copy_from_slice(&next_mac);
                current_routing[34..34 + next_addr_bytes.len()].copy_from_slice(next_addr_bytes);

                let remainder_len = ROUTING_INFO_SIZE - SHIFT_SIZE;
                current_routing[SHIFT_SIZE..].copy_from_slice(&routing_info[0..remainder_len]);
            }

            apply_stream_cipher(&rho, &[0u8; 12], &mut current_routing);
            let mac = compute_mac(&mu, &current_routing);

            routing_info = current_routing;
            next_mac = mac;
        }

        let mut payload_pi = [0u8; 32];
        rng.fill(&mut payload_pi);
        let payload_keys = LionessKeys::from_pi(&payload_pi);

        let mut header = SphinxHeader {
            ephemeral_key: ephemeral_public_keys[0],
            routing_info,
            mac: next_mac,
            nonce: 0,
        };
        header.solve_pow(pow_difficulty)?;

        let surb = Surb {
            id,
            header,
            first_hop: path[0].address.clone(),
            payload_keys: payload_keys.clone(),
        };

        let recovery = SurbRecovery {
            id,
            layer_keys,
            payload_keys,
        };

        Ok((surb, recovery))
    }

    /// Wraps a reply message into a 32KB `SphinxPacket` using this SURB. Called by the service.
    pub fn encapsulate(&self, message: &[u8]) -> Result<SphinxPacket, SurbError> {
        use super::packet::PACKET_SIZE;
        use super::HEADER_SIZE as SPHINX_HEADER_SIZE;

        let body_size = PACKET_SIZE - SPHINX_HEADER_SIZE;

        if message.len() >= body_size {
            return Err(SurbError::MessageTooLarge {
                size: message.len(),
            });
        }

        let mut body = vec![0u8; body_size];
        body[..message.len()].copy_from_slice(message);
        body[message.len()] = 0x80;

        lioness_encrypt(&self.payload_keys, &mut body);

        let packet_bytes = self.header.to_bytes(&body);

        if packet_bytes.len() != PACKET_SIZE {
            let mut final_packet = vec![0u8; PACKET_SIZE];
            let copy_len = packet_bytes.len().min(PACKET_SIZE);
            final_packet[..copy_len].copy_from_slice(&packet_bytes[..copy_len]);
            return SphinxPacket::from_bytes(final_packet).map_err(SurbError::Packet);
        }

        SphinxPacket::from_bytes(packet_bytes).map_err(SurbError::Packet)
    }
}

/// Recovery keys kept by the SURB sender to decrypt replies. Zeroized on drop.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SurbRecovery {
    pub id: [u8; 16],
    /// Per-hop Lioness keys (applied in order to peel onion layers)
    pub layer_keys: Vec<LionessKeys>,
    /// Final Lioness keys to decrypt the inner message
    pub payload_keys: LionessKeys,
}

impl SurbRecovery {
    /// Decrypts a reply by peeling onion layers then decrypting the inner payload.
    pub fn decrypt(&self, encrypted_body: &[u8]) -> Result<Vec<u8>, SurbError> {
        let mut body = encrypted_body.to_vec();

        // Undo each relay's lioness_decrypt with lioness_encrypt (Lioness is NOT self-inverse)
        for keys in &self.layer_keys {
            lioness_encrypt(keys, &mut body);
        }

        lioness_decrypt(&self.payload_keys, &mut body);

        let unpadded = unpad_iso7816(&body)?;

        Ok(unpadded)
    }

    /// Decrypts a full `SphinxPacket` reply. Extracts the body at offset 472 (Sphinx header size).
    pub fn decrypt_packet(&self, packet: &SphinxPacket) -> Result<Vec<u8>, SurbError> {
        let packet_bytes = packet.as_bytes();
        let body_start = super::HEADER_SIZE;
        let encrypted_body = &packet_bytes[body_start..];

        self.decrypt(encrypted_body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::StaticSecret as X25519SecretKey;

    fn generate_test_path(num_hops: usize) -> (Vec<PathHop>, Vec<X25519SecretKey>) {
        let mut rng = rand::thread_rng();
        let secret_keys: Vec<X25519SecretKey> = (0..num_hops)
            .map(|_| X25519SecretKey::random_from_rng(&mut rng))
            .collect();

        let path: Vec<PathHop> = secret_keys
            .iter()
            .enumerate()
            .map(|(i, sk)| PathHop {
                public_key: X25519PublicKey::from(sk),
                address: format!("node_{}_addr", i),
            })
            .collect();

        (path, secret_keys)
    }

    #[test]
    fn test_surb_construction() {
        let (path, _) = generate_test_path(3);
        let id: [u8; 16] = rand::random();

        let result = Surb::new(&path, id, 0);
        assert!(result.is_ok());

        let (surb, recovery) = result.unwrap();

        assert_eq!(surb.id, id);
        assert_eq!(surb.first_hop, "node_0_addr");

        assert_eq!(recovery.id, id);
        assert_eq!(recovery.layer_keys.len(), 3);
        assert_eq!(recovery.payload_keys.k1, surb.payload_keys.k1);
        assert_eq!(recovery.payload_keys.k2, surb.payload_keys.k2);
        assert_eq!(recovery.payload_keys.k3, surb.payload_keys.k3);
        assert_eq!(recovery.payload_keys.k4, surb.payload_keys.k4);
    }

    #[test]
    fn test_surb_encapsulate() {
        let (path, _) = generate_test_path(3);
        let id: [u8; 16] = rand::random();

        let (surb, _recovery) = Surb::new(&path, id, 0).expect("SURB construction failed");

        let message = b"Hello Reply";
        let result = surb.encapsulate(message);
        assert!(result.is_ok());

        let packet = result.unwrap();
        assert_eq!(packet.as_bytes().len(), crate::sphinx::packet::PACKET_SIZE);
    }

    #[test]
    fn test_surb_full_roundtrip() {
        let (path, _secret_keys) = generate_test_path(3);
        let id: [u8; 16] = rand::random();

        let (surb, recovery) = Surb::new(&path, id, 0).expect("SURB construction failed");

        let message = b"Transaction confirmed: 0x1234567890abcdef";
        let _packet = surb.encapsulate(message).expect("Encapsulation failed");
        let body_size = 512;
        let mut test_body = vec![0u8; body_size];
        test_body[..message.len()].copy_from_slice(message);

        let original = test_body.clone();

        lioness_encrypt(&surb.payload_keys, &mut test_body);
        lioness_decrypt(&recovery.payload_keys, &mut test_body);

        assert_eq!(test_body, original);
    }

    #[test]
    fn test_surb_empty_path() {
        let path: Vec<PathHop> = vec![];
        let id: [u8; 16] = rand::random();

        let result = Surb::new(&path, id, 0);
        assert!(matches!(result, Err(SurbError::EmptyPath)));
    }

    #[test]
    fn test_surb_serialization() {
        let (path, _) = generate_test_path(2);
        let id: [u8; 16] = rand::random();

        let (surb, _) = Surb::new(&path, id, 0).expect("SURB construction failed");

        let json = serde_json::to_string(&surb).expect("Serialization failed");
        let deserialized: Surb = serde_json::from_str(&json).expect("Deserialization failed");

        assert_eq!(deserialized.id, surb.id);
        assert_eq!(deserialized.first_hop, surb.first_hop);
        assert_eq!(deserialized.payload_keys.k1, surb.payload_keys.k1);
        assert_eq!(deserialized.payload_keys.k2, surb.payload_keys.k2);
    }

    /// Random data should fail ISO 7816-4 padding validation (cover traffic defense).
    #[test]
    fn test_decrypt_rejects_random_data() {
        let (path, _) = generate_test_path(3);
        let id: [u8; 16] = rand::random();

        let (_, recovery) = Surb::new(&path, id, 0).expect("SURB construction failed");

        let mut rng = rand::thread_rng();

        let random_body: Vec<u8> = (0..32296).map(|_| rand::Rng::gen::<u8>(&mut rng)).collect();
        let result = recovery.decrypt(&random_body);
        let mut failures = 0;
        for _ in 0..100 {
            let random_data: Vec<u8> = (0..32296).map(|_| rand::Rng::gen::<u8>(&mut rng)).collect();
            if recovery.decrypt(&random_data).is_err() {
                failures += 1;
            }
        }
        assert!(
            failures >= 90,
            "only {failures}/100 random inputs were rejected -- padding check too permissive",
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_surb_full_roundtrip_with_sphinx() {
        let (path, secret_keys) = generate_test_path(3);
        let id: [u8; 16] = rand::random();

        let (surb, recovery) = Surb::new(&path, id, 0).expect("SURB construction failed");

        let message = b"Transaction confirmed: 0x1234567890abcdef";
        let packet = surb.encapsulate(message).expect("Encapsulation failed");

        let packet_bytes = packet.into_bytes();
        let (header0, body0) = SphinxHeader::from_bytes(&packet_bytes).expect("Parse failed");
        let result0 = super::super::into_result(
            header0
                .process(&secret_keys[0], body0.to_vec())
                .expect("Hop 0 failed"),
        );

        let (next_packet1, body1) = match result0 {
            super::super::ProcessResult::Forward {
                next_packet,
                processed_body,
                ..
            } => (next_packet, processed_body),
            super::super::ProcessResult::Exit { .. } => panic!("Hop 0 should be forward"),
        };

        let bytes1 = next_packet1.to_bytes(&body1);
        let (header1, body1_raw) = SphinxHeader::from_bytes(&bytes1).expect("Parse failed");
        let result1 = super::super::into_result(
            header1
                .process(&secret_keys[1], body1_raw.to_vec())
                .expect("Hop 1 failed"),
        );

        let (next_packet2, body2) = match result1 {
            super::super::ProcessResult::Forward {
                next_packet,
                processed_body,
                ..
            } => (next_packet, processed_body),
            super::super::ProcessResult::Exit { .. } => panic!("Hop 1 should be forward"),
        };

        let bytes2 = next_packet2.to_bytes(&body2);
        let (header2, body2_raw) = SphinxHeader::from_bytes(&bytes2).expect("Parse failed");
        let result2 = super::super::into_result(
            header2
                .process(&secret_keys[2], body2_raw.to_vec())
                .expect("Hop 2 failed"),
        );

        let exit_payload = match result2 {
            super::super::ProcessResult::Exit { payload } => payload,
            super::super::ProcessResult::Forward { .. } => panic!("Hop 2 should be exit"),
        };

        let decrypted = recovery
            .decrypt(&exit_payload)
            .expect("SURB decryption failed");
        assert_eq!(decrypted, message);
    }

    /// Regression: body offset must be 472 (sphinx header), not 1036 (AEAD header + nonce).
    #[test]
    fn test_decrypt_packet_correct_offset() {
        use super::super::packet::PACKET_SIZE;

        let (path, _secret_keys) = generate_test_path(3);
        let id: [u8; 16] = rand::random();

        let (surb, recovery) = Surb::new(&path, id, 0).expect("SURB construction failed");
        let message = b"decrypt_packet regression test payload";
        let packet = surb.encapsulate(message).expect("Encapsulation failed");

        let recovery_no_layers = SurbRecovery {
            id: recovery.id,
            layer_keys: vec![],
            payload_keys: recovery.payload_keys.clone(),
        };

        let result = recovery_no_layers.decrypt_packet(&packet);
        assert!(result.is_ok(), "decrypt_packet failed: {:?}", result.err());
        assert_eq!(result.unwrap(), message.as_slice());

        let packet_bytes = packet.as_bytes();
        let sphinx_header_size = super::super::HEADER_SIZE;
        assert_eq!(sphinx_header_size, 472);
        let body_manual = &packet_bytes[sphinx_header_size..];
        let manual_result = recovery_no_layers.decrypt(body_manual);
        assert_eq!(manual_result.unwrap(), message.as_slice());

        assert_eq!(packet_bytes.len(), PACKET_SIZE);
    }

    /// Guards against regression to the old wrong body offset (1036 instead of 472).
    #[test]
    fn test_decrypt_packet_wrong_offset_would_fail() {
        use super::super::packet::PACKET_SIZE;

        let (path, _secret_keys) = generate_test_path(3);
        let id: [u8; 16] = rand::random();

        let (surb, recovery) = Surb::new(&path, id, 0).expect("SURB construction failed");
        let message = b"offset regression test";
        let packet = surb.encapsulate(message).expect("Encapsulation failed");

        let recovery_no_layers = SurbRecovery {
            id: recovery.id,
            layer_keys: vec![],
            payload_keys: recovery.payload_keys.clone(),
        };

        let packet_bytes = packet.as_bytes();
        let wrong_offset = super::super::packet::HEADER_SIZE + super::super::packet::NONCE_SIZE;
        let correct_offset = super::super::HEADER_SIZE;

        assert_eq!(wrong_offset, 1036);
        assert_eq!(correct_offset, 472);
        assert_ne!(wrong_offset, correct_offset);

        let wrong_body = &packet_bytes[wrong_offset..];
        let wrong_result = recovery_no_layers.decrypt(wrong_body);
        assert!(
            wrong_result.is_err(),
            "offset 1036 unexpectedly decrypted Ok({} bytes)",
            wrong_result.as_ref().map(|v| v.len()).unwrap_or(0)
        );

        let correct_body = &packet_bytes[correct_offset..];
        let correct_result = recovery_no_layers.decrypt(correct_body);
        assert!(
            correct_result.is_ok(),
            "offset 472 failed: {:?}",
            correct_result.err()
        );
        assert_eq!(correct_result.unwrap(), message.as_slice());

        let via_method = recovery_no_layers.decrypt_packet(&packet);
        assert!(via_method.is_ok());
        assert_eq!(via_method.unwrap(), message.as_slice());

        assert_eq!(packet_bytes.len(), PACKET_SIZE);
    }

    #[test]
    fn test_surb_rejects_empty_address() {
        let mut rng = rand::thread_rng();
        let sk = X25519SecretKey::random_from_rng(&mut rng);
        let pk = X25519PublicKey::from(&sk);

        let path = vec![PathHop {
            public_key: pk,
            address: String::new(),
        }];
        let id: [u8; 16] = rand::random();

        let result = Surb::new(&path, id, 0);
        assert!(
            matches!(result, Err(SurbError::InvalidAddress { index: 0, .. })),
            "got: {result:?}",
        );
    }

    #[test]
    fn test_surb_rejects_oversized_address() {
        let mut rng = rand::thread_rng();
        let sk = X25519SecretKey::random_from_rng(&mut rng);
        let pk = X25519PublicKey::from(&sk);

        let long_address = "x".repeat(256);
        let path = vec![PathHop {
            public_key: pk,
            address: long_address,
        }];
        let id: [u8; 16] = rand::random();

        let result = Surb::new(&path, id, 0);
        assert!(
            matches!(result, Err(SurbError::InvalidAddress { index: 0, .. })),
            "got: {result:?}",
        );
    }

    #[test]
    fn test_unpad_iso7816_valid() {
        use crate::sphinx::unpad_iso7816_inner;

        // Simple case: "hello" + 0x80 + three 0x00 bytes
        let mut padded = b"hello".to_vec();
        padded.push(0x80);
        padded.extend_from_slice(&[0x00, 0x00, 0x00]);

        let result = unpad_iso7816_inner(&padded);
        assert_eq!(result, Some(b"hello".to_vec()));
    }

    #[test]
    fn test_unpad_iso7816_marker_at_end() {
        use crate::sphinx::unpad_iso7816_inner;

        let mut padded = b"data".to_vec();
        padded.push(0x80);

        let result = unpad_iso7816_inner(&padded);
        assert_eq!(result, Some(b"data".to_vec()));
    }

    #[test]
    fn test_unpad_iso7816_invalid_rejected() {
        use crate::sphinx::unpad_iso7816_inner;

        let corrupted = vec![0x01, 0x02, 0x80, 0xFF];
        let result = unpad_iso7816_inner(&corrupted);
        assert_eq!(result, None);
    }

    #[test]
    fn test_unpad_iso7816_empty_rejected() {
        use crate::sphinx::unpad_iso7816_inner;

        let result = unpad_iso7816_inner(&[]);
        assert_eq!(result, None);
    }

    #[test]
    fn test_unpad_iso7816_no_marker_rejected() {
        use crate::sphinx::unpad_iso7816_inner;

        let no_marker = vec![0x01, 0x02, 0x03, 0x04];
        let result = unpad_iso7816_inner(&no_marker);
        assert_eq!(result, None);
    }

    #[test]
    fn test_unpad_iso7816_empty_payload() {
        use crate::sphinx::unpad_iso7816_inner;

        let just_marker = vec![0x80, 0x00, 0x00];
        let result = unpad_iso7816_inner(&just_marker);
        assert_eq!(result, Some(vec![]));
    }

    #[test]
    fn test_surb_id_hex_roundtrip() {
        let id: [u8; 16] = rand::random();

        let (path, _) = {
            let mut rng = rand::thread_rng();
            let sk = X25519SecretKey::random_from_rng(&mut rng);
            let pk = X25519PublicKey::from(&sk);
            let path = vec![PathHop {
                public_key: pk,
                address: "node_0".into(),
            }];
            (path, ())
        };

        let (_, recovery) = Surb::new(&path, id, 0).expect("SURB construction must succeed");

        let hex = hex::encode(recovery.id);
        let decoded = hex::decode(&hex).expect("hex decode");
        let recovered: [u8; 16] = decoded.try_into().expect("16 bytes");

        assert_eq!(recovery.id, recovered);
        assert_eq!(hex.len(), 32);
    }
}
