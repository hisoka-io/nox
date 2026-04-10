pub mod lioness;
pub mod packet;
pub mod pow;
pub mod surb;

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{ChaCha20, Key, Nonce};
use curve25519_dalek::constants::X25519_BASEPOINT;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};
/// Constant-time ISO 7816-4 unpadding. Returns `None` if padding is invalid.
pub(crate) fn unpad_iso7816_inner(data: &[u8]) -> Option<Vec<u8>> {
    use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

    if data.is_empty() {
        return None;
    }

    let mut marker_pos: i64 = -1;
    let mut found_marker = Choice::from(0u8);

    for i in (0..data.len()).rev() {
        let is_marker = data[i].ct_eq(&0x80);
        let should_update = is_marker & !found_marker;
        marker_pos = i64::conditional_select(&marker_pos, &(i as i64), should_update);
        found_marker |= is_marker;
    }

    if marker_pos < 0 {
        return None;
    }

    let marker_idx = marker_pos as usize;

    let mut all_zeros = Choice::from(1u8);
    for &byte in &data[marker_idx + 1..] {
        all_zeros &= byte.ct_eq(&0x00);
    }

    if !bool::from(all_zeros) {
        return None;
    }

    Some(data[..marker_idx].to_vec())
}

pub const ROUTING_INFO_SIZE: usize = 400;
pub const MAC_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 8;
pub const HEADER_SIZE: usize = 32 + ROUTING_INFO_SIZE + MAC_SIZE + NONCE_SIZE;
/// Per-hop routing info shift: Flag(1) + Len(1) + MAC(32) + Address(max ~90) = 124, rounded to 128.
pub const SHIFT_SIZE: usize = 128;

#[derive(Debug, Error)]
pub enum SphinxError {
    #[error("Integrity Check Failed (Invalid MAC)")]
    MacMismatch,
    #[error("Serialization Error: {0}")]
    Serialization(String),
    #[error("Packet too short")]
    InvalidSize,
    #[error("Crypto Error: {0}")]
    Crypto(String),
    #[error("PoW error: {0}")]
    Pow(#[from] pow::PowError),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SphinxHeader {
    pub ephemeral_key: X25519PublicKey,
    #[serde(with = "BigArray")]
    pub routing_info: [u8; ROUTING_INFO_SIZE],
    pub mac: [u8; MAC_SIZE],
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PathHop {
    pub public_key: X25519PublicKey,
    pub address: String,
}

/// Per-hop timing breakdown (nanoseconds). Only with `hop-metrics` feature.
#[cfg(feature = "hop-metrics")]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HopTimings {
    pub ecdh_ns: u64,
    pub key_derive_ns: u64,
    pub mac_verify_ns: u64,
    pub routing_decrypt_ns: u64,
    pub body_decrypt_ns: u64,
    pub blinding_ns: u64,
    pub total_sphinx_ns: u64,
}

#[derive(Debug)]
pub enum ProcessResult {
    Forward {
        next_hop: String,
        next_packet: Box<SphinxHeader>,
        processed_body: Vec<u8>,
    },
    Exit {
        payload: Vec<u8>,
    },
}

#[cfg(feature = "hop-metrics")]
pub type ProcessOutput = (ProcessResult, HopTimings);

#[cfg(not(feature = "hop-metrics"))]
pub type ProcessOutput = ProcessResult;

/// Extract the [`ProcessResult`], discarding timing data if present.
#[inline]
#[must_use]
pub fn into_result(output: ProcessOutput) -> ProcessResult {
    #[cfg(feature = "hop-metrics")]
    {
        output.0
    }
    #[cfg(not(feature = "hop-metrics"))]
    {
        output
    }
}
impl SphinxHeader {
    /// Blake3 hash of (`ephemeral_key`, `mac`, `nonce`) for replay detection.
    #[must_use]
    pub fn compute_replay_tag(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.ephemeral_key.as_bytes());
        hasher.update(&self.mac);
        hasher.update(&self.nonce.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Process a Sphinx packet at this hop: ECDH, MAC verify, decrypt routing + body, blind key.
    pub fn process(
        &self,
        node_sk: &X25519SecretKey,
        body: Vec<u8>,
    ) -> Result<ProcessOutput, SphinxError> {
        #[cfg(feature = "hop-metrics")]
        let total_start = std::time::Instant::now();

        #[cfg(feature = "hop-metrics")]
        let t0 = std::time::Instant::now();

        let shared_secret = node_sk.diffie_hellman(&self.ephemeral_key);

        #[cfg(feature = "hop-metrics")]
        let ecdh_ns = t0.elapsed().as_nanos() as u64;

        #[cfg(feature = "hop-metrics")]
        let t1 = std::time::Instant::now();

        let (rho, mu, pi, blinding_factor) = derive_keys(shared_secret.as_bytes());

        #[cfg(feature = "hop-metrics")]
        let key_derive_ns = t1.elapsed().as_nanos() as u64;

        #[cfg(feature = "hop-metrics")]
        let t2 = std::time::Instant::now();

        let calculated_mac = compute_mac(&mu, &self.routing_info);
        if calculated_mac.ct_eq(&self.mac).unwrap_u8() == 0 {
            return Err(SphinxError::MacMismatch);
        }

        #[cfg(feature = "hop-metrics")]
        let mac_verify_ns = t2.elapsed().as_nanos() as u64;

        #[cfg(feature = "hop-metrics")]
        let t3 = std::time::Instant::now();

        let mut extended_routing = [0u8; ROUTING_INFO_SIZE + SHIFT_SIZE];
        extended_routing[..ROUTING_INFO_SIZE].copy_from_slice(&self.routing_info);

        // Zero nonce is safe: rho is unique per hop, so each (key, nonce) pair is used exactly once.
        apply_stream_cipher(&rho, &[0u8; 12], &mut extended_routing);

        let decrypted_routing: [u8; ROUTING_INFO_SIZE] = extended_routing[..ROUTING_INFO_SIZE]
            .try_into()
            .map_err(|_| SphinxError::Serialization("Routing size mismatch".into()))?;
        let shifted_routing: [u8; ROUTING_INFO_SIZE] = extended_routing
            [SHIFT_SIZE..SHIFT_SIZE + ROUTING_INFO_SIZE]
            .try_into()
            .map_err(|_| SphinxError::Serialization("Routing size mismatch".into()))?;

        #[cfg(feature = "hop-metrics")]
        let routing_decrypt_ns = t3.elapsed().as_nanos() as u64;

        #[cfg(feature = "hop-metrics")]
        let t4 = std::time::Instant::now();

        let mut processed_body = body;
        if processed_body.len() < lioness::MIN_BODY_SIZE {
            return Err(SphinxError::Serialization(format!(
                "Body too small for Lioness SPRP: {} bytes, minimum {}",
                processed_body.len(),
                lioness::MIN_BODY_SIZE
            )));
        }
        let lioness_keys = lioness::LionessKeys::from_pi(&pi);
        lioness::lioness_decrypt(&lioness_keys, &mut processed_body);

        #[cfg(feature = "hop-metrics")]
        let body_decrypt_ns = t4.elapsed().as_nanos() as u64;

        let hop_type = decrypted_routing[0];

        #[cfg(feature = "hop-metrics")]
        let mut blinding_ns = 0u64;

        let result = if hop_type == 0x00 {
            let addr_len = decrypted_routing[1] as usize;
            let next_mac_start = 2;
            let next_mac_end = 34;
            let addr_start = 34;
            let addr_end = 34 + addr_len;

            if addr_end > SHIFT_SIZE {
                return Err(SphinxError::Serialization(
                    "Address length exceeds SHIFT_SIZE".into(),
                ));
            }

            let mut next_mac = [0u8; 32];
            next_mac.copy_from_slice(&decrypted_routing[next_mac_start..next_mac_end]);

            let next_hop = std::str::from_utf8(&decrypted_routing[addr_start..addr_end])
                .map(str::to_owned)
                .map_err(|_| SphinxError::Serialization("Invalid Address UTF8".into()))?;

            #[cfg(feature = "hop-metrics")]
            let t5 = std::time::Instant::now();

            let point = MontgomeryPoint(self.ephemeral_key.to_bytes());
            let blinded_point = point * blinding_factor;
            let next_ephemeral_key = X25519PublicKey::from(blinded_point.to_bytes());

            #[cfg(feature = "hop-metrics")]
            {
                blinding_ns = t5.elapsed().as_nanos() as u64;
            }

            ProcessResult::Forward {
                next_hop,
                next_packet: Box::new(SphinxHeader {
                    ephemeral_key: next_ephemeral_key,
                    routing_info: shifted_routing,
                    mac: next_mac,
                    nonce: 0,
                }),
                processed_body,
            }
        } else {
            ProcessResult::Exit {
                payload: processed_body,
            }
        };

        #[cfg(feature = "hop-metrics")]
        {
            let total_sphinx_ns = total_start.elapsed().as_nanos() as u64;
            Ok((
                result,
                HopTimings {
                    ecdh_ns,
                    key_derive_ns,
                    mac_verify_ns,
                    routing_decrypt_ns,
                    body_decrypt_ns,
                    blinding_ns,
                    total_sphinx_ns,
                },
            ))
        }

        #[cfg(not(feature = "hop-metrics"))]
        Ok(result)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), SphinxError> {
        if bytes.len() < HEADER_SIZE {
            return Err(SphinxError::InvalidSize);
        }

        let pk_end = 32;
        let route_end = pk_end + ROUTING_INFO_SIZE;
        let mac_end = route_end + MAC_SIZE;
        let nonce_end = mac_end + NONCE_SIZE;

        let pk_bytes: [u8; 32] = bytes[0..pk_end]
            .try_into()
            .map_err(|_| SphinxError::InvalidSize)?;
        let ephemeral_key = X25519PublicKey::from(pk_bytes);

        let mut routing_info = [0u8; ROUTING_INFO_SIZE];
        routing_info.copy_from_slice(&bytes[pk_end..route_end]);

        let mut mac = [0u8; MAC_SIZE];
        mac.copy_from_slice(&bytes[route_end..mac_end]);

        let nonce_bytes: [u8; 8] = bytes[mac_end..nonce_end]
            .try_into()
            .map_err(|_| SphinxError::InvalidSize)?;
        let nonce = u64::from_be_bytes(nonce_bytes);

        let header = SphinxHeader {
            ephemeral_key,
            routing_info,
            mac,
            nonce,
        };

        let payload = &bytes[nonce_end..];
        Ok((header, payload))
    }

    #[must_use]
    pub fn to_bytes(&self, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE + payload.len());
        out.extend_from_slice(self.ephemeral_key.as_bytes());
        out.extend_from_slice(&self.routing_info);
        out.extend_from_slice(&self.mac);
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[must_use]
    pub fn verify_pow(&self, difficulty: u32) -> bool {
        if difficulty == 0 {
            return true;
        }
        let hash = self.compute_hash();
        pow::count_leading_zeros(&hash) >= difficulty
    }

    /// Solves `PoW` by brute-forcing nonces (single-threaded).
    pub fn solve_pow(&mut self, difficulty: u32) -> Result<(), SphinxError> {
        if difficulty == 0 {
            return Ok(());
        }
        if difficulty > pow::MAX_DIFFICULTY {
            return Err(pow::PowError::DifficultyTooHigh { difficulty }.into());
        }
        loop {
            if self.verify_pow(difficulty) {
                break;
            }
            self.nonce = self.nonce.wrapping_add(1);
        }
        Ok(())
    }

    /// Solves `PoW` using the parallel solver.
    pub fn solve_pow_parallel(
        &mut self,
        difficulty: u32,
        threads: usize,
    ) -> Result<(), SphinxError> {
        if difficulty == 0 {
            return Ok(());
        }

        let solver = pow::PowSolver::new(pow::Sha256Pow, threads);
        let hash_data = self.compute_hash_for_pow();
        self.nonce = solver.solve(&hash_data, difficulty, self.nonce)?;
        Ok(())
    }

    /// Header data without the nonce, for the `PoW` solver.
    fn compute_hash_for_pow(&self) -> [u8; 32 + ROUTING_INFO_SIZE + MAC_SIZE] {
        let mut data = [0u8; 32 + ROUTING_INFO_SIZE + MAC_SIZE];
        data[..32].copy_from_slice(self.ephemeral_key.as_bytes());
        data[32..32 + ROUTING_INFO_SIZE].copy_from_slice(&self.routing_info);
        data[32 + ROUTING_INFO_SIZE..].copy_from_slice(&self.mac);
        data
    }

    fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.ephemeral_key.as_bytes());
        hasher.update(self.routing_info);
        hasher.update(self.mac);
        hasher.update(self.nonce.to_be_bytes());
        hasher.finalize().into()
    }
}

#[inline]
#[must_use]
pub fn derive_keys(shared_secret: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 32], Scalar) {
    let ss_bytes = shared_secret;

    let mut hasher = Sha256::new();
    hasher.update(b"rho");
    hasher.update(ss_bytes);
    let rho: [u8; 32] = hasher.finalize().into();

    let mut hasher = Sha256::new();
    hasher.update(b"mu");
    hasher.update(ss_bytes);
    let mu: [u8; 32] = hasher.finalize().into();

    let mut hasher = Sha256::new();
    hasher.update(b"pi");
    hasher.update(ss_bytes);
    let pi: [u8; 32] = hasher.finalize().into();

    let mut hasher = Sha256::new();
    hasher.update(b"blind");
    hasher.update(ss_bytes);
    let blind_bytes: [u8; 32] = hasher.finalize().into();
    let blind_scalar = Scalar::from_bytes_mod_order(blind_bytes);

    (rho, mu, pi, blind_scalar)
}

#[inline]
#[allow(clippy::expect_used)]
pub(crate) fn compute_mac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC key length is always valid for SHA256");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

#[inline]
pub(crate) fn apply_stream_cipher(key: &[u8; 32], iv: &[u8; 12], data: &mut [u8]) {
    let key = Key::from_slice(key);
    let nonce = Nonce::from_slice(iv);
    let mut cipher = ChaCha20::new(key, nonce);
    cipher.apply_keystream(data);
}

/// Single-hop convenience wrapper for tests only.
#[cfg(test)]
pub fn build_packet(
    node_pk: X25519PublicKey,
    payload: &[u8],
    _is_exit: bool,
    pow_difficulty: u32,
) -> Result<Vec<u8>, SphinxError> {
    let path = vec![PathHop {
        public_key: node_pk,
        address: "0xEXIT".into(),
    }];
    build_multi_hop_packet(&path, payload, pow_difficulty)
}

pub fn build_multi_hop_packet(
    path: &[PathHop],
    payload: &[u8],
    pow_difficulty: u32,
) -> Result<Vec<u8>, SphinxError> {
    if path.is_empty() {
        return Err(SphinxError::Serialization("Empty path".into()));
    }

    let mut rng = rand::rngs::OsRng;

    // Body must be padded to full capacity BEFORE Lioness encryption.
    // Lioness output depends on the full block size -- a size mismatch between
    // sender and relay produces garbage.
    let body_capacity = packet::PACKET_SIZE - HEADER_SIZE;
    let mut current_body = vec![0u8; body_capacity];
    let copy_len = payload.len().min(body_capacity);
    current_body[..copy_len].copy_from_slice(&payload[..copy_len]);

    let mut ephemeral_public_keys = Vec::with_capacity(path.len());
    let mut shared_secrets = Vec::with_capacity(path.len());
    let mut blinding_factors = Vec::with_capacity(path.len());

    // Raw Scalar avoids X25519 clamping interference during blinding
    let mut current_secret_scalar = Scalar::random(&mut rng);
    let initial_pk_point = X25519_BASEPOINT * current_secret_scalar;
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
    for shared_secret in shared_secrets.iter().take(path.len().saturating_sub(1)) {
        let (rho, _, _, _) = derive_keys(shared_secret);
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

    for i in (0..path.len()).rev() {
        let shared = shared_secrets[i];
        let (rho, mu, pi, _) = derive_keys(&shared);

        let body_keys = lioness::LionessKeys::from_pi(&pi);
        lioness::lioness_encrypt(&body_keys, &mut current_body);

        let mut current_routing = [0u8; ROUTING_INFO_SIZE];
        if i == path.len() - 1 {
            current_routing[0] = 0x01;
            if !filler.is_empty() {
                let filler_start = ROUTING_INFO_SIZE - filler.len();
                current_routing[filler_start..].copy_from_slice(&filler);
            }
        } else {
            current_routing[0] = 0x00;
            let next_addr_bytes = path[i + 1].address.as_bytes();
            current_routing[1] = u8::try_from(next_addr_bytes.len()).map_err(|_| {
                SphinxError::Serialization(format!(
                    "Address too long ({} bytes, max 255)",
                    next_addr_bytes.len()
                ))
            })?;
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

    let mut final_header = SphinxHeader {
        ephemeral_key: ephemeral_public_keys[0],
        routing_info,
        mac: next_mac,
        nonce: 0,
    };

    final_header.solve_pow(pow_difficulty)?;
    Ok(final_header.to_bytes(&current_body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // #[ignore]
    fn test_multi_hop_integrity() {
        let mut rng = rand::thread_rng();

        let sks: Vec<X25519SecretKey> = (0..3)
            .map(|_| X25519SecretKey::random_from_rng(&mut rng))
            .collect();
        let pks: Vec<X25519PublicKey> = sks.iter().map(X25519PublicKey::from).collect();

        let path = vec![
            PathHop {
                public_key: pks[0],
                address: "node_0_addr".into(),
            },
            PathHop {
                public_key: pks[1],
                address: "node_1_addr".into(),
            },
            PathHop {
                public_key: pks[2],
                address: "EXIT_ADDR".into(),
            },
        ];

        let payload = b"DeepOnion".to_vec();
        println!("Original Payload: {:?}", payload);

        let packet = build_multi_hop_packet(&path, &payload, 0).expect("Build failed");

        println!("\n>>> Processing Hop 0");
        let (header0, body0) = SphinxHeader::from_bytes(&packet).unwrap();
        let res0 = into_result(
            header0
                .process(&sks[0], body0.to_vec())
                .expect("Hop 0 failed"),
        );

        let (next_hop0, packet0, body0_peeled) = match res0 {
            ProcessResult::Forward {
                next_hop,
                next_packet,
                processed_body,
                ..
            } => (next_hop, next_packet, processed_body),
            _ => panic!("Hop 0 should be forward"),
        };
        assert_eq!(next_hop0, "node_1_addr");

        let bytes1 = packet0.to_bytes(&body0_peeled);
        let (header1, body1) = SphinxHeader::from_bytes(&bytes1).unwrap();

        println!("\n>>> Processing Hop 1");
        let res1 = into_result(
            header1
                .process(&sks[1], body1.to_vec())
                .expect("Hop 1 failed"),
        );

        let (next_hop1, packet1, body1_peeled) = match res1 {
            ProcessResult::Forward {
                next_hop,
                next_packet,
                processed_body,
                ..
            } => (next_hop, next_packet, processed_body),
            _ => panic!("Hop 1 should be forward"),
        };
        assert_eq!(next_hop1, "EXIT_ADDR");
        let bytes2 = packet1.to_bytes(&body1_peeled);
        let (header2, body2) = SphinxHeader::from_bytes(&bytes2).unwrap();

        println!("\n>>> Processing Hop 2");
        let res2 = into_result(
            header2
                .process(&sks[2], body2.to_vec())
                .expect("Hop 2 failed"),
        );

        match res2 {
            ProcessResult::Exit {
                payload: final_payload,
            } => {
                // Body is padded to full capacity (32296 bytes). The payload
                // sits at the start, followed by zero padding.
                let body_capacity = packet::PACKET_SIZE - HEADER_SIZE;
                assert_eq!(final_payload.len(), body_capacity);
                assert_eq!(&final_payload[..payload.len()], payload.as_slice(),);
                // Remaining bytes must be zero padding
                assert!(final_payload[payload.len()..].iter().all(|&b| b == 0),);
            }
            _ => panic!("Hop 2 should be exit"),
        }
    }

    /// Regression: body must be padded BEFORE Lioness encryption to match relay body size.
    #[test]
    fn test_lioness_body_size_consistency() {
        let mut rng = rand::thread_rng();
        let sks: Vec<X25519SecretKey> = (0..3)
            .map(|_| X25519SecretKey::random_from_rng(&mut rng))
            .collect();
        let pks: Vec<X25519PublicKey> = sks.iter().map(X25519PublicKey::from).collect();

        let path = vec![
            PathHop {
                public_key: pks[0],
                address: "entry".into(),
            },
            PathHop {
                public_key: pks[1],
                address: "mix".into(),
            },
            PathHop {
                public_key: pks[2],
                address: "exit".into(),
            },
        ];

        let payload = vec![0x42u8; 91];
        let packet = build_multi_hop_packet(&path, &payload, 0).expect("Build failed");

        assert_eq!(packet.len(), packet::PACKET_SIZE);

        let (h0, b0) = SphinxHeader::from_bytes(&packet).expect("Parse failed");
        let body_capacity = packet::PACKET_SIZE - HEADER_SIZE;
        assert_eq!(b0.len(), body_capacity);

        let r0 = into_result(h0.process(&sks[0], b0.to_vec()).expect("Hop 0 failed"));
        let (p1, b1) = match r0 {
            ProcessResult::Forward {
                next_packet,
                processed_body,
                ..
            } => (next_packet, processed_body),
            _ => panic!("Expected forward at hop 0"),
        };
        assert_eq!(b1.len(), body_capacity);

        let bytes1 = p1.to_bytes(&b1);
        let (h1, b1r) = SphinxHeader::from_bytes(&bytes1).expect("Parse failed");
        let r1 = into_result(h1.process(&sks[1], b1r.to_vec()).expect("Hop 1 failed"));
        let (p2, b2) = match r1 {
            ProcessResult::Forward {
                next_packet,
                processed_body,
                ..
            } => (next_packet, processed_body),
            _ => panic!("Expected forward at hop 1"),
        };
        assert_eq!(b2.len(), body_capacity);

        let bytes2 = p2.to_bytes(&b2);
        let (h2, b2r) = SphinxHeader::from_bytes(&bytes2).expect("Parse failed");
        let r2 = into_result(h2.process(&sks[2], b2r.to_vec()).expect("Hop 2 failed"));

        match r2 {
            ProcessResult::Exit {
                payload: exit_payload,
            } => {
                assert_eq!(exit_payload.len(), body_capacity);
                assert_eq!(&exit_payload[..payload.len()], payload.as_slice());
                assert!(exit_payload[payload.len()..].iter().all(|&b| b == 0));
            }
            _ => panic!("Expected exit at hop 2"),
        }
    }

    #[test]
    fn test_sphinx_peel_hop() {
        let mut rng = rand::thread_rng();

        let node_sk = X25519SecretKey::random_from_rng(&mut rng);
        let node_pk = X25519PublicKey::from(&node_sk);

        let sender_ephemeral_sk = X25519SecretKey::random_from_rng(&mut rng);
        let sender_ephemeral_pk = X25519PublicKey::from(&sender_ephemeral_sk);

        let shared_secret = sender_ephemeral_sk.diffie_hellman(&node_pk);
        let (rho, mu, _pi, _blind) = derive_keys(shared_secret.as_bytes());

        let next_hop = "NEXT";
        let mut routing_data = [0u8; ROUTING_INFO_SIZE];
        routing_data[0] = 0x00; // Forward
        routing_data[1] = next_hop.len() as u8;
        routing_data[2..34].copy_from_slice(&[0u8; 32]); // Dummy next MAC
        routing_data[34..34 + next_hop.len()].copy_from_slice(next_hop.as_bytes());

        apply_stream_cipher(&rho, &[0u8; 12], &mut routing_data);
        let mac = compute_mac(&mu, &routing_data);

        let header = SphinxHeader {
            ephemeral_key: sender_ephemeral_pk,
            routing_info: routing_data,
            mac,
            nonce: 0,
        };

        let body = vec![0u8; lioness::MIN_BODY_SIZE];
        let result = into_result(header.process(&node_sk, body).unwrap());

        match result {
            ProcessResult::Forward { next_hop: h, .. } => {
                assert_eq!(h, "NEXT");
            }
            _ => panic!("Expected Forward result"),
        }
    }

    #[test]
    fn test_integrity_failure() {
        let mut rng = rand::thread_rng();
        let node_sk = X25519SecretKey::random_from_rng(&mut rng);
        let dummy_sk = X25519SecretKey::random_from_rng(&mut rng);
        let dummy_pk = X25519PublicKey::from(&dummy_sk);

        let header = SphinxHeader {
            ephemeral_key: dummy_pk,
            routing_info: [0u8; ROUTING_INFO_SIZE],
            mac: [0u8; 32],
            nonce: 0,
        };

        let result = header.process(&node_sk, vec![]);
        assert!(matches!(result, Err(SphinxError::MacMismatch)));
    }

    #[test]
    fn test_identical_payloads_produce_unique_packets() {
        use sha2::{Digest, Sha256};

        let mut rng = rand::thread_rng();

        let node_sk = X25519SecretKey::random_from_rng(&mut rng);
        let node_pk = X25519PublicKey::from(&node_sk);

        let payload = b"PAYLOAD_REPLAY_CHECK".to_vec();

        let packet_1 = build_packet(node_pk, &payload, true, 0).unwrap();
        let packet_2 = build_packet(node_pk, &payload, true, 0).unwrap();

        assert_ne!(packet_1, packet_2);

        let mut hasher1 = Sha256::new();
        hasher1.update(&packet_1);
        let hash1 = hasher1.finalize();

        let mut hasher2 = Sha256::new();
        hasher2.update(&packet_2);
        let hash2 = hasher2.finalize();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_sphinx_fuzzing_no_panic() {
        use rand::Rng;

        let mut rng = rand::thread_rng();

        for _ in 0..1000 {
            let len = rng.gen_range(0..2000);
            let mut bytes = vec![0u8; len];
            rng.fill(&mut bytes[..]);

            let result = SphinxHeader::from_bytes(&bytes);
            if let Err(e) = result {
                assert!(!format!("{}", e).is_empty());
            }
        }
    }

    #[test]
    fn test_derive_keys_deterministic() {
        let ss = [0x42u8; 32];
        let (rho1, mu1, pi1, blind1) = derive_keys(&ss);
        let (rho2, mu2, pi2, blind2) = derive_keys(&ss);
        assert_eq!(rho1, rho2);
        assert_eq!(mu1, mu2);
        assert_eq!(pi1, pi2);
        assert_eq!(blind1, blind2);
    }

    #[test]
    fn test_derive_keys_different_shared_secrets() {
        let ss_a = [0x01u8; 32];
        let ss_b = [0x02u8; 32];
        let (rho_a, mu_a, pi_a, _) = derive_keys(&ss_a);
        let (rho_b, mu_b, pi_b, _) = derive_keys(&ss_b);
        assert_ne!(rho_a, rho_b);
        assert_ne!(mu_a, mu_b);
        assert_ne!(pi_a, pi_b);
    }

    #[test]
    fn test_derive_keys_outputs_are_distinct() {
        let ss = [0x55u8; 32];
        let (rho, mu, pi, blind) = derive_keys(&ss);
        let blind_bytes = blind.to_bytes();
        assert_ne!(rho, mu);
        assert_ne!(rho, pi);
        assert_ne!(mu, pi);
        assert_ne!(rho, blind_bytes);
    }

    #[test]
    fn test_compute_mac_known_vector() {
        let key = [0u8; 32];
        let data = b"test";
        let mac = compute_mac(&key, data);

        let mac2 = compute_mac(&key, data);
        assert_eq!(mac, mac2);

        assert_ne!(mac, [0u8; 32]);
        assert_eq!(mac.len(), 32);

        let mac_diff = compute_mac(&key, b"different");
        assert_ne!(mac, mac_diff);
    }

    /// ChaCha20 XOR is its own inverse -- foundational property for Sphinx.
    #[test]
    fn test_apply_stream_cipher_identity() {
        let key = [0xABu8; 32];
        let iv = [0u8; 12];
        let original = b"sphinx routing information payload".to_vec();

        let mut data = original.clone();
        apply_stream_cipher(&key, &iv, &mut data);
        assert_ne!(data, original);

        apply_stream_cipher(&key, &iv, &mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_apply_stream_cipher_different_keys() {
        let key_a = [0x11u8; 32];
        let key_b = [0x22u8; 32];
        let iv = [0u8; 12];
        let plaintext = b"hello sphinx world".to_vec();

        let mut ct_a = plaintext.clone();
        apply_stream_cipher(&key_a, &iv, &mut ct_a);

        let mut ct_b = plaintext.clone();
        apply_stream_cipher(&key_b, &iv, &mut ct_b);

        assert_ne!(ct_a, ct_b);
    }

    #[test]
    fn test_replay_tag_uniqueness() {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let mut tags = std::collections::HashSet::new();
        for _ in 0..20 {
            let mut routing_info = [0u8; ROUTING_INFO_SIZE];
            rng.fill(&mut routing_info[..]);
            let mut mac = [0u8; MAC_SIZE];
            rng.fill(&mut mac[..]);
            let nonce: u64 = rng.gen();

            let header = SphinxHeader {
                ephemeral_key: X25519PublicKey::from(&X25519SecretKey::random_from_rng(&mut rng)),
                routing_info,
                mac,
                nonce,
            };
            let tag = header.compute_replay_tag();
            tags.insert(tag);
        }
        assert_eq!(tags.len(), 20);
    }

    /// HEADER_SIZE must match the actual wire size -- SURB parsing depends on it.
    #[test]
    fn test_sphinx_header_size_constant() {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let mut routing_info = [0u8; ROUTING_INFO_SIZE];
        rng.fill(&mut routing_info[..]);
        let mut mac = [0u8; MAC_SIZE];
        rng.fill(&mut mac[..]);

        let header = SphinxHeader {
            ephemeral_key: X25519PublicKey::from(&X25519SecretKey::random_from_rng(&mut rng)),
            routing_info,
            mac,
            nonce: 12345,
        };

        let serialized = header.to_bytes(&[]);
        assert_eq!(
            serialized.len(),
            HEADER_SIZE,
            "to_bytes(&[]) produced {} bytes, expected HEADER_SIZE={HEADER_SIZE}",
            serialized.len()
        );

        assert_eq!(HEADER_SIZE, 32 + ROUTING_INFO_SIZE + MAC_SIZE + NONCE_SIZE);
    }
}
