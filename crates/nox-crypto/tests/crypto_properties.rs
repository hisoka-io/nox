//! Proptest-based invariant tests for the packet encryption layer.

use nox_crypto::sphinx::packet::{SphinxPacket, MAX_PAYLOAD_SIZE, PACKET_SIZE};
use proptest::prelude::*;
use rand::Rng;

#[test]
fn prop_roundtrip_any_payload() {
    proptest!(|(
        payload_len in 0usize..MAX_PAYLOAD_SIZE,
        key_seed in any::<u64>(),
        nonce_seed in any::<u64>(),
    )| {
        let mut rng = rand::thread_rng();

        let payload: Vec<u8> = (0..payload_len).map(|_| rng.gen()).collect();

        let key = {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&key_seed.to_le_bytes());
            k
        };
        let nonce = {
            let mut n = [0u8; 12];
            n[..8].copy_from_slice(&nonce_seed.to_le_bytes());
            n
        };

        let packet = SphinxPacket::new(&payload, &key, &nonce)
            .expect("Encryption should succeed for valid inputs");

        let decrypted = packet.unwrap(&key)
            .expect("Decryption should succeed with correct key");

        prop_assert_eq!(decrypted, payload, "Roundtrip failed");
    });
}

#[test]
fn prop_packet_size_invariant() {
    proptest!(|(
        payload_len in 0usize..MAX_PAYLOAD_SIZE,
        key_seed in any::<u64>(),
    )| {
        let mut rng = rand::thread_rng();
        let payload: Vec<u8> = (0..payload_len).map(|_| rng.gen()).collect();

        let key = {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&key_seed.to_le_bytes());
            k
        };
        let nonce = [0u8; 12];

        let packet = SphinxPacket::new(&payload, &key, &nonce)
            .expect("Packet creation should succeed");

        prop_assert_eq!(
            packet.as_bytes().len(),
            PACKET_SIZE,
            "Packet size must be exactly {} bytes, got {}",
            PACKET_SIZE,
            packet.as_bytes().len()
        );
    });
}

#[test]
fn prop_avalanche_effect() {
    proptest!(|(
        payload_len in 1usize..100usize,  // Keep small for performance
        key_seed in any::<u64>(),
        flip_pos in 0usize..PACKET_SIZE,  // Position to flip
    )| {
        let mut rng = rand::thread_rng();
        let payload: Vec<u8> = (0..payload_len).map(|_| rng.gen()).collect();

        let key = {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&key_seed.to_le_bytes());
            k
        };
        let nonce = [0u8; 12];

        let packet = SphinxPacket::new(&payload, &key, &nonce)
            .expect("Packet creation should succeed");

        let packet_bytes = packet.as_bytes().to_vec();
        let mut tampered = packet_bytes.clone();

        use nox_crypto::sphinx::packet::{HEADER_SIZE, NONCE_SIZE};
        if flip_pos >= HEADER_SIZE + NONCE_SIZE {
            tampered[flip_pos] ^= 0xFF;

            let tampered_packet = SphinxPacket::from_bytes(tampered)
                .expect("Packet structure should still be valid");

            let result = tampered_packet.unwrap(&key);
            prop_assert!(
                result.is_err(),
                "Tampered packet should fail to decrypt (avalanche effect)"
            );
        }
    });
}

#[test]
fn prop_different_keys_different_ciphertext() {
    proptest!(|(
        payload_len in 1usize..100usize,
        key1_seed in any::<u64>(),
        key2_seed in any::<u64>(),
    )| {
        prop_assume!(key1_seed != key2_seed);

        let mut rng = rand::thread_rng();
        let payload: Vec<u8> = (0..payload_len).map(|_| rng.gen()).collect();

        let key1 = {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&key1_seed.to_le_bytes());
            k
        };
        let key2 = {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&key2_seed.to_le_bytes());
            k
        };
        let nonce = [0u8; 12];

        let packet1 = SphinxPacket::new(&payload, &key1, &nonce)
            .expect("Packet 1 creation should succeed");
        let packet2 = SphinxPacket::new(&payload, &key2, &nonce)
            .expect("Packet 2 creation should succeed");

        prop_assert_ne!(
            packet1.as_bytes(),
            packet2.as_bytes(),
            "Different keys must produce different ciphertexts"
        );
    });
}

#[test]
fn prop_wrong_key_fails() {
    proptest!(|(
        payload_len in 1usize..100usize,
        correct_key_seed in any::<u64>(),
        wrong_key_seed in any::<u64>(),
    )| {
        prop_assume!(correct_key_seed != wrong_key_seed);

        let mut rng = rand::thread_rng();
        let payload: Vec<u8> = (0..payload_len).map(|_| rng.gen()).collect();

        let correct_key = {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&correct_key_seed.to_le_bytes());
            k
        };
        let wrong_key = {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&wrong_key_seed.to_le_bytes());
            k
        };
        let nonce = [0u8; 12];

        let packet = SphinxPacket::new(&payload, &correct_key, &nonce)
            .expect("Packet creation should succeed");

        let result = packet.unwrap(&wrong_key);
        prop_assert!(
            result.is_err(),
            "Decryption with wrong key must fail"
        );
    });
}
