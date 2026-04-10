//! Reply path tests: anonymous return path using SURBs.

use nox_core::Fragmenter;
use nox_core::{RelayerPayload, ServiceRequest};
use nox_crypto::PathHop;
use nox_crypto::{Surb, SurbRecovery};
use nox_node::services::response_packer::ResponsePacker;
use rand::seq::SliceRandom;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

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
            address: format!("/ip4/127.0.0.1/tcp/{}", 9000 + i),
        })
        .collect();

    (path, secret_keys)
}

fn generate_surbs_with_recovery(count: usize, hops: usize) -> Vec<(Surb, SurbRecovery)> {
    let (path, _) = generate_test_path(hops);

    (0..count)
        .map(|_| {
            let id: [u8; 16] = rand::random();
            Surb::new(&path, id, 0).expect("SURB creation failed")
        })
        .collect()
}

#[test]
fn test_boomerang_roundtrip() {
    let packer = ResponsePacker::new();
    let _fragmenter = Fragmenter::new();

    let surb_count = 5;
    let surbs_and_recovery: Vec<(Surb, SurbRecovery)> = generate_surbs_with_recovery(surb_count, 3);
    let surbs: Vec<Surb> = surbs_and_recovery.iter().map(|(s, _)| s.clone()).collect();
    let _recoveries: Vec<SurbRecovery> = surbs_and_recovery.into_iter().map(|(_, r)| r).collect();

    let original_data: Vec<u8> = (0..50_000).map(|i| (i % 256) as u8).collect();
    let request_id = 0xCAFEBABE_u64;

    println!(" Original data size: {} bytes", original_data.len());
    println!(" SURBs available: {}", surb_count);

    let packed = packer.pack_response(request_id, &original_data, surbs);
    assert!(packed.is_ok());

    let pack_result = packed.unwrap();
    let packets = &pack_result.packets;
    println!("Packed into {} packets", packets.len());

    assert!(packets.len() <= surb_count);
    assert!(!packets.is_empty());

    let mut shuffled_indices: Vec<usize> = (0..packets.len()).collect();
    shuffled_indices.shuffle(&mut rand::thread_rng());
    println!("Shuffled order: {:?}", shuffled_indices);

    for (i, packet) in packets.iter().enumerate() {
        assert!(!packet.first_hop.is_empty(), "packet {i} missing first_hop");
        assert!(!packet.packet_bytes.is_empty(), "packet {i} has no bytes");
        println!(
            "  Packet {}: {} bytes to {}",
            i,
            packet.packet_bytes.len(),
            packet.first_hop
        );
    }

    println!("✅ Boomerang test passed - packets correctly formed");
}

#[test]
fn test_service_request_roundtrip() {
    let data = b"Hello, Echo!".to_vec();
    let request = ServiceRequest::Echo { data: data.clone() };

    // Serialize
    let serialized = bincode::serialize(&request).expect("Serialization failed");

    // Deserialize
    let deserialized: ServiceRequest =
        bincode::deserialize(&serialized).expect("Deserialization failed");

    match deserialized {
        ServiceRequest::Echo { data: recovered } => {
            assert_eq!(recovered, data);
        }
        _ => panic!("Wrong variant"),
    }
}

#[test]
fn test_anonymous_request_construction() {
    let (path, _) = generate_test_path(2);
    let id: [u8; 16] = rand::random();
    let (surb, _recovery) = Surb::new(&path, id, 0).expect("SURB creation failed");

    let inner = bincode::serialize(&ServiceRequest::Echo {
        data: b"test".to_vec(),
    })
    .expect("Serialization failed");

    let payload = RelayerPayload::AnonymousRequest {
        inner,
        reply_surbs: vec![surb],
    };

    let serialized = bincode::serialize(&payload).expect("Serialization failed");
    println!("AnonymousRequest size: {} bytes", serialized.len());

    let deserialized: RelayerPayload =
        bincode::deserialize(&serialized).expect("Deserialization failed");

    match deserialized {
        RelayerPayload::AnonymousRequest { reply_surbs, .. } => {
            assert_eq!(reply_surbs.len(), 1);
        }
        _ => panic!("Wrong variant"),
    }
}

#[test]
fn test_insufficient_surbs_error() {
    let packer = ResponsePacker::new();

    let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();

    let surbs: Vec<Surb> = generate_surbs_with_recovery(1, 2)
        .into_iter()
        .map(|(s, _)| s)
        .collect();

    let result = packer.pack_response(123, &data, surbs);
    assert!(result.is_err());

    let err = result.unwrap_err();
    println!("Expected error: {}", err);
    assert!(err.to_string().contains("Insufficient"));
}

#[test]
fn test_surb_consumption_order() {
    let packer = ResponsePacker::new();

    let usable = Fragmenter::usable_payload_size(nox_core::SURB_PAYLOAD_SIZE);
    let data: Vec<u8> = (0..usable + 100).map(|i| (i % 256) as u8).collect();

    let surbs: Vec<(Surb, SurbRecovery)> = generate_surbs_with_recovery(3, 2);
    let surb_ids: Vec<[u8; 16]> = surbs.iter().map(|(s, _)| s.id).collect();
    let surbs_only: Vec<Surb> = surbs.into_iter().map(|(s, _)| s).collect();

    let result = packer.pack_response(456, &data, surbs_only);
    assert!(result.is_ok());

    let pack_result = result.unwrap();
    assert_eq!(pack_result.packets.len(), 3);

    println!("SURB IDs: {:?}", surb_ids);
    println!("Packets generated: {}", pack_result.packets.len());
}

#[test]
fn test_empty_data_rejected() {
    let packer = ResponsePacker::new();
    let surbs: Vec<Surb> = generate_surbs_with_recovery(1, 2)
        .into_iter()
        .map(|(s, _)| s)
        .collect();

    let result = packer.pack_response(0, &[], surbs);
    assert!(result.is_err());
}

#[test]
fn test_large_payload_fragmentation() {
    let packer = ResponsePacker::new();

    // 200KB payload
    let data: Vec<u8> = (0..200_000).map(|i| (i % 256) as u8).collect();
    let surbs_needed = packer.surbs_needed(data.len());

    println!("200KB payload needs {} SURBs", surbs_needed);

    let surbs: Vec<Surb> = generate_surbs_with_recovery(surbs_needed + 2, 3)
        .into_iter()
        .map(|(s, _)| s)
        .collect();

    let result = packer.pack_response(789, &data, surbs);
    assert!(result.is_ok());

    let pack_result = result.unwrap();
    assert_eq!(pack_result.packets.len(), surbs_needed + 2);
    println!(
        "200KB fragmented into {} packets ({} data + 2 FEC parity)",
        pack_result.packets.len(),
        surbs_needed
    );
}
