//! Values the node and the TypeScript SDK (`@hisoka-io/nox-client`) must agree on, as fixed
//! vectors. The layer and bincode vectors are the ones the SDK pins in `tests/topology.test.ts`
//! and `tests/bincode.test.ts`; the fingerprints are what its `computeTopologyFingerprint`
//! returns. `nox-core` `payloads.rs` pins the other bincode vectors the two sides share.

use curve25519_dalek::constants::X25519_BASEPOINT;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use ethers::types::{Address, Bytes, H256, U256};
use hmac::{Hmac, Mac};
use nox_core::models::payloads::encode_payload;
use nox_core::models::topology::primary_layer_for_role;
use nox_core::{
    compute_topology_fingerprint, PaidTransactionOutcomeV2, PaidTransactionRejectionCodeV2,
    ServiceRequest,
};
use nox_crypto::derive_keys;
use sha2::Sha256;
use std::str::FromStr;
use tiny_keccak::Hasher;

const ADDRESSES: [&str; 4] = [
    "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD45",
    "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
];

#[test]
fn primary_layers_match_the_sdk() {
    // (address, layers for roles 1, 2 and 3). The first three rows are the SDK's "pinned
    // primary-layer vectors" (role 1, 2 and 3 in turn).
    let vectors = [
        ("0x0000000000000000000000000000000000000001", [1, 2, 2]),
        ("0x0000000000000000000000000000000000000002", [1, 2, 2]),
        ("0x0000000000000000000000000000000000000004", [0, 2, 1]),
        (ADDRESSES[0], [0, 2, 1]),
        (ADDRESSES[1], [0, 2, 0]),
        (ADDRESSES[2], [0, 2, 0]),
        (ADDRESSES[3], [0, 2, 2]),
    ];
    for (address, layers) in vectors {
        for (role, layer) in (1..=3).zip(layers) {
            assert_eq!(
                primary_layer_for_role(address, role),
                layer,
                "{address} role {role}"
            );
        }
    }
}

#[test]
fn full_nodes_spread_over_the_three_layers() {
    let mut counts = [0_u32; 3];
    let total = 1000_u64;
    for i in 0..total {
        let address = format!("0x{:040x}", (i * 0x1234_5678 + 0xab_cdef) % (1 << 40));
        counts[usize::from(primary_layer_for_role(&address, 3))] += 1;
    }
    for (layer, count) in counts.into_iter().enumerate() {
        assert!(
            (267..400).contains(&count),
            "layer {layer} holds {count} of {total} full nodes"
        );
    }
}

#[test]
fn topology_fingerprint_matches_the_sdk() {
    let fingerprint = |addresses: &[&str]| {
        let addresses: Vec<String> = addresses.iter().map(ToString::to_string).collect();
        hex::encode(compute_topology_fingerprint(&addresses))
    };
    assert_eq!(
        fingerprint(&ADDRESSES[..1]),
        "eb15edf4342b42c31d1ed7a670102b9d1b5a75c1c0954be2646ba16c1a365ef6"
    );
    assert_eq!(
        fingerprint(&ADDRESSES),
        "65ab5e61791e34e826373e5af2b29c498cca6a2a2168ca34f3a33ea50a065994"
    );
}

#[test]
fn paid_transaction_outcomes_match_the_sdk() {
    let submitted = PaidTransactionOutcomeV2::Submitted {
        execution_id: [7; 32],
        transaction_hash: [8; 32],
    };
    assert_eq!(
        hex::encode(encode_payload(&submitted).unwrap()),
        format!("0100000000{}{}", "07".repeat(32), "08".repeat(32))
    );

    let rejected = PaidTransactionOutcomeV2::Rejected {
        execution_id: Some([7; 32]),
        code: PaidTransactionRejectionCodeV2::WrongChain,
        retryable: false,
        detail: "request chain does not match exit chain".to_string(),
    };
    assert_eq!(hex::encode(encode_payload(&rejected).unwrap()), "0101000000010707070707070707070707070707070707070707070707070707070707070707010000000027000000000000007265717565737420636861696e20646f6573206e6f74206d61746368206578697420636861696e");
}

#[test]
fn submit_transaction_request_keeps_the_legacy_bytes() {
    let request = ServiceRequest::SubmitTransaction {
        to: [0xab; 20],
        data: vec![1, 2, 3],
    };
    let mut expected = vec![1, 3, 0, 0, 0];
    expected.extend([0xab; 20]);
    expected.extend([3, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3]);
    assert_eq!(encode_payload(&request).unwrap(), expected);
}

#[test]
fn sphinx_key_derivation_vectors() {
    let (rho, mu, pi, blind) = derive_keys(&[0xab; 32]);
    assert_eq!(
        hex::encode(rho),
        "df3c16178b7664eec6cb56e0424be462617c4965f87ac22a91f8e349baa4827a"
    );
    assert_eq!(
        hex::encode(mu),
        "e56ae22b8dc75b14cdfc0adda2f649c00f6edd3b9522eda0dffc8ee2ab98bc1c"
    );
    assert_eq!(
        hex::encode(pi),
        "fd27b3aaf5e7d7246e5ceb7ec99787d379caa2d25212364f9feb2dbb72434688"
    );
    assert_eq!(
        hex::encode(blind.to_bytes()),
        "e53989ede3a1442955689f951dab199d341f95413c46b7ee7c7b3c117a797906"
    );
}

/// The group, scalar and MAC operations Sphinx is built from, on fixed inputs. Point
/// multiplication is the raw Montgomery ladder: X25519 clamping would change both results.
#[test]
fn sphinx_primitive_vectors() {
    assert_eq!(
        hex::encode(0x0102_0304_0506_0708_u64.to_be_bytes()),
        "0102030405060708"
    );

    let mut scalar_bytes = [0_u8; 32];
    for (byte, value) in scalar_bytes.iter_mut().zip(1..) {
        *byte = value;
    }
    let point = X25519_BASEPOINT * Scalar::from_bytes_mod_order(scalar_bytes);
    assert_eq!(
        hex::encode(point.to_bytes()),
        "bcd6886bb4119943e0d74eb75fa44d28b11e65d78aa98f94149bb261174f3834"
    );
    let blinded = MontgomeryPoint(point.to_bytes()) * Scalar::from_bytes_mod_order([0x42; 32]);
    assert_eq!(
        hex::encode(blinded.to_bytes()),
        "7edc9c252a71ca345010d6193a65e9d9ef9ae870c937967295277ddcafbd5c4d"
    );

    let mut high_scalar = [0xff_u8; 32];
    high_scalar[31] = 0x7f;
    let unclamped = X25519_BASEPOINT * Scalar::from_bytes_mod_order(high_scalar);
    assert_eq!(
        hex::encode(unclamped.to_bytes()),
        "210142ed5157ad3d1b58074fa3e9f077710a6a9dc320b7edc0298fd255079f06"
    );

    let mut mac = Hmac::<Sha256>::new_from_slice(&[0x11; 32]).unwrap();
    mac.update(&[0x22; 100]);
    assert_eq!(
        hex::encode(mac.finalize().into_bytes()),
        "3286fc7e8142ab9618fc1fc94721b6c881464776ceb7958f790881a6f0d391e8"
    );

    let mut a = [0_u8; 32];
    a[0] = 0x10;
    let mut b = [0_u8; 32];
    b[0] = 0x20;
    let (a, b) = (
        Scalar::from_bytes_mod_order(a),
        Scalar::from_bytes_mod_order(b),
    );
    assert_eq!(
        hex::encode((a + b).to_bytes()),
        "3000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        hex::encode((a * b).to_bytes()),
        "0002000000000000000000000000000000000000000000000000000000000000"
    );
}

fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = tiny_keccak::Keccak::v256();
    hasher.update(input);
    let mut output = [0_u8; 32];
    hasher.finalize(&mut output);
    output
}

/// Solidity `keccak256(abi.encodePacked(bytes32, address, uint8))`.
fn fingerprint_update(previous: &[u8; 32], address: &str, action: u8) -> [u8; 32] {
    let mut input = previous.to_vec();
    input.extend(hex::decode(address.trim_start_matches("0x")).unwrap());
    input.push(action);
    keccak256(&input)
}

/// `keccak256(target || calldata || fee)` reduced into the BN254 scalar field.
fn execution_hash(target: &str, calldata: &[u8], fee: u64) -> H256 {
    let mut input = Address::from_str(target).unwrap().as_bytes().to_vec();
    input.extend(Bytes::from(calldata.to_vec()).as_ref());
    let mut fee_bytes = [0_u8; 32];
    U256::from(fee).to_big_endian(&mut fee_bytes);
    input.extend(fee_bytes);

    let modulus = U256::from_dec_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    )
    .unwrap();
    let mut reduced = [0_u8; 32];
    (U256::from_big_endian(&keccak256(&input)) % modulus).to_big_endian(&mut reduced);
    H256::from(reduced)
}

/// The two hashes of the first SDK generation, as this file defines them. Neither has a caller
/// in the node or in the current SDK.
#[test]
fn first_generation_hash_vectors() {
    let previous = [0xab; 32];
    assert_eq!(
        hex::encode(fingerprint_update(&previous, ADDRESSES[0], 0)),
        "7dc17da4618b8a7cf051f8641e760dd2d50aeed0579ae6c24448bf119ebeb868"
    );
    assert_eq!(
        hex::encode(fingerprint_update(&previous, ADDRESSES[0], 1)),
        "681a5ab6cd1f55523b592221d1e1443b0484ed0a57400d8be104532f53d5270d"
    );

    let vectors: [(&str, &[u8], u64, &str); 4] = [
        (
            "0x1234567890123456789012345678901234567890",
            &[0xab, 0xcd, 0x12, 0x34],
            1_000_000_000_000_000_000,
            "23cc3a49809d3078c55a13a2c1893bd937204c036089d7822da9b29b94400a2e",
        ),
        (
            "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            &[],
            100_000_000,
            "2083ddf010852309c90373720590431e75e12e9e06ab8d4e0cdd9baa456e8e6f",
        ),
        (
            "0x0000000000000000000000000000000000000001",
            &[0x42; 256],
            50_000_000_000_000_000,
            "0fa8124131785b2b589716f908d26f15977ca4bba63f4ebb7391a97689d7d4a7",
        ),
        (
            "0xffffffffffffffffffffffffffffffffffffffff",
            &[0x12, 0x34, 0x56, 0x78],
            0,
            "06706d274d41a5f14e55eef385a982bc930ce7c95ac00c3bcf4756eef0b91268",
        ),
    ];
    for (target, calldata, fee, expected) in vectors {
        assert_eq!(hex::encode(execution_hash(target, calldata, fee)), expected);
    }
}
