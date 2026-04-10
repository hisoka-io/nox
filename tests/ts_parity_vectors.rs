//! Test vector generator for TypeScript SDK parity verification.

use curve25519_dalek::constants::X25519_BASEPOINT;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use hmac::{Hmac, Mac};
use nox_crypto::derive_keys;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[test]
fn generate_ts_parity_vectors() {
    println!("\n");
    println!("// =============================================================================");
    println!("// TypeScript SDK Parity Test Vectors");
    println!("// Generated from Rust NOX implementation");
    println!("// =============================================================================");
    println!();

    println!("// KDF Test Vectors (derive_keys)");
    println!("// Algorithm: SHA256 with domain separation prefixes");
    let shared_secret = [0xab_u8; 32];
    let (rho, mu, pi, blind) = derive_keys(&shared_secret);

    println!("export const KDF_VECTORS = {{");
    println!("  input: \"{}\",", hex::encode(shared_secret));
    println!("  rho: \"{}\",", hex::encode(rho));
    println!("  mu: \"{}\",", hex::encode(mu));
    println!("  pi: \"{}\",", hex::encode(pi));
    println!("  blind: \"{}\",", hex::encode(blind.to_bytes()));
    println!("}};");
    println!();

    println!("// Nonce Endianness Vectors");
    println!("// Format: Big-endian (to_be_bytes)");
    let nonce: u64 = 0x0102030405060708;
    println!("export const NONCE_VECTORS = {{");
    println!("  value: 0x{:016x}n,", nonce);
    println!("  bytes_be: \"{}\",", hex::encode(nonce.to_be_bytes()));
    println!("}};");
    println!();

    // Point multiplication uses raw MontgomeryPoint * Scalar (no X25519 clamping)
    println!("// Point Multiplication Vectors (NO X25519 clamping)");
    println!("// Algorithm: Raw MontgomeryPoint * Scalar (curve25519_dalek)");

    // Generate a known point using the basepoint
    // Use a scalar that would be affected by clamping to prove unclamped behavior
    let scalar_bytes: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let scalar = Scalar::from_bytes_mod_order(scalar_bytes);
    let point = X25519_BASEPOINT * scalar;
    let point_bytes = point.to_bytes();

    // Multiply by another scalar (the blinding factor pattern)
    let multiplier_bytes: [u8; 32] = [0x42; 32];
    let multiplier = Scalar::from_bytes_mod_order(multiplier_bytes);
    let result = MontgomeryPoint(point_bytes) * multiplier;

    println!("export const POINT_MULT_VECTORS = {{");
    println!("  // Point generated from basepoint * scalar");
    println!("  point: \"{}\",", hex::encode(point_bytes));
    println!("  scalar: \"{}\",", hex::encode(multiplier_bytes));
    println!("  // Result of MontgomeryPoint * Scalar (unclamped)");
    println!("  result: \"{}\",", hex::encode(result.to_bytes()));
    println!("}};");
    println!();

    println!("// Clamping-sensitive scalar test");
    let clamping_scalar_bytes: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f, // Bit 255 is actually at byte[31] bit 7
    ];
    let clamping_scalar = Scalar::from_bytes_mod_order(clamping_scalar_bytes);
    let basepoint = X25519_BASEPOINT;
    let clamping_result = basepoint * clamping_scalar;

    println!("export const CLAMPING_TEST_VECTORS = {{");
    println!("  // Basepoint (9 in little-endian u-coordinate)");
    println!("  point: \"{}\",", hex::encode(basepoint.to_bytes()));
    println!("  scalar: \"{}\",", hex::encode(clamping_scalar_bytes));
    println!("  // If TypeScript produces this result, clamping is NOT applied (correct)");
    println!(
        "  result_unclamped: \"{}\",",
        hex::encode(clamping_result.to_bytes())
    );
    println!("}};");
    println!();

    println!("// MAC Vectors (HMAC-SHA256)");
    let mac_key = [0x11_u8; 32];
    let mac_data = [0x22_u8; 100];
    let mut mac = HmacSha256::new_from_slice(&mac_key).expect("HMAC key length is valid");
    mac.update(&mac_data);
    let mac_result = mac.finalize().into_bytes();

    println!("export const MAC_VECTORS = {{");
    println!("  key: \"{}\",", hex::encode(mac_key));
    println!("  data: \"{}\",", hex::encode(mac_data));
    println!("  mac: \"{}\",", hex::encode(mac_result));
    println!("}};");
    println!();

    println!("// Scalar Operations Vectors");
    let scalar_a_bytes: [u8; 32] = [
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    let scalar_b_bytes: [u8; 32] = [
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    let scalar_a = Scalar::from_bytes_mod_order(scalar_a_bytes);
    let scalar_b = Scalar::from_bytes_mod_order(scalar_b_bytes);
    let scalar_sum = scalar_a + scalar_b;
    let scalar_product = scalar_a * scalar_b;

    println!("export const SCALAR_OPS_VECTORS = {{");
    println!("  a: \"{}\",", hex::encode(scalar_a_bytes));
    println!("  b: \"{}\",", hex::encode(scalar_b_bytes));
    println!("  // a + b mod L (curve order)");
    println!("  sum: \"{}\",", hex::encode(scalar_sum.to_bytes()));
    println!("  // a * b mod L (curve order)");
    println!("  product: \"{}\",", hex::encode(scalar_product.to_bytes()));
    println!("}};");
    println!();

    println!("// =============================================================================");
    println!("// End of Test Vectors");
    println!("// =============================================================================");
    println!();
}

#[test]
fn verify_vector_consistency() {
    let shared_secret = [0xab_u8; 32];
    let (rho, mu, pi, blind) = derive_keys(&shared_secret);
    assert_eq!(rho.len(), 32);
    assert_eq!(mu.len(), 32);
    assert_eq!(pi.len(), 32);
    assert_eq!(blind.to_bytes().len(), 32);

    let nonce: u64 = 0x0102030405060708;
    let be_bytes = nonce.to_be_bytes();
    assert_eq!(be_bytes[0], 0x01);
    assert_eq!(be_bytes[7], 0x08);

    let scalar_bytes: [u8; 32] = [0x42; 32];
    let scalar = Scalar::from_bytes_mod_order(scalar_bytes);
    let point1 = X25519_BASEPOINT * scalar;
    let point2 = X25519_BASEPOINT * scalar;
    assert_eq!(point1.to_bytes(), point2.to_bytes());

    println!("All vector consistency checks passed!");
}

use sha2::Digest;
use tiny_keccak::Hasher;

/// `sha256(lowercase_address)[0] % 3 + 1` -- must match TypeScript & Solidity.
fn compute_layer(address: &str) -> u8 {
    let address_lower = address.to_lowercase();
    let hash = sha2::Sha256::digest(address_lower.as_bytes());
    (hash[0] % 3) + 1
}

/// Must match Solidity `abi.encodePacked(bytes32, address, uint8)`.
fn compute_fingerprint_update(prev: &[u8; 32], address: &str, action_type: u8) -> [u8; 32] {
    let address_clean = address.trim_start_matches("0x").to_lowercase();
    let address_bytes = hex::decode(&address_clean).expect("Invalid hex address");

    assert_eq!(address_bytes.len(), 20, "Address must be 20 bytes");

    let mut input = Vec::with_capacity(53);
    input.extend_from_slice(prev);
    input.extend_from_slice(&address_bytes);
    input.push(action_type);

    let mut hasher = tiny_keccak::Keccak::v256();
    hasher.update(&input);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

#[test]
fn generate_layer_assignment_vectors() {
    println!("\n=== Layer Assignment Test Vectors ===\n");

    let test_addresses = [
        "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD45",
        "0x0000000000000000000000000000000000000001",
        "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    ];

    println!("export const LAYER_VECTORS = [");
    for address in &test_addresses {
        let layer = compute_layer(address);
        println!(
            "  {{ address: \"{}\", expectedLayer: {} }},",
            address, layer
        );
    }
    println!("];");
}

#[test]
fn generate_fingerprint_vectors() {
    println!("\n=== Fingerprint Test Vectors ===\n");

    let prev = [0xab_u8; 32];
    let address = "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD45";
    let register = compute_fingerprint_update(&prev, address, 0);
    let unregister = compute_fingerprint_update(&prev, address, 1);

    println!("// Fingerprint Update Vectors");
    println!("export const FINGERPRINT_VECTORS = {{");
    println!("  prevFingerprint: \"{}\",", hex::encode(prev));
    println!("  address: \"{}\",", address);
    println!("  registerResult: \"{}\",", hex::encode(register));
    println!("  unregisterResult: \"{}\",", hex::encode(unregister));
    println!("}};");
}

use ethers::types::{Address, Bytes, H256, U256};
use std::str::FromStr;

fn compute_execution_hash(target: &Address, calldata: &Bytes, fee: &U256) -> H256 {
    use tiny_keccak::Hasher;

    let mut data = Vec::new();
    data.extend_from_slice(target.as_bytes());
    data.extend_from_slice(calldata.as_ref());
    let mut fee_bytes = [0u8; 32];
    fee.to_big_endian(&mut fee_bytes);
    data.extend_from_slice(&fee_bytes);

    let mut hasher = tiny_keccak::Keccak::v256();
    hasher.update(&data);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);

    let modulus = U256::from_dec_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    )
    .unwrap();

    let hash_u256 = U256::from_big_endian(&hash);
    let reduced = hash_u256 % modulus;

    let mut result_bytes = [0u8; 32];
    reduced.to_big_endian(&mut result_bytes);
    H256::from_slice(&result_bytes)
}

#[test]
fn generate_execution_hash_vectors() {
    println!("\n=== Execution Hash Test Vectors ===\n");

    let target1 = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
    let calldata1 = Bytes::from(hex::decode("abcd1234").unwrap());
    let fee1 = U256::from(1000000000000000000u64); // 1 ETH in wei
    let hash1 = compute_execution_hash(&target1, &calldata1, &fee1);

    let target2 = Address::from_str("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap();
    let calldata2 = Bytes::new();
    let fee2 = U256::from(100000000u64); // 100 USDC (6 decimals)
    let hash2 = compute_execution_hash(&target2, &calldata2, &fee2);

    let target3 = Address::from_str("0x0000000000000000000000000000000000000001").unwrap();
    let calldata3 = Bytes::from(vec![0x42u8; 256]);
    let fee3 = U256::from(50000000000000000u64); // 0.05 ETH
    let hash3 = compute_execution_hash(&target3, &calldata3, &fee3);

    let target4 = Address::from_str("0xffffffffffffffffffffffffffffffffffffffff").unwrap();
    let calldata4 = Bytes::from(hex::decode("12345678").unwrap());
    let fee4 = U256::zero();
    let hash4 = compute_execution_hash(&target4, &calldata4, &fee4);

    println!("export const EXECUTION_HASH_VECTORS = [");
    println!("  {{");
    println!("    target: \"{:?}\",", target1);
    println!("    calldata: \"{}\",", hex::encode(calldata1.as_ref()));
    println!("    fee: \"{}n\",", fee1);
    println!("    expectedHash: \"{}\",", hex::encode(hash1.as_bytes()));
    println!("  }},");
    println!("  {{");
    println!("    target: \"{:?}\",", target2);
    println!("    calldata: \"\",");
    println!("    fee: \"{}n\",", fee2);
    println!("    expectedHash: \"{}\",", hex::encode(hash2.as_bytes()));
    println!("  }},");
    println!("  {{");
    println!("    target: \"{:?}\",", target3);
    println!("    calldata: \"{}\",", hex::encode(calldata3.as_ref()));
    println!("    fee: \"{}n\",", fee3);
    println!("    expectedHash: \"{}\",", hex::encode(hash3.as_bytes()));
    println!("  }},");
    println!("  {{");
    println!("    target: \"{:?}\",", target4);
    println!("    calldata: \"{}\",", hex::encode(calldata4.as_ref()));
    println!("    fee: \"0n\",");
    println!("    expectedHash: \"{}\",", hex::encode(hash4.as_bytes()));
    println!("  }},");
    println!("];");
    println!();

    println!("export const BN254_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;");
}

#[test]
fn verify_layer_distribution() {
    let mut counts = [0_u32; 3];
    let total = 1000;

    for i in 0..total {
        let hex = format!("{:040x}", (i as u64 * 0x12345678 + 0xabcdef) % (1u64 << 40));
        let address = format!("0x{}", hex);
        let layer = compute_layer(&address) as usize;
        counts[layer - 1] += 1;
    }

    println!("\nLayer Distribution over {} addresses:", total);
    println!(
        "  Layer 1 (Entry): {} ({:.1}%)",
        counts[0],
        counts[0] as f64 / total as f64 * 100.0
    );
    println!(
        "  Layer 2 (Mix):   {} ({:.1}%)",
        counts[1],
        counts[1] as f64 / total as f64 * 100.0
    );
    println!(
        "  Layer 3 (Exit):  {} ({:.1}%)",
        counts[2],
        counts[2] as f64 / total as f64 * 100.0
    );

    // Verify roughly even distribution
    let expected = total / 3;
    let tolerance = expected / 5; // 20% tolerance

    assert!(
        counts[0] > expected - tolerance && counts[0] < expected + tolerance,
        "Layer 1 count {} should be roughly {}",
        counts[0],
        expected
    );
    assert!(
        counts[1] > expected - tolerance && counts[1] < expected + tolerance,
        "Layer 2 count {} should be roughly {}",
        counts[1],
        expected
    );
    assert!(
        counts[2] > expected - tolerance && counts[2] < expected + tolerance,
        "Layer 3 count {} should be roughly {}",
        counts[2],
        expected
    );

    println!("\nDistribution verified: all layers within 20% of expected!");
}
