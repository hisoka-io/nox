use nox_crypto::sphinx::{SphinxHeader, HEADER_SIZE};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

#[test]
#[allow(clippy::assertions_on_constants)]
fn test_sphinx_header_x25519_properties() {
    assert!(
        HEADER_SIZE <= 1024,
        "Sphinx Header size must fit within the 1024 byte packet reservation"
    );
    assert_eq!(HEADER_SIZE, 472, "Sphinx Header expected to be 472 bytes");

    let rng = OsRng;
    let sk = StaticSecret::random_from_rng(rng);
    let pk = PublicKey::from(&sk);

    assert_eq!(
        pk.as_bytes().len(),
        32,
        "X25519 Public Key must be 32 bytes"
    );

    let header = SphinxHeader {
        ephemeral_key: pk,
        routing_info: [0u8; 400],
        mac: [0u8; 32],
        nonce: 12345,
    };

    let bytes = header.to_bytes(&[]);
    assert_eq!(
        &bytes[0..32],
        pk.as_bytes(),
        "First 32 bytes of SphinxHeader must be the X25519 ephemeral key"
    );
}

/// Documents that X25519 clamping differs from raw Scalar multiplication.
/// Sphinx uses raw Scalar to avoid clamping interference during blinding.
#[test]
fn test_x25519_clamping_behavior() {
    use curve25519_dalek::constants::X25519_BASEPOINT;
    use curve25519_dalek::scalar::Scalar;

    // Scalar with bits that clamping will alter (low 3 bits, bit 255)
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes[0] = 0xFF;
    scalar_bytes[31] = 0xFF;

    let sk = StaticSecret::from(scalar_bytes);
    let pk = PublicKey::from(&sk);

    let s = Scalar::from_bytes_mod_order(scalar_bytes);
    let derived_point = X25519_BASEPOINT * s;
    let derived_pk_bytes = derived_point.to_bytes();
    assert_ne!(
        derived_pk_bytes,
        *pk.as_bytes(),
        "Raw scalar mult vs Clamped X25519 should differ for this test scalar"
    );
}
