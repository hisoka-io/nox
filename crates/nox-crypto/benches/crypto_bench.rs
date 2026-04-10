use criterion::{black_box, criterion_group, criterion_main, Criterion};
use nox_crypto::sphinx::{SphinxHeader, ROUTING_INFO_SIZE};
use rand::thread_rng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

fn bench_key_generation(c: &mut Criterion) {
    c.bench_function("x25519_keygen", |b| {
        b.iter(|| {
            let rng = thread_rng();
            X25519SecretKey::random_from_rng(black_box(rng))
        })
    });
}

fn bench_ecdh(c: &mut Criterion) {
    let mut rng = thread_rng();
    let sk = X25519SecretKey::random_from_rng(&mut rng);
    let pk = X25519PublicKey::from(&sk);

    c.bench_function("x25519_ecdh", |b| {
        b.iter(|| black_box(sk.diffie_hellman(&pk)))
    });
}

fn bench_sphinx_process(c: &mut Criterion) {
    let mut rng = thread_rng();
    let node_sk = X25519SecretKey::random_from_rng(&mut rng);

    let sender_sk = X25519SecretKey::random_from_rng(&mut rng);
    let sender_pk = X25519PublicKey::from(&sender_sk);

    // Create a mathematically valid header structure (MAC check will fail, but math runs)
    let header = SphinxHeader {
        ephemeral_key: sender_pk,
        routing_info: [0u8; ROUTING_INFO_SIZE],
        mac: [0u8; 32],
        nonce: 2,
    };

    c.bench_function("sphinx_process_layer", |b| {
        b.iter(|| {
            // This measures the cost of 1 hop processing (ECDH + Key Derivation + Stream Cipher)
            let _ = header.process(black_box(&node_sk), vec![]);
        })
    });
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_ecdh,
    bench_sphinx_process
);
criterion_main!(benches);
