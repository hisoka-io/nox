//! DarkPool Cryptographic Primitives Benchmarks
//!
//! Measures throughput of core cryptographic operations used across the protocol:
//! Poseidon2 hashing, AES-128-CBC, BabyJubJub operations, KDF, and DLEQ proofs.

use ark_ff::PrimeField;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use darkpool_crypto::{
    aes128_decrypt, aes128_encrypt, derive_public_key_from_sk, derive_shared_secret_bjj,
    generate_dleq_proof, kdf_to_aes_key_iv, poseidon_hash, random_field, IPoseidonHasher, Kdf,
    NoxHasher, PublicKey, SecretKey, BASE8,
};
use ethers_core::types::U256;

fn bench_poseidon_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("Poseidon2");

    for input_count in [1, 2, 3, 4, 8, 13] {
        let inputs: Vec<_> = (0..input_count).map(|i| U256::from(i + 1)).collect();

        group.bench_with_input(
            BenchmarkId::new("hash", format!("{input_count}_inputs")),
            &inputs,
            |b, inputs| b.iter(|| poseidon_hash(black_box(inputs))),
        );
    }

    group.finish();
}

fn bench_poseidon_native(c: &mut Criterion) {
    let mut group = c.benchmark_group("Poseidon2_Native");
    let hasher = NoxHasher::new();

    for input_count in [1, 2, 3, 4, 8, 13] {
        let inputs: Vec<_> = (0..input_count)
            .map(|i| ark_bn254::Fr::from((i + 1) as u64))
            .collect();

        group.bench_with_input(
            BenchmarkId::new("hash_fr", format!("{input_count}_inputs")),
            &inputs,
            |b, inputs| b.iter(|| hasher.hash(black_box(inputs))),
        );
    }

    group.finish();
}

fn bench_aes(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES128_CBC");

    let shared_secret = random_field();
    let (key, iv) = kdf_to_aes_key_iv(shared_secret);
    let plaintext = [0x42u8; 192];
    let ciphertext = aes128_encrypt(&plaintext, &key, &iv);

    group.bench_function("encrypt_192B", |b| {
        b.iter(|| aes128_encrypt(black_box(&plaintext), black_box(&key), black_box(&iv)))
    });

    group.bench_function("decrypt_208B", |b| {
        b.iter(|| aes128_decrypt(black_box(&ciphertext), black_box(&key), black_box(&iv)))
    });

    group.bench_function("kdf_to_aes_key_iv", |b| {
        b.iter(|| kdf_to_aes_key_iv(black_box(shared_secret)))
    });

    group.finish();
}

fn bench_bjj(c: &mut Criterion) {
    let mut group = c.benchmark_group("BabyJubJub");

    // Setup: generate two keypairs
    let mut rng = rand::thread_rng();
    let sk_a = SecretKey::generate(&mut rng);
    let pk_a = sk_a.public_key().expect("valid pk");
    let sk_b = SecretKey::generate(&mut rng);
    let pk_b = sk_b.public_key().expect("valid pk");

    // Scalar for mul_scalar
    let scalar_le = {
        use ark_ff::BigInteger;
        sk_a.0.into_bigint().to_bytes_le()
    };

    group.bench_function("keygen", |b| {
        b.iter(|| {
            let sk = SecretKey::generate(&mut rand::thread_rng());
            black_box(sk)
        })
    });

    group.bench_function("public_key", |b| b.iter(|| black_box(&sk_a).public_key()));

    group.bench_function("mul_scalar", |b| {
        b.iter(|| BASE8.mul_scalar(black_box(&scalar_le)))
    });

    group.bench_function("point_add", |b| {
        b.iter(|| black_box(&pk_a).add(black_box(&pk_b)))
    });

    group.bench_function("ecdh_derive_shared_secret", |b| {
        b.iter(|| black_box(&sk_a).derive_shared_secret(black_box(&pk_b)))
    });

    // Compressed point serialization
    group.bench_function("to_bytes_compressed", |b| {
        b.iter(|| black_box(&pk_a).to_bytes())
    });

    group.bench_function("from_hex_decompress", |b| {
        let hex = pk_a.to_hex();
        b.iter(|| PublicKey::from_hex(black_box(&hex)))
    });

    group.finish();
}

fn bench_ecdh(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH_U256");

    let sk_u256 = random_field();
    let (pk_x, pk_y) = derive_public_key_from_sk(sk_u256).expect("valid pk");
    let peer_sk = random_field();
    let peer_pk = derive_public_key_from_sk(peer_sk).expect("valid peer pk");

    group.bench_function("derive_public_key", |b| {
        b.iter(|| derive_public_key_from_sk(black_box(sk_u256)))
    });

    group.bench_function("derive_shared_secret_full", |b| {
        // 2 scalar muls: subgroup validation + ECDH
        b.iter(|| derive_shared_secret_bjj(black_box(sk_u256), black_box(peer_pk)))
    });

    // For comparison: raw bjj_scalar_mul
    group.bench_function("bjj_scalar_mul", |b| {
        b.iter(|| darkpool_crypto::bjj_scalar_mul(black_box(sk_u256), black_box((pk_x, pk_y))))
    });

    group.finish();
}

fn bench_kdf(c: &mut Criterion) {
    let mut group = c.benchmark_group("KDF");

    let master = random_field();

    group.bench_function("derive_no_nonce", |b| {
        b.iter(|| Kdf::derive(black_box("hisoka.spend"), black_box(master), None))
    });

    group.bench_function("derive_with_nonce", |b| {
        b.iter(|| {
            Kdf::derive(
                black_box("hisoka.spend"),
                black_box(master),
                Some(U256::from(42)),
            )
        })
    });

    group.bench_function("derive_indexed", |b| {
        b.iter(|| Kdf::derive_indexed(black_box("hisoka.enc"), black_box(master), black_box(7)))
    });

    group.finish();
}

fn bench_dleq(c: &mut Criterion) {
    let mut group = c.benchmark_group("DLEQ");

    // Longer measurement time for this expensive operation
    group.sample_size(20);

    let recipient_sk = random_field();
    let compliance_sk = random_field();
    let compliance_pk = derive_public_key_from_sk(compliance_sk).expect("valid compliance pk");

    group.bench_function("generate_proof", |b| {
        b.iter(|| generate_dleq_proof(black_box(recipient_sk), black_box(compliance_pk)))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_poseidon_hash,
    bench_poseidon_native,
    bench_aes,
    bench_bjj,
    bench_ecdh,
    bench_kdf,
    bench_dleq,
);
criterion_main!(benches);
