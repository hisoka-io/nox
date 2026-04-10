//! Sphinx Packet Benchmarks
//!
//! Measures Sphinx packet construction at varying hop counts, per-hop processing cost,
//! packet serialization, and replay tag computation. These are the core numbers
//! that compete with Katzenpost's published 144us (Go NIKE Sphinx).

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nox_crypto::sphinx::{
    build_multi_hop_packet, into_result, PathHop, ProcessResult, SphinxHeader,
};
use rand::{rngs::OsRng, RngCore};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

/// Generate a path of N hops with random keys. Returns (path, secret_keys).
fn generate_path(num_hops: usize) -> (Vec<PathHop>, Vec<X25519SecretKey>) {
    let secret_keys: Vec<X25519SecretKey> = (0..num_hops)
        .map(|_| X25519SecretKey::random_from_rng(OsRng))
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

// 1.1.7 + 1.1.8 + existing: Sphinx Construction at 1, 2, 3 hops

fn bench_packet_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("Sphinx_Construction");

    let payload = vec![0u8; 1024]; // 1KB payload

    for hop_count in [1, 2, 3] {
        let (path, _sks) = generate_path(hop_count);

        group.bench_with_input(
            BenchmarkId::new("build_packet", format!("{hop_count}_hop")),
            &(path, payload.clone()),
            |b, (path, payload)| {
                b.iter(|| build_multi_hop_packet(black_box(path), black_box(payload), black_box(0)))
            },
        );
    }

    group.finish();
}

// 1.1.9: Per-hop cost isolation -- show processing is O(1) per hop

fn bench_per_hop_cost(c: &mut Criterion) {
    let mut group = c.benchmark_group("Sphinx_PerHop");

    let (path, secret_keys) = generate_path(3);
    let payload = vec![0u8; 1024];

    let packet_bytes =
        build_multi_hop_packet(&path, &payload, 0).expect("build_multi_hop_packet failed");

    let mut current_bytes = packet_bytes;
    for hop_idx in 0..3 {
        let (header, body) = SphinxHeader::from_bytes(&current_bytes).expect("from_bytes failed");
        let sk = secret_keys[hop_idx].clone();

        let body_vec = body.to_vec();
        let header_clone = header.clone();

        group.bench_with_input(
            BenchmarkId::new("process", format!("hop_{hop_idx}")),
            &(header_clone, body_vec, sk.clone()),
            |b, (hdr, body_v, secret)| {
                b.iter(|| {
                    black_box(hdr)
                        .process(black_box(secret), black_box(body_v.clone()))
                        .expect("process failed")
                })
            },
        );

        let result = into_result(header.process(&sk, body.to_vec()).expect("process failed"));
        match result {
            ProcessResult::Forward {
                next_packet,
                processed_body,
                ..
            } => {
                current_bytes = next_packet.to_bytes(&processed_body);
            }
            ProcessResult::Exit { .. } => {
                break;
            }
        }
    }

    group.finish();
}

// 1.1.10: Packet serialization (to_bytes / from_bytes for ~32KB packets)

fn bench_packet_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("Sphinx_Serialization");

    let (path, _) = generate_path(3);
    let payload = vec![0u8; 1024];

    let packet_bytes =
        build_multi_hop_packet(&path, &payload, 0).expect("build_multi_hop_packet failed");

    let (header, body) = SphinxHeader::from_bytes(&packet_bytes).expect("from_bytes failed");
    let body_vec = body.to_vec();

    group.throughput(Throughput::Bytes(packet_bytes.len() as u64));

    group.bench_function("to_bytes", |b| {
        b.iter(|| black_box(&header).to_bytes(black_box(&body_vec)))
    });

    group.bench_function("from_bytes", |b| {
        b.iter(|| SphinxHeader::from_bytes(black_box(&packet_bytes)))
    });

    group.finish();
}

// Existing: Replay tag computation (blake3 hash over header)

fn bench_compute_replay_tag(c: &mut Criterion) {
    let mut group = c.benchmark_group("Sphinx_ReplayTag");

    let mut rng = OsRng;
    let mut routing_info = [0u8; 400];
    let mut mac = [0u8; 32];
    rng.fill_bytes(&mut routing_info);
    rng.fill_bytes(&mut mac);

    let ephemeral_sk = X25519SecretKey::random_from_rng(OsRng);
    let ephemeral_key = X25519PublicKey::from(&ephemeral_sk);

    let header = SphinxHeader {
        ephemeral_key,
        routing_info,
        mac,
        nonce: 123456789,
    };

    group.bench_function("blake3_replay_tag", |b| {
        b.iter(|| black_box(&header).compute_replay_tag())
    });
    group.finish();
}

// Existing: Single-hop process (raw ECDH + MAC + stream cipher + routing shift)

fn bench_packet_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("Sphinx_Processing");

    let my_sk = X25519SecretKey::random_from_rng(OsRng);
    let my_pk = X25519PublicKey::from(&my_sk);
    let payload = vec![0u8; 1024];

    let path = vec![PathHop {
        public_key: my_pk,
        address: "exit".to_string(),
    }];

    let packet_bytes = build_multi_hop_packet(&path, &payload, 0).expect("Build failed");
    let (header, body) = SphinxHeader::from_bytes(&packet_bytes).expect("Failed to parse");

    group.bench_function("process_hop", |b| {
        b.iter(|| {
            black_box::<&SphinxHeader>(&header).process(black_box(&my_sk), black_box(body.to_vec()))
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_packet_construction,
    bench_per_hop_cost,
    bench_packet_serialization,
    bench_compute_replay_tag,
    bench_packet_processing,
);
criterion_main!(benches);
