//! Exit Node Benchmarks
//!
//! Measures throughput of critical Exit Node operations.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nox_core::Fragmenter;
use nox_crypto::{PathHop, Surb};
use nox_node::services::response_packer::ResponsePacker;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

/// Generate test SURBs for benchmarking
fn generate_surbs(count: usize) -> Vec<Surb> {
    let mut rng = rand::thread_rng();
    let sk = X25519SecretKey::random_from_rng(&mut rng);
    let path = vec![PathHop {
        public_key: X25519PublicKey::from(&sk),
        address: "/ip4/127.0.0.1/tcp/9000".to_string(),
    }];

    (0..count)
        .map(|_| {
            let id: [u8; 16] = rand::random();
            let (surb, _) = Surb::new(&path, id, 0).expect("SURB creation");
            surb
        })
        .collect()
}

/// Benchmark ResponsePacker with varying data sizes.
/// SURBs are pre-generated outside the hot loop to isolate packing throughput
/// from SURB construction cost (which is benchmarked separately below).
fn bench_response_packer(c: &mut Criterion) {
    let packer = ResponsePacker::new();

    let mut group = c.benchmark_group("ResponsePacker");

    for size_kb in [10, 100, 500, 1000].iter() {
        let size_bytes = size_kb * 1024;
        let data: Vec<_> = (0..size_bytes).map(|i| (i % 256) as u8).collect();
        let surbs_needed = packer.surbs_needed(size_bytes) + 2;

        // Pre-generate a pool of SURB sets so the hot loop only measures packing.
        // Criterion runs many iterations, so we create enough sets to cycle through.
        let surb_pool_size = 64;
        let surb_pool: Vec<_> = (0..surb_pool_size)
            .map(|_| generate_surbs(surbs_needed))
            .collect();

        group.throughput(Throughput::Bytes(size_bytes as u64));
        group.bench_with_input(
            BenchmarkId::new("pack_response", format!("{}KB", size_kb)),
            &(data, surb_pool),
            |b, (data, surb_pool)| {
                let mut idx = 0usize;
                b.iter(|| {
                    let surbs = surb_pool[idx % surb_pool.len()].clone();
                    idx += 1;
                    let result = packer.pack_response(12345, black_box(data), surbs);
                    black_box(result)
                })
            },
        );
    }

    group.finish();
}

/// Benchmark fragmentation only (without SURB encapsulation)
fn bench_fragmentation(c: &mut Criterion) {
    let fragmenter = Fragmenter::new();

    let mut group = c.benchmark_group("Fragmenter");

    for size_kb in [10, 100, 500, 1000].iter() {
        let size_bytes = size_kb * 1024;
        let data: Vec<_> = (0..size_bytes).map(|i| (i % 256) as u8).collect();

        group.throughput(Throughput::Bytes(size_bytes as u64));
        group.bench_with_input(
            BenchmarkId::new("fragment", format!("{}KB", size_kb)),
            &data,
            |b, data| {
                b.iter(|| {
                    let result = fragmenter.fragment(999, black_box(data), 30_000);
                    black_box(result)
                })
            },
        );
    }

    group.finish();
}

/// Benchmark SURB creation
fn bench_surb_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("SURB");

    // Max hops = ROUTING_INFO_SIZE / SHIFT_SIZE = 400 / 128 = 3
    for hop_count in [1, 2, 3].iter() {
        group.bench_with_input(
            BenchmarkId::new("create", format!("{}_hops", hop_count)),
            hop_count,
            |b, &hop_count| {
                let mut rng = rand::thread_rng();
                let path: Vec<_> = (0..hop_count)
                    .map(|i| {
                        let sk = X25519SecretKey::random_from_rng(&mut rng);
                        PathHop {
                            public_key: X25519PublicKey::from(&sk),
                            address: format!("/ip4/127.0.0.1/tcp/{}", 9000 + i),
                        }
                    })
                    .collect();

                b.iter(|| {
                    let id: [u8; 16] = rand::random();
                    let result = Surb::new(black_box(&path), id, 0);
                    black_box(result)
                })
            },
        );
    }

    group.finish();
}

/// Benchmark SURB encapsulation
fn bench_surb_encapsulation(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let sk = X25519SecretKey::random_from_rng(&mut rng);
    let path = vec![PathHop {
        public_key: X25519PublicKey::from(&sk),
        address: "/ip4/127.0.0.1/tcp/9000".to_string(),
    }];

    let mut group = c.benchmark_group("SURB_Encapsulate");

    for size in [100, 1000, 10_000, 30_000].iter() {
        let data: Vec<_> = (0..*size).map(|i| (i % 256) as u8).collect();

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("encapsulate", format!("{}_bytes", size)),
            &data,
            |b, data| {
                b.iter(|| {
                    let id: [u8; 16] = rand::random();
                    let (surb, _) = Surb::new(&path, id, 0).expect("SURB creation");
                    let result = surb.encapsulate(black_box(data));
                    black_box(result)
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_response_packer,
    bench_fragmentation,
    bench_surb_creation,
    bench_surb_encapsulation,
);

criterion_main!(benches);
