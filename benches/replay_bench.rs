use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use nox_core::IReplayProtection;
use nox_node::infra::persistence::rotational_bloom::RotationalBloomFilter;
use nox_node::SledRepository;
use rand::Rng;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

fn bench_replay_protection(c: &mut Criterion) {
    let mut group = c.benchmark_group("replay_protection");
    group.throughput(Throughput::Elements(1));

    // Runtime
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Setup Sled
    let dir = tempdir().unwrap();
    let sled_repo = Arc::new(SledRepository::new(dir.path()).unwrap());

    // Setup Bloom
    let bloom_filter = Arc::new(RotationalBloomFilter::new(
        1_000_000,
        0.001,
        Duration::from_secs(3600),
    ));

    // Generate random tags
    let mut rng = rand::thread_rng();
    let tags: Vec<_> = (0..10_000)
        .map(|_| {
            let mut d = [0u8; 32];
            rng.fill(&mut d);
            d.to_vec()
        })
        .collect();

    // Use AtomicUsize for thread-safe interior mutability
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let tags_arc = Arc::new(tags);

    {
        let counter = counter.clone();
        let tags = tags_arc.clone();
        group.bench_function("sled_insert", |b| {
            b.to_async(&rt).iter(|| async {
                let idx = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let tag = &tags[idx % tags.len()];
                let _ = sled_repo.check_and_tag(tag, 3600).await;
            })
        });
    }

    {
        let counter = counter.clone();
        let tags = tags_arc.clone();
        group.bench_function("bloom_insert", |b| {
            b.to_async(&rt).iter(|| async {
                let idx = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let tag = &tags[idx % tags.len()];
                let _ = bloom_filter.check_and_tag(tag, 3600).await;
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_replay_protection);
criterion_main!(benches);
