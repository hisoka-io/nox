//! Relayer Pipeline Stage Benchmarks
//!
//! Measures per-stage overhead of the 4-stage relayer pipeline:
//!   Ingest (parse + replay check) → Worker (Sphinx process) →
//!   Mix (DelayQueue insert/expire) → Egress (event bus publish)
//!
//! These benchmarks isolate pipeline orchestration costs that are
//! NOT captured by the Sphinx crypto micro-benchmarks.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nox_core::events::NoxEvent;
use nox_core::traits::{IEventPublisher, IEventSubscriber, IMixStrategy, IReplayProtection};
use nox_crypto::sphinx::{build_multi_hop_packet, PathHop, SphinxHeader};
use nox_node::infra::event_bus::TokioEventBus;
use nox_node::infra::persistence::rotational_bloom::RotationalBloomFilter;
use nox_node::services::mixing::NoMixStrategy;
use nox_node::services::relayer::worker::{MixMessage, MixMessageKind};
use std::sync::Arc;
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

fn create_test_keys(count: usize) -> (Vec<X25519SecretKey>, Vec<X25519PublicKey>) {
    let mut rng = rand::thread_rng();
    let sks: Vec<X25519SecretKey> = (0..count)
        .map(|_| X25519SecretKey::random_from_rng(&mut rng))
        .collect();
    let pks: Vec<X25519PublicKey> = sks.iter().map(X25519PublicKey::from).collect();
    (sks, pks)
}

/// Pre-build a pool of valid Sphinx packets for the given path.
fn build_packet_pool(path: &[PathHop], payload: &[u8], pool_size: usize) -> Vec<Vec<u8>> {
    (0..pool_size)
        .map(|_| build_multi_hop_packet(path, payload, 0).expect("packet build"))
        .collect()
}

// Stage 1: Ingest - SphinxHeader::from_bytes + replay tag computation

fn bench_ingest_parse(c: &mut Criterion) {
    let (_sks, pks) = create_test_keys(3);
    let path: Vec<PathHop> = pks
        .iter()
        .enumerate()
        .map(|(i, pk)| PathHop {
            public_key: *pk,
            address: format!("node_{i}"),
        })
        .collect();

    let payload = vec![0xABu8; 256];
    let packets = build_packet_pool(&path, &payload, 128);

    let mut group = c.benchmark_group("Pipeline_Ingest");
    group.throughput(Throughput::Elements(1));

    // Benchmark header parsing from raw bytes
    group.bench_function("header_parse", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let pkt = &packets[idx % packets.len()];
            idx += 1;
            let result = SphinxHeader::from_bytes(black_box(pkt));
            black_box(result)
        })
    });

    // Benchmark replay tag computation (Blake3 hash)
    {
        let (header, _body) = SphinxHeader::from_bytes(&packets[0]).expect("parse");
        group.bench_function("replay_tag_compute", |b| {
            b.iter(|| {
                let tag = black_box(&header).compute_replay_tag();
                black_box(tag)
            })
        });
    }

    // Benchmark replay check via RotationalBloomFilter (async)
    {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let bloom = Arc::new(RotationalBloomFilter::new(
            1_000_000,
            0.001,
            Duration::from_secs(3600),
        ));

        // Pre-compute replay tags from unique packets
        let tags: Vec<[u8; 32]> = packets
            .iter()
            .map(|pkt| {
                let (h, _) = SphinxHeader::from_bytes(pkt).unwrap();
                h.compute_replay_tag()
            })
            .collect();

        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let tags_arc = Arc::new(tags);

        let counter_c = counter.clone();
        let tags_c = tags_arc.clone();
        let bloom_c = bloom.clone();
        group.bench_function("replay_bloom_check", |b| {
            b.to_async(&rt).iter(|| {
                let idx = counter_c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let tag = tags_c[idx % tags_c.len()];
                let bl = bloom_c.clone();
                async move {
                    let result = bl.check_and_tag(&tag, 3600).await;
                    black_box(result)
                }
            })
        });
    }

    // Combined: parse + tag + bloom check (full ingest hot path)
    {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let bloom = Arc::new(RotationalBloomFilter::new(
            1_000_000,
            0.001,
            Duration::from_secs(3600),
        ));

        // Use fresh packets so bloom doesn't see duplicates
        let fresh_packets = build_packet_pool(&path, &payload, 512);
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let counter_c = counter.clone();
        let bloom_c = bloom.clone();
        let pkts = Arc::new(fresh_packets);
        group.bench_function("full_ingest_path", |b| {
            b.to_async(&rt).iter(|| {
                let idx = counter_c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let pkt = pkts[idx % pkts.len()].clone();
                let bl = bloom_c.clone();
                async move {
                    let (header, _body) = SphinxHeader::from_bytes(&pkt).unwrap();
                    let tag = header.compute_replay_tag();
                    let result = bl.check_and_tag(&tag, 3600).await;
                    black_box(result)
                }
            })
        });
    }

    group.finish();
}

// Stage 2: Worker - Sphinx process + delay assignment + message construction

fn bench_worker_process(c: &mut Criterion) {
    let (sks, pks) = create_test_keys(3);
    let path: Vec<PathHop> = pks
        .iter()
        .enumerate()
        .map(|(i, pk)| PathHop {
            public_key: *pk,
            address: if i == 2 {
                "EXIT".into()
            } else {
                format!("node_{i}")
            },
        })
        .collect();

    let payload = vec![0xCDu8; 256];

    let mut group = c.benchmark_group("Pipeline_Worker");
    group.throughput(Throughput::Elements(1));

    // Benchmark Sphinx process (the crypto hot path) at hop 0 (forward)
    {
        let packets = build_packet_pool(&path, &payload, 128);
        // Pre-parse headers + bodies
        let parsed: Vec<(SphinxHeader, Vec<u8>)> = packets
            .iter()
            .map(|pkt| {
                let (h, b) = SphinxHeader::from_bytes(pkt).unwrap();
                (h, b.to_vec())
            })
            .collect();

        let node_sk = &sks[0];

        group.bench_function("sphinx_process_forward", |b| {
            let mut idx = 0usize;
            b.iter(|| {
                let (ref header, ref body) = parsed[idx % parsed.len()];
                idx += 1;
                let result = header.process(black_box(node_sk), body.clone());
                black_box(result)
            })
        });
    }

    // Benchmark Sphinx process at exit hop (single hop packet)
    {
        let exit_path = vec![PathHop {
            public_key: pks[0],
            address: "EXIT".into(),
        }];
        let exit_packets = build_packet_pool(&exit_path, &payload, 128);
        let parsed_exit: Vec<(SphinxHeader, Vec<u8>)> = exit_packets
            .iter()
            .map(|pkt| {
                let (h, b) = SphinxHeader::from_bytes(pkt).unwrap();
                (h, b.to_vec())
            })
            .collect();

        let node_sk = &sks[0];

        group.bench_function("sphinx_process_exit", |b| {
            let mut idx = 0usize;
            b.iter(|| {
                let (ref header, ref body) = parsed_exit[idx % parsed_exit.len()];
                idx += 1;
                let result = header.process(black_box(node_sk), body.clone());
                black_box(result)
            })
        });
    }

    // Benchmark mix strategy delay sampling (Poisson vs NoMix)
    {
        let poisson = nox_node::services::mixing::PoissonMixStrategy::new(1.0);
        group.bench_function("delay_sample_poisson_1ms", |b| {
            b.iter(|| {
                let d = poisson.get_delay();
                black_box(d)
            })
        });

        let no_mix = NoMixStrategy;
        group.bench_function("delay_sample_nomix", |b| {
            b.iter(|| {
                let d = no_mix.get_delay();
                black_box(d)
            })
        });
    }

    // Benchmark full worker hot path: process + delay + MixMessage construction
    {
        let packets = build_packet_pool(&path, &payload, 128);
        let parsed: Vec<(SphinxHeader, Vec<u8>)> = packets
            .iter()
            .map(|pkt| {
                let (h, b) = SphinxHeader::from_bytes(pkt).unwrap();
                (h, b.to_vec())
            })
            .collect();

        let node_sk = &sks[0];
        let mix_strategy: Arc<dyn IMixStrategy> = Arc::new(NoMixStrategy);

        group.bench_function("full_worker_path", |b| {
            let mut idx = 0usize;
            b.iter(|| {
                let (ref header, ref body) = parsed[idx % parsed.len()];
                idx += 1;
                let start = Instant::now();

                let output = header.process(black_box(node_sk), body.clone()).unwrap();

                let result = nox_crypto::sphinx::into_result(output);
                let delay = mix_strategy.get_delay();

                let kind = match result {
                    nox_crypto::sphinx::ProcessResult::Forward {
                        next_hop,
                        next_packet,
                        processed_body,
                        ..
                    } => {
                        let forwarded_bytes = next_packet.to_bytes(&processed_body);
                        MixMessageKind::Forward {
                            next_hop,
                            packet: forwarded_bytes,
                        }
                    }
                    nox_crypto::sphinx::ProcessResult::Exit { payload } => {
                        MixMessageKind::Exit { payload }
                    }
                };

                let msg = MixMessage {
                    kind,
                    delay,
                    packet_id: String::new(),
                    original_processing_start: start,
                    #[cfg(feature = "hop-metrics")]
                    hop_timings: None,
                };

                black_box(msg)
            })
        });
    }

    group.finish();
}

// Stage 3: Mix - DelayQueue insert + expire throughput

fn bench_mix_delay_queue(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("Pipeline_Mix");
    group.throughput(Throughput::Elements(1));

    // Benchmark DelayQueue insert (zero delay = immediate expire)
    group.bench_function("delay_queue_insert_zero", |b| {
        b.to_async(&rt).iter(|| async {
            let mut dq = tokio_util::time::DelayQueue::new();
            let payload = vec![0u8; 32768];
            dq.insert(black_box(payload), Duration::ZERO);
            black_box(dq.len())
        })
    });

    // Benchmark DelayQueue insert with realistic delay
    group.bench_function("delay_queue_insert_1ms", |b| {
        b.to_async(&rt).iter(|| async {
            let mut dq = tokio_util::time::DelayQueue::new();
            let payload = vec![0u8; 32768];
            dq.insert(black_box(payload), Duration::from_millis(1));
            black_box(dq.len())
        })
    });

    // Benchmark sustained insert into a pre-loaded queue (tests heap pressure)
    for queue_depth in [100, 1000, 10_000] {
        group.bench_with_input(
            BenchmarkId::new("insert_into_loaded_queue", queue_depth),
            &queue_depth,
            |b, &depth| {
                b.to_async(&rt).iter(|| async move {
                    let mut dq = tokio_util::time::DelayQueue::new();
                    // Pre-load queue
                    for i in 0..depth {
                        dq.insert(i, Duration::from_millis(500));
                    }
                    // Measure single insert into loaded queue
                    let start = Instant::now();
                    dq.insert(black_box(depth + 1), Duration::from_millis(1));
                    black_box(start.elapsed())
                })
            },
        );
    }

    group.finish();
}

// Stage 4: Egress - event bus publish throughput

fn bench_egress_publish(c: &mut Criterion) {
    let mut group = c.benchmark_group("Pipeline_Egress");
    group.throughput(Throughput::Elements(1));

    // Benchmark event bus publish (forward packet event)
    {
        let bus = Arc::new(TokioEventBus::new(4096));
        // Must have at least one subscriber or publish returns Err
        let _sub = bus.subscribe();

        let packet_data = vec![0u8; 32768];

        group.bench_function("publish_send_packet", |b| {
            let mut idx = 0u64;
            b.iter(|| {
                idx += 1;
                let event = NoxEvent::SendPacket {
                    next_hop_peer_id: String::from("peer_abc"),
                    packet_id: String::new(),
                    data: packet_data.clone(),
                };
                let result = bus.publish(black_box(event));
                black_box(result)
            })
        });
    }

    // Benchmark event bus publish (exit payload event)
    {
        let bus = Arc::new(TokioEventBus::new(4096));
        let _sub = bus.subscribe();

        let payload_data = vec![0u8; 1024];

        group.bench_function("publish_payload_decrypted", |b| {
            b.iter(|| {
                let event = NoxEvent::PayloadDecrypted {
                    packet_id: String::new(),
                    payload: payload_data.clone(),
                };
                let result = bus.publish(black_box(event));
                black_box(result)
            })
        });
    }

    // Benchmark event bus publish (tracing event - lightweight)
    {
        let bus = Arc::new(TokioEventBus::new(4096));
        let _sub = bus.subscribe();

        group.bench_function("publish_packet_processed", |b| {
            b.iter(|| {
                let event = NoxEvent::PacketProcessed {
                    packet_id: String::new(),
                    duration_ms: 42,
                };
                let result = bus.publish(black_box(event));
                black_box(result)
            })
        });
    }

    // Benchmark with multiple subscribers (contention)
    for sub_count in [1, 4, 16] {
        let bus = Arc::new(TokioEventBus::new(4096));
        let _subs: Vec<_> = (0..sub_count).map(|_| bus.subscribe()).collect();

        let payload = vec![0u8; 32768];

        group.bench_with_input(
            BenchmarkId::new("publish_with_subscribers", sub_count),
            &sub_count,
            |b, _| {
                b.iter(|| {
                    let event = NoxEvent::SendPacket {
                        next_hop_peer_id: String::from("peer_abc"),
                        packet_id: String::new(),
                        data: payload.clone(),
                    };
                    let result = bus.publish(black_box(event));
                    black_box(result)
                })
            },
        );
    }

    group.finish();
}

// Combined: Full pipeline pass (ingest parse → worker process → egress publish)

fn bench_full_pipeline_pass(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let (sks, pks) = create_test_keys(3);
    let path: Vec<PathHop> = pks
        .iter()
        .enumerate()
        .map(|(i, pk)| PathHop {
            public_key: *pk,
            address: if i == 2 {
                "EXIT".into()
            } else {
                format!("node_{i}")
            },
        })
        .collect();

    let payload = vec![0xEFu8; 256];
    let packets = build_packet_pool(&path, &payload, 256);

    let bloom = Arc::new(RotationalBloomFilter::new(
        1_000_000,
        0.001,
        Duration::from_secs(3600),
    ));
    let bus = Arc::new(TokioEventBus::new(4096));
    let _sub = bus.subscribe();
    let node_sk = Arc::new(sks[0].clone());

    let mut group = c.benchmark_group("Pipeline_FullPass");
    group.throughput(Throughput::Elements(1));

    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let pkts = Arc::new(packets);

    let counter_c = counter.clone();
    let bloom_c = bloom.clone();
    let bus_c = bus.clone();
    let pkts_c = pkts.clone();
    let sk_c = node_sk.clone();

    group.bench_function("ingest_to_egress_forward", |b| {
        b.to_async(&rt).iter(|| {
            let idx = counter_c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let pkt = pkts_c[idx % pkts_c.len()].clone();
            let bl = bloom_c.clone();
            let ev = bus_c.clone();
            let sk = sk_c.clone();

            async move {
                // Ingest
                let (header, body) = SphinxHeader::from_bytes(&pkt).unwrap();
                let body = body.to_vec();
                let tag = header.compute_replay_tag();
                let _ = bl.check_and_tag(&tag, 3600).await;

                // Worker
                let output = header.process(&sk, body).unwrap();
                let result = nox_crypto::sphinx::into_result(output);

                // Egress
                match result {
                    nox_crypto::sphinx::ProcessResult::Forward {
                        next_hop,
                        next_packet,
                        processed_body,
                        ..
                    } => {
                        let data = next_packet.to_bytes(&processed_body);
                        let _ = ev.publish(NoxEvent::SendPacket {
                            next_hop_peer_id: next_hop,
                            packet_id: String::new(),
                            data,
                        });
                    }
                    nox_crypto::sphinx::ProcessResult::Exit { payload } => {
                        let _ = ev.publish(NoxEvent::PayloadDecrypted {
                            packet_id: String::new(),
                            payload,
                        });
                    }
                }

                black_box(())
            }
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_ingest_parse,
    bench_worker_process,
    bench_mix_delay_queue,
    bench_egress_publish,
    bench_full_pipeline_pass,
);

criterion_main!(benches);
