//! SURB (Single Use Reply Block) Benchmarks
//!
//! Measures SURB full round-trip latency, client-side decrypt cost, and trial
//! decryption scaling. These are numbers nobody else publishes -- Nym and Katzenpost
//! have zero SURB performance data.
//!
//! Key metrics:
//! - Full round-trip: create SURB -> encapsulate -> process N hops -> decrypt
//! - Decrypt-only: isolate client-side ChaCha20 layer peeling cost
//! - Trial decryption: O(registered_surbs × hops × body_size) worst-case scaling

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use nox_crypto::sphinx::{into_result, PathHop, ProcessResult, SphinxHeader};
use nox_crypto::{Surb, SurbRecovery};
use rand::rngs::OsRng;
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

/// Build a fully-processed SURB payload: create SURB, encapsulate message,
/// process through N hops via SphinxHeader::process(), return the exit payload
/// and the SurbRecovery needed to decrypt it.
fn build_processed_surb_payload(num_hops: usize, message: &[u8]) -> (Vec<u8>, SurbRecovery) {
    let (path, secret_keys) = generate_path(num_hops);
    let id: [u8; 16] = rand::random();

    let (surb, recovery) = Surb::new(&path, id, 0).expect("SURB creation failed");
    let packet = surb.encapsulate(message).expect("encapsulate failed");

    // Process through each relay hop
    let mut current_bytes = packet.into_bytes();
    for (hop_idx, sk) in secret_keys.iter().enumerate() {
        let (header, body) = SphinxHeader::from_bytes(&current_bytes).expect("parse failed");
        let result = into_result(header.process(sk, body.to_vec()).expect("process failed"));

        match result {
            ProcessResult::Forward {
                next_packet,
                processed_body,
                ..
            } => {
                current_bytes = next_packet.to_bytes(&processed_body);
            }
            ProcessResult::Exit { payload } => {
                assert_eq!(hop_idx, num_hops - 1, "exit must be last hop");
                return (payload, recovery);
            }
        }
    }
    panic!("never reached exit hop");
}

// 1.2.3: SURB Full Round-Trip (construct + encapsulate + peel N hops + decrypt)

fn bench_surb_full_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("SURB_FullRoundtrip");
    group.sample_size(50);

    let message = b"Transaction confirmed: 0x1234567890abcdef";

    for hop_count in [1, 2, 3] {
        group.bench_with_input(
            BenchmarkId::new("roundtrip", format!("{hop_count}_hop")),
            &hop_count,
            |b, &hops| {
                b.iter(|| {
                    let (path, secret_keys) = generate_path(hops);
                    let id: [u8; 16] = rand::random();

                    // Phase 1: Create SURB
                    let (surb, recovery) =
                        Surb::new(black_box(&path), id, 0).expect("SURB creation");

                    // Phase 2: Encapsulate
                    let packet = surb
                        .encapsulate(black_box(message.as_slice()))
                        .expect("encapsulate");

                    // Phase 3: Process through N hops
                    let mut current_bytes = packet.into_bytes();
                    let mut exit_payload = Vec::new();
                    for (hop_idx, sk) in secret_keys.iter().enumerate() {
                        let (header, body) =
                            SphinxHeader::from_bytes(&current_bytes).expect("parse");
                        let result =
                            into_result(header.process(sk, body.to_vec()).expect("process"));

                        match result {
                            ProcessResult::Forward {
                                next_packet,
                                processed_body,
                                ..
                            } => {
                                current_bytes = next_packet.to_bytes(&processed_body);
                            }
                            ProcessResult::Exit { payload } => {
                                exit_payload = payload;
                                assert_eq!(hop_idx, hops - 1);
                                break;
                            }
                        }
                    }

                    // Phase 4: Client decrypts
                    let decrypted = recovery.decrypt(black_box(&exit_payload)).expect("decrypt");
                    black_box(decrypted)
                })
            },
        );
    }

    group.finish();
}

// 1.2.4: SURB Decrypt Only (client-side layer peeling -- N+1 ChaCha20 passes)

fn bench_surb_decrypt_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("SURB_DecryptOnly");

    let message = b"Transaction confirmed: 0x1234567890abcdef";

    for hop_count in [1, 2, 3] {
        // Pre-build the processed payload outside the hot loop
        let (exit_payload, recovery) = build_processed_surb_payload(hop_count, message.as_slice());

        group.bench_with_input(
            BenchmarkId::new("decrypt", format!("{hop_count}_hop")),
            &(exit_payload, recovery),
            |b, (payload, rec)| {
                b.iter(|| {
                    let decrypted = rec.decrypt(black_box(payload)).expect("decrypt");
                    black_box(decrypted)
                })
            },
        );
    }

    group.finish();
}

// 1.2.5: Trial Decryption Cost (N registered SURBs, worst-case)

fn bench_surb_trial_decryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("SURB_TrialDecrypt");
    group.sample_size(30);

    let message = b"Transaction confirmed: 0x1234567890abcdef";
    let hops = 3; // Realistic 3-hop path

    for num_surbs in [1, 10, 50, 100] {
        // Build N SURBs. The LAST one is the "correct" one (worst-case: try all before match).
        let mut surb_registry: Vec<([u8; 16], SurbRecovery)> = Vec::with_capacity(num_surbs);

        for _ in 0..num_surbs {
            let (path, _sks) = generate_path(hops);
            let id: [u8; 16] = rand::random();
            let (_surb, recovery) = Surb::new(&path, id, 0).expect("SURB creation");
            surb_registry.push((id, recovery));
        }

        // Build the "correct" payload matching the LAST registered SURB
        let last_idx = num_surbs - 1;
        let (path, secret_keys) = generate_path(hops);
        let id: [u8; 16] = rand::random();
        let (surb, recovery) = Surb::new(&path, id, 0).expect("SURB creation");
        surb_registry[last_idx] = (id, recovery);

        // Build the payload processed through the correct path
        let packet = surb.encapsulate(message.as_slice()).expect("encapsulate");
        let mut current_bytes = packet.into_bytes();
        let mut exit_payload = Vec::new();
        for (hop_idx, sk) in secret_keys.iter().enumerate() {
            let (header, body) = SphinxHeader::from_bytes(&current_bytes).expect("parse");
            let result = into_result(header.process(sk, body.to_vec()).expect("process"));
            match result {
                ProcessResult::Forward {
                    next_packet,
                    processed_body,
                    ..
                } => {
                    current_bytes = next_packet.to_bytes(&processed_body);
                }
                ProcessResult::Exit { payload } => {
                    exit_payload = payload;
                    assert_eq!(hop_idx, hops - 1);
                    break;
                }
            }
        }

        group.bench_with_input(
            BenchmarkId::new("trial_decrypt", format!("{num_surbs}_surbs")),
            &(exit_payload, surb_registry),
            |b, (payload, registry)| {
                b.iter(|| {
                    // Simulate MixnetClient::handle_response() trial decryption loop
                    let mut found = None;
                    for (surb_id, recovery) in registry.iter() {
                        if let Ok(decrypted) = recovery.decrypt(black_box(payload)) {
                            found = Some((*surb_id, decrypted));
                            break;
                        }
                    }
                    black_box(found.expect("must find matching SURB"))
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_surb_full_roundtrip,
    bench_surb_decrypt_only,
    bench_surb_trial_decryption,
);
criterion_main!(benches);
