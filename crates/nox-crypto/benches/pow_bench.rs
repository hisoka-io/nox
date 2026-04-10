//! Proof-of-Work Benchmarks
//!
//! Measures PoW solve times at various difficulties for both SHA-256 and Blake3,
//! plus verification and raw hash throughput. Critical for calibrating the
//! `min_pow_difficulty` config parameter.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use nox_crypto::{Blake3Pow, PowAlgorithm, PowSolver, Sha256Pow};

/// Realistic header data size: ephemeral_key(32) + routing_info(400) + mac(32) = 464 bytes.
fn header_data() -> Vec<u8> {
    vec![0xAB; 464]
}

// Raw Hash Throughput

fn bench_raw_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("PoW_RawHash");

    let data = header_data();
    // Append an 8-byte nonce like the real solver does
    let mut data_with_nonce = data.clone();
    data_with_nonce.extend_from_slice(&42u64.to_le_bytes());

    group.bench_function("sha256", |b| {
        b.iter(|| Sha256Pow.hash(black_box(&data_with_nonce)))
    });

    group.bench_function("blake3", |b| {
        b.iter(|| Blake3Pow.hash(black_box(&data_with_nonce)))
    });

    group.finish();
}

// PoW Verification (O(1) -- single hash + leading zero check)

fn bench_pow_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("PoW_Verify");

    let data = header_data();
    let difficulty = 16u32;

    // Pre-solve nonces for verification benchmarks
    let sha_solver = PowSolver::new(Sha256Pow, 1);
    let sha_nonce = sha_solver.solve(&data, difficulty, 0).expect("sha solve");

    let blake_solver = PowSolver::new(Blake3Pow, 1);
    let blake_nonce = blake_solver
        .solve(&data, difficulty, 0)
        .expect("blake solve");

    group.bench_function("sha256_d16", |b| {
        b.iter(|| {
            sha_solver.verify(
                black_box(&data),
                black_box(sha_nonce),
                black_box(difficulty),
            )
        })
    });

    group.bench_function("blake3_d16", |b| {
        b.iter(|| {
            blake_solver.verify(
                black_box(&data),
                black_box(blake_nonce),
                black_box(difficulty),
            )
        })
    });

    group.finish();
}

// PoW Solve -- Single-Threaded (isolate per-hash cost)

fn bench_pow_solve_single(c: &mut Criterion) {
    let mut group = c.benchmark_group("PoW_Solve_1T");

    let data = header_data();

    // Difficulty 4 and 8 are fast enough for criterion's default sample count.
    // Difficulty 12 and 16 need reduced samples.
    for difficulty in [4, 8, 12] {
        if difficulty >= 12 {
            group.sample_size(20);
        }

        group.bench_with_input(
            BenchmarkId::new("sha256", format!("d{difficulty}")),
            &difficulty,
            |b, &diff| {
                let solver = PowSolver::new(Sha256Pow, 1);
                b.iter(|| solver.solve(black_box(&data), diff, 0))
            },
        );

        group.bench_with_input(
            BenchmarkId::new("blake3", format!("d{difficulty}")),
            &difficulty,
            |b, &diff| {
                let solver = PowSolver::new(Blake3Pow, 1);
                b.iter(|| solver.solve(black_box(&data), diff, 0))
            },
        );
    }

    group.finish();
}

// PoW Solve -- Multi-Threaded (realistic production config)

fn bench_pow_solve_parallel(c: &mut Criterion) {
    let mut group = c.benchmark_group("PoW_Solve_MT");
    group.sample_size(20);

    let data = header_data();

    // d12+ take ms-seconds, use reduced samples
    for difficulty in [12, 16] {
        group.bench_with_input(
            BenchmarkId::new("sha256", format!("d{difficulty}")),
            &difficulty,
            |b, &diff| {
                let solver = PowSolver::new(Sha256Pow, 0); // 0 = all cores
                b.iter(|| solver.solve(black_box(&data), diff, 0))
            },
        );

        group.bench_with_input(
            BenchmarkId::new("blake3", format!("d{difficulty}")),
            &difficulty,
            |b, &diff| {
                let solver = PowSolver::new(Blake3Pow, 0); // 0 = all cores
                b.iter(|| solver.solve(black_box(&data), diff, 0))
            },
        );
    }

    group.finish();
}

// 1.3.5: PoW Calibration Curve (solve_time vs difficulty d4..d24)

fn bench_pow_calibration_curve(c: &mut Criterion) {
    let mut group = c.benchmark_group("PoW_Calibration");
    group.sample_size(10);

    let data = header_data();

    // Sweep difficulty from d4 to d24 in steps of 2.
    // SHA-256 only (the production algorithm). This produces the exponential
    // curve needed for setting `min_pow_difficulty` in NoxConfig.
    //
    // Expected: ~2^(d-4) * base_cost, doubling per +1 difficulty bit.
    // d4 ~3us, d8 ~15us, d12 ~250us, d16 ~2ms, d20 ~30ms, d24 ~500ms
    for difficulty in (4..=24).step_by(2) {
        let threads = if difficulty <= 12 { 1 } else { 0 }; // MT for d14+
        let solver = PowSolver::new(Sha256Pow, threads);

        group.bench_with_input(
            BenchmarkId::new("sha256", format!("d{difficulty}")),
            &difficulty,
            |b, &diff| b.iter(|| solver.solve(black_box(&data), diff, 0)),
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_raw_hash,
    bench_pow_verify,
    bench_pow_solve_single,
    bench_pow_solve_parallel,
    bench_pow_calibration_curve,
);
criterion_main!(benches);
