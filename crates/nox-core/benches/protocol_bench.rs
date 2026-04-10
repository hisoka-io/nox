//! NOX Protocol Benchmarks
//!
//! Measures throughput of core protocol operations:
//! - Reed-Solomon FEC encoding and decoding (novel contribution)
//! - Fragment serialization / deserialization
//! - Full reassembly pipeline

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nox_core::protocol::fec::{decode_shards, encode_parity_shards, FecInfo};
use nox_core::{Fragment, Fragmenter, Reassembler, ReassemblerConfig, SURB_PAYLOAD_SIZE};
use rand::Rng;

/// Generate random data of a given size.
fn random_data(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..size).map(|_| rng.gen()).collect()
}

// FEC Encoding

fn bench_fec_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("FEC_Encode");

    // (data_shard_count, parity_count, shard_size_bytes)
    let configs = [
        (10, 3, 1_024, "D10_P3_1KB"),
        (10, 3, 30_700, "D10_P3_30KB"),
        (50, 15, 1_024, "D50_P15_1KB"),
        (50, 15, 30_700, "D50_P15_30KB"),
    ];

    for &(d, p, shard_size, label) in &configs {
        let data_shards: Vec<_> = (0..d).map(|_| random_data(shard_size)).collect();
        let total_bytes = d * shard_size;

        group.throughput(Throughput::Bytes(total_bytes as u64));
        group.bench_with_input(
            BenchmarkId::new("encode", label),
            &data_shards,
            |b, shards| b.iter(|| encode_parity_shards(black_box(shards), p)),
        );
    }

    group.finish();
}

// FEC Decoding

fn bench_fec_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("FEC_Decode");

    let shard_size = 30_700usize; // Realistic SURB payload size
    let d = 10usize;
    let p = 3usize;
    let original_data = random_data(d * shard_size);

    // Encode
    let data_shards: Vec<_> = original_data
        .chunks(shard_size)
        .map(|c| c.to_vec())
        .collect();
    let parity = encode_parity_shards(&data_shards, p).expect("encode");

    let original_len = original_data.len() as u64;

    // Fast path: all data shards present
    group.throughput(Throughput::Bytes(original_len));
    group.bench_function("fast_path_all_present", |b| {
        b.iter(|| {
            let mut shards: Vec<Option<Vec<u8>>> = data_shards
                .iter()
                .chain(parity.iter())
                .map(|s| Some(s.clone()))
                .collect();
            decode_shards(black_box(&mut shards), d, original_len)
        })
    });

    // RS path: 1 data shard missing
    group.bench_function("rs_path_1_missing", |b| {
        b.iter(|| {
            let mut shards: Vec<Option<Vec<u8>>> = data_shards
                .iter()
                .chain(parity.iter())
                .map(|s| Some(s.clone()))
                .collect();
            shards[0] = None; // Drop first data shard
            decode_shards(black_box(&mut shards), d, original_len)
        })
    });

    // RS path: 3 data shards missing (max recoverable with P=3)
    group.bench_function("rs_path_3_missing", |b| {
        b.iter(|| {
            let mut shards: Vec<Option<Vec<u8>>> = data_shards
                .iter()
                .chain(parity.iter())
                .map(|s| Some(s.clone()))
                .collect();
            shards[0] = None;
            shards[3] = None;
            shards[7] = None;
            decode_shards(black_box(&mut shards), d, original_len)
        })
    });

    group.finish();
}

// Fragment Serialization

fn bench_fragment_serde(c: &mut Criterion) {
    let mut group = c.benchmark_group("Fragment_Serde");

    // Realistic fragment: 30KB data payload
    let data = random_data(SURB_PAYLOAD_SIZE);
    let fragment = Fragment::new(12345, 10, 0, data.clone()).expect("fragment");

    let serialized = fragment.to_bytes().expect("serialize");
    let byte_len = serialized.len() as u64;

    group.throughput(Throughput::Bytes(byte_len));

    group.bench_function("to_bytes_30KB", |b| {
        b.iter(|| black_box(&fragment).to_bytes())
    });

    group.bench_function("from_bytes_30KB", |b| {
        b.iter(|| Fragment::from_bytes(black_box(&serialized)))
    });

    // With FEC metadata
    let fec_fragment = Fragment::new_with_fec(
        12345,
        13,
        0,
        data,
        FecInfo {
            data_shard_count: 10,
            original_data_len: 307_000,
        },
    )
    .expect("fec fragment");
    let fec_serialized = fec_fragment.to_bytes().expect("serialize");

    group.bench_function("to_bytes_30KB_fec", |b| {
        b.iter(|| black_box(&fec_fragment).to_bytes())
    });

    group.bench_function("from_bytes_30KB_fec", |b| {
        b.iter(|| Fragment::from_bytes(black_box(&fec_serialized)))
    });

    group.finish();
}

// Fragmentation

fn bench_fragmenter(c: &mut Criterion) {
    let mut group = c.benchmark_group("Fragmenter");
    let fragmenter = Fragmenter::new();

    for &(size_kb, label) in &[(1, "1KB"), (100, "100KB"), (500, "500KB"), (1000, "1MB")] {
        let size_bytes = size_kb * 1024;
        let data = random_data(size_bytes);

        group.throughput(Throughput::Bytes(size_bytes as u64));
        group.bench_with_input(BenchmarkId::new("fragment", label), &data, |b, data| {
            b.iter(|| fragmenter.fragment(999, black_box(data), SURB_PAYLOAD_SIZE))
        });
    }

    group.finish();
}

// Reassembly Pipeline

fn bench_reassembly(c: &mut Criterion) {
    let mut group = c.benchmark_group("Reassembler");

    // Prepare fragments for a 100KB message
    let fragmenter = Fragmenter::new();
    let data = random_data(100 * 1024);
    let fragments = fragmenter
        .fragment(42, &data, SURB_PAYLOAD_SIZE)
        .expect("fragment");
    let fragment_count = fragments.len();

    group.bench_function("reassemble_100KB", |b| {
        b.iter(|| {
            let mut reassembler = Reassembler::new(ReassemblerConfig::default());
            let mut result = None;
            for frag in &fragments {
                if let Ok(Some(data)) = reassembler.add_fragment(frag.clone()) {
                    result = Some(data);
                }
            }
            black_box(result)
        })
    });

    // Prepare fragments for a 1MB message
    let data_1mb = random_data(1024 * 1024);
    let fragments_1mb = fragmenter
        .fragment(99, &data_1mb, SURB_PAYLOAD_SIZE)
        .expect("fragment");

    group.bench_function("reassemble_1MB", |b| {
        b.iter(|| {
            let mut reassembler = Reassembler::new(ReassemblerConfig::default());
            let mut result = None;
            for frag in &fragments_1mb {
                if let Ok(Some(data)) = reassembler.add_fragment(frag.clone()) {
                    result = Some(data);
                }
            }
            black_box(result)
        })
    });

    // Bench add_fragment individually (amortized per fragment)
    group.throughput(Throughput::Elements(fragment_count as u64));
    group.bench_function("add_fragment_amortized", |b| {
        b.iter(|| {
            let mut reassembler = Reassembler::new(ReassemblerConfig::default());
            for frag in &fragments {
                let _ = reassembler.add_fragment(black_box(frag.clone()));
            }
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_fec_encode,
    bench_fec_decode,
    bench_fragment_serde,
    bench_fragmenter,
    bench_reassembly,
);
criterion_main!(benches);
