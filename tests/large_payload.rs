//! Large payload integration tests: Fragmenter + FEC encode/decode pipeline (1 MB to 50 MB).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use nox_core::protocol::fec;
use nox_core::{FecInfo, Fragment, Fragmenter, Reassembler, ReassemblerConfig, SURB_PAYLOAD_SIZE};
use sha2::{Digest, Sha256};

fn make_payload(size: usize, seed: u8) -> Vec<u8> {
    (0..size)
        .map(|i| seed.wrapping_add((i & 0xFF) as u8).wrapping_mul(0x6B))
        .collect()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn make_fec_fragments(message_id: u64, data: &[u8], extra_parity: usize) -> Vec<Fragment> {
    let fragmenter = Fragmenter::with_max_size(data.len() + 1024);
    let mut data_frags = fragmenter
        .fragment(message_id, data, SURB_PAYLOAD_SIZE)
        .expect("fragment() failed");

    let d = data_frags.len();

    if extra_parity == 0 {
        return data_frags;
    }

    let total = (d + extra_parity) as u32;

    let raw_chunks: Vec<Vec<u8>> = data_frags.iter().map(|f| f.data.clone()).collect();
    let (padded, _) = fec::pad_to_uniform(&raw_chunks).expect("pad_to_uniform");
    let parity_shards =
        fec::encode_parity_shards(&padded, extra_parity).expect("encode_parity_shards");

    let fec_info = FecInfo {
        data_shard_count: d as u32,
        original_data_len: data.len() as u64,
    };

    for (i, frag) in data_frags.iter_mut().enumerate() {
        frag.data.clone_from(&padded[i]);
        frag.total_fragments = total;
        frag.fec = Some(fec_info.clone());
    }

    let mut all_frags = data_frags;
    for (i, parity_data) in parity_shards.into_iter().enumerate() {
        all_frags.push(
            Fragment::new_with_fec(
                message_id,
                total,
                (d + i) as u32,
                parity_data,
                fec_info.clone(),
            )
            .expect("new_with_fec"),
        );
    }

    all_frags
}

fn reassemble_with_drops(frags: Vec<Fragment>, drop_indices: &[usize]) -> Option<Vec<u8>> {
    let config = ReassemblerConfig {
        max_buffer_bytes: 400 * 1024 * 1024,
        ..Default::default()
    };
    let mut reassembler = Reassembler::new(config);
    let mut result = None;

    for (i, frag) in frags.into_iter().enumerate() {
        if drop_indices.contains(&i) {
            continue;
        }
        match reassembler.add_fragment(frag) {
            Ok(Some(data)) => {
                result = Some(data);
                break;
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!("Reassembly error at fragment {i}: {e}");
                return None;
            }
        }
    }

    result
}

#[test]
#[ignore = "large payload test -- run with: make test-large"]
fn test_1mb_no_loss_integrity() {
    let data = make_payload(1024 * 1024, 0xAA);
    let expected_hash = sha256(&data);

    let frags = make_fec_fragments(1, &data, 2);
    let total = frags.len();
    eprintln!("1 MB -> {total} fragments");

    let result = reassemble_with_drops(frags, &[]).expect("reassemble failed");
    assert_eq!(sha256(&result), expected_hash, "SHA-256 mismatch");
    assert_eq!(result.len(), data.len());
}

#[test]
#[ignore = "large payload test -- run with: make test-large"]
fn test_7mb_fec_recovery() {
    let data = make_payload(7 * 1024 * 1024, 0xBB);
    let expected_hash = sha256(&data);

    let frag_count = {
        let f = Fragmenter::with_max_size(data.len() + 1024);
        f.fragment(42, &data, SURB_PAYLOAD_SIZE)
            .expect("fragment")
            .len()
    };
    let parity = ((frag_count / 10).max(1)).min(255 - frag_count);

    let frags = make_fec_fragments(10, &data, parity);
    let total = frags.len();
    let drops: Vec<usize> = (0..parity).collect();
    eprintln!(
        "7 MB -> {total} fragments (data={frag_count}, parity={parity}), dropping {} data shards",
        drops.len()
    );

    let result = reassemble_with_drops(frags, &drops).expect("FEC recovery failed");
    assert_eq!(sha256(&result), expected_hash);
    assert_eq!(result.len(), data.len());
}

#[test]
#[ignore = "large payload test -- run with: make test-large"]
fn test_50mb_no_loss_integrity() {
    let data = make_payload(50 * 1024 * 1024, 0xCC);
    let expected_hash = sha256(&data);

    let frags = make_fec_fragments(100, &data, 0);
    let total = frags.len();
    eprintln!("50 MB -> {total} fragments (no FEC)");

    let result = reassemble_with_drops(frags, &[]).expect("reassemble failed");
    assert_eq!(sha256(&result), expected_hash);
    assert_eq!(result.len(), data.len());
}

#[test]
#[ignore = "large payload test -- run with: make test-large"]
fn test_10mb_no_loss_integrity() {
    let data = make_payload(10 * 1024 * 1024, 0xDD);
    let expected_hash = sha256(&data);

    let frags = make_fec_fragments(300, &data, 0);
    let total = frags.len();
    eprintln!("10 MB -> {total} fragments (no FEC)");

    let result = reassemble_with_drops(frags, &[]).expect("reassemble failed");
    assert_eq!(sha256(&result), expected_hash);
    assert_eq!(result.len(), data.len());
}

#[test]
#[ignore = "large payload test -- run with: make test-large"]
fn test_max_fec_loss_boundary() {
    let data = make_payload(1024 * 1024, 0x11);
    let expected_hash = sha256(&data);

    let frag_count = {
        let f = Fragmenter::with_max_size(data.len() + 1024);
        f.fragment(42, &data, SURB_PAYLOAD_SIZE)
            .expect("fragment")
            .len()
    };
    let parity = (frag_count / 10).max(1);
    let frags = make_fec_fragments(42, &data, parity);
    let total = frags.len();

    let drops: Vec<usize> = ((total - parity)..total).collect();
    eprintln!("max-loss test: {total} frags, dropping {parity} parity shards");

    let result = reassemble_with_drops(frags, &drops).expect("should recover");
    assert_eq!(sha256(&result), expected_hash);
}

#[test]
#[ignore = "large payload test -- run with: make test-large"]
fn test_irrecoverable_loss_returns_error() {
    let data = make_payload(512 * 1024, 0x22);

    let frag_count = {
        let f = Fragmenter::with_max_size(data.len() + 1024);
        f.fragment(42, &data, SURB_PAYLOAD_SIZE)
            .expect("fragment")
            .len()
    };
    let parity = (frag_count / 10).max(1);
    let frags = make_fec_fragments(43, &data, parity);
    let total = frags.len();

    let mut drops: Vec<usize> = ((total - parity)..total).collect();
    drops.push(0);
    eprintln!(
        "irrecoverable test: {total} frags, parity={parity}, dropping {}",
        drops.len()
    );

    let result = reassemble_with_drops(frags, &drops);
    assert!(result.is_none(), "expected None on irrecoverable loss");
}

#[test]
#[ignore = "large payload test -- run with: make test-large"]
fn test_1mb_sha256_no_fec() {
    let data = make_payload(1024 * 1024, 0xEE);
    let expected_hash = sha256(&data);

    let frags = make_fec_fragments(301, &data, 0);
    let result = reassemble_with_drops(frags, &[]).expect("reassemble");
    assert_eq!(sha256(&result), expected_hash);
    assert_eq!(result.len(), data.len());
}
