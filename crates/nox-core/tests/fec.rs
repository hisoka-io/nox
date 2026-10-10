//! Reed-Solomon FEC through `Fragmenter` and `Reassembler` at SURB payload size: shard
//! boundaries, reordering, random drops and the largest message the protocol accepts.

use nox_core::protocol::fec;
use nox_core::protocol::fragmentation::MAX_MESSAGE_SIZE;
use nox_core::{FecInfo, Fragment, Fragmenter, Reassembler, ReassemblerConfig, SURB_PAYLOAD_SIZE};

fn usable() -> usize {
    Fragmenter::usable_payload_size(SURB_PAYLOAD_SIZE)
}

fn make_fec_fragments(data: &[u8], extra_parity: usize) -> Vec<Fragment> {
    let request_id: u64 = rand::random();
    let fragmenter = Fragmenter::new();
    let mut data_frags = fragmenter
        .fragment(request_id, data, SURB_PAYLOAD_SIZE)
        .expect("fragment() failed");

    let d = data_frags.len();
    let p = extra_parity;

    if p == 0 {
        return data_frags;
    }

    let total = (d + p) as u32;

    let raw_chunks: Vec<Vec<u8>> = data_frags.iter().map(|f| f.data.clone()).collect();
    let (padded, _) = fec::pad_to_uniform(&raw_chunks).expect("pad_to_uniform failed");

    let parity_shards = fec::encode_parity_shards(&padded, p).expect("encode_parity_shards failed");

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
                request_id,
                total,
                (d + i) as u32,
                parity_data,
                fec_info.clone(),
            )
            .expect("Fragment::new_with_fec failed"),
        );
    }

    all_frags
}

fn reassemble(fragments: Vec<Fragment>) -> Result<Vec<u8>, String> {
    let mut reassembler = Reassembler::new(ReassemblerConfig::default());
    let mut result = None;

    for frag in fragments {
        match reassembler.add_fragment(frag) {
            Ok(Some(data)) => {
                result = Some(data);
                break;
            }
            Ok(None) => {}
            Err(e) => return Err(e.to_string()),
        }
    }

    result.ok_or_else(|| "Reassembler did not complete".to_string())
}

fn drop_seq(frags: Vec<Fragment>, seq: u32) -> Vec<Fragment> {
    frags.into_iter().filter(|f| f.sequence != seq).collect()
}

#[test]
fn test_fec_drop_last_data_shard() {
    let data: Vec<u8> = (0..60_000).map(|i| i as u8).collect();
    let frags = make_fec_fragments(&data, 2);

    let d = frags[0].fec.as_ref().unwrap().data_shard_count as usize;
    let last_data_seq = (d - 1) as u32;

    let frags = drop_seq(frags, last_data_seq);
    let recovered = reassemble(frags).expect("Last-shard-drop recovery failed");
    assert_eq!(recovered, data, "Last-shard drop data mismatch");
}

#[test]
fn test_fec_exact_one_surb() {
    let data: Vec<u8> = vec![0x42; usable()]; // exactly one SURB worth
    let frags = make_fec_fragments(&data, 1);
    assert_eq!(frags.len(), 2, "Expected D=1 + P=1");

    let recovered = reassemble(frags).expect("Exact-one-SURB recovery failed");
    assert_eq!(recovered, data);
}

#[test]
fn test_fec_exact_two_surbs() {
    let data: Vec<u8> = vec![0x55; usable() * 2];
    let frags = make_fec_fragments(&data, 2);
    assert_eq!(frags.len(), 4, "Expected D=2 + P=2");

    // Drop one data shard -- still recoverable
    let frags = drop_seq(frags, 0);
    let recovered = reassemble(frags).expect("Exact-two-SURB drop recovery failed");
    assert_eq!(recovered, data);
}

#[test]
fn test_fec_tiny_data() {
    let data: Vec<u8> = vec![0xFF];
    let frags = make_fec_fragments(&data, 1);
    assert_eq!(frags.len(), 2);

    let recovered = reassemble(frags).expect("Tiny data recovery failed");
    assert_eq!(recovered, data);
}

#[test]
fn test_fec_large_data_three_parity() {
    let data: Vec<u8> = (0..500_000).map(|i| (i % 251) as u8).collect();
    let frags = make_fec_fragments(&data, 3);

    let d = frags[0].fec.as_ref().unwrap().data_shard_count as usize;
    assert!(d > 3, "Expected multi-shard data");

    // Drop first data shard -- RS recovery
    let frags = drop_seq(frags, 0);
    let recovered = reassemble(frags).expect("Large-data RS recovery failed");
    assert_eq!(recovered, data, "Large data RS recovery mismatch");
}

#[test]
fn test_fec_random_drop_always_recoverable() {
    use rand::seq::SliceRandom;
    use rand::Rng;

    let mut rng = rand::thread_rng();
    let p = 2usize;

    for trial in 0..100 {
        let size = rng.gen_range(1_000..100_000);
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let frags = make_fec_fragments(&data, p);
        let total = frags.len();
        let d = frags[0].fec.as_ref().unwrap().data_shard_count as usize;

        // Drop at most P fragments (guaranteed recoverable)
        let drop_count = rng.gen_range(0..=p);
        let mut indices: Vec<usize> = (0..total).collect();
        indices.shuffle(&mut rng);
        let drop_seqs: std::collections::HashSet<u32> = indices
            .into_iter()
            .take(drop_count)
            .map(|i| frags[i].sequence)
            .collect();

        let remaining: Vec<Fragment> = frags
            .into_iter()
            .filter(|f| !drop_seqs.contains(&f.sequence))
            .collect();

        // If we dropped at least one data shard but still have >= d remaining overall shards, it's recoverable
        let data_shard_count = remaining
            .iter()
            .filter(|f| (f.sequence as usize) < d)
            .count();
        let parity_count_remaining = remaining.len() - data_shard_count;
        let missing_data = d - data_shard_count;
        let is_recoverable = missing_data <= parity_count_remaining;

        let result = reassemble(remaining);
        if is_recoverable {
            assert!(
                result.is_ok(),
                "Trial {}: drop={} should be recoverable, got: {:?}",
                trial,
                drop_count,
                result.err()
            );
            assert_eq!(
                result.unwrap(),
                data,
                "Trial {}: recovered data mismatch",
                trial
            );
        }
        // If not recoverable by our analysis, we just verify it doesn't panic
    }
}

#[test]
fn test_fec_out_of_order_delivery() {
    use rand::seq::SliceRandom;

    let data: Vec<u8> = (0..70_000).map(|i| (i % 251) as u8).collect();
    let mut frags = make_fec_fragments(&data, 2);

    // Shuffle delivery order (simulates mixnet reordering)
    frags.shuffle(&mut rand::thread_rng());

    let recovered = reassemble(frags).expect("Out-of-order delivery failed");
    assert_eq!(recovered, data, "Out-of-order recovered data mismatch");
}

#[test]
fn test_fec_out_of_order_with_drop() {
    use rand::seq::SliceRandom;

    let data: Vec<u8> = (0..70_000).map(|i| (i % 251) as u8).collect();
    let mut frags = make_fec_fragments(&data, 2);

    // Drop middle data shard
    let d = frags[0].fec.as_ref().unwrap().data_shard_count as usize;
    let mid = (d / 2) as u32;
    frags.retain(|f| f.sequence != mid);

    // Shuffle
    frags.shuffle(&mut rand::thread_rng());

    let recovered = reassemble(frags).expect("Out-of-order+drop recovery failed");
    assert_eq!(recovered, data, "Out-of-order+drop data mismatch");
}

/// The largest message the protocol accepts, with a tenth of its shards as parity and that
/// many data shards lost.
#[test]
fn test_fec_recovery_at_max_message_size() {
    let data: Vec<u8> = (0..MAX_MESSAGE_SIZE).map(|i| (i % 251) as u8).collect();
    let d = data.len().div_ceil(usable());
    let parity = d / 10;
    assert!(d + parity <= fec::MAX_TOTAL_SHARDS);

    let frags = make_fec_fragments(&data, parity);
    assert_eq!(frags.len(), d + parity);

    let remaining: Vec<Fragment> = frags
        .into_iter()
        .filter(|f| f.sequence as usize >= parity)
        .collect();
    let recovered = reassemble(remaining).expect("recovery at the size limit failed");
    assert!(
        recovered == data,
        "recovered data differs from the original"
    );
}
