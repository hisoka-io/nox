//! Fragmentation E2E: chaos, memory safety, max message sizes, SURB response reassembly.

use nox_client::surb_budget::{
    SurbBudget, ESTIMATED_SURB_SERIALIZED_SIZE, MAX_SURBS, USABLE_RESPONSE_PER_SURB,
};
use nox_core::protocol::fragmentation::{
    DEFAULT_MAX_BUFFER_BYTES, DEFAULT_STALE_TIMEOUT_SECS, FRAGMENT_OVERHEAD,
    MAX_FRAGMENTS_PER_MESSAGE, MAX_MESSAGE_SIZE,
};
use nox_core::{
    Fragment, FragmentationError, Fragmenter, Reassembler, ReassemblerConfig, SURB_PAYLOAD_SIZE,
};
use nox_crypto::MAX_PAYLOAD_SIZE;
use rand::seq::SliceRandom;
use std::time::Duration;

#[test]
fn test_max_message_size_equals_200_times_32kb() {
    assert_eq!(MAX_MESSAGE_SIZE, 200 * 32 * 1024);
    assert_eq!(MAX_MESSAGE_SIZE, 6_553_600);
}

#[test]
fn test_max_fragments_is_9500() {
    assert_eq!(MAX_FRAGMENTS_PER_MESSAGE, 9_500);
}

#[test]
fn test_stale_timeout_is_120_seconds() {
    assert_eq!(DEFAULT_STALE_TIMEOUT_SECS, 120);
}

#[test]
fn test_forward_capacity_exceeds_max_surbs() {
    let usable_per_fragment = MAX_PAYLOAD_SIZE - FRAGMENT_OVERHEAD;
    let forward_capacity = MAX_FRAGMENTS_PER_MESSAGE as usize * usable_per_fragment;
    let theoretical_max_surbs = forward_capacity / ESTIMATED_SURB_SERIALIZED_SIZE;

    assert!(
        theoretical_max_surbs >= MAX_SURBS,
        "forward capacity ({theoretical_max_surbs} SURBs) < MAX_SURBS ({MAX_SURBS})"
    );
}

#[test]
fn test_surb_payload_size_is_30kb() {
    assert_eq!(SURB_PAYLOAD_SIZE, 30 * 1024);
}

#[test]
fn test_usable_response_per_surb() {
    assert_eq!(
        USABLE_RESPONSE_PER_SURB,
        SURB_PAYLOAD_SIZE - FRAGMENT_OVERHEAD
    );
    assert_eq!(USABLE_RESPONSE_PER_SURB, 30_699);
}

#[test]
fn test_max_payload_size() {
    assert_eq!(MAX_PAYLOAD_SIZE, 31_716);
}

#[test]
fn test_default_buffer_capacity() {
    let typical_large_response = 1_000_000;
    let messages_at_capacity = DEFAULT_MAX_BUFFER_BYTES / typical_large_response;
    assert!(messages_at_capacity >= 5);
}

#[test]
fn test_shuffle_reconstruction_500kb() {
    let fragmenter = Fragmenter::new();
    let mut reassembler = Reassembler::new(ReassemblerConfig::default());

    let original: Vec<u8> = (0..500_000_u32)
        .map(|i| ((i * 7 + 13) % 256) as u8)
        .collect();

    let mut fragments = fragmenter.fragment(12345, &original, 32_000).unwrap();
    fragments.shuffle(&mut rand::thread_rng());

    let mut result = None;
    for frag in fragments {
        if let Some(data) = reassembler.add_fragment(frag).unwrap() {
            result = Some(data);
        }
    }

    let reconstructed = result.expect("Message should be reconstructed");
    assert_eq!(reconstructed.len(), original.len());
    assert_eq!(reconstructed, original);
}

#[test]
fn test_missing_fragment_no_completion() {
    let fragmenter = Fragmenter::new();
    let mut reassembler = Reassembler::new(ReassemblerConfig::default());

    let original: Vec<u8> = (0..50_000).map(|i| (i % 256) as u8).collect();
    let fragments = fragmenter.fragment(42, &original, 5_000).unwrap();
    let drop_index = 5;
    assert!(fragments.len() > drop_index);

    for (i, frag) in fragments.into_iter().enumerate() {
        if i == drop_index {
            continue;
        }
        let result = reassembler.add_fragment(frag).unwrap();
        assert!(result.is_none());
    }

    assert!(reassembler.has_message(42));
    let (received, total) = reassembler.message_progress(42).unwrap();
    assert_eq!(received, total - 1);
}

#[test]
fn test_duplicate_fragments_idempotent() {
    let fragmenter = Fragmenter::new();
    let mut reassembler = Reassembler::new(ReassemblerConfig::default());

    let original: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
    let fragments = fragmenter.fragment(99, &original, 1_000).unwrap();
    let dup_index = 2;
    assert!(fragments.len() > dup_index);

    let dup_fragment = fragments[dup_index].clone();
    for _ in 0..3 {
        let result = reassembler.add_fragment(dup_fragment.clone()).unwrap();
        assert!(result.is_none());
    }

    let mut result = None;
    for frag in fragments {
        if let Some(data) = reassembler.add_fragment(frag).unwrap() {
            result = Some(data);
        }
    }

    assert_eq!(result.unwrap(), original);
}

#[test]
fn test_corrupt_inconsistent_total_fragments() {
    let mut reassembler = Reassembler::new(ReassemblerConfig::default());

    let frag1 = Fragment::new(100, 5, 0, vec![1, 2, 3, 4, 5]).unwrap();
    reassembler.add_fragment(frag1).unwrap();

    let frag2 = Fragment {
        message_id: 100,
        total_fragments: 10,
        sequence: 1,
        data: vec![6, 7, 8, 9, 10],
        fec: None,
    };

    let err = reassembler.add_fragment(frag2).unwrap_err();
    assert!(matches!(
        err,
        FragmentationError::InconsistentMetadata {
            expected: 5,
            got: 10
        }
    ));
}

#[test]
fn test_corrupt_absurd_total_fragments() {
    let err = Fragment::new(1, u32::MAX, 0, vec![1, 2, 3]).unwrap_err();
    assert!(matches!(err, FragmentationError::TooManyFragments { .. }));

    let err = Fragment::new(1, MAX_FRAGMENTS_PER_MESSAGE + 1, 0, vec![1]).unwrap_err();
    assert!(matches!(err, FragmentationError::TooManyFragments { .. }));
}

#[test]
fn test_corrupt_invalid_sequence() {
    let err = Fragment::new(1, 10, 10, vec![1]).unwrap_err();
    assert!(matches!(
        err,
        FragmentationError::InvalidSequence { got: 10, total: 10 }
    ));

    let err = Fragment::new(1, 10, 50, vec![1]).unwrap_err();
    assert!(matches!(err, FragmentationError::InvalidSequence { .. }));
}

#[test]
fn test_prune_stale_messages() {
    let config = ReassemblerConfig {
        max_buffer_bytes: 1_000_000,
        max_concurrent_messages: 100,
        stale_timeout: Duration::from_millis(50),
    };
    let mut reassembler = Reassembler::new(config);

    for msg_id in 0..10 {
        let frag = Fragment::new(msg_id, 100, 0, vec![0u8; 100]).unwrap();
        reassembler.add_fragment(frag).unwrap();
    }
    assert_eq!(reassembler.pending_count(), 10);

    std::thread::sleep(Duration::from_millis(100));

    let pruned = reassembler.prune_stale(Duration::from_millis(50));
    assert_eq!(pruned, 10);
    assert_eq!(reassembler.pending_count(), 0);
    assert_eq!(reassembler.buffered_bytes(), 0);
}

#[test]
fn test_memory_limit_eviction() {
    let config = ReassemblerConfig {
        max_buffer_bytes: 1000,
        max_concurrent_messages: 3,
        stale_timeout: Duration::from_secs(60),
    };
    let mut reassembler = Reassembler::new(config);

    for msg_id in 0_u64..5 {
        let frag = Fragment::new(msg_id, 10, 0, vec![0u8; 200]).unwrap();
        reassembler.add_fragment(frag).unwrap();
        std::thread::sleep(Duration::from_millis(10));
    }

    assert!(reassembler.pending_count() <= 3);
    assert!(!reassembler.has_message(0));
    assert!(!reassembler.has_message(1));
    assert!(reassembler.has_message(4));
}

#[test]
fn test_max_message_size_roundtrip() {
    let fragmenter = Fragmenter::new();
    let mut reassembler = Reassembler::new(ReassemblerConfig {
        max_buffer_bytes: 100_000_000,
        max_concurrent_messages: 10,
        stale_timeout: Duration::from_secs(60),
    });

    let size = 640 * 1024;
    let original: Vec<u8> = (0..size as u32).map(|i| (i % 256) as u8).collect();

    let fragments = fragmenter.fragment(1, &original, 32_000).unwrap();

    let mut result = None;
    for frag in fragments {
        if let Some(data) = reassembler.add_fragment(frag).unwrap() {
            result = Some(data);
        }
    }

    assert_eq!(result.unwrap(), original);
}

#[test]
fn test_message_too_large_rejected() {
    let fragmenter = Fragmenter::with_max_size(10_000);

    let too_large = vec![0u8; 20_000];
    let err = fragmenter.fragment(1, &too_large, 1000).unwrap_err();

    assert!(matches!(
        err,
        FragmentationError::MessageTooLarge {
            size: 20000,
            max: 10000
        }
    ));
}

#[test]
fn test_max_achievable_message_roundtrip() {
    let fragmenter = Fragmenter::new();
    let mut reassembler = Reassembler::new(ReassemblerConfig {
        max_buffer_bytes: 100_000_000,
        max_concurrent_messages: 10,
        stale_timeout: Duration::from_secs(60),
    });

    // Forward-path max is bounded by MAX_MESSAGE_SIZE (~6.25 MB), not
    // MAX_FRAGMENTS_PER_MESSAGE (9500). Use the forward-path limit.
    let usable = Fragmenter::usable_payload_size(MAX_PAYLOAD_SIZE);
    let max_forward_fragments = MAX_MESSAGE_SIZE / usable;
    let max_achievable = max_forward_fragments * usable;

    let original: Vec<u8> = (0..max_achievable as u32)
        .map(|i| ((i * 7 + 13) % 256) as u8)
        .collect();

    let fragments = fragmenter.fragment(1, &original, MAX_PAYLOAD_SIZE).unwrap();
    assert_eq!(fragments.len(), max_forward_fragments);

    let mut result = None;
    for frag in fragments {
        if let Some(data) = reassembler.add_fragment(frag).unwrap() {
            result = Some(data);
        }
    }

    assert_eq!(result.expect("reassembly incomplete"), original);
}

#[test]
fn test_max_achievable_shuffled_reassembly() {
    let fragmenter = Fragmenter::new();
    let mut reassembler = Reassembler::new(ReassemblerConfig {
        max_buffer_bytes: 100_000_000,
        max_concurrent_messages: 10,
        stale_timeout: Duration::from_secs(60),
    });

    // Forward-path max bounded by MAX_MESSAGE_SIZE (~6.25 MB)
    let usable = Fragmenter::usable_payload_size(MAX_PAYLOAD_SIZE);
    let max_forward_fragments = MAX_MESSAGE_SIZE / usable;
    let max_achievable = max_forward_fragments * usable;

    let original: Vec<u8> = (0..max_achievable as u32)
        .map(|i| ((i * 11 + 3) % 256) as u8)
        .collect();

    let mut fragments = fragmenter
        .fragment(42, &original, MAX_PAYLOAD_SIZE)
        .unwrap();
    fragments.shuffle(&mut rand::thread_rng());

    let mut result = None;
    for frag in fragments {
        if let Some(data) = reassembler.add_fragment(frag).unwrap() {
            result = Some(data);
        }
    }

    assert_eq!(result.expect("shuffled reassembly failed"), original);
}

#[test]
fn test_exactly_200_fragments() {
    let fragmenter = Fragmenter::new();
    let mut reassembler = Reassembler::new(ReassemblerConfig {
        max_buffer_bytes: 100_000_000,
        max_concurrent_messages: 10,
        stale_timeout: Duration::from_secs(60),
    });

    let usable_per_fragment = Fragmenter::usable_payload_size(MAX_PAYLOAD_SIZE);
    let target_size = usable_per_fragment * 200;
    let size = target_size.min(MAX_MESSAGE_SIZE);

    let original: Vec<u8> = (0..size as u32).map(|i| (i % 256) as u8).collect();

    let fragments = fragmenter
        .fragment(100, &original, MAX_PAYLOAD_SIZE)
        .unwrap();
    assert_eq!(fragments.len(), 200);

    for (i, frag) in fragments.iter().enumerate() {
        assert_eq!(frag.message_id, 100);
        assert_eq!(frag.total_fragments, 200);
        assert_eq!(frag.sequence, i as u32);
    }

    let mut result = None;
    for frag in fragments {
        if let Some(data) = reassembler.add_fragment(frag).unwrap() {
            result = Some(data);
        }
    }

    assert_eq!(result.unwrap(), original);
}

#[test]
fn test_interleaved_messages_chaos() {
    let fragmenter = Fragmenter::new();
    let mut reassembler = Reassembler::new(ReassemblerConfig {
        max_buffer_bytes: 50_000_000,
        max_concurrent_messages: 100,
        stale_timeout: Duration::from_secs(60),
    });

    let mut rng = rand::thread_rng();
    let num_messages = 20;
    let message_size = 10_000;

    let mut all_fragments: Vec<(u64, Fragment)> = Vec::new();
    let mut originals: Vec<(u64, Vec<u8>)> = Vec::new();

    for msg_id in 0..num_messages {
        let data: Vec<u8> = (0..message_size)
            .map(|i| ((msg_id as usize * 1000 + i) % 256) as u8)
            .collect();
        let frags = fragmenter.fragment(msg_id, &data, 1000).unwrap();
        for frag in frags {
            all_fragments.push((msg_id, frag));
        }
        originals.push((msg_id, data));
    }

    all_fragments.shuffle(&mut rng);

    let mut completed: Vec<(u64, Vec<u8>)> = Vec::new();
    for (_expected_id, frag) in all_fragments {
        let msg_id = frag.message_id;
        if let Some(data) = reassembler.add_fragment(frag).unwrap() {
            completed.push((msg_id, data));
        }
    }

    assert_eq!(completed.len(), num_messages as usize);

    for (msg_id, data) in completed {
        let expected = originals
            .iter()
            .find(|(id, _)| *id == msg_id)
            .map(|(_, d)| d)
            .unwrap();
        assert_eq!(&data, expected, "message {msg_id} corrupted");
    }
}

#[test]
fn test_single_fragment_message() {
    let fragmenter = Fragmenter::new();
    let mut reassembler = Reassembler::new(ReassemblerConfig::default());

    let original = vec![1, 2, 3, 4, 5];
    let fragments = fragmenter.fragment(1, &original, 10_000).unwrap();

    assert_eq!(fragments.len(), 1);
    assert_eq!(fragments[0].total_fragments, 1);
    assert_eq!(fragments[0].sequence, 0);

    let result = reassembler
        .add_fragment(fragments.into_iter().next().unwrap())
        .unwrap();
    assert_eq!(result.unwrap(), original);
}

#[test]
fn test_exact_chunk_size_fit() {
    let fragmenter = Fragmenter::new();
    let mut reassembler = Reassembler::new(ReassemblerConfig::default());

    let chunk_size = 1000;
    let usable = chunk_size - 20;
    let original: Vec<u8> = (0..(usable * 3)).map(|i| (i % 256) as u8).collect();

    let fragments = fragmenter.fragment(1, &original, chunk_size).unwrap();

    let mut result = None;
    for frag in fragments {
        if let Some(data) = reassembler.add_fragment(frag).unwrap() {
            result = Some(data);
        }
    }

    assert_eq!(result.unwrap(), original);
}

#[test]
fn test_empty_message_rejected() {
    let fragmenter = Fragmenter::new();
    let err = fragmenter.fragment(1, &[], 1000).unwrap_err();
    assert!(matches!(err, FragmentationError::EmptyMessage));
}

#[test]
fn test_fragment_serialization_roundtrip() {
    let frag = Fragment::new(
        0xDEADBEEF_CAFEBABE,
        150,
        75,
        (0..1000).map(|i| (i % 256) as u8).collect(),
    )
    .unwrap();

    let bytes = frag.to_bytes().unwrap();
    let recovered = Fragment::from_bytes(&bytes).unwrap();

    assert_eq!(frag.message_id, recovered.message_id);
    assert_eq!(frag.total_fragments, recovered.total_fragments);
    assert_eq!(frag.sequence, recovered.sequence);
    assert_eq!(frag.data, recovered.data);
}

#[test]
fn test_forward_fragmentation_with_surb_payload() {
    let fragmenter = Fragmenter::new();
    let mut reassembler = Reassembler::new(ReassemblerConfig {
        max_buffer_bytes: 100_000_000,
        max_concurrent_messages: 10,
        stale_timeout: Duration::from_secs(60),
    });

    let inner_request_size = 200;
    let surb_count = 100;
    let total_surb_bytes = surb_count * ESTIMATED_SURB_SERIALIZED_SIZE;
    let overhead = 50;
    let total_payload_size = inner_request_size + total_surb_bytes + overhead;

    let payload: Vec<u8> = (0..total_payload_size as u32)
        .map(|i| (i % 256) as u8)
        .collect();

    let fragments = fragmenter
        .fragment(999, &payload, MAX_PAYLOAD_SIZE)
        .unwrap();
    assert!(fragments.len() >= 2);

    let mut result = None;
    for frag in fragments {
        if let Some(data) = reassembler.add_fragment(frag).unwrap() {
            result = Some(data);
        }
    }

    assert_eq!(result.unwrap(), payload);
}

#[test]
fn test_forward_fragmentation_max_surbs() {
    let fragmenter = Fragmenter::new();
    let mut reassembler = Reassembler::new(ReassemblerConfig {
        max_buffer_bytes: 100_000_000,
        max_concurrent_messages: 10,
        stale_timeout: Duration::from_secs(60),
    });

    let total_surb_bytes = MAX_SURBS * ESTIMATED_SURB_SERIALIZED_SIZE;
    let total_payload = total_surb_bytes + 300;

    assert!(total_payload <= MAX_MESSAGE_SIZE);

    let payload: Vec<u8> = (0..total_payload as u32).map(|i| (i % 256) as u8).collect();

    let fragments = fragmenter
        .fragment(7777, &payload, MAX_PAYLOAD_SIZE)
        .unwrap();
    assert!(fragments.len() <= MAX_FRAGMENTS_PER_MESSAGE as usize);

    let mut result = None;
    for frag in fragments {
        if let Some(data) = reassembler.add_fragment(frag).unwrap() {
            result = Some(data);
        }
    }

    assert_eq!(result.unwrap(), payload);
}

#[test]
fn test_surb_response_reassembly_simulation() {
    let fragmenter = Fragmenter::new();
    let mut reassembler = Reassembler::new(ReassemblerConfig {
        max_buffer_bytes: 50_000_000,
        max_concurrent_messages: 10,
        stale_timeout: Duration::from_secs(60),
    });

    let response_size = 500_000;
    let response: Vec<u8> = (0..response_size as u32)
        .map(|i| ((i * 3 + 17) % 256) as u8)
        .collect();

    let mut fragments = fragmenter
        .fragment(1234, &response, SURB_PAYLOAD_SIZE)
        .unwrap();
    let expected_surbs = fragments.len();

    let budget = SurbBudget::for_response_size(response_size);
    assert!(budget.surb_count() >= expected_surbs);

    fragments.shuffle(&mut rand::thread_rng());

    let mut result = None;
    for frag in fragments {
        if let Some(data) = reassembler.add_fragment(frag).unwrap() {
            result = Some(data);
        }
    }

    assert_eq!(result.unwrap(), response);
}

#[test]
fn test_concurrent_surb_response_reassembly() {
    let fragmenter = Fragmenter::new();
    let mut reassembler = Reassembler::new(ReassemblerConfig {
        max_buffer_bytes: 100_000_000,
        max_concurrent_messages: 100,
        stale_timeout: Duration::from_secs(60),
    });

    let mut rng = rand::thread_rng();
    let num_requests = 10;

    let mut originals: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut all_fragments: Vec<Fragment> = Vec::new();

    for req_id in 0..num_requests {
        let size = (req_id as usize + 1) * 30_000;
        let data: Vec<u8> = (0..size as u32)
            .map(|i| ((req_id as u32 * 1000 + i) % 256) as u8)
            .collect();

        let frags = fragmenter
            .fragment(req_id, &data, SURB_PAYLOAD_SIZE)
            .unwrap();
        all_fragments.extend(frags);
        originals.push((req_id, data));
    }

    all_fragments.shuffle(&mut rng);

    let mut completed: Vec<(u64, Vec<u8>)> = Vec::new();
    for frag in all_fragments {
        let msg_id = frag.message_id;
        if let Some(data) = reassembler.add_fragment(frag).unwrap() {
            completed.push((msg_id, data));
        }
    }

    assert_eq!(completed.len(), num_requests as usize);

    for (msg_id, data) in &completed {
        let expected = originals
            .iter()
            .find(|(id, _)| id == msg_id)
            .map(|(_, d)| d)
            .unwrap();
        assert_eq!(data, expected, "request {msg_id} corrupted");
    }
}
