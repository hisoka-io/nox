//! Fragmentation chaos tests: shuffle, drops, duplicates, corruption, memory pressure.

use nox_core::protocol::fragmentation::{
    Fragment, FragmentationError, Fragmenter, Reassembler, ReassemblerConfig,
    MAX_FRAGMENTS_PER_MESSAGE,
};
use rand::seq::SliceRandom;
use std::time::Duration;

#[test]
fn test_shuffle_reconstruction_500kb() {
    let fragmenter = Fragmenter::new();
    let mut reassembler = Reassembler::new(ReassemblerConfig::default());

    let original: Vec<u8> = (0..500_000_u32)
        .map(|i| ((i * 7 + 13) % 256) as u8)
        .collect();

    let mut fragments = fragmenter.fragment(12345, &original, 32_000).unwrap();
    let fragment_count = fragments.len();
    println!("Generated {} fragments for 500KB message", fragment_count);

    let mut rng = rand::thread_rng();
    fragments.shuffle(&mut rng);

    let mut result = None;
    for (i, frag) in fragments.into_iter().enumerate() {
        if let Some(data) = reassembler.add_fragment(frag).unwrap() {
            result = Some(data);
            println!("Message completed at fragment #{}", i + 1);
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
            println!("Dropping fragment #{}", i);
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

    let reconstructed = result.expect("Should complete");
    assert_eq!(reconstructed, original);
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
    assert!(
        matches!(
            err,
            FragmentationError::InconsistentMetadata {
                expected: 5,
                got: 10
            }
        ),
        "got {err:?} instead of InconsistentMetadata"
    );
}

#[test]
fn test_corrupt_absurd_total_fragments() {
    let err = Fragment::new(1, u32::MAX, 0, vec![1, 2, 3]).unwrap_err();
    assert!(
        matches!(err, FragmentationError::TooManyFragments { .. }),
        "got {err:?} instead of TooManyFragments"
    );

    let err = Fragment::new(1, MAX_FRAGMENTS_PER_MESSAGE + 1, 0, vec![1]).unwrap_err();
    assert!(matches!(err, FragmentationError::TooManyFragments { .. }));
}

#[test]
fn test_corrupt_invalid_sequence() {
    let err = Fragment::new(1, 10, 10, vec![1]).unwrap_err();
    assert!(
        matches!(
            err,
            FragmentationError::InvalidSequence { got: 10, total: 10 }
        ),
        "got {err:?} instead of InvalidSequence"
    );

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
        max_buffer_bytes: 1000,     // Very small: 1KB
        max_concurrent_messages: 3, // Max 3 messages
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
        max_buffer_bytes: 100_000_000, // 100MB for test
        max_concurrent_messages: 10,
        stale_timeout: Duration::from_secs(60),
    });

    let size = 640 * 1024;
    let original: Vec<u8> = (0..size as u32).map(|i| (i % 256) as u8).collect();

    let fragments = fragmenter.fragment(1, &original, 32_000).unwrap();
    println!("640KB message fragmented into {} chunks", fragments.len());

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

    assert!(
        matches!(
            err,
            FragmentationError::MessageTooLarge {
                size: 20000,
                max: 10000
            }
        ),
        "got {err:?} instead of MessageTooLarge"
    );
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
    println!("Total fragments: {}, shuffled", all_fragments.len());

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
