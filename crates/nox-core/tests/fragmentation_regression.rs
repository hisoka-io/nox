//! Regression tests for fragmentation edge cases.

use nox_core::protocol::fragmentation::{
    Fragment, FragmentationError, Fragmenter, Reassembler, ReassemblerConfig,
};
use std::time::Duration;

#[test]
fn test_duplicate_before_ensure_capacity() {
    let config = ReassemblerConfig {
        max_buffer_bytes: 100_000,
        max_concurrent_messages: 2, // Only 2 slots
        stale_timeout: Duration::from_secs(60),
    };
    let mut reassembler = Reassembler::new(config);

    let frag_a = Fragment::new(100, 10, 0, vec![0xAA; 500]).unwrap();
    let frag_b = Fragment::new(200, 10, 0, vec![0xBB; 500]).unwrap();
    reassembler.add_fragment(frag_a.clone()).unwrap();
    reassembler.add_fragment(frag_b).unwrap();
    assert_eq!(reassembler.pending_count(), 2);

    reassembler.add_fragment(frag_a).unwrap();
    assert_eq!(reassembler.pending_count(), 2);
    assert!(
        reassembler.has_message(100),
        "Message 100 should survive duplicate"
    );
    assert!(
        reassembler.has_message(200),
        "Message 200 should survive duplicate"
    );
}

#[test]
fn test_duplicate_sequence_same_data_accepted() {
    let mut reassembler = Reassembler::new(ReassemblerConfig::default());

    let frag = Fragment::new(42, 5, 0, vec![1, 2, 3, 4, 5]).unwrap();

    reassembler.add_fragment(frag.clone()).unwrap();
    let result = reassembler.add_fragment(frag).unwrap();
    assert!(result.is_none());
    let (received, total) = reassembler.message_progress(42).unwrap();
    assert_eq!(received, 1);
    assert_eq!(total, 5);
}

#[test]
fn test_duplicate_sequence_different_data_rejected() {
    let mut reassembler = Reassembler::new(ReassemblerConfig::default());

    let frag1 = Fragment::new(42, 5, 0, vec![1, 2, 3]).unwrap();
    reassembler.add_fragment(frag1).unwrap();

    let frag2 = Fragment::new(42, 5, 0, vec![9, 9, 9]).unwrap();
    let err = reassembler.add_fragment(frag2).unwrap_err();

    assert!(
        matches!(
            err,
            FragmentationError::DuplicateDataMismatch {
                message_id: 42,
                sequence: 0
            }
        ),
        "Expected DuplicateDataMismatch, got: {:?}",
        err
    );
}

#[test]
fn test_full_reassembly_with_duplicate_fragment() {
    let fragmenter = Fragmenter::new();
    let mut reassembler = Reassembler::new(ReassemblerConfig::default());

    let original: Vec<u8> = (0..5_000).map(|i| (i % 256) as u8).collect();
    let fragments = fragmenter.fragment(1, &original, 1_000).unwrap();

    let dup = fragments[2].clone();
    reassembler.add_fragment(dup).unwrap();

    let mut result = None;
    for frag in fragments {
        if let Some(data) = reassembler.add_fragment(frag).unwrap() {
            result = Some(data);
        }
    }

    assert_eq!(
        result.unwrap(),
        original,
        "Data should reconstruct correctly despite duplicate"
    );
}
