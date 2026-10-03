//! Reed-Solomon FEC for SURB responses. D-of-(D+P) reconstruction over GF(2^8).
//! Applied response-path only (exit -> client). All shards must be uniform size
//! (last data shard zero-padded); output truncated to `original_data_len`.

use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// GF(2^8) Reed-Solomon supports at most 255 shards (data + parity).
pub const MAX_TOTAL_SHARDS: usize = 255;

/// FEC parameters carried on every fragment (12 bytes). Present on all fragments
/// because any could be dropped and the reassembler needs these from whichever arrives first.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FecInfo {
    pub data_shard_count: u32,
    /// Used to truncate zero-padding from the last data shard after reconstruction.
    pub original_data_len: u64,
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum FecError {
    #[error("No data shards provided")]
    EmptyDataShards,

    #[error("Zero parity shards requested")]
    ZeroParityShards,

    #[error("Total shards {total} exceeds GF(2^8) limit of 255 (data={data}, parity={parity})")]
    TooManyShards {
        data: usize,
        parity: usize,
        total: usize,
    },

    #[error(
        "Non-uniform shard sizes: first shard is {expected} bytes, shard {index} is {got} bytes"
    )]
    NonUniformShards {
        expected: usize,
        index: usize,
        got: usize,
    },

    #[error("Empty shard data (all shards must be non-empty)")]
    EmptyShardData,

    #[error("Reed-Solomon encoder creation failed: {0}")]
    EncoderCreationFailed(String),

    #[error("Reed-Solomon encoding failed: {0}")]
    EncodingFailed(String),

    #[error("Reed-Solomon reconstruction failed: {0}")]
    ReconstructionFailed(String),

    #[error(
        "Insufficient shards for reconstruction: have {available}, need {required} (data_shard_count)"
    )]
    InsufficientShards { available: usize, required: usize },

    #[error("Shard array length {got} does not match expected {expected} (data + parity)")]
    ShardCountMismatch { expected: usize, got: usize },

    #[error(
        "original_data_len {original_data_len} exceeds the {max} bytes carried by {data_shards} data shards of {shard_len} bytes"
    )]
    OriginalLengthOutOfRange {
        original_data_len: u64,
        max: u64,
        data_shards: usize,
        shard_len: usize,
    },
}

/// Generate parity shards from uniform-length data shards using Reed-Solomon.
/// Caller MUST zero-pad the last data shard to match the others before calling.
pub fn encode_parity_shards(
    data_shards: &[Vec<u8>],
    parity_count: usize,
) -> Result<Vec<Vec<u8>>, FecError> {
    if data_shards.is_empty() {
        return Err(FecError::EmptyDataShards);
    }
    if parity_count == 0 {
        return Err(FecError::ZeroParityShards);
    }

    let total = data_shards.len() + parity_count;
    if total > MAX_TOTAL_SHARDS {
        return Err(FecError::TooManyShards {
            data: data_shards.len(),
            parity: parity_count,
            total,
        });
    }

    let shard_size = data_shards[0].len();
    if shard_size == 0 {
        return Err(FecError::EmptyShardData);
    }

    for (i, shard) in data_shards.iter().enumerate().skip(1) {
        if shard.len() != shard_size {
            return Err(FecError::NonUniformShards {
                expected: shard_size,
                index: i,
                got: shard.len(),
            });
        }
    }

    let rs = ReedSolomon::new(data_shards.len(), parity_count)
        .map_err(|e| FecError::EncoderCreationFailed(e.to_string()))?;

    let mut parity: Vec<Vec<u8>> = (0..parity_count).map(|_| vec![0u8; shard_size]).collect();

    let data_refs: Vec<&[u8]> = data_shards.iter().map(Vec::as_slice).collect();
    let mut parity_refs: Vec<&mut [u8]> = parity.iter_mut().map(Vec::as_mut_slice).collect();

    rs.encode_sep(&data_refs, &mut parity_refs)
        .map_err(|e| FecError::EncodingFailed(e.to_string()))?;

    Ok(parity)
}

/// Pad data shards to uniform size for RS alignment. Last chunk is zero-padded.
pub fn pad_to_uniform(data_chunks: &[Vec<u8>]) -> Result<(Vec<Vec<u8>>, usize), FecError> {
    if data_chunks.is_empty() {
        return Err(FecError::EmptyDataShards);
    }

    let shard_size = data_chunks[0].len();
    let padded: Vec<Vec<u8>> = data_chunks
        .iter()
        .map(|chunk| {
            if chunk.len() == shard_size {
                chunk.clone()
            } else {
                let mut padded = chunk.clone();
                padded.resize(shard_size, 0);
                padded
            }
        })
        .collect();

    Ok((padded, shard_size))
}

/// Checks that every present shard is non-empty and the same length, and returns that length.
/// Returns `None` when no shard is present.
fn uniform_shard_len(shards: &[Option<Vec<u8>>]) -> Result<Option<usize>, FecError> {
    let mut expected: Option<usize> = None;
    for (index, shard) in shards.iter().enumerate() {
        let Some(data) = shard else { continue };
        if data.is_empty() {
            return Err(FecError::EmptyShardData);
        }
        match expected {
            None => expected = Some(data.len()),
            Some(len) if len != data.len() => {
                return Err(FecError::NonUniformShards {
                    expected: len,
                    index,
                    got: data.len(),
                });
            }
            Some(_) => {}
        }
    }
    Ok(expected)
}

/// Bounds `original_data_len` by the bytes the data shards actually carry, so the output
/// allocation never exceeds the received data.
fn bounded_output_len(
    data_shard_count: usize,
    shard_len: usize,
    original_data_len: u64,
) -> Result<usize, FecError> {
    let max = u64::try_from(data_shard_count)
        .ok()
        .zip(u64::try_from(shard_len).ok())
        .and_then(|(d, len)| d.checked_mul(len))
        .unwrap_or(u64::MAX);
    let out_of_range = || FecError::OriginalLengthOutOfRange {
        original_data_len,
        max,
        data_shards: data_shard_count,
        shard_len,
    };
    if original_data_len > max {
        return Err(out_of_range());
    }
    usize::try_from(original_data_len).map_err(|_| out_of_range())
}

/// Reconstruct original data from a (possibly incomplete) set of D+P shard slots.
/// Fast path if all data shards present; RS reconstruction otherwise.
///
/// Inputs may come from an untrusted peer: shard counts, shard lengths and
/// `original_data_len` are validated before any allocation, and every failure is a typed error.
pub fn decode_shards(
    shards: &mut [Option<Vec<u8>>],
    data_shard_count: usize,
    original_data_len: u64,
) -> Result<Vec<u8>, FecError> {
    if data_shard_count == 0 {
        return Err(FecError::EmptyDataShards);
    }

    let total_shards = shards.len();
    if total_shards < data_shard_count {
        return Err(FecError::ShardCountMismatch {
            expected: data_shard_count,
            got: total_shards,
        });
    }

    let parity_count = total_shards - data_shard_count;

    let available = shards.iter().filter(|s| s.is_some()).count();
    if available < data_shard_count {
        return Err(FecError::InsufficientShards {
            available,
            required: data_shard_count,
        });
    }

    let Some(shard_len) = uniform_shard_len(shards)? else {
        return Err(FecError::InsufficientShards {
            available,
            required: data_shard_count,
        });
    };
    let output_len = bounded_output_len(data_shard_count, shard_len, original_data_len)?;

    let all_data_present = shards[..data_shard_count].iter().all(Option::is_some);
    if !all_data_present {
        if parity_count == 0 {
            return Err(FecError::InsufficientShards {
                available,
                required: data_shard_count,
            });
        }
        if total_shards > MAX_TOTAL_SHARDS {
            return Err(FecError::TooManyShards {
                data: data_shard_count,
                parity: parity_count,
                total: total_shards,
            });
        }

        let rs = ReedSolomon::new(data_shard_count, parity_count)
            .map_err(|e| FecError::EncoderCreationFailed(e.to_string()))?;

        rs.reconstruct(shards)
            .map_err(|e| FecError::ReconstructionFailed(e.to_string()))?;
    }

    let mut result = Vec::with_capacity(output_len);
    for shard in &shards[..data_shard_count] {
        let Some(data) = shard.as_ref() else {
            return Err(FecError::ReconstructionFailed(
                "RS reconstruction did not fill all data shards".to_string(),
            ));
        };
        let remaining = output_len - result.len();
        result.extend_from_slice(&data[..data.len().min(remaining)]);
        if result.len() == output_len {
            break;
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_data_shards(data: &[u8], shard_size: usize) -> Vec<Vec<u8>> {
        let chunks: Vec<Vec<u8>> = data.chunks(shard_size).map(|c| c.to_vec()).collect();
        let (padded, _) = pad_to_uniform(&chunks).unwrap();
        padded
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let original = b"Hello, Reed-Solomon FEC for mixnet responses!".to_vec();
        let shard_size = 16;
        let data_shards = make_data_shards(&original, shard_size);
        let d = data_shards.len(); // 3 data shards

        let parity = encode_parity_shards(&data_shards, 2).unwrap();
        assert_eq!(parity.len(), 2);
        assert!(parity.iter().all(|p| p.len() == shard_size));

        let mut shards: Vec<Option<Vec<u8>>> = data_shards
            .iter()
            .chain(parity.iter())
            .map(|s| Some(s.clone()))
            .collect();

        let recovered = decode_shards(&mut shards, d, original.len() as u64).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_single_data_shard_recovery() {
        let original = b"Short message".to_vec();
        let shard_size = original.len();
        let data_shards = vec![original.clone()]; // D=1

        let parity = encode_parity_shards(&data_shards, 1).unwrap(); // P=1
        assert_eq!(parity.len(), 1);
        assert_eq!(parity[0].len(), shard_size);

        let mut shards: Vec<Option<Vec<u8>>> = vec![None, Some(parity[0].clone())];

        let recovered = decode_shards(&mut shards, 1, original.len() as u64).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_fast_path_no_rs_needed() {
        let original: Vec<u8> = (0..100).collect();
        let shard_size = 25;
        let data_shards = make_data_shards(&original, shard_size);
        let d = data_shards.len(); // 4

        let parity = encode_parity_shards(&data_shards, 2).unwrap();

        let mut shards: Vec<Option<Vec<u8>>> = data_shards
            .iter()
            .map(|s| Some(s.clone()))
            .chain(std::iter::repeat_with(|| None).take(parity.len()))
            .collect();

        let recovered = decode_shards(&mut shards, d, original.len() as u64).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_drop_data_shard_rs_recovery() {
        let original: Vec<u8> = (0..300).map(|i| (i % 256) as u8).collect();
        let shard_size = 100;
        let data_shards = make_data_shards(&original, shard_size);
        let d = data_shards.len(); // 3

        let parity = encode_parity_shards(&data_shards, 2).unwrap();

        let mut shards: Vec<Option<Vec<u8>>> = vec![
            Some(data_shards[0].clone()),
            None, // dropped!
            Some(data_shards[2].clone()),
            Some(parity[0].clone()),
            Some(parity[1].clone()),
        ];

        let recovered = decode_shards(&mut shards, d, original.len() as u64).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_padding_edge_case() {
        let original: Vec<u8> = (0..50).collect();
        let shard_size = 16;
        let data_shards = make_data_shards(&original, shard_size);
        let d = data_shards.len(); // ceil(50/16) = 4

        assert_eq!(d, 4);
        assert!(data_shards.iter().all(|s| s.len() == shard_size));
        assert_eq!(data_shards[3][2..], vec![0u8; 14]);

        let parity = encode_parity_shards(&data_shards, 1).unwrap();

        let mut shards: Vec<Option<Vec<u8>>> = data_shards
            .iter()
            .chain(parity.iter())
            .map(|s| Some(s.clone()))
            .collect();

        let recovered = decode_shards(&mut shards, d, original.len() as u64).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_max_shard_boundary() {
        let shard_size = 8;
        let data_shards: Vec<Vec<u8>> = (0..200).map(|i| vec![i as u8; shard_size]).collect();

        let parity = encode_parity_shards(&data_shards, 55).unwrap(); // 200 + 55 = 255
        assert_eq!(parity.len(), 55);

        let result = encode_parity_shards(&data_shards, 56);
        assert!(matches!(
            result,
            Err(FecError::TooManyShards { total: 256, .. })
        ));
    }

    #[test]
    fn test_insufficient_shards_error() {
        let original: Vec<u8> = (0..300).map(|i| (i % 256) as u8).collect();
        let shard_size = 100;
        let data_shards = make_data_shards(&original, shard_size);
        let d = data_shards.len(); // 3

        let parity = encode_parity_shards(&data_shards, 2).unwrap();

        let mut shards: Vec<Option<Vec<u8>>> = vec![
            None,
            None,
            Some(data_shards[2].clone()),
            None,
            Some(parity[1].clone()),
        ];

        let result = decode_shards(&mut shards, d, original.len() as u64);
        assert!(matches!(
            result,
            Err(FecError::InsufficientShards {
                available: 2,
                required: 3,
            })
        ));
    }

    #[test]
    fn test_fec_info_serialization_roundtrip() {
        let info = FecInfo {
            data_shard_count: 10,
            original_data_len: 307_000,
        };

        let bytes = bincode::serialize(&info).unwrap();
        let recovered: FecInfo = bincode::deserialize(&bytes).unwrap();
        assert_eq!(info, recovered);

        assert_eq!(bytes.len(), 12); // u32 (4) + u64 (8)
    }

    #[test]
    fn test_option_fec_info_none_overhead() {
        let none_info: Option<FecInfo> = None;
        let bytes = bincode::serialize(&none_info).unwrap();
        assert!(bytes.len() <= 4);

        let some_info: Option<FecInfo> = Some(FecInfo {
            data_shard_count: 10,
            original_data_len: 307_000,
        });
        let some_bytes = bincode::serialize(&some_info).unwrap();
        assert!(some_bytes.len() <= 16);
    }

    #[test]
    fn test_empty_data_shards_error() {
        let result = encode_parity_shards(&[], 2);
        assert!(matches!(result, Err(FecError::EmptyDataShards)));
    }

    #[test]
    fn test_zero_parity_error() {
        let shards = vec![vec![1u8, 2, 3]];
        let result = encode_parity_shards(&shards, 0);
        assert!(matches!(result, Err(FecError::ZeroParityShards)));
    }

    #[test]
    fn test_non_uniform_shards_error() {
        let shards = vec![vec![1u8, 2, 3], vec![4u8, 5]];
        let result = encode_parity_shards(&shards, 1);
        assert!(matches!(
            result,
            Err(FecError::NonUniformShards {
                expected: 3,
                index: 1,
                got: 2,
            })
        ));
    }

    #[test]
    fn test_pad_to_uniform() {
        let chunks = vec![vec![1, 2, 3, 4, 5], vec![6, 7, 8, 9, 10], vec![11, 12]];

        let (padded, shard_size) = pad_to_uniform(&chunks).unwrap();
        assert_eq!(shard_size, 5);
        assert_eq!(padded.len(), 3);
        assert!(padded.iter().all(|s| s.len() == 5));
        assert_eq!(padded[2], vec![11, 12, 0, 0, 0]);
    }

    #[test]
    fn test_pad_to_uniform_empty_error() {
        let result = pad_to_uniform(&[]);
        assert!(matches!(result, Err(FecError::EmptyDataShards)));
    }

    #[test]
    fn test_large_payload_fec() {
        let original: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let shard_size = 30_700;
        let data_shards = make_data_shards(&original, shard_size);
        let d = data_shards.len(); // ceil(100000/30700) = 4

        let p = ((d as f64) * 0.3).ceil() as usize; // 30% FEC = 2
        let parity = encode_parity_shards(&data_shards, p).unwrap();

        let mut shards: Vec<Option<Vec<u8>>> = data_shards
            .iter()
            .chain(parity.iter())
            .map(|s| Some(s.clone()))
            .collect();

        shards[1] = None;
        shards[d] = None;

        let recovered = decode_shards(&mut shards, d, original.len() as u64).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_drop_all_parity_fast_path() {
        let original: Vec<u8> = (0..200).collect();
        let shard_size = 50;
        let data_shards = make_data_shards(&original, shard_size);
        let d = data_shards.len();

        let parity = encode_parity_shards(&data_shards, 3).unwrap();

        let mut shards: Vec<Option<Vec<u8>>> = data_shards
            .iter()
            .map(|s| Some(s.clone()))
            .chain(std::iter::repeat_with(|| None).take(parity.len()))
            .collect();

        let recovered = decode_shards(&mut shards, d, original.len() as u64).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_mixed_data_and_parity_drops() {
        let original: Vec<u8> = (0..500).map(|i| (i % 256) as u8).collect();
        let shard_size = 100;
        let data_shards = make_data_shards(&original, shard_size);
        let d = data_shards.len(); // 5

        let parity = encode_parity_shards(&data_shards, 3).unwrap(); // P=3

        let mut shards: Vec<Option<Vec<u8>>> = data_shards
            .iter()
            .chain(parity.iter())
            .map(|s| Some(s.clone()))
            .collect();

        shards[0] = None;
        shards[3] = None;
        shards[5] = None;
        let recovered = decode_shards(&mut shards, d, original.len() as u64).unwrap();
        assert_eq!(recovered, original);
    }

    fn encoded_shards(original: &[u8], shard_size: usize, parity: usize) -> Vec<Option<Vec<u8>>> {
        let data_shards = make_data_shards(original, shard_size);
        let parity = encode_parity_shards(&data_shards, parity).unwrap();
        data_shards
            .iter()
            .chain(parity.iter())
            .map(|s| Some(s.clone()))
            .collect()
    }

    #[test]
    fn test_huge_original_len_fast_path_rejected() {
        let mut shards = encoded_shards(&[7u8; 100], 50, 1);
        let result = decode_shards(&mut shards, 2, u64::MAX);
        assert!(matches!(
            result,
            Err(FecError::OriginalLengthOutOfRange {
                original_data_len: u64::MAX,
                max: 100,
                data_shards: 2,
                shard_len: 50,
            })
        ));
    }

    #[test]
    fn test_huge_original_len_rs_path_rejected() {
        let mut shards = encoded_shards(&[7u8; 100], 50, 1);
        shards[0] = None;
        let result = decode_shards(&mut shards, 2, 1 << 40);
        assert!(matches!(
            result,
            Err(FecError::OriginalLengthOutOfRange { max: 100, .. })
        ));
    }

    #[test]
    fn test_original_len_one_past_capacity_rejected() {
        let mut shards = encoded_shards(&[7u8; 100], 50, 1);
        assert!(matches!(
            decode_shards(&mut shards, 2, 101),
            Err(FecError::OriginalLengthOutOfRange { .. })
        ));
        let mut shards = encoded_shards(&[7u8; 100], 50, 1);
        assert_eq!(decode_shards(&mut shards, 2, 100).unwrap(), vec![7u8; 100]);
    }

    #[test]
    fn test_zero_data_shards_rejected() {
        let mut shards = vec![Some(vec![1u8; 8]); 3];
        assert!(matches!(
            decode_shards(&mut shards, 0, 8),
            Err(FecError::EmptyDataShards)
        ));
        let mut empty: Vec<Option<Vec<u8>>> = Vec::new();
        assert!(matches!(
            decode_shards(&mut empty, 0, 0),
            Err(FecError::EmptyDataShards)
        ));
    }

    #[test]
    fn test_more_data_shards_than_slots_rejected() {
        let mut shards = vec![Some(vec![1u8; 8]); 3];
        assert!(matches!(
            decode_shards(&mut shards, 4, 8),
            Err(FecError::ShardCountMismatch {
                expected: 4,
                got: 3
            })
        ));
    }

    #[test]
    fn test_mismatched_shard_sizes_fast_path_rejected() {
        let mut shards = vec![Some(vec![1u8; 8]), Some(vec![2u8; 3]), None];
        assert!(matches!(
            decode_shards(&mut shards, 2, 11),
            Err(FecError::NonUniformShards {
                expected: 8,
                index: 1,
                got: 3
            })
        ));
    }

    #[test]
    fn test_mismatched_parity_size_rs_path_rejected() {
        let mut shards = encoded_shards(&[9u8; 64], 16, 2);
        shards[1] = None;
        if let Some(parity) = shards[4].as_mut() {
            parity.push(0);
        }
        assert!(matches!(
            decode_shards(&mut shards, 4, 64),
            Err(FecError::NonUniformShards { index: 4, .. })
        ));
    }

    #[test]
    fn test_empty_shard_rejected() {
        let mut shards = vec![Some(Vec::new()), Some(Vec::new())];
        assert!(matches!(
            decode_shards(&mut shards, 2, 0),
            Err(FecError::EmptyShardData)
        ));
    }

    #[test]
    fn test_too_many_shards_rs_path_rejected() {
        let mut shards: Vec<Option<Vec<u8>>> = vec![Some(vec![0u8; 4]); 300];
        shards[0] = None;
        assert!(matches!(
            decode_shards(&mut shards, 200, 800),
            Err(FecError::TooManyShards { total: 300, .. })
        ));
    }

    #[test]
    fn test_large_data_shard_count_fast_path_bounded() {
        let mut shards: Vec<Option<Vec<u8>>> = vec![Some(vec![3u8; 2]); 9_500];
        let out = decode_shards(&mut shards, 9_500, 19_000).unwrap();
        assert_eq!(out.len(), 19_000);
        let mut shards: Vec<Option<Vec<u8>>> = vec![Some(vec![3u8; 2]); 9_500];
        assert!(matches!(
            decode_shards(&mut shards, 9_500, 19_001),
            Err(FecError::OriginalLengthOutOfRange { max: 19_000, .. })
        ));
    }

    /// Random malformed shard sets: decode must return (never panic) and any output must
    /// fit within the bytes the data shards carry.
    #[test]
    fn test_fuzz_malformed_shards_never_panic() {
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};

        let mut rng = StdRng::seed_from_u64(0x00F0_EC0D);
        for _ in 0..3_000 {
            let total: usize = rng.gen_range(0..40);
            let mut shards: Vec<Option<Vec<u8>>> = (0..total)
                .map(|_| {
                    if rng.gen_bool(0.25) {
                        None
                    } else {
                        let len = if rng.gen_bool(0.8) {
                            16
                        } else {
                            rng.gen_range(0..32)
                        };
                        Some((0..len).map(|_| rng.gen()).collect())
                    }
                })
                .collect();
            let data_shard_count = rng.gen_range(0..=total + 2);
            let original_data_len = match rng.gen_range(0..4) {
                0 => rng.gen(),
                1 => u64::MAX,
                2 => rng.gen_range(0..1_024),
                _ => (data_shard_count as u64) * 16,
            };
            if let Ok(out) = decode_shards(&mut shards, data_shard_count, original_data_len) {
                assert!(out.len() as u64 <= original_data_len);
                assert!(out.len() <= data_shard_count * 32);
            }
        }
    }
}
