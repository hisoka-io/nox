//! Reed-Solomon FEC for SURB responses. D-of-(D+P) reconstruction over GF(2^8).
//! Applied response-path only (exit -> client). All shards must be uniform size
//! (last data shard zero-padded); output truncated to `original_data_len`.

use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
    if total > 255 {
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

/// Reconstruct original data from a (possibly incomplete) set of D+P shard slots.
/// Fast path if all data shards present; RS reconstruction otherwise.
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

    let all_data_present = shards[..data_shard_count].iter().all(Option::is_some);
    if all_data_present {
        let mut result = Vec::with_capacity(original_data_len as usize);
        for shard in &shards[..data_shard_count] {
            if let Some(data) = shard.as_ref() {
                result.extend_from_slice(data);
            }
        }
        result.truncate(original_data_len as usize);
        return Ok(result);
    }

    if parity_count == 0 {
        return Err(FecError::InsufficientShards {
            available,
            required: data_shard_count,
        });
    }

    let rs = ReedSolomon::new(data_shard_count, parity_count)
        .map_err(|e| FecError::EncoderCreationFailed(e.to_string()))?;

    rs.reconstruct(shards)
        .map_err(|e| FecError::ReconstructionFailed(e.to_string()))?;

    let mut result = Vec::with_capacity(original_data_len as usize);
    for shard in &shards[..data_shard_count] {
        match shard.as_ref() {
            Some(data) => result.extend_from_slice(data),
            None => {
                return Err(FecError::ReconstructionFailed(
                    "RS reconstruction did not fill all data shards".to_string(),
                ));
            }
        }
    }
    result.truncate(original_data_len as usize);

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
}
