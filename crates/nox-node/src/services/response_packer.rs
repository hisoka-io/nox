//! Fragments response data and packs each fragment into a SURB for anonymous return.
//! Supports FEC (Reed-Solomon parity), multi-round SURB replenishment, and distress signaling.

use crate::telemetry::metrics::MetricsService;
use nox_core::models::payloads::{encode_payload, RelayerPayload};
use nox_core::protocol::fec::{self, FecError, FecInfo};
use nox_core::protocol::fragmentation::{Fragment, FragmentationError, FRAGMENT_OVERHEAD};
use nox_crypto::sphinx::surb::{Surb, SurbError};
use thiserror::Error;
use tracing::{info, warn};

pub use nox_core::protocol::fragmentation::SURB_PAYLOAD_SIZE;

#[derive(Debug, Error)]
pub enum PackerError {
    #[error("Insufficient SURBs: need {needed}, have {available}")]
    InsufficientSurbs { needed: usize, available: usize },

    #[error("Fragmentation error: {0}")]
    Fragmentation(#[from] FragmentationError),

    #[error("SURB encapsulation error: {0}")]
    Surb(#[from] SurbError),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Empty response data")]
    EmptyData,

    #[error("FEC encoding error: {0}")]
    Fec(#[from] FecError),
}

#[derive(Debug)]
pub struct PackedPacket {
    pub first_hop: String,
    pub packet_bytes: Vec<u8>,
    /// Propagated as `packet_id` so the client can do O(1) SURB registry lookup.
    pub surb_id: [u8; 16],
}

/// Tracks fragment numbering across multi-round SURB replenishment.
#[derive(Debug, Clone)]
pub struct ContinuationState {
    pub original_total_fragments: u32,
    pub fragments_already_sent: u32,
    pub original_data_len: usize,
}

#[derive(Debug, Clone)]
pub struct PendingResponseState {
    pub remaining_data: Vec<u8>,
    pub continuation: ContinuationState,
}

#[derive(Debug)]
pub struct PackResult {
    pub packets: Vec<PackedPacket>,
    /// `None` when entire response was delivered; `Some` on partial (distress path).
    pub remaining: Option<PendingResponseState>,
}

pub struct ResponsePacker {
    metrics: Option<MetricsService>,
}

impl Default for ResponsePacker {
    fn default() -> Self {
        Self::new()
    }
}

impl ResponsePacker {
    #[must_use]
    pub fn new() -> Self {
        Self { metrics: None }
    }

    #[must_use]
    pub fn with_metrics(mut self, metrics: MetricsService) -> Self {
        self.metrics = Some(metrics);
        self
    }

    fn usable_per_fragment() -> usize {
        SURB_PAYLOAD_SIZE.saturating_sub(FRAGMENT_OVERHEAD)
    }

    /// Extra SURBs beyond data needs become FEC parity shards.
    /// Fewer SURBs than needed triggers a `NeedMoreSurbs` distress signal.
    pub fn pack_response(
        &self,
        request_id: u64,
        data: &[u8],
        mut surbs: Vec<Surb>,
    ) -> Result<PackResult, PackerError> {
        if data.is_empty() {
            if let Some(ref m) = self.metrics {
                m.response_pack_total
                    .get_or_create(&vec![(
                        "result".to_string(),
                        "error_empty_data".to_string(),
                    )])
                    .inc();
            }
            return Err(PackerError::EmptyData);
        }

        let usable = Self::usable_per_fragment();
        if usable == 0 {
            return Err(PackerError::Fragmentation(
                FragmentationError::InvalidChunkSize(SURB_PAYLOAD_SIZE),
            ));
        }

        let d = data.len().div_ceil(usable);
        let total_fragments = d as u32;

        // Distress path: need at least 2 SURBs (1+ data, 1 distress signal).
        if d > surbs.len() {
            if surbs.len() < 2 {
                if let Some(ref m) = self.metrics {
                    m.response_pack_total
                        .get_or_create(&vec![(
                            "result".to_string(),
                            "error_insufficient_surbs".to_string(),
                        )])
                        .inc();
                }
                return Err(PackerError::InsufficientSurbs {
                    needed: d,
                    available: surbs.len(),
                });
            }
            let data_surb_count = surbs.len() - 1;
            let Some(distress_surb) = surbs.pop() else {
                return Err(PackerError::InsufficientSurbs {
                    needed: d,
                    available: 0,
                });
            };
            let fragments_remaining = (d - data_surb_count) as u32;

            let mut fragments: Vec<Fragment> = data
                .chunks(usable)
                .take(data_surb_count)
                .enumerate()
                .map(|(i, chunk)| Fragment {
                    message_id: request_id,
                    total_fragments,
                    sequence: i as u32,
                    data: chunk.to_vec(),
                    fec: None,
                })
                .collect();

            let mut packets =
                self.pack_fragments_with_surbs(request_id, &mut fragments, &mut surbs)?;

            let distress_packet =
                self.pack_distress_signal(request_id, fragments_remaining, distress_surb)?;
            packets.push(distress_packet);

            let bytes_sent = data_surb_count * usable;
            let remaining_bytes = if bytes_sent < data.len() {
                data[bytes_sent..].to_vec()
            } else {
                Vec::new()
            };

            if let Some(ref m) = self.metrics {
                m.response_pack_total
                    .get_or_create(&vec![(
                        "result".to_string(),
                        "partial_need_more_surbs".to_string(),
                    )])
                    .inc();
            }
            return Ok(PackResult {
                packets,
                remaining: if remaining_bytes.is_empty() {
                    None
                } else {
                    Some(PendingResponseState {
                        remaining_data: remaining_bytes,
                        continuation: ContinuationState {
                            original_total_fragments: total_fragments,
                            fragments_already_sent: data_surb_count as u32,
                            original_data_len: data.len(),
                        },
                    })
                },
            });
        }

        let mut fragments: Vec<Fragment> = data
            .chunks(usable)
            .enumerate()
            .map(|(i, chunk)| Fragment {
                message_id: request_id,
                total_fragments,
                sequence: i as u32,
                data: chunk.to_vec(),
                fec: None,
            })
            .collect();

        // FEC: RS GF(2^8) supports max 255 total shards; clamp or skip accordingly.
        let mut p = surbs.len() - d;
        let all_fragments = if p > 0 && d > 0 {
            let max_parity = 255usize.saturating_sub(d);
            if max_parity == 0 {
                info!(
                    request_id,
                    data_shards = d,
                    "Skipping FEC: data shards exceed RS GF(2^8) limit of 255"
                );
                if let Some(ref m) = self.metrics {
                    m.fec_operations_total
                        .get_or_create(&vec![
                            ("type".to_string(), "encode".to_string()),
                            ("result".to_string(), "skip_too_many_data".to_string()),
                        ])
                        .inc();
                }
                fragments
            } else {
                if p > max_parity {
                    info!(
                        request_id,
                        data_shards = d,
                        requested_parity = p,
                        clamped_parity = max_parity,
                        "Clamping FEC parity to RS GF(2^8) limit"
                    );
                    p = max_parity;
                }
                match Self::apply_fec(request_id, data.len(), &mut fragments, p) {
                    Ok(frags) => {
                        if let Some(ref m) = self.metrics {
                            m.fec_operations_total
                                .get_or_create(&vec![
                                    ("type".to_string(), "encode".to_string()),
                                    ("result".to_string(), "success".to_string()),
                                ])
                                .inc();
                        }
                        frags
                    }
                    Err(e) => {
                        warn!(
                            request_id,
                            error = %e,
                            "FEC encoding failed, falling back to data-only fragments"
                        );
                        if let Some(ref m) = self.metrics {
                            m.fec_operations_total
                                .get_or_create(&vec![
                                    ("type".to_string(), "encode".to_string()),
                                    ("result".to_string(), "error_fallback".to_string()),
                                ])
                                .inc();
                        }
                        fragments
                    }
                }
            }
        } else {
            fragments
        };

        // Parallelized via rayon (~0.3ms per 32 KB Lioness encrypt per fragment).
        let total = all_fragments.len();
        let consumed_surbs: Vec<_> = surbs.drain(..total).collect();

        let pack_results: Vec<Result<PackedPacket, PackerError>> = {
            use rayon::prelude::*;
            all_fragments
                .into_par_iter()
                .zip(consumed_surbs.into_par_iter())
                .map(|(fragment, surb)| {
                    let response = RelayerPayload::ServiceResponse {
                        request_id,
                        fragment,
                    };
                    let serialized =
                        encode_payload(&response).map_err(PackerError::Serialization)?;
                    let sphinx_packet = surb.encapsulate(&serialized).map_err(PackerError::Surb)?;
                    let packet_bytes = sphinx_packet.into_bytes();
                    Ok(PackedPacket {
                        first_hop: surb.first_hop.clone(),
                        packet_bytes,
                        surb_id: surb.id,
                    })
                })
                .collect()
        };

        let mut packets = Vec::with_capacity(total);
        for result in pack_results {
            match result {
                Ok(packet) => packets.push(packet),
                Err(e) => {
                    if let Some(ref m) = self.metrics {
                        m.response_pack_total
                            .get_or_create(&vec![("result".to_string(), "error_pack".to_string())])
                            .inc();
                    }
                    return Err(e);
                }
            }
        }

        if let Some(ref m) = self.metrics {
            m.response_pack_total
                .get_or_create(&vec![("result".to_string(), "success".to_string())])
                .inc();
        }

        Ok(PackResult {
            packets,
            remaining: None,
        })
    }

    /// Continue packing with fresh SURBs, preserving fragment numbering from prior rounds.
    pub fn pack_continuation(
        &self,
        request_id: u64,
        state: &PendingResponseState,
        mut surbs: Vec<Surb>,
    ) -> Result<PackResult, PackerError> {
        let data = &state.remaining_data;
        if data.is_empty() {
            return Err(PackerError::EmptyData);
        }

        let usable = Self::usable_per_fragment();
        if usable == 0 {
            return Err(PackerError::Fragmentation(
                FragmentationError::InvalidChunkSize(SURB_PAYLOAD_SIZE),
            ));
        }

        let cont = &state.continuation;
        let original_total = cont.original_total_fragments;
        let seq_offset = cont.fragments_already_sent;

        let chunks: Vec<&[u8]> = data.chunks(usable).collect();
        let remaining_d = chunks.len();

        if remaining_d > surbs.len() {
            if surbs.len() < 2 {
                return Err(PackerError::InsufficientSurbs {
                    needed: remaining_d,
                    available: surbs.len(),
                });
            }
            let data_surb_count = surbs.len() - 1;
            let Some(distress_surb) = surbs.pop() else {
                return Err(PackerError::InsufficientSurbs {
                    needed: remaining_d,
                    available: 0,
                });
            };

            let mut fragments: Vec<Fragment> = chunks[..data_surb_count]
                .iter()
                .enumerate()
                .map(|(i, chunk)| Fragment {
                    message_id: request_id,
                    total_fragments: original_total,
                    sequence: seq_offset + i as u32,
                    data: chunk.to_vec(),
                    fec: None,
                })
                .collect();

            let fragments_remaining = (remaining_d - data_surb_count) as u32;
            let mut packets =
                self.pack_fragments_with_surbs(request_id, &mut fragments, &mut surbs)?;

            let distress_packet =
                self.pack_distress_signal(request_id, fragments_remaining, distress_surb)?;
            packets.push(distress_packet);

            let bytes_sent_this_round = data_surb_count * usable;
            let tail = if bytes_sent_this_round < data.len() {
                data[bytes_sent_this_round..].to_vec()
            } else {
                Vec::new()
            };

            return Ok(PackResult {
                packets,
                remaining: if tail.is_empty() {
                    None
                } else {
                    Some(PendingResponseState {
                        remaining_data: tail,
                        continuation: ContinuationState {
                            original_total_fragments: original_total,
                            fragments_already_sent: seq_offset + data_surb_count as u32,
                            original_data_len: cont.original_data_len,
                        },
                    })
                },
            });
        }

        // FEC skipped on continuation rounds (would change total_fragments, breaking reassembly).
        let mut fragments: Vec<Fragment> = chunks
            .iter()
            .enumerate()
            .map(|(i, chunk)| Fragment {
                message_id: request_id,
                total_fragments: original_total,
                sequence: seq_offset + i as u32,
                data: chunk.to_vec(),
                fec: None,
            })
            .collect();

        let packets = self.pack_fragments_with_surbs(request_id, &mut fragments, &mut surbs)?;

        if let Some(ref m) = self.metrics {
            m.response_pack_total
                .get_or_create(&vec![(
                    "result".to_string(),
                    "continuation_success".to_string(),
                )])
                .inc();
        }

        Ok(PackResult {
            packets,
            remaining: None,
        })
    }

    /// Pack a single chunk into one SURB packet (used by streaming response path).
    pub fn pack_single_fragment(
        &self,
        request_id: u64,
        chunk: &[u8],
        surb: &Surb,
        sequence: u32,
        total_fragments: u32,
    ) -> Result<PackedPacket, PackerError> {
        let fragment = Fragment {
            message_id: request_id,
            total_fragments,
            sequence,
            data: chunk.to_vec(),
            fec: None,
        };
        let response = RelayerPayload::ServiceResponse {
            request_id,
            fragment,
        };
        let serialized = encode_payload(&response).map_err(PackerError::Serialization)?;
        let sphinx_packet = surb.encapsulate(&serialized).map_err(PackerError::Surb)?;
        Ok(PackedPacket {
            first_hop: surb.first_hop.clone(),
            packet_bytes: sphinx_packet.into_bytes(),
            surb_id: surb.id,
        })
    }

    fn pack_fragments_with_surbs(
        &self,
        request_id: u64,
        fragments: &mut [Fragment],
        surbs: &mut Vec<Surb>,
    ) -> Result<Vec<PackedPacket>, PackerError> {
        let mut packets = Vec::with_capacity(fragments.len());
        for (fragment, surb) in fragments.iter().zip(surbs.drain(..fragments.len())) {
            let response = RelayerPayload::ServiceResponse {
                request_id,
                fragment: fragment.clone(),
            };
            let serialized = encode_payload(&response).map_err(PackerError::Serialization)?;
            let sphinx_packet = surb.encapsulate(&serialized).map_err(PackerError::Surb)?;
            packets.push(PackedPacket {
                first_hop: surb.first_hop.clone(),
                packet_bytes: sphinx_packet.into_bytes(),
                surb_id: surb.id,
            });
        }
        Ok(packets)
    }

    pub fn pack_distress_signal(
        &self,
        request_id: u64,
        fragments_remaining: u32,
        surb: Surb,
    ) -> Result<PackedPacket, PackerError> {
        let signal = RelayerPayload::NeedMoreSurbs {
            request_id,
            fragments_remaining,
        };
        let serialized = encode_payload(&signal).map_err(PackerError::Serialization)?;
        let sphinx_packet = surb.encapsulate(&serialized).map_err(PackerError::Surb)?;
        Ok(PackedPacket {
            first_hop: surb.first_hop.clone(),
            packet_bytes: sphinx_packet.into_bytes(),
            surb_id: surb.id,
        })
    }

    fn apply_fec(
        request_id: u64,
        original_data_len: usize,
        data_fragments: &mut Vec<Fragment>,
        parity_count: usize,
    ) -> Result<Vec<Fragment>, PackerError> {
        let d = data_fragments.len();
        let total = (d + parity_count) as u32;

        let raw_chunks: Vec<Vec<u8>> = data_fragments.iter().map(|f| f.data.clone()).collect();
        let (padded, _shard_size) = fec::pad_to_uniform(&raw_chunks)?;

        let parity_shards = fec::encode_parity_shards(&padded, parity_count)?;

        let fec_info = FecInfo {
            data_shard_count: d as u32,
            original_data_len: original_data_len as u64,
        };

        for (i, fragment) in data_fragments.iter_mut().enumerate() {
            fragment.data.clone_from(&padded[i]);
            fragment.total_fragments = total;
            fragment.fec = Some(fec_info.clone());
        }

        let mut all_fragments: Vec<Fragment> = std::mem::take(data_fragments);
        for (i, parity_data) in parity_shards.into_iter().enumerate() {
            all_fragments.push(
                Fragment::new_with_fec(
                    request_id,
                    total,
                    (d + i) as u32,
                    parity_data,
                    fec_info.clone(),
                )
                .map_err(PackerError::Fragmentation)?,
            );
        }

        Ok(all_fragments)
    }

    #[must_use]
    pub fn surbs_needed(&self, data_size: usize) -> usize {
        if data_size == 0 {
            return 0;
        }
        let usable = Self::usable_per_fragment();
        data_size.div_ceil(usable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nox_crypto::sphinx::PathHop;
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

    fn make_test_surbs(count: usize) -> Vec<Surb> {
        let mut surbs = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();

        for _ in 0..count {
            let sk = X25519SecretKey::random_from_rng(&mut rng);
            let path = vec![PathHop {
                public_key: X25519PublicKey::from(&sk),
                address: "/ip4/127.0.0.1/tcp/9000".to_string(),
            }];

            let id: [u8; 16] = rand::random();
            let (surb, _recovery) = Surb::new(&path, id, 0).expect("SURB creation failed");
            surbs.push(surb);
        }

        surbs
    }

    #[test]
    fn test_pack_single_fragment() {
        let packer = ResponsePacker::new();
        let data = b"Hello, World!";
        let surbs = make_test_surbs(1);

        let result = packer.pack_response(123, data, surbs);
        assert!(result.is_ok());

        let pack_result = result.unwrap();
        assert_eq!(pack_result.packets.len(), 1);
        assert!(!pack_result.packets[0].packet_bytes.is_empty());
        assert!(pack_result.remaining.is_none());
    }

    #[test]
    fn test_pack_multiple_fragments() {
        let packer = ResponsePacker::new();
        let data: Vec<u8> = (0..50_000).map(|i| (i % 256) as u8).collect();
        let surbs_needed = packer.surbs_needed(data.len());
        let surbs = make_test_surbs(surbs_needed + 1); // Extra for safety

        let result = packer.pack_response(456, &data, surbs);
        assert!(result.is_ok());

        let pack_result = result.unwrap();
        assert!(
            pack_result.packets.len() >= 2,
            "Should need multiple packets"
        );
    }

    #[test]
    fn test_insufficient_surbs() {
        let packer = ResponsePacker::new();
        let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let surbs = make_test_surbs(1); // Not enough!

        let result = packer.pack_response(789, &data, surbs);
        assert!(matches!(result, Err(PackerError::InsufficientSurbs { .. })));
    }

    #[test]
    fn test_empty_data() {
        let packer = ResponsePacker::new();
        let surbs = make_test_surbs(1);

        let result = packer.pack_response(0, &[], surbs);
        assert!(matches!(result, Err(PackerError::EmptyData)));
    }

    #[test]
    fn test_surbs_needed_calculation() {
        use nox_core::protocol::fragmentation::Fragmenter;
        let packer = ResponsePacker::new();
        let usable = Fragmenter::usable_payload_size(SURB_PAYLOAD_SIZE);

        assert_eq!(packer.surbs_needed(0), 0);
        assert_eq!(packer.surbs_needed(100), 1);
        assert_eq!(packer.surbs_needed(usable), 1);
        assert_eq!(packer.surbs_needed(usable + 1), 2);
        assert!(packer.surbs_needed(usable * 2) >= 2);
    }

    #[test]
    fn test_fec_with_extra_surbs() {
        let packer = ResponsePacker::new();
        let data: Vec<u8> = (0..50_000).map(|i| (i % 256) as u8).collect();
        let d = packer.surbs_needed(data.len());
        let surbs = make_test_surbs(d + 1); // 1 extra for parity

        let result = packer.pack_response(100, &data, surbs);
        assert!(result.is_ok());

        let pack_result = result.unwrap();
        assert_eq!(pack_result.packets.len(), d + 1);
        assert!(pack_result.remaining.is_none());
    }

    #[test]
    fn test_no_fec_with_exact_surbs() {
        let packer = ResponsePacker::new();
        let data: Vec<u8> = (0..50_000).map(|i| (i % 256) as u8).collect();
        let d = packer.surbs_needed(data.len());
        let surbs = make_test_surbs(d); // Exact, no extras

        let result = packer.pack_response(200, &data, surbs);
        assert!(result.is_ok());

        let pack_result = result.unwrap();
        assert_eq!(pack_result.packets.len(), d);
    }

    #[test]
    fn test_single_fragment_fec() {
        let packer = ResponsePacker::new();
        let data = b"Small response";
        let surbs = make_test_surbs(2); // D=1, P=1

        let result = packer.pack_response(300, data, surbs);
        assert!(result.is_ok());

        let pack_result = result.unwrap();
        assert_eq!(pack_result.packets.len(), 2);
    }

    #[test]
    fn test_surbs_needed_unchanged() {
        let packer = ResponsePacker::new();
        let usable = ResponsePacker::usable_per_fragment();

        assert_eq!(packer.surbs_needed(usable), 1);
        assert_eq!(packer.surbs_needed(usable * 3), 3);
    }

    #[test]
    fn test_distress_signal_emitted_on_partial_surbs() {
        let packer = ResponsePacker::new();
        // 100 KB -> needs ~4 data fragments
        let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let d = packer.surbs_needed(data.len());
        assert!(d >= 4, "test requires D >= 4 data fragments");

        let surbs = make_test_surbs(3);
        let result = packer.pack_response(999, &data, surbs);
        assert!(
            result.is_ok(),
            "partial delivery should succeed, not error: {:?}",
            result.err()
        );
        let pack_result = result.unwrap();
        assert_eq!(pack_result.packets.len(), 3);
        assert!(pack_result.remaining.is_some());
    }

    #[test]
    fn test_distress_requires_at_least_two_surbs() {
        let packer = ResponsePacker::new();
        let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let surbs = make_test_surbs(1);
        let result = packer.pack_response(111, &data, surbs);
        assert!(matches!(result, Err(PackerError::InsufficientSurbs { .. })));
    }

    #[test]
    fn test_no_distress_when_surbs_exact() {
        let packer = ResponsePacker::new();
        let data: Vec<u8> = (0..60_000).map(|i| (i % 256) as u8).collect();
        let d = packer.surbs_needed(data.len());
        let surbs = make_test_surbs(d);
        let result = packer.pack_response(222, &data, surbs);
        assert!(result.is_ok());
        let pack_result = result.unwrap();
        assert_eq!(pack_result.packets.len(), d);
        assert!(pack_result.remaining.is_none());
    }

    #[test]
    fn test_continuation_fragment_numbering() {
        let packer = ResponsePacker::new();
        // 200 KB data -> needs ~7 data fragments
        let data: Vec<u8> = (0..200_000).map(|i| (i % 256) as u8).collect();
        let d = packer.surbs_needed(data.len());
        assert!(d >= 7, "test requires at least 7 data fragments, got {d}");

        let surbs = make_test_surbs(4);
        let result = packer.pack_response(42, &data, surbs).unwrap();
        assert_eq!(result.packets.len(), 4);
        let pending = result.remaining.expect("should have remaining state");
        assert_eq!(pending.continuation.fragments_already_sent, 3);
        assert_eq!(pending.continuation.original_total_fragments, d as u32);
        assert_eq!(pending.continuation.original_data_len, data.len());

        let surbs2 = make_test_surbs(d);
        let result2 = packer.pack_continuation(42, &pending, surbs2).unwrap();
        assert_eq!(result2.packets.len(), d - 3);
        assert!(result2.remaining.is_none());
    }

    #[test]
    fn test_pack_single_fragment_basic() {
        let packer = ResponsePacker::new();
        let chunk = vec![0xABu8; 1000];
        let surb = make_test_surbs(1).remove(0);
        let result = packer.pack_single_fragment(42, &chunk, &surb, 0, 5);
        assert!(result.is_ok());
        let packed = result.unwrap();
        assert!(!packed.packet_bytes.is_empty());
        assert_eq!(packed.surb_id, surb.id);
    }

    #[test]
    fn test_pack_single_fragment_sequence() {
        let packer = ResponsePacker::new();
        let surbs = make_test_surbs(3);
        for (i, surb) in surbs.iter().enumerate() {
            let chunk = vec![i as u8; 500];
            let result = packer.pack_single_fragment(99, &chunk, surb, i as u32, 3);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_fec_fallback_over_255_shards() {
        let packer = ResponsePacker::new();
        let data: Vec<u8> = vec![0x42; 8 * 1024 * 1024];
        let d = packer.surbs_needed(data.len());
        assert!(d > 255, "test requires >255 data fragments, got {d}");

        let surbs = make_test_surbs(d + 50);
        let result = packer.pack_response(1, &data, surbs);
        assert!(
            result.is_ok(),
            "should succeed with FEC fallback, not error"
        );
        let pack = result.unwrap();
        assert_eq!(
            pack.packets.len(),
            d,
            "should have {d} data-only packets (FEC skipped)"
        );
        assert!(pack.remaining.is_none());
    }

    #[test]
    fn test_fec_parity_clamped_to_255_limit() {
        use nox_core::protocol::fragmentation::Fragmenter;
        let packer = ResponsePacker::new();
        let usable = Fragmenter::usable_payload_size(SURB_PAYLOAD_SIZE);
        let data: Vec<u8> = vec![0x42; usable * 200];
        let d = packer.surbs_needed(data.len());
        assert_eq!(d, 200);

        let surbs = make_test_surbs(300);
        let result = packer.pack_response(2, &data, surbs);
        assert!(result.is_ok());
        let pack = result.unwrap();
        assert_eq!(
            pack.packets.len(),
            255,
            "should clamp to 255 total (200 data + 55 parity)"
        );
    }

    #[test]
    fn test_multi_round_continuation() {
        let packer = ResponsePacker::new();
        let data: Vec<u8> = (0..300_000).map(|i| (i % 256) as u8).collect();
        let d = packer.surbs_needed(data.len());
        assert!(d >= 10, "test requires at least 10 data fragments, got {d}");

        let surbs = make_test_surbs(3);
        let r1 = packer.pack_response(7, &data, surbs).unwrap();
        assert_eq!(r1.packets.len(), 3);
        let p1 = r1.remaining.expect("round 1 should have remaining");
        assert_eq!(p1.continuation.fragments_already_sent, 2);

        let surbs = make_test_surbs(3);
        let r2 = packer.pack_continuation(7, &p1, surbs).unwrap();
        assert_eq!(r2.packets.len(), 3);
        let p2 = r2.remaining.expect("round 2 should have remaining");
        assert_eq!(p2.continuation.fragments_already_sent, 4);

        let surbs = make_test_surbs(d);
        let r3 = packer.pack_continuation(7, &p2, surbs).unwrap();
        assert!(r3.remaining.is_none(), "round 3 should complete delivery");
        assert_eq!(r3.packets.len(), d - 4);
    }
}
