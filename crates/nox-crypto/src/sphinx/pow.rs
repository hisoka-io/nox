//! Hashcash-style `PoW` for Sphinx `DoS` prevention. SHA-256 and Blake3 algorithms with parallel solving.

#[cfg(feature = "rayon-pow")]
use rayon::prelude::*;
use sha2::{Digest, Sha256};
#[cfg(feature = "rayon-pow")]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(feature = "rayon-pow")]
use std::sync::Arc;
use thiserror::Error;

pub const DEFAULT_THREADS: usize = 0;

#[cfg(feature = "rayon-pow")]
const BATCH_SIZE: u64 = 10_000;

/// Capped at 64 to prevent unsolvable puzzles (64 leading zeros ~ 1.8e19 hashes).
pub const MAX_DIFFICULTY: u32 = 64;

pub const MIN_DIFFICULTY: u32 = 0;

#[derive(Debug, Error)]
pub enum PowError {
    #[error("PoW difficulty {difficulty} exceeds maximum allowed {MAX_DIFFICULTY}")]
    DifficultyTooHigh { difficulty: u32 },
}

/// Swappable `PoW` hash algorithm.
pub trait PowAlgorithm: Send + Sync {
    fn hash(&self, data: &[u8]) -> [u8; 32];
    fn name(&self) -> &'static str;
}

/// SHA-256 based `PoW`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256Pow;

impl PowAlgorithm for Sha256Pow {
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    fn name(&self) -> &'static str {
        "SHA-256"
    }
}

/// Blake3 based `PoW` (~3x faster than SHA-256).
#[derive(Debug, Clone, Copy, Default)]
pub struct Blake3Pow;

impl PowAlgorithm for Blake3Pow {
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        blake3::hash(data).into()
    }

    fn name(&self) -> &'static str {
        "BLAKE3"
    }
}

/// Counts leading zero bits in a hash using u64-wide operations.
#[inline]
#[must_use]
pub fn count_leading_zeros(hash: &[u8]) -> u32 {
    let mut zeros = 0u32;
    let mut chunks = hash.chunks_exact(8);
    for chunk in chunks.by_ref() {
        let word = u64::from_be_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
        if word == 0 {
            zeros += 64;
        } else {
            zeros += word.leading_zeros();
            return zeros;
        }
    }
    for byte in chunks.remainder() {
        if *byte == 0 {
            zeros += 8;
        } else {
            zeros += byte.leading_zeros();
            return zeros;
        }
    }
    zeros
}

/// Returns true if the hash has at least `difficulty` leading zero bits.
#[inline]
#[must_use]
pub fn meets_difficulty(hash: &[u8], difficulty: u32) -> bool {
    count_leading_zeros(hash) >= difficulty
}

/// Parallel `PoW` solver using rayon work-stealing.
#[derive(Clone)]
pub struct PowSolver<A: PowAlgorithm> {
    algorithm: A,
    #[cfg_attr(not(feature = "rayon-pow"), allow(dead_code))]
    num_threads: usize,
}

impl<A: PowAlgorithm + Clone + 'static> PowSolver<A> {
    /// Creates a new solver. `num_threads` = 0 means all cores.
    pub fn new(algorithm: A, num_threads: usize) -> Self {
        Self {
            algorithm,
            num_threads,
        }
    }

    /// Finds a nonce producing a hash with `difficulty` leading zero bits.
    #[cfg(feature = "rayon-pow")]
    pub fn solve(
        &self,
        header_data: &[u8],
        difficulty: u32,
        start_nonce: u64,
    ) -> Result<u64, PowError> {
        if difficulty > MAX_DIFFICULTY {
            return Err(PowError::DifficultyTooHigh { difficulty });
        }

        if difficulty == 0 {
            return Ok(start_nonce);
        }

        let threads = if self.num_threads == 0 {
            rayon::current_num_threads()
        } else {
            self.num_threads
        };

        if difficulty <= 8 || threads == 1 {
            Ok(self.solve_single_threaded(header_data, difficulty, start_nonce))
        } else {
            Ok(self.solve_parallel(header_data, difficulty, start_nonce))
        }
    }

    /// Single-threaded solve (WASM-compatible path).
    #[cfg(not(feature = "rayon-pow"))]
    pub fn solve(
        &self,
        header_data: &[u8],
        difficulty: u32,
        start_nonce: u64,
    ) -> Result<u64, PowError> {
        if difficulty > MAX_DIFFICULTY {
            return Err(PowError::DifficultyTooHigh { difficulty });
        }

        if difficulty == 0 {
            return Ok(start_nonce);
        }

        Ok(self.solve_single_threaded(header_data, difficulty, start_nonce))
    }

    fn solve_single_threaded(&self, header_data: &[u8], difficulty: u32, start_nonce: u64) -> u64 {
        let mut nonce = start_nonce;
        let mut buffer = Vec::with_capacity(header_data.len() + 8);
        buffer.extend_from_slice(header_data);
        buffer.extend_from_slice(&[0u8; 8]);

        loop {
            let nonce_pos = buffer.len() - 8;
            buffer[nonce_pos..].copy_from_slice(&nonce.to_be_bytes());

            let hash = self.algorithm.hash(&buffer);
            if meets_difficulty(&hash, difficulty) {
                return nonce;
            }
            nonce = nonce.wrapping_add(1);
        }
    }

    #[cfg(feature = "rayon-pow")]
    fn solve_parallel(&self, header_data: &[u8], difficulty: u32, start_nonce: u64) -> u64 {
        let found = Arc::new(AtomicBool::new(false));
        let result = Arc::new(AtomicU64::new(0));
        let header = header_data.to_vec();
        let algo = self.algorithm.clone();

        (0..u64::MAX / BATCH_SIZE).into_par_iter().find_any(|&i| {
            if found.load(Ordering::Relaxed) {
                return true;
            }

            let batch_start = start_nonce.wrapping_add(i * BATCH_SIZE);
            let mut buffer = Vec::with_capacity(header.len() + 8);
            buffer.extend_from_slice(&header);
            buffer.extend_from_slice(&[0u8; 8]);

            for offset in 0..BATCH_SIZE {
                if found.load(Ordering::Relaxed) {
                    return true;
                }

                let nonce = batch_start.wrapping_add(offset);
                let nonce_pos = buffer.len() - 8;
                buffer[nonce_pos..].copy_from_slice(&nonce.to_be_bytes());

                let hash = algo.hash(&buffer);
                if meets_difficulty(&hash, difficulty) {
                    result.store(nonce, Ordering::Relaxed);
                    found.store(true, Ordering::Relaxed);
                    return true;
                }
            }
            false
        });

        result.load(Ordering::Relaxed)
    }

    /// Verifies a nonce. Returns `false` for difficulty > `MAX_DIFFICULTY`.
    #[inline]
    pub fn verify(&self, header_data: &[u8], nonce: u64, difficulty: u32) -> bool {
        if difficulty == 0 {
            return true;
        }

        if difficulty > MAX_DIFFICULTY {
            return false;
        }

        let mut buffer = Vec::with_capacity(header_data.len() + 8);
        buffer.extend_from_slice(header_data);
        buffer.extend_from_slice(&nonce.to_be_bytes());

        let hash = self.algorithm.hash(&buffer);
        meets_difficulty(&hash, difficulty)
    }
}

/// SHA-256 solver using all available cores.
#[must_use]
pub fn default_solver() -> PowSolver<Sha256Pow> {
    PowSolver::new(Sha256Pow, DEFAULT_THREADS)
}

/// Blake3 solver using all available cores.
#[must_use]
pub fn fast_solver() -> PowSolver<Blake3Pow> {
    PowSolver::new(Blake3Pow, DEFAULT_THREADS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_pow_low_difficulty() {
        let solver = default_solver();
        let header_data = b"test_header_data";

        let start = Instant::now();
        let nonce = solver.solve(header_data, 4, 0).expect("solve failed");
        let elapsed = start.elapsed();

        assert!(solver.verify(header_data, nonce, 4));
        println!(
            "Low difficulty (4 bits): nonce={}, time={:?}",
            nonce, elapsed
        );
        assert!(elapsed.as_millis() < 100, "Should resolve in <100ms");
    }

    #[test]
    fn test_pow_moderate_difficulty() {
        let solver = default_solver();
        let header_data = b"sphinx_header_ephemeral_key_routing_info_mac";

        let start = Instant::now();
        let nonce = solver.solve(header_data, 16, 0).expect("solve failed");
        let elapsed = start.elapsed();

        assert!(solver.verify(header_data, nonce, 16));
        println!(
            "Moderate difficulty (16 bits): nonce={}, time={:?}",
            nonce, elapsed
        );
    }

    #[test]
    fn test_pow_tamper_invalidates() {
        let solver = default_solver();
        let header_data = b"original_header";
        let nonce = solver.solve(header_data, 12, 0).expect("solve failed");

        assert!(solver.verify(header_data, nonce, 12));

        let tampered = b"tampered_header";
        assert!(!solver.verify(tampered, nonce, 12));
    }

    #[test]
    fn test_zero_difficulty() {
        let solver = default_solver();
        let header_data = b"any_data";

        let nonce = solver.solve(header_data, 0, 42).expect("solve failed");
        assert_eq!(nonce, 42);
        assert!(solver.verify(header_data, nonce, 0));
    }

    #[test]
    fn test_count_leading_zeros() {
        assert_eq!(count_leading_zeros(&[0x00, 0x00, 0x00, 0xFF]), 24);
        assert_eq!(count_leading_zeros(&[0x00, 0x0F, 0x00, 0x00]), 12);
        assert_eq!(count_leading_zeros(&[0x80, 0x00, 0x00, 0x00]), 0);
        assert_eq!(count_leading_zeros(&[0x00, 0x00, 0x00, 0x00]), 32);
    }

    #[test]
    fn test_difficulty_bounds_enforced() {
        let solver = default_solver();
        let header_data = b"test_data";

        let result = solver.solve(header_data, MAX_DIFFICULTY + 1, 0);
        assert!(
            matches!(result, Err(PowError::DifficultyTooHigh { difficulty }) if difficulty == MAX_DIFFICULTY + 1),
            "Difficulty {} should be rejected",
            MAX_DIFFICULTY + 1
        );

        assert!(
            !solver.verify(header_data, 0, MAX_DIFFICULTY + 1),
            "verify() should return false for excessive difficulty"
        );
    }
}
