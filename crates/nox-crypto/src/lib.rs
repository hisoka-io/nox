//! Sphinx mix format and cryptographic protocols for the NOX mixnet.
//! Based on Danezis & Goldberg, "Sphinx: A Compact and Provably Secure Mix Format" (IEEE S&P 2009).

pub mod sphinx;

pub use sphinx::{
    build_multi_hop_packet, derive_keys, PathHop, ProcessResult, SphinxError, SphinxHeader,
};

pub use sphinx::{HEADER_SIZE, MAC_SIZE, NONCE_SIZE, ROUTING_INFO_SIZE, SHIFT_SIZE};

pub use sphinx::packet::{PacketError, SphinxPacket};
pub use sphinx::packet::{
    HEADER_SIZE as PACKET_HEADER_SIZE, MAX_PAYLOAD_SIZE, NONCE_SIZE as PACKET_NONCE_SIZE,
    PACKET_SIZE, PAYLOAD_OVERHEAD, POLY1305_TAG_SIZE,
};

pub use sphinx::surb::{Surb, SurbError, SurbRecovery, DEFAULT_POW_DIFFICULTY};

pub use sphinx::pow::{
    count_leading_zeros, default_solver, fast_solver, meets_difficulty, Blake3Pow, PowAlgorithm,
    PowError, PowSolver, Sha256Pow, DEFAULT_THREADS, MAX_DIFFICULTY, MIN_DIFFICULTY,
};
