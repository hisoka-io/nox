//! Packet identifiers carried in `SphinxPacket.id`.
//!
//! Each node picks the identifier it sends to the next hop. The only value
//! that is carried from one hop to the next is a reply handle: the SURB ID of
//! a reply, written as `reply-0-{32 hex}`, which the entry node needs to file
//! the reply for its client.

use serde::{Deserialize, Serialize};

/// SURB ID carried by a reply, 16 bytes.
pub type ReplyHandle = [u8; 16];

/// Labels that nodes of earlier versions put in front of a reply's SURB ID.
const LEGACY_REPLY_LABELS: [&str; 6] = [
    "reply",
    "rpc",
    "echo",
    "distress",
    "replenish",
    "preemptive",
];

/// Wire identifier for a reply: `reply-0-{surb id hex}`.
#[must_use]
pub fn reply_wire_id(handle: &ReplyHandle) -> String {
    format!("reply-0-{}", hex::encode(handle))
}

/// Reads the reply handle from a wire identifier.
///
/// Accepts exactly `{label}-{1..=20 digits}-{32 lowercase hex}`, where label is
/// one of the reply labels used by this and earlier versions. Anything else
/// carries no handle.
#[must_use]
pub fn parse_legacy_handle(wire_id: &str) -> Option<ReplyHandle> {
    let mut parts = wire_id.split('-');
    let label = parts.next()?;
    let counter = parts.next()?;
    let suffix = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    if !LEGACY_REPLY_LABELS.contains(&label) {
        return None;
    }
    if counter.is_empty() || counter.len() > 20 || !counter.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut handle = [0u8; 16];
    hex::decode_to_slice(suffix, &mut handle).ok()?;
    Some(handle)
}

/// Where a packet handed to the network layer came from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum PacketOrigin {
    /// Built on this node (exit replies, cover traffic, local tooling).
    #[default]
    Originated,
    /// Received from a peer, processed and passed on to the next hop.
    Relayed {
        /// Libp2p peer ID of the node the packet came from, when it came over P2P.
        prev_peer: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "00112233445566778899aabbccddeeff";

    #[test]
    fn accepts_every_reply_label() {
        for label in LEGACY_REPLY_LABELS {
            let id = format!("{label}-42-{HEX}");
            assert_eq!(
                parse_legacy_handle(&id).map(hex::encode).as_deref(),
                Some(HEX),
                "{id}"
            );
        }
        assert!(parse_legacy_handle(&format!("reply-0-{HEX}")).is_some());
        assert!(parse_legacy_handle(&format!("rpc-18446744073709551615-{HEX}")).is_some());
    }

    #[test]
    fn rejects_other_shapes() {
        let rejected = [
            "http-00000000deadbeef".to_string(),
            "6f1c1f9e-9c4b-4a3e-9d0e-6c2a4a1f6b11".to_string(),
            "mixnet-7".to_string(),
            format!("reply-1-{HEX}-frag-0"),
            format!("reply-1-{}", &HEX[..31]),
            format!("reply-1-{HEX}0"),
            format!("reply-1-{}", HEX.to_uppercase()),
            format!("reply-1-{HEX}-"),
            format!("reply--{HEX}"),
            format!("reply-1-2-{HEX}"),
            format!("reply-x1-{HEX}"),
            format!("reply-123456789012345678901-{HEX}"),
            format!("cover-1-{HEX}"),
            HEX.to_string(),
            String::new(),
        ];
        for id in rejected {
            assert!(parse_legacy_handle(&id).is_none(), "{id}");
        }
    }

    #[test]
    fn reply_wire_id_roundtrips() {
        let handle = [0xabu8; 16];
        let id = reply_wire_id(&handle);
        assert_eq!(id, format!("reply-0-{}", "ab".repeat(16)));
        assert_eq!(parse_legacy_handle(&id), Some(handle));
    }
}
