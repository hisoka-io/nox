//! Choice of the packet identifier sent to the next hop.
//!
//! In the default per-hop mode every node sends a fresh random identifier.
//! The one exception is a reply's handle (`reply-0-{surb id}`), which the
//! entry node needs to file the reply for its client:
//!
//! - an exit puts it on the replies it builds from a client's SURB;
//! - a node relaying a packet passes it on only when the packet came from an
//!   exit-capable registry member, which is where replies come from.
//!
//! Entry nodes never pass an identifier on, since packets reach them over
//! HTTP, and every other packet gets a fresh identifier.

use crate::config::WireIdMode;
use nox_core::models::wire_id::{reply_wire_id, PacketOrigin, ReplyHandle};
use rand::RngCore;

/// What kind of identifier was sent, for metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireIdKind {
    Fresh,
    LegacyHandle,
    Passthrough,
}

impl WireIdKind {
    #[must_use]
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::LegacyHandle => "legacy_handle",
            Self::Passthrough => "passthrough",
        }
    }
}

/// Why a reply handle was not passed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleDropReason {
    /// The previous hop is not a known registry member.
    UnknownLayer,
    /// The previous hop cannot be an exit, so the packet is not a reply.
    ForwardDirection,
    /// The packet did not arrive over P2P.
    EntryOrExit,
}

impl HandleDropReason {
    #[must_use]
    pub fn as_label(self) -> &'static str {
        match self {
            Self::UnknownLayer => "unknown_layer",
            Self::ForwardDirection => "forward_direction",
            Self::EntryOrExit => "entry_or_exit",
        }
    }
}

/// Outcome of [`choose_wire_id`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireIdChoice {
    pub wire_id: String,
    pub kind: WireIdKind,
    pub dropped: Option<HandleDropReason>,
}

/// A fresh identifier: 16 random bytes from the OS, as 32 lowercase hex.
#[must_use]
pub fn fresh_wire_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// True when a registry role can serve as an exit (layer 2).
#[must_use]
pub fn role_is_exit_capable(role: u8) -> bool {
    matches!(role, 2 | 3)
}

/// Picks the identifier to send with an outbound packet.
///
/// `peer_role` returns the registry role of a libp2p peer ID, or `None` when
/// the peer is not a known member.
pub fn choose_wire_id(
    mode: WireIdMode,
    packet_id: &str,
    reply_handle: Option<&ReplyHandle>,
    origin: &PacketOrigin,
    peer_role: impl Fn(&str) -> Option<u8>,
) -> WireIdChoice {
    if mode == WireIdMode::Passthrough {
        return WireIdChoice {
            wire_id: packet_id.to_string(),
            kind: WireIdKind::Passthrough,
            dropped: None,
        };
    }

    let fresh = |dropped| WireIdChoice {
        wire_id: fresh_wire_id(),
        kind: WireIdKind::Fresh,
        dropped,
    };
    let Some(handle) = reply_handle else {
        return fresh(None);
    };
    let carry = || WireIdChoice {
        wire_id: reply_wire_id(handle),
        kind: WireIdKind::LegacyHandle,
        dropped: None,
    };

    match origin {
        PacketOrigin::Originated => carry(),
        PacketOrigin::Relayed { prev_peer: None } => fresh(Some(HandleDropReason::EntryOrExit)),
        PacketOrigin::Relayed {
            prev_peer: Some(prev),
        } => match peer_role(prev) {
            None => fresh(Some(HandleDropReason::UnknownLayer)),
            Some(role) if role_is_exit_capable(role) => carry(),
            Some(_) => fresh(Some(HandleDropReason::ForwardDirection)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const H: ReplyHandle = [0x5a; 16];

    fn roles(peer: &str) -> Option<u8> {
        match peer {
            "relay" => Some(1),
            "exit" => Some(2),
            "full" => Some(3),
            _ => None,
        }
    }

    fn relayed(prev: &str) -> PacketOrigin {
        PacketOrigin::Relayed {
            prev_peer: Some(prev.to_string()),
        }
    }

    fn is_fresh(id: &str) -> bool {
        id.len() == 32
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    #[test]
    fn reply_from_exit_keeps_its_handle() {
        for prev in ["exit", "full"] {
            let c = choose_wire_id(WireIdMode::PerHop, "local", Some(&H), &relayed(prev), roles);
            assert_eq!(c.wire_id, reply_wire_id(&H));
            assert_eq!(c.kind, WireIdKind::LegacyHandle);
            assert_eq!(c.dropped, None);
        }
    }

    #[test]
    fn handle_from_relay_role_peer_is_not_passed_on() {
        let c = choose_wire_id(
            WireIdMode::PerHop,
            "local",
            Some(&H),
            &relayed("relay"),
            roles,
        );
        assert!(is_fresh(&c.wire_id), "{}", c.wire_id);
        assert_eq!(c.dropped, Some(HandleDropReason::ForwardDirection));
    }

    #[test]
    fn unknown_previous_hop_gets_fresh_id() {
        let c = choose_wire_id(
            WireIdMode::PerHop,
            "local",
            Some(&H),
            &relayed("stranger"),
            roles,
        );
        assert!(is_fresh(&c.wire_id));
        assert_eq!(c.dropped, Some(HandleDropReason::UnknownLayer));
    }

    #[test]
    fn packets_not_received_over_p2p_never_pass_a_handle_on() {
        let origin = PacketOrigin::Relayed { prev_peer: None };
        let c = choose_wire_id(WireIdMode::PerHop, "http-1", Some(&H), &origin, roles);
        assert!(is_fresh(&c.wire_id));
        assert_eq!(c.dropped, Some(HandleDropReason::EntryOrExit));
    }

    #[test]
    fn exit_replies_carry_the_surb_handle() {
        let c = choose_wire_id(
            WireIdMode::PerHop,
            "anything",
            Some(&H),
            &PacketOrigin::Originated,
            roles,
        );
        assert_eq!(c.wire_id, format!("reply-0-{}", hex::encode(H)));
    }

    #[test]
    fn packets_without_handle_get_fresh_ids_every_time() {
        let mut seen = HashSet::new();
        for i in 0..10_000 {
            let origin = if i % 2 == 0 {
                PacketOrigin::Originated
            } else {
                relayed("exit")
            };
            let local = format!("http-{i:016x}");
            let c = choose_wire_id(WireIdMode::PerHop, &local, None, &origin, roles);
            assert!(is_fresh(&c.wire_id));
            assert_ne!(c.wire_id, local);
            assert_eq!(c.kind, WireIdKind::Fresh);
            assert!(seen.insert(c.wire_id), "duplicate fresh identifier");
        }
    }

    #[test]
    fn passthrough_sends_the_local_id() {
        let c = choose_wire_id(
            WireIdMode::Passthrough,
            "http-00000000deadbeef",
            Some(&H),
            &relayed("relay"),
            roles,
        );
        assert_eq!(c.wire_id, "http-00000000deadbeef");
        assert_eq!(c.kind, WireIdKind::Passthrough);
    }
}
