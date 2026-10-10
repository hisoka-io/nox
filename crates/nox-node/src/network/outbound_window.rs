//! Per-peer limit on open packet requests (NOX-180).
//!
//! Every Sphinx packet travels as its own libp2p request-response stream. A
//! receiving node serves at most `network.max_concurrent_streams` of them per
//! connection and drops the streams above that without telling the sender,
//! so a many-fragment reply handed to the swarm at once lost fragments at the
//! next hop. The window keeps at most `limit` requests open per peer and
//! holds the rest, in order, until earlier ones are answered or fail.

use libp2p::PeerId;
use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

/// What to do with a packet handed to [`OutboundWindow::submit`].
#[derive(Debug, PartialEq, Eq)]
pub enum Submit<M> {
    /// A slot was free: send it now and report the request id with
    /// [`OutboundWindow::sent`].
    Send(M),
    /// Held until a slot frees up.
    Queued,
    /// The peer's queue is full; the packet is dropped.
    Full,
}

#[derive(Debug)]
struct PeerState<M> {
    in_flight: usize,
    queued: VecDeque<M>,
}

#[derive(Debug)]
pub struct OutboundWindow<I, M> {
    limit: usize,
    queue_limit: usize,
    peers: HashMap<PeerId, PeerState<M>>,
    owners: HashMap<I, PeerId>,
}

impl<I: Hash + Eq, M> OutboundWindow<I, M> {
    /// `limit` open requests per peer (at least 1), `queue_limit` packets
    /// held per peer beyond those.
    #[must_use]
    pub fn new(limit: usize, queue_limit: usize) -> Self {
        Self {
            limit: limit.max(1),
            queue_limit,
            peers: HashMap::new(),
            owners: HashMap::new(),
        }
    }

    pub fn submit(&mut self, peer: PeerId, message: M) -> Submit<M> {
        let state = self.peers.entry(peer).or_insert_with(|| PeerState {
            in_flight: 0,
            queued: VecDeque::new(),
        });
        if state.in_flight < self.limit {
            state.in_flight += 1;
            Submit::Send(message)
        } else if state.queued.len() < self.queue_limit {
            state.queued.push_back(message);
            Submit::Queued
        } else {
            Submit::Full
        }
    }

    /// Records the id of a request sent for `peer` after [`Submit::Send`]
    /// or [`OutboundWindow::complete`].
    pub fn sent(&mut self, id: I, peer: PeerId) {
        self.owners.insert(id, peer);
    }

    /// Frees the slot of a request that was answered or failed. Returns the
    /// next held packet for that peer, which takes the slot and must be sent
    /// (and reported with [`OutboundWindow::sent`]). Ids this window did not
    /// send are ignored.
    pub fn complete(&mut self, id: &I) -> Option<(PeerId, M)> {
        let peer = self.owners.remove(id)?;
        let state = self.peers.get_mut(&peer)?;
        if let Some(next) = state.queued.pop_front() {
            return Some((peer, next));
        }
        state.in_flight = state.in_flight.saturating_sub(1);
        if state.in_flight == 0 {
            self.peers.remove(&peer);
        }
        None
    }

    /// Whether `id` is an open request this window sent.
    #[must_use]
    pub fn owns(&self, id: &I) -> bool {
        self.owners.contains_key(id)
    }

    /// Packets held across all peers.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.peers.values().map(|s| s.queued.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn sends_up_to_the_limit_then_queues_in_order() {
        let mut w = OutboundWindow::<u32, u32>::new(2, 10);
        let p = peer();
        assert_eq!(w.submit(p, 0), Submit::Send(0));
        w.sent(100, p);
        assert_eq!(w.submit(p, 1), Submit::Send(1));
        w.sent(101, p);
        assert_eq!(w.submit(p, 2), Submit::Queued);
        assert_eq!(w.submit(p, 3), Submit::Queued);
        assert_eq!(w.queued(), 2);

        assert_eq!(w.complete(&101), Some((p, 2)));
        w.sent(102, p);
        assert_eq!(w.complete(&100), Some((p, 3)));
        w.sent(103, p);
        assert_eq!(w.complete(&102), None);
        assert_eq!(w.complete(&103), None);
        assert_eq!(w.queued(), 0);
        assert!(w.peers.is_empty() && w.owners.is_empty());
    }

    #[test]
    fn peers_have_separate_windows() {
        let mut w = OutboundWindow::<u32, u32>::new(1, 10);
        let (a, b) = (peer(), peer());
        assert_eq!(w.submit(a, 0), Submit::Send(0));
        w.sent(1, a);
        assert_eq!(w.submit(a, 1), Submit::Queued);
        assert_eq!(w.submit(b, 2), Submit::Send(2));
        w.sent(2, b);
        assert_eq!(w.complete(&2), None);
        assert_eq!(w.complete(&1), Some((a, 1)));
    }

    #[test]
    fn a_full_queue_refuses_more() {
        let mut w = OutboundWindow::<u32, u32>::new(1, 1);
        let p = peer();
        assert_eq!(w.submit(p, 0), Submit::Send(0));
        w.sent(1, p);
        assert_eq!(w.submit(p, 1), Submit::Queued);
        assert_eq!(w.submit(p, 2), Submit::Full);
    }

    #[test]
    fn unknown_ids_change_nothing() {
        let mut w = OutboundWindow::<u32, u32>::new(1, 4);
        let p = peer();
        assert_eq!(w.submit(p, 0), Submit::Send(0));
        w.sent(1, p);
        assert!(w.owns(&1) && !w.owns(&99));
        assert_eq!(w.complete(&99), None);
        assert_eq!(w.submit(p, 1), Submit::Queued);
        assert_eq!(w.complete(&1), Some((p, 1)));
    }
}
