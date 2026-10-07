//! Per-tunnel exchange state without I/O: seq order, the downstream window, the SURBs of the
//! current exchange and the part flush policy.

use nox_core::{TunnelFinV1, TunnelRejectCodeV1, TunnelReplyV1, TUNNEL_PART_MAX_DATA};
use std::collections::VecDeque;
use std::time::Duration;
use tokio::time::Instant;

#[derive(Debug, Clone, Copy)]
pub struct FlushPolicy {
    /// Send a part that is not full after this much upstream silence.
    pub idle: Duration,
    /// Send a part that is not full this long after its first byte.
    pub max: Duration,
}

/// One client request as the window sees it.
#[derive(Debug)]
pub struct Exchange<S> {
    pub seq: u32,
    pub ack_offset: u64,
    pub data: Vec<u8>,
    pub close: bool,
    pub surbs: Vec<S>,
    pub hold: Duration,
}

/// What an accepted request asks of the upstream socket.
#[derive(Debug, PartialEq, Eq)]
pub enum Accepted {
    /// A copy of the current seq: nothing is written again.
    Copy,
    /// The next seq: write `data` once, then half-close when `close` is set.
    Write { data: Vec<u8>, close: bool },
}

#[derive(Debug)]
pub struct Part<S> {
    pub surb: S,
    pub reply: TunnelReplyV1,
}

/// Downstream bytes are numbered from 0 for the life of the tunnel. The window keeps every
/// byte from the client's acknowledged offset on, sent or not, so a copy can resend them.
#[derive(Debug)]
pub struct Window<S> {
    seq: Option<u32>,
    base: u64,
    buffer: VecDeque<u8>,
    cursor: u64,
    sent_max: u64,
    eof: bool,
    fin_sent: bool,
    surbs: VecDeque<S>,
    max_surbs: usize,
    hold_until: Option<Instant>,
    last_read: Option<Instant>,
    unsent_since: Option<Instant>,
}

impl<S> Window<S> {
    pub fn new(max_surbs: usize) -> Self {
        Self {
            seq: None,
            base: 0,
            buffer: VecDeque::new(),
            cursor: 0,
            sent_max: 0,
            eof: false,
            fin_sent: false,
            surbs: VecDeque::new(),
            max_surbs,
            hold_until: None,
            last_read: None,
            unsent_since: None,
        }
    }

    fn end(&self) -> u64 {
        self.base + self.buffer.len() as u64
    }

    fn unsent(&self) -> usize {
        (self.end() - self.cursor) as usize
    }

    /// Bytes held, sent or not.
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// Bytes the upstream may add before the window is full.
    pub fn room(&self, max_window: usize) -> usize {
        if self.eof {
            0
        } else {
            max_window.saturating_sub(self.buffer.len())
        }
    }

    /// The current exchange still holds SURBs.
    pub fn in_flight(&self) -> bool {
        !self.surbs.is_empty()
    }

    /// The upstream closed its side of the connection.
    pub fn upstream_closed(&self) -> bool {
        self.eof
    }

    /// The upstream closed and its last byte went out with `Eof`.
    pub fn drained(&self) -> bool {
        self.eof && self.fin_sent
    }

    /// Drained, and the client acknowledged every byte.
    pub fn finished(&self) -> bool {
        self.drained() && self.base == self.end() && self.surbs.is_empty()
    }

    pub fn seq(&self) -> Option<u32> {
        self.seq
    }

    /// Takes one SURB of the current exchange, for a rejection that ends the tunnel.
    pub fn take_surb(&mut self) -> Option<S> {
        self.surbs.pop_front()
    }

    /// Applies a client request. The first request must carry seq 0; after that a request
    /// repeats the current seq (a copy) or carries the next one.
    pub fn accept(
        &mut self,
        exchange: Exchange<S>,
        now: Instant,
    ) -> Result<Accepted, TunnelRejectCodeV1> {
        let is_copy = match self.seq {
            None if exchange.seq == 0 => false,
            Some(current) if exchange.seq == current => true,
            Some(current) if current.checked_add(1) == Some(exchange.seq) => false,
            _ => return Err(TunnelRejectCodeV1::OutOfOrder),
        };
        if exchange.ack_offset > self.sent_max {
            return Err(TunnelRejectCodeV1::Malformed);
        }
        self.acknowledge(exchange.ack_offset);
        self.hold_until = Some(now + exchange.hold);
        if is_copy {
            self.cursor = self.base;
            self.fin_sent = false;
            let room = self.max_surbs.saturating_sub(self.surbs.len());
            self.surbs.extend(exchange.surbs.into_iter().take(room));
            return Ok(Accepted::Copy);
        }
        self.seq = Some(exchange.seq);
        self.surbs = exchange.surbs.into_iter().take(self.max_surbs).collect();
        Ok(Accepted::Write {
            data: exchange.data,
            close: exchange.close,
        })
    }

    fn acknowledge(&mut self, ack_offset: u64) {
        if ack_offset <= self.base {
            return;
        }
        let freed = (ack_offset - self.base) as usize;
        self.buffer.drain(..freed.min(self.buffer.len()));
        self.base = ack_offset;
        self.cursor = self.cursor.max(self.base);
    }

    pub fn push_upstream(&mut self, bytes: &[u8], now: Instant) {
        if bytes.is_empty() {
            return;
        }
        if self.unsent() == 0 {
            self.unsent_since = Some(now);
        }
        self.buffer.extend(bytes);
        self.last_read = Some(now);
    }

    pub fn mark_eof(&mut self) {
        self.eof = true;
    }

    /// Ends the stream where it stands: unsent bytes beyond what the SURBs held can carry are
    /// dropped, so the parts still to send end with `Eof`.
    pub fn truncate(&mut self) {
        let carried = self.surbs.len().saturating_mul(TUNNEL_PART_MAX_DATA);
        let keep = (self.cursor - self.base) as usize + self.unsent().min(carried);
        self.buffer.truncate(keep);
        self.eof = true;
    }

    fn ready(&self, now: Instant, flush: FlushPolicy) -> bool {
        self.unsent() >= TUNNEL_PART_MAX_DATA
            || self.eof
            || self.cursor < self.sent_max
            || self.last_read.is_some_and(|at| now >= at + flush.idle)
            || self.unsent_since.is_some_and(|at| now >= at + flush.max)
    }

    /// The next part to send, if any. The last SURB of an exchange is kept for `Eof` or,
    /// when bytes still wait, `NeedSurbs`.
    pub fn next_part(&mut self, now: Instant, flush: FlushPolicy) -> Option<Part<S>> {
        if self.surbs.is_empty() || self.fin_sent {
            return None;
        }
        let unsent = self.unsent();
        let ends_stream = self.eof && unsent <= TUNNEL_PART_MAX_DATA;
        if unsent == 0 && !ends_stream {
            return None;
        }
        if !ends_stream && !self.ready(now, flush) {
            return None;
        }
        let length = unsent.min(TUNNEL_PART_MAX_DATA);
        let fin = if ends_stream {
            Some(TunnelFinV1::Eof)
        } else if self.surbs.len() == 1 {
            Some(TunnelFinV1::NeedSurbs)
        } else {
            None
        };
        let surb = self.surbs.pop_front()?;
        let start = (self.cursor - self.base) as usize;
        let data = self.buffer.range(start..start + length).copied().collect();
        let reply = TunnelReplyV1::Data {
            seq: self.seq.unwrap_or_default(),
            offset: self.cursor,
            data,
            fin,
        };
        self.cursor += length as u64;
        self.sent_max = self.sent_max.max(self.cursor);
        self.unsent_since = (self.unsent() > 0).then_some(now);
        if fin.is_some() {
            self.end_exchange();
        }
        self.fin_sent = ends_stream;
        Some(Part { surb, reply })
    }

    /// When the hold deadline passed with SURBs left, one empty `Expired` part ends the
    /// exchange.
    pub fn expire(&mut self, now: Instant) -> Option<Part<S>> {
        if self.hold_until.is_none_or(|until| now < until) {
            return None;
        }
        let surb = self.surbs.pop_front()?;
        self.end_exchange();
        Some(Part {
            surb,
            reply: TunnelReplyV1::Data {
                seq: self.seq.unwrap_or_default(),
                offset: self.cursor,
                data: Vec::new(),
                fin: Some(TunnelFinV1::Expired),
            },
        })
    }

    fn end_exchange(&mut self) {
        self.surbs.clear();
        self.hold_until = None;
    }

    /// When the window next needs attention without new input: a flush or the hold deadline.
    pub fn next_deadline(&self, flush: FlushPolicy) -> Option<Instant> {
        if self.surbs.is_empty() {
            return None;
        }
        let flush_at = (self.unsent() > 0)
            .then(|| {
                let idle = self.last_read.map(|at| at + flush.idle);
                let max = self.unsent_since.map(|at| at + flush.max);
                idle.into_iter().chain(max).min()
            })
            .flatten();
        self.hold_until.into_iter().chain(flush_at).min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLUSH: FlushPolicy = FlushPolicy {
        idle: Duration::from_millis(3),
        max: Duration::from_millis(25),
    };
    const HOLD: Duration = Duration::from_secs(20);

    fn exchange(seq: u32, ack_offset: u64, surbs: std::ops::Range<u32>) -> Exchange<u32> {
        Exchange {
            seq,
            ack_offset,
            data: vec![seq as u8],
            close: false,
            surbs: surbs.collect(),
            hold: HOLD,
        }
    }

    fn data_of(part: &Part<u32>) -> (u64, usize, Option<TunnelFinV1>) {
        match &part.reply {
            TunnelReplyV1::Data {
                offset, data, fin, ..
            } => (*offset, data.len(), *fin),
            TunnelReplyV1::Rejected { .. } => panic!("expected data"),
        }
    }

    #[test]
    fn seq_state_machine() {
        let now = Instant::now();
        let mut window = Window::new(32);
        assert_eq!(
            window.accept(exchange(1, 0, 0..2), now),
            Err(TunnelRejectCodeV1::OutOfOrder)
        );
        assert_eq!(
            window.accept(exchange(0, 0, 0..2), now),
            Ok(Accepted::Write {
                data: vec![0],
                close: false
            })
        );
        assert_eq!(window.accept(exchange(0, 0, 2..4), now), Ok(Accepted::Copy));
        assert_eq!(
            window.accept(exchange(1, 0, 4..6), now),
            Ok(Accepted::Write {
                data: vec![1],
                close: false
            })
        );
        assert_eq!(window.accept(exchange(1, 0, 6..8), now), Ok(Accepted::Copy));
        assert_eq!(
            window.accept(exchange(3, 0, 8..9), now),
            Err(TunnelRejectCodeV1::OutOfOrder)
        );
        assert_eq!(
            window.accept(exchange(0, 0, 8..9), now),
            Err(TunnelRejectCodeV1::OutOfOrder)
        );
        assert_eq!(
            window.accept(exchange(1, 1, 8..9), now),
            Err(TunnelRejectCodeV1::Malformed),
            "acknowledging bytes never sent"
        );
        assert_eq!(window.seq(), Some(1));
    }

    #[test]
    fn window_acks_rewinds_and_reserves_the_last_surb() {
        let mut now = Instant::now();
        let mut window = Window::new(32);
        window.accept(exchange(0, 0, 0..3), now).ok();
        let total = TUNNEL_PART_MAX_DATA * 3 + 10;
        window.push_upstream(&vec![7; total], now);

        let first = window.next_part(now, FLUSH).expect("full part");
        assert_eq!(data_of(&first), (0, TUNNEL_PART_MAX_DATA, None));
        let second = window.next_part(now, FLUSH).expect("full part");
        assert_eq!(
            data_of(&second),
            (TUNNEL_PART_MAX_DATA as u64, TUNNEL_PART_MAX_DATA, None)
        );
        let last = window.next_part(now, FLUSH).expect("reserved SURB");
        assert_eq!(
            data_of(&last),
            (
                2 * TUNNEL_PART_MAX_DATA as u64,
                TUNNEL_PART_MAX_DATA,
                Some(TunnelFinV1::NeedSurbs)
            )
        );
        assert!(!window.in_flight());
        assert!(window.next_part(now, FLUSH).is_none());

        // A copy acknowledging the first part rewinds to it and resends the rest.
        let acked = TUNNEL_PART_MAX_DATA as u64;
        assert_eq!(
            window.accept(exchange(0, acked, 3..8), now),
            Ok(Accepted::Copy)
        );
        assert_eq!(window.buffered(), total - TUNNEL_PART_MAX_DATA);
        let resent = window.next_part(now, FLUSH).expect("resend");
        assert_eq!(data_of(&resent), (acked, TUNNEL_PART_MAX_DATA, None));
        window.next_part(now, FLUSH).expect("resend");
        let tail = window.next_part(now, FLUSH);
        assert!(tail.is_none(), "10 bytes wait for the flush policy");
        now += FLUSH.idle;
        let tail = window.next_part(now, FLUSH).expect("idle flush");
        assert_eq!(data_of(&tail), (3 * TUNNEL_PART_MAX_DATA as u64, 10, None));

        window.mark_eof();
        let eof = window.next_part(now, FLUSH).expect("end of stream");
        assert_eq!(data_of(&eof), (total as u64, 0, Some(TunnelFinV1::Eof)));
        assert!(window.drained() && !window.finished());
        assert!(window.accept(exchange(1, total as u64, 0..0), now).is_ok());
        assert!(window.finished());
    }

    #[test]
    fn window_pauses_reads_when_full_and_expires_held_surbs() {
        let now = Instant::now();
        let max_window = 4 * TUNNEL_PART_MAX_DATA;
        let mut window = Window::new(32);
        window.accept(exchange(0, 0, 0..2), now).ok();
        window.push_upstream(&vec![1; max_window], now);
        assert_eq!(window.room(max_window), 0);
        window.next_part(now, FLUSH).expect("part");
        assert_eq!(
            window.room(max_window),
            0,
            "sent bytes stay until acknowledged"
        );

        let mut idle = Window::new(32);
        idle.accept(exchange(0, 0, 0..4), now).ok();
        assert_eq!(idle.next_deadline(FLUSH), Some(now + HOLD));
        assert!(idle.expire(now).is_none());
        let expired = idle.expire(now + HOLD).expect("hold deadline");
        assert_eq!(data_of(&expired), (0, 0, Some(TunnelFinV1::Expired)));
        assert!(!idle.in_flight());
    }

    #[test]
    fn truncate_ends_the_stream_on_the_surbs_held() {
        let now = Instant::now();
        let mut window = Window::new(32);
        window.accept(exchange(0, 0, 0..2), now).ok();
        window.push_upstream(&vec![3; TUNNEL_PART_MAX_DATA * 3], now);
        window.truncate();
        let first = window.next_part(now, FLUSH).expect("part");
        assert_eq!(data_of(&first), (0, TUNNEL_PART_MAX_DATA, None));
        let last = window.next_part(now, FLUSH).expect("end of stream");
        assert_eq!(
            data_of(&last),
            (
                TUNNEL_PART_MAX_DATA as u64,
                TUNNEL_PART_MAX_DATA,
                Some(TunnelFinV1::Eof)
            )
        );
        assert!(window.drained() && window.next_part(now, FLUSH).is_none());
    }

    #[test]
    fn small_parts_flush_on_upstream_silence_or_the_ceiling() {
        let start = Instant::now();
        let mut window = Window::new(32);
        window.accept(exchange(0, 0, 0..8), start).ok();
        let mut now = start;
        for _ in 0..10 {
            window.push_upstream(&[1; 100], now);
            assert!(window.next_part(now, FLUSH).is_none());
            now += Duration::from_millis(2);
        }
        assert!(window.next_part(start + FLUSH.max, FLUSH).is_some());
    }
}
