//! End-to-end TLS tunnels (`ServiceRequest::TunnelV1`).
//!
//! The client runs TLS itself; the exit relays TLS records between the client and one
//! upstream host over one TCP connection per tunnel. The exit checks the destination and the
//! record framing, never holds a key, and never sees the plaintext.

mod clienthello;
mod records;
mod window;

use crate::config::{HttpConfig, TunnelConfig};
use crate::services::response_packer::ResponsePacker;
use crate::services::security;
use crate::telemetry::metrics::MetricsService;
use nox_core::events::NoxEvent;
use nox_core::models::payloads::encode_payload;
use nox_core::models::wire_id::{reply_wire_id, PacketOrigin};
use nox_core::traits::IEventPublisher;
use nox_core::{TunnelRejectCodeV1, TunnelReplyV1, TunnelRequestV1, TUNNEL_ID_LEN};
use nox_crypto::sphinx::surb::Surb;
use parking_lot::Mutex;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{sleep_until, Instant};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use window::{Accepted, Exchange, FlushPolicy, Part, Window};

type TunnelId = [u8; TUNNEL_ID_LEN];

/// Largest single upstream read.
const READ_CHUNK: usize = 64 * 1024;
/// Longest DNS name.
const MAX_HOST_LEN: usize = 253;
/// Longest DNS label.
const MAX_LABEL_LEN: usize = 63;
/// How often expired tombstones are dropped, checked on tunnel opens.
const TOMBSTONE_PRUNE_INTERVAL: Duration = Duration::from_secs(5);
/// How long a tunnel waits before reading again when the exit-wide buffer is full.
const BUFFER_FULL_RETRY: Duration = Duration::from_millis(5);

/// A refused tunnel request: the code the client receives and a short reason.
#[derive(Debug, Error)]
#[error("{code:?}: {detail}")]
pub struct TunnelError {
    pub code: TunnelRejectCodeV1,
    pub detail: String,
}

impl TunnelError {
    fn new(code: TunnelRejectCodeV1, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

/// First 4 bytes of a tunnel ID, the only form that appears in logs.
struct ShortId<'a>(&'a TunnelId);

impl std::fmt::Display for ShortId<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0
            .iter()
            .take(4)
            .try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

/// Token bucket for tunnel opens across the exit.
struct OpenBucket {
    tokens: f64,
    rate: f64,
    burst: f64,
    refilled: Instant,
}

impl OpenBucket {
    fn new(config: &TunnelConfig, now: Instant) -> Self {
        let burst = f64::from(config.opens_burst);
        Self {
            tokens: burst,
            rate: f64::from(config.opens_per_sec),
            burst,
            refilled: now,
        }
    }

    fn try_take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.refilled).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        self.refilled = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

struct SessionEntry {
    host: String,
    port: u16,
    sender: mpsc::Sender<Exchange<Surb>>,
    last_request: Instant,
    /// Connecting, or holding SURBs of an exchange. Such tunnels are never evicted.
    busy: Arc<AtomicBool>,
    cancel: CancellationToken,
}

struct Table {
    sessions: HashMap<TunnelId, SessionEntry>,
    /// Closed tunnel IDs and when they may be forgotten.
    tombstones: HashMap<TunnelId, Instant>,
    opens: OpenBucket,
    next_prune: Instant,
}

impl Table {
    fn is_tombstoned(&self, id: &TunnelId, now: Instant) -> bool {
        self.tombstones.get(id).is_some_and(|until| now < *until)
    }

    fn prune(&mut self, now: Instant) {
        if now >= self.next_prune {
            self.tombstones.retain(|_, until| now < *until);
            self.next_prune = now + TOMBSTONE_PRUNE_INTERVAL;
        }
    }

    /// The longest-idle tunnel with nothing in flight.
    fn eviction_candidate(&self) -> Option<TunnelId> {
        self.sessions
            .iter()
            .filter(|(_, entry)| !entry.busy.load(Ordering::Acquire))
            .min_by_key(|(_, entry)| entry.last_request)
            .map(|(id, _)| *id)
    }
}

struct Shared {
    config: TunnelConfig,
    allowed_domains: Option<Vec<String>>,
    allow_private_ips: bool,
    packer: Arc<ResponsePacker>,
    publisher: Arc<dyn IEventPublisher>,
    metrics: MetricsService,
    table: Mutex<Table>,
    /// Downstream bytes held across all tunnels.
    buffered: AtomicUsize,
    cancel: CancellationToken,
}

impl Shared {
    fn flush_policy(&self) -> FlushPolicy {
        FlushPolicy {
            idle: Duration::from_millis(self.config.flush_idle_ms),
            max: Duration::from_millis(self.config.flush_max_ms),
        }
    }

    fn count(family: &Family<Vec<(String, String)>, Counter>, label: &str, value: &str) {
        family
            .get_or_create(&vec![(label.to_string(), value.to_string())])
            .inc();
    }

    fn count_exchange(&self, kind: &str) {
        Self::count(&self.metrics.tunnel_exchanges_total, "kind", kind);
    }

    fn count_open(&self, result: &str) {
        Self::count(&self.metrics.tunnel_opens_total, "result", result);
    }

    fn count_close(&self, reason: &str) {
        Self::count(&self.metrics.tunnel_closes_total, "reason", reason);
    }

    fn send(&self, surb: &Surb, reply: &TunnelReplyV1, message_id: u64) {
        let body = match encode_payload(reply) {
            Ok(body) => body,
            Err(e) => {
                debug!(error = %e, "Tunnel reply encoding failed");
                return;
            }
        };
        let packed = match self
            .packer
            .pack_single_fragment(message_id, &body, surb, 0, 1)
        {
            Ok(packed) => packed,
            Err(e) => {
                debug!(error = %e, "Tunnel reply sealing failed");
                return;
            }
        };
        if let Err(e) = self.publisher.publish(NoxEvent::SendPacket {
            next_hop_peer_id: packed.first_hop.clone(),
            packet_id: reply_wire_id(&packed.surb_id),
            data: packed.packet_bytes.clone(),
            reply_handle: packed.reply_handle(),
            origin: PacketOrigin::Originated,
        }) {
            debug!(error = %e, "Tunnel reply publish failed");
        }
    }

    fn reject(&self, surb: Option<&Surb>, seq: u32, error: &TunnelError) {
        self.count_exchange("rejected");
        if let Some(surb) = surb {
            self.send(
                surb,
                &TunnelReplyV1::rejected(seq, error.code, &error.detail),
                0,
            );
        }
    }

    fn set_sessions_gauge(&self, sessions: usize) {
        self.metrics.tunnel_sessions_active.set(sessions as i64);
    }

    /// Removes a tunnel and refuses its ID until `tombstone_until`.
    fn forget(&self, id: &TunnelId, tombstone_until: Instant) {
        let mut table = self.table.lock();
        table.sessions.remove(id);
        table.tombstones.insert(*id, tombstone_until);
        self.set_sessions_gauge(table.sessions.len());
    }
}

/// Exit side of `ServiceRequest::TunnelV1`. Requests are checked in the exit's tunnel lane
/// and handed to one task per tunnel, which owns the upstream socket.
pub struct TunnelHandler {
    shared: Arc<Shared>,
}

impl TunnelHandler {
    /// Tunnels close when `cancel` is cancelled.
    #[must_use]
    pub fn new(
        config: TunnelConfig,
        http: &HttpConfig,
        packer: Arc<ResponsePacker>,
        publisher: Arc<dyn IEventPublisher>,
        metrics: MetricsService,
        cancel: CancellationToken,
    ) -> Self {
        let now = Instant::now();
        let table = Table {
            sessions: HashMap::new(),
            tombstones: HashMap::new(),
            opens: OpenBucket::new(&config, now),
            next_prune: now + TOMBSTONE_PRUNE_INTERVAL,
        };
        Self {
            shared: Arc::new(Shared {
                config,
                allowed_domains: http.allowed_domains.clone(),
                allow_private_ips: http.allow_private_ips,
                packer,
                publisher,
                metrics,
                table: Mutex::new(table),
                buffered: AtomicUsize::new(0),
                cancel,
            }),
        }
    }

    /// Open tunnels.
    #[must_use]
    pub fn sessions(&self) -> usize {
        self.shared.table.lock().sessions.len()
    }

    /// Downstream bytes held across all tunnels.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.shared.buffered.load(Ordering::Acquire)
    }

    /// Checks one request and hands it to its tunnel. Never waits on the network.
    pub fn handle(&self, request: TunnelRequestV1, mut surbs: Vec<Surb>) {
        let shared = &self.shared;
        let config = &shared.config;
        let seq = request.seq;
        if !config.enabled {
            shared.reject(
                surbs.first(),
                seq,
                &TunnelError::new(TunnelRejectCodeV1::Disabled, "tunnels are disabled"),
            );
            return;
        }
        if surbs.is_empty() && !request.close {
            shared.count_exchange("dropped");
            return;
        }
        surbs.truncate(config.max_surbs_per_exchange);
        if let Err(error) = check_bounds(config, &request) {
            shared.reject(surbs.first(), seq, &error);
            return;
        }
        if let Some(open) = &request.open {
            if let Err(error) = self.check_open(&open.host, open.port, &request.data) {
                shared.count_open(error.code.as_str());
                debug!(tunnel = %ShortId(&request.tunnel_id), %error, "Tunnel open refused");
                shared.reject(surbs.first(), seq, &error);
                return;
            }
        }
        let hold = Duration::from_millis(u64::from(
            request
                .hold_ms
                .clamp(config.min_hold_ms, config.max_hold_ms),
        ));
        let now = Instant::now();
        let exchange = Exchange {
            seq,
            ack_offset: request.ack_offset,
            data: request.data,
            close: request.close,
            surbs,
            hold,
        };
        if let Err((error, exchange)) = self.route(request.tunnel_id, request.open, exchange, now) {
            if request.seq == 0 {
                shared.count_open(error.code.as_str());
            }
            debug!(tunnel = %ShortId(&request.tunnel_id), %error, "Tunnel request refused");
            shared.reject(exchange.surbs.first(), seq, &error);
        }
    }

    fn check_open(&self, host: &str, port: u16, data: &[u8]) -> Result<(), TunnelError> {
        let shared = &self.shared;
        if !shared.config.allowed_ports.contains(&port) {
            return Err(TunnelError::new(
                TunnelRejectCodeV1::PortNotAllowed,
                format!("port {port} is not open for tunnels"),
            ));
        }
        check_host(host)?;
        security::is_domain_allowed(host, &shared.allowed_domains).map_err(|_| {
            TunnelError::new(
                TunnelRejectCodeV1::HostNotAllowed,
                "host is not in this exit's domain list",
            )
        })?;
        clienthello::check_client_hello(data, host).map_err(|error| {
            let code = if error.is_host_mismatch() {
                TunnelRejectCodeV1::HostNotAllowed
            } else {
                TunnelRejectCodeV1::NotTls
            };
            TunnelError::new(code, error.to_string())
        })
    }

    /// Passes the exchange to its tunnel, or opens the tunnel. Returns the exchange with the
    /// error when it was not accepted, so the rejection can use its SURBs.
    fn route(
        &self,
        id: TunnelId,
        open: Option<nox_core::TunnelOpenV1>,
        exchange: Exchange<Surb>,
        now: Instant,
    ) -> Result<(), (TunnelError, Exchange<Surb>)> {
        let shared = &self.shared;
        let mut table = shared.table.lock();
        table.prune(now);
        if table.is_tombstoned(&id, now) {
            return Err((
                TunnelError::new(TunnelRejectCodeV1::Expired, "tunnel is closed"),
                exchange,
            ));
        }
        if let Some(entry) = table.sessions.get_mut(&id) {
            if open
                .as_ref()
                .is_some_and(|open| open.host != entry.host || open.port != entry.port)
            {
                return Err((
                    TunnelError::new(
                        TunnelRejectCodeV1::OutOfOrder,
                        "tunnel is open to another destination",
                    ),
                    exchange,
                ));
            }
            entry.last_request = now;
            if !exchange.surbs.is_empty() {
                entry.busy.store(true, Ordering::Release);
            }
            if entry.sender.try_send(exchange).is_err() {
                shared.count_exchange("dropped");
            }
            return Ok(());
        }
        let Some(open) = open else {
            return Err((
                TunnelError::new(TunnelRejectCodeV1::UnknownSession, "no such tunnel"),
                exchange,
            ));
        };
        if !table.opens.try_take(now) {
            return Err((
                TunnelError::new(TunnelRejectCodeV1::RateLimited, "tunnel open rate exceeded"),
                exchange,
            ));
        }
        if table.sessions.len() >= shared.config.max_sessions {
            let Some(victim) = table.eviction_candidate() else {
                return Err((
                    TunnelError::new(TunnelRejectCodeV1::SessionLimit, "all tunnels are busy"),
                    exchange,
                ));
            };
            if let Some(entry) = table.sessions.remove(&victim) {
                entry.cancel.cancel();
                table.tombstones.insert(
                    victim,
                    now + Duration::from_secs(shared.config.session_max_secs),
                );
                shared.count_close("evicted");
                debug!(tunnel = %ShortId(&victim), "Idle tunnel evicted for a new open");
            }
        }

        let (sender, receiver) = mpsc::channel(shared.config.session_queue);
        if let Err(error) = sender.try_send(exchange) {
            let exchange = match error {
                mpsc::error::TrySendError::Full(exchange)
                | mpsc::error::TrySendError::Closed(exchange) => exchange,
            };
            return Err((
                TunnelError::new(TunnelRejectCodeV1::SessionLimit, "tunnel queue unavailable"),
                exchange,
            ));
        }
        let busy = Arc::new(AtomicBool::new(true));
        let cancel = shared.cancel.child_token();
        table.sessions.insert(
            id,
            SessionEntry {
                host: open.host.clone(),
                port: open.port,
                sender,
                last_request: now,
                busy: busy.clone(),
                cancel: cancel.clone(),
            },
        );
        shared.set_sessions_gauge(table.sessions.len());
        drop(table);

        let session = Session {
            shared: shared.clone(),
            id,
            host: open.host,
            port: open.port,
            opened: now,
            busy,
            cancel,
        };
        tokio::spawn(session.run(receiver));
        Ok(())
    }
}

fn check_bounds(config: &TunnelConfig, request: &TunnelRequestV1) -> Result<(), TunnelError> {
    if request.data.len() > config.max_write_bytes {
        return Err(TunnelError::new(
            TunnelRejectCodeV1::Malformed,
            format!(
                "write of {} bytes exceeds {}",
                request.data.len(),
                config.max_write_bytes
            ),
        ));
    }
    if (request.seq == 0) != request.open.is_some() {
        return Err(TunnelError::new(
            TunnelRejectCodeV1::Malformed,
            "open must be present exactly on seq 0",
        ));
    }
    Ok(())
}

/// A DNS name in ASCII (IDNs as punycode), not an IP literal, without a trailing dot.
fn check_host(host: &str) -> Result<(), TunnelError> {
    let refuse = |detail: &str| TunnelError::new(TunnelRejectCodeV1::HostNotAllowed, detail);
    if host.parse::<IpAddr>().is_ok() || host.starts_with('[') {
        return Err(refuse("tunnels reach hosts by name, not by IP address"));
    }
    if host.is_empty() || host.len() > MAX_HOST_LEN {
        return Err(refuse("host name length is out of range"));
    }
    let valid = host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    });
    if !valid {
        return Err(refuse("host is not a DNS name"));
    }
    Ok(())
}

/// Why a tunnel task ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseReason {
    Eof,
    Client,
    Idle,
    Lifetime,
    ByteLimit,
    NotTls,
    Upstream,
    /// Evicted or shut down; counted by whoever cancelled it.
    Cancelled,
}

impl CloseReason {
    const fn label(self) -> Option<&'static str> {
        match self {
            Self::Eof => Some("eof"),
            Self::Client => Some("client"),
            Self::Idle => Some("idle"),
            Self::Lifetime => Some("lifetime"),
            Self::ByteLimit => Some("byte_limit"),
            Self::NotTls => Some("not_tls"),
            Self::Upstream => Some("upstream"),
            Self::Cancelled => None,
        }
    }
}

struct Session {
    shared: Arc<Shared>,
    id: TunnelId,
    host: String,
    port: u16,
    opened: Instant,
    busy: Arc<AtomicBool>,
    cancel: CancellationToken,
}

/// Upstream socket and the bytes waiting to be written to it.
struct Upstream {
    reader: OwnedReadHalf,
    writer: OwnedWriteHalf,
    pending: Vec<u8>,
    written: usize,
    shutdown_after_write: bool,
    write_closed: bool,
}

struct SessionState {
    window: Window<Surb>,
    framer: records::RecordFramer,
    bytes: u64,
    parts: u64,
    last_request: Instant,
    held: usize,
    /// Rejection sent once the tunnel is gone, so a client that reacts to it finds the slot
    /// free.
    closing_reply: Option<(Option<Surb>, u32, TunnelError)>,
}

impl Session {
    async fn run(self, mut receiver: mpsc::Receiver<Exchange<Surb>>) {
        let Some(first) = receiver.recv().await else {
            self.finish(None);
            return;
        };
        let connected = tokio::select! {
            result = self.connect() => result,
            () = self.cancel.cancelled() => {
                self.finish(None);
                return;
            }
        };
        let stream = match connected {
            Ok(stream) => stream,
            Err(error) => {
                self.shared.count_open(error.code.as_str());
                debug!(tunnel = %ShortId(&self.id), %error, "Tunnel connect failed");
                self.finish(None);
                self.shared.reject(first.surbs.first(), first.seq, &error);
                return;
            }
        };
        self.shared.count_open("opened");
        debug!(tunnel = %ShortId(&self.id), host = %self.host, "Tunnel open");
        let (reader, writer) = stream.into_split();
        let mut upstream = Upstream {
            reader,
            writer,
            pending: Vec::new(),
            written: 0,
            shutdown_after_write: false,
            write_closed: false,
        };
        let mut state = SessionState {
            window: Window::new(self.shared.config.max_surbs_per_exchange),
            framer: records::RecordFramer::default(),
            bytes: 0,
            parts: 0,
            last_request: Instant::now(),
            held: 0,
            closing_reply: None,
        };
        let reason = match self.on_exchange(first, &mut state, &mut upstream) {
            Some(reason) => reason,
            None => self.pump(&mut receiver, &mut state, &mut upstream).await,
        };
        if let Some(label) = reason.label() {
            self.shared.count_close(label);
        }
        debug!(tunnel = %ShortId(&self.id), reason = ?reason, "Tunnel closed");
        self.release(&mut state);
        self.finish(Some(reason));
        if let Some((surb, seq, error)) = state.closing_reply.take() {
            self.shared.reject(surb.as_ref(), seq, &error);
        }
    }

    async fn connect(&self) -> Result<TcpStream, TunnelError> {
        let timeout = Duration::from_millis(self.shared.config.connect_timeout_ms);
        let addresses = tokio::time::timeout(
            timeout,
            security::resolve_hostname_all(&self.host, self.port),
        )
        .await
        .map_err(|_| TunnelError::new(TunnelRejectCodeV1::DnsFailed, "DNS lookup timed out"))?
        .map_err(|e| TunnelError::new(TunnelRejectCodeV1::DnsFailed, e.to_string()))?;
        for address in &addresses {
            security::is_ip_allowed(*address, self.shared.allow_private_ips).map_err(|e| {
                TunnelError::new(TunnelRejectCodeV1::DestinationBlocked, e.to_string())
            })?;
        }
        let port = self.port;
        let attempt = async {
            let mut last_error = None;
            for address in addresses {
                match TcpStream::connect(SocketAddr::new(address, port)).await {
                    Ok(stream) => return Ok(stream),
                    Err(e) => last_error = Some(e),
                }
            }
            Err(last_error.map_or_else(|| "no address".to_string(), |e| e.to_string()))
        };
        let stream = tokio::time::timeout(timeout, attempt)
            .await
            .map_err(|_| {
                TunnelError::new(
                    TunnelRejectCodeV1::ConnectFailed,
                    format!("connect timed out after {}ms", timeout.as_millis()),
                )
            })?
            .map_err(|e| TunnelError::new(TunnelRejectCodeV1::ConnectFailed, e))?;
        stream
            .set_nodelay(true)
            .map_err(|e| TunnelError::new(TunnelRejectCodeV1::ConnectFailed, e.to_string()))?;
        Ok(stream)
    }

    /// Relays until the tunnel ends and returns why.
    async fn pump(
        &self,
        receiver: &mut mpsc::Receiver<Exchange<Surb>>,
        state: &mut SessionState,
        upstream: &mut Upstream,
    ) -> CloseReason {
        let config = &self.shared.config;
        let flush = self.shared.flush_policy();
        let lifetime_end = self.opened + Duration::from_secs(config.session_max_secs);
        let idle = Duration::from_secs(config.session_idle_secs);
        let mut read_buffer = vec![0_u8; READ_CHUNK];
        loop {
            if upstream.shutdown_after_write
                && !upstream.write_closed
                && upstream.pending.is_empty()
            {
                upstream.write_closed = true;
                if let Err(e) = upstream.writer.shutdown().await {
                    debug!(tunnel = %ShortId(&self.id), error = %e, "Tunnel half-close failed");
                }
            }
            let now = Instant::now();
            self.send_ready(state, now, !receiver.is_empty());
            if state.window.finished() {
                return CloseReason::Eof;
            }
            let room = state.window.room(config.max_window_bytes).min(READ_CHUNK);
            let budget_full =
                self.shared.buffered.load(Ordering::Acquire) >= config.max_total_buffered_bytes;
            let can_read = room > 0 && !budget_full;
            let can_write = upstream.written < upstream.pending.len();
            let deadline = state.window.next_deadline(flush);
            let idle_end = state.last_request + idle;

            tokio::select! {
                () = self.cancel.cancelled() => return CloseReason::Cancelled,
                exchange = receiver.recv() => {
                    let Some(exchange) = exchange else {
                        return CloseReason::Cancelled;
                    };
                    if let Some(reason) = self.on_exchange(exchange, state, upstream) {
                        return reason;
                    }
                }
                read = upstream.reader.read(&mut read_buffer[..room]), if can_read => {
                    match read {
                        Ok(0) => state.window.mark_eof(),
                        Ok(n) => {
                            if let Some(reason) = self.on_upstream(&read_buffer[..n], state) {
                                return reason;
                            }
                        }
                        Err(e) => {
                            debug!(tunnel = %ShortId(&self.id), error = %e, "Tunnel upstream read failed");
                            self.end_with(state, TunnelRejectCodeV1::UpstreamClosed, "upstream connection reset");
                            return CloseReason::Upstream;
                        }
                    }
                }
                written = upstream.writer.write(&upstream.pending[upstream.written..]), if can_write => {
                    match written {
                        Ok(n) if n > 0 => {
                            upstream.written += n;
                            if upstream.written == upstream.pending.len() {
                                upstream.pending.clear();
                                upstream.written = 0;
                            }
                        }
                        Ok(_) | Err(_) => {
                            self.end_with(state, TunnelRejectCodeV1::UpstreamClosed, "upstream stopped accepting data");
                            return CloseReason::Upstream;
                        }
                    }
                }
                () = sleep_until(deadline.unwrap_or(lifetime_end)), if deadline.is_some() => {}
                () = sleep_until(now + BUFFER_FULL_RETRY), if room > 0 && budget_full => {}
                () = sleep_until(idle_end) => {
                    return if state.window.drained() { CloseReason::Eof } else { CloseReason::Idle };
                }
                () = sleep_until(lifetime_end) => {
                    self.end_with(state, TunnelRejectCodeV1::Expired, "tunnel lifetime reached");
                    return CloseReason::Lifetime;
                }
            }
        }
    }

    /// Applies one client request. Returns a reason when it ends the tunnel.
    fn on_exchange(
        &self,
        exchange: Exchange<Surb>,
        state: &mut SessionState,
        upstream: &mut Upstream,
    ) -> Option<CloseReason> {
        let now = Instant::now();
        state.last_request = now;
        let seq = exchange.seq;
        let teardown = exchange.close && exchange.surbs.is_empty();
        let first_surb = exchange.surbs.first().cloned();
        let accepted = state.window.accept(exchange, now);
        self.sync_buffered(state);
        match accepted {
            Err(code) => {
                let detail = if code == TunnelRejectCodeV1::Malformed {
                    "acknowledged offset is beyond the bytes sent"
                } else {
                    "seq is neither the current one nor the next"
                };
                self.shared
                    .reject(first_surb.as_ref(), seq, &TunnelError::new(code, detail));
                None
            }
            Ok(Accepted::Copy) => {
                self.shared.count_exchange("copy");
                teardown.then_some(CloseReason::Client)
            }
            Ok(Accepted::Write { data, close }) => {
                self.shared.count_exchange("write");
                if teardown {
                    return Some(CloseReason::Client);
                }
                if let Err(e) = state.framer.feed(&data) {
                    debug!(tunnel = %ShortId(&self.id), error = %e, "Tunnel data is not TLS");
                    self.end_with(state, TunnelRejectCodeV1::NotTls, &e.to_string());
                    return Some(CloseReason::NotTls);
                }
                if let Some(reason) = self.add_bytes(state, data.len(), "up") {
                    return Some(reason);
                }
                if upstream.shutdown_after_write && !data.is_empty() {
                    self.end_with(
                        state,
                        TunnelRejectCodeV1::UpstreamClosed,
                        "tunnel write side is closed",
                    );
                    return Some(CloseReason::Upstream);
                }
                upstream.pending.extend_from_slice(&data);
                upstream.shutdown_after_write |= close;
                None
            }
        }
    }

    fn on_upstream(&self, bytes: &[u8], state: &mut SessionState) -> Option<CloseReason> {
        if let Some(reason) = self.add_bytes(state, bytes.len(), "down") {
            return Some(reason);
        }
        state.window.push_upstream(bytes, Instant::now());
        self.sync_buffered(state);
        None
    }

    fn add_bytes(
        &self,
        state: &mut SessionState,
        count: usize,
        direction: &str,
    ) -> Option<CloseReason> {
        self.shared
            .metrics
            .tunnel_bytes_total
            .get_or_create(&vec![("direction".to_string(), direction.to_string())])
            .inc_by(count as u64);
        state.bytes = state.bytes.saturating_add(count as u64);
        if state.bytes > self.shared.config.max_session_bytes {
            self.end_with(
                state,
                TunnelRejectCodeV1::ByteLimit,
                "tunnel byte limit reached",
            );
            return Some(CloseReason::ByteLimit);
        }
        None
    }

    /// Sends every part that is due. The busy flag is updated first, so a client acting on
    /// a final part never finds this tunnel still marked busy.
    fn send_ready(&self, state: &mut SessionState, now: Instant, queued: bool) {
        let flush = self.shared.flush_policy();
        let mut parts = Vec::new();
        while let Some(part) = state.window.next_part(now, flush) {
            parts.push(part);
        }
        parts.extend(state.window.expire(now));
        self.busy
            .store(state.window.in_flight() || queued, Ordering::Release);
        for part in &parts {
            self.send_part(state, part);
        }
    }

    fn send_part(&self, state: &mut SessionState, part: &Part<Surb>) {
        state.parts += 1;
        self.shared.metrics.tunnel_parts_total.inc();
        self.shared.send(&part.surb, &part.reply, state.parts);
    }

    /// Ends the tunnel with a rejection on a SURB of the current exchange, when one is left.
    fn end_with(&self, state: &mut SessionState, code: TunnelRejectCodeV1, detail: &str) {
        let seq = state.window.seq().unwrap_or_default();
        let surb = state.window.take_surb();
        state.closing_reply = Some((surb, seq, TunnelError::new(code, detail)));
    }

    /// Mirrors this tunnel's held bytes into the exit-wide total.
    fn sync_buffered(&self, state: &mut SessionState) {
        let now_held = state.window.buffered();
        if now_held > state.held {
            self.shared
                .buffered
                .fetch_add(now_held - state.held, Ordering::AcqRel);
        } else {
            self.shared
                .buffered
                .fetch_sub(state.held - now_held, Ordering::AcqRel);
        }
        state.held = now_held;
    }

    fn release(&self, state: &mut SessionState) {
        self.shared.buffered.fetch_sub(state.held, Ordering::AcqRel);
        state.held = 0;
    }

    fn finish(&self, reason: Option<CloseReason>) {
        let until = self.opened + Duration::from_secs(self.shared.config.session_max_secs);
        if reason != Some(CloseReason::Cancelled) {
            self.shared.forget(&self.id, until);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nox_core::{TunnelFinV1, TUNNEL_PART_MAX_DATA};
    use nox_crypto::sphinx::surb::Surb;
    use nox_crypto::PathHop;

    #[test]
    fn a_full_part_fits_one_v2_surb() {
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let path = [PathHop {
            public_key: x25519_dalek::PublicKey::from(&secret),
            address: "/ip4/127.0.0.1/tcp/9000".to_string(),
        }];
        let (surb, mut recovery) = Surb::new_v2(&path, 0).expect("SURB");
        recovery.layer_keys.clear();
        let reply = TunnelReplyV1::Data {
            seq: u32::MAX,
            offset: u64::MAX,
            data: vec![0xa5; TUNNEL_PART_MAX_DATA],
            fin: Some(TunnelFinV1::NeedSurbs),
        };
        let body = encode_payload(&reply).expect("encode");
        let packer = ResponsePacker::new().with_reply_v2(true);
        let packed = packer
            .pack_single_fragment(u64::MAX, &body, &surb, 0, 1)
            .expect("a full part must fit one SURB");
        assert!(packed.v2);
        let opened = recovery
            .decrypt(&packed.packet_bytes[nox_crypto::HEADER_SIZE..])
            .expect("decrypt");
        let nox_core::RelayerPayload::ServiceResponse { fragment, .. } =
            nox_core::models::payloads::decode_payload(&opened).expect("response")
        else {
            panic!("expected a service response");
        };
        assert_eq!(
            nox_core::models::payloads::decode_payload::<TunnelReplyV1>(&fragment.data)
                .expect("reply"),
            reply
        );
    }

    #[test]
    fn hosts_must_be_dns_names() {
        for host in ["rpc.example", "a-b.c0.example", "xn--bcher-kva.example"] {
            assert!(check_host(host).is_ok(), "{host}");
        }
        let long_label = format!("{}.example", "a".repeat(MAX_LABEL_LEN + 1));
        for host in [
            "",
            "10.0.0.1",
            "::1",
            "[::1]",
            "rpc.example.",
            "rpc..example",
            "rpc_example.org",
            "rpc.example:443",
            "bücher.example",
            long_label.as_str(),
        ] {
            assert!(check_host(host).is_err(), "{host}");
        }
    }

    #[test]
    fn open_bucket_refills_at_the_configured_rate() {
        let config = TunnelConfig {
            opens_per_sec: 2,
            opens_burst: 2,
            ..TunnelConfig::default()
        };
        let start = Instant::now();
        let mut bucket = OpenBucket::new(&config, start);
        assert!(bucket.try_take(start) && bucket.try_take(start));
        assert!(!bucket.try_take(start));
        assert!(bucket.try_take(start + Duration::from_millis(500)));
        assert!(!bucket.try_take(start + Duration::from_millis(500)));
    }
}
