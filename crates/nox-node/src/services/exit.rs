//! Exit service: reassembles fragmented messages and routes to handlers.

use crate::config::{ExitWorkerConfig, FragmentationConfig};
use crate::services::handlers::echo::EchoHandler;
use crate::services::handlers::ethereum::EthereumHandler;
use crate::services::handlers::http::HttpHandler;
use crate::services::handlers::rpc::RpcHandler;
use crate::services::handlers::traffic::TrafficHandler;
use crate::services::response_packer::ResponsePacker;
use crate::telemetry::metrics::MetricsService;
use nox_core::events::NoxEvent;
use nox_core::models::payloads::{
    decode_padded_relayer_payload_limited, decode_payload_limited, encode_payload, RelayerPayload,
    ServiceRequest,
};
use nox_core::models::wire_id::{reply_wire_id, PacketOrigin};
use nox_core::protocol::fragmentation::{
    Fragment, FragmentationError, Reassembler, ReassemblerConfig, MAX_MESSAGE_SIZE,
};
use nox_core::traits::service::ServiceHandler;
use nox_core::traits::IEventSubscriber;
use nox_core::IEventPublisher;
use nox_crypto::sphinx::surb::Surb;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Max size for deserializing a single Sphinx packet payload (64 KB).
///
/// A single Sphinx packet body is `MAX_PAYLOAD_SIZE` = 31,716 bytes. We use 64 KB here to
/// give bincode deserialization headroom for the wrapper envelope.
const MAX_SINGLE_PAYLOAD_SIZE: u64 = 64 * 1024;

/// Max size for deserializing a reassembled (multi-fragment) payload.
///
/// Derived from the protocol's fragmentation constants:
///   `MAX_MESSAGE_SIZE = MAX_FRAGMENTS_PER_MESSAGE × 32 × 1024 = 200 × 32,768 = 6,553,600 bytes`
///
/// This is the largest payload a client can send through the forward path (200 fragments ×
/// 32 KB each). Using a hard-coded magic number here would create a silent disparity with
/// the fragmentation engine -- instead we derive it directly so the two layers stay in sync.
///
/// Note: the SURB response path is separately limited by `MAX_SURBS × USABLE_RESPONSE_PER_SURB`
/// (~270 MB theoretical), but that is controlled on the client side by `SurbBudget`, not here.
const MAX_REASSEMBLED_PAYLOAD_SIZE: u64 = MAX_MESSAGE_SIZE as u64;

use crate::services::handlers::http::StashRemainingFn;

use crate::services::response_packer::PendingResponseState;

/// Stashed partial response state awaiting SURB replenishment from the client.
pub type PendingReplenishments = Arc<Mutex<HashMap<u64, PendingResponseState>>>;

/// SURBs that arrived via `ReplenishSurbs` before a pending state existed.
pub type SurbAccumulator = Arc<Mutex<HashMap<u64, Vec<Surb>>>>;

/// Dispatch lane for a decoded exit payload. Each lane has its own bounded queue and
/// concurrency limit (see [`ExitWorkerConfig`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitLane {
    /// Paid transaction submissions (v2 and legacy).
    Paid,
    /// Paid quote requests.
    Quote,
    /// HTTP, RPC and signed-transaction broadcast proxying.
    Proxy,
    /// Echo and cover traffic.
    Control,
}

impl ExitLane {
    pub const ALL: [Self; 4] = [Self::Paid, Self::Quote, Self::Proxy, Self::Control];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Paid => "paid",
            Self::Quote => "quote",
            Self::Proxy => "proxy",
            Self::Control => "control",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Paid => 0,
            Self::Quote => 1,
            Self::Proxy => 2,
            Self::Control => 3,
        }
    }

    const fn concurrency(self, config: &ExitWorkerConfig) -> usize {
        match self {
            Self::Paid => config.paid_concurrency,
            Self::Quote => config.quote_concurrency,
            Self::Proxy => config.proxy_concurrency,
            Self::Control => config.control_concurrency,
        }
    }
}

/// Where a decoded payload is handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitDispatch {
    /// Handled in the bus loop: cheap, or order-sensitive (SURB replenishment).
    Inline,
    /// Handed to a worker lane.
    Lane(ExitLane),
}

/// `ServiceRequest` variant indices in the bincode wire layout (u32 little-endian after the
/// one-byte payload version). The layout is frozen across Rust and TypeScript.
const SERVICE_REQUEST_ECHO: u32 = 0;
const SERVICE_REQUEST_HTTP: u32 = 1;
const SERVICE_REQUEST_RPC: u32 = 2;
const SERVICE_REQUEST_SUBMIT_TRANSACTION: u32 = 3;
const SERVICE_REQUEST_BROADCAST: u32 = 4;
#[cfg(test)]
const SERVICE_REQUEST_REPLENISH_SURBS: u32 = 5;
const SERVICE_REQUEST_PAID_TRANSACTION_V2: u32 = 6;
const SERVICE_REQUEST_PAID_QUOTE_V2: u32 = 7;

/// Picks the dispatch lane from the payload variant without decoding the request body.
#[must_use]
pub fn classify_payload(command: &RelayerPayload) -> ExitDispatch {
    match command {
        RelayerPayload::SubmitTransaction { .. } => ExitDispatch::Lane(ExitLane::Paid),
        RelayerPayload::Dummy { .. } | RelayerPayload::Heartbeat { .. } => {
            ExitDispatch::Lane(ExitLane::Control)
        }
        RelayerPayload::Fragment { .. }
        | RelayerPayload::ServiceResponse { .. }
        | RelayerPayload::NeedMoreSurbs { .. } => ExitDispatch::Inline,
        RelayerPayload::AnonymousRequest { inner, .. } => {
            let tag = match inner.as_slice() {
                [version, a, b, c, d, ..]
                    if *version == nox_core::models::payloads::PAYLOAD_VERSION =>
                {
                    u32::from_le_bytes([*a, *b, *c, *d])
                }
                _ => return ExitDispatch::Inline,
            };
            match tag {
                SERVICE_REQUEST_ECHO => ExitDispatch::Lane(ExitLane::Control),
                SERVICE_REQUEST_HTTP | SERVICE_REQUEST_RPC | SERVICE_REQUEST_BROADCAST => {
                    ExitDispatch::Lane(ExitLane::Proxy)
                }
                SERVICE_REQUEST_SUBMIT_TRANSACTION | SERVICE_REQUEST_PAID_TRANSACTION_V2 => {
                    ExitDispatch::Lane(ExitLane::Paid)
                }
                SERVICE_REQUEST_PAID_QUOTE_V2 => ExitDispatch::Lane(ExitLane::Quote),
                // ReplenishSurbs stays in order with the bus; unknown tags are logged inline.
                _ => ExitDispatch::Inline,
            }
        }
    }
}

type LaneJob = (String, RelayerPayload);

#[derive(Clone)]
pub struct ExitService {
    bus_subscriber: Arc<dyn IEventSubscriber>,
    ethereum_handler: Option<Arc<EthereumHandler>>,
    traffic_handler: Arc<TrafficHandler>,
    http_handler: Option<Arc<HttpHandler>>,
    echo_handler: Option<Arc<EchoHandler>>,
    rpc_handler: Option<Arc<RpcHandler>>,
    reassembler: Arc<Mutex<Reassembler>>,
    prune_interval: Duration,
    stale_timeout: Duration,
    metrics: MetricsService,
    cancel_token: CancellationToken,
    pending_replenishments: PendingReplenishments,
    surb_accumulator: SurbAccumulator,
    response_packer: Arc<ResponsePacker>,
    publisher: Arc<dyn IEventPublisher>,
    workers: ExitWorkerConfig,
}

impl ExitService {
    pub fn new(
        bus_subscriber: Arc<dyn IEventSubscriber>,
        ethereum_handler: Arc<EthereumHandler>,
        traffic_handler: Arc<TrafficHandler>,
        metrics: MetricsService,
    ) -> Self {
        Self::with_all_handlers(
            bus_subscriber,
            ethereum_handler,
            traffic_handler,
            None,
            None,
            None,
            FragmentationConfig::default(),
            metrics,
        )
    }

    pub fn with_handlers(
        bus_subscriber: Arc<dyn IEventSubscriber>,
        ethereum_handler: Arc<EthereumHandler>,
        traffic_handler: Arc<TrafficHandler>,
        http_handler: Arc<HttpHandler>,
        echo_handler: Arc<EchoHandler>,
        frag_config: FragmentationConfig,
        metrics: MetricsService,
    ) -> Self {
        Self::with_all_handlers(
            bus_subscriber,
            ethereum_handler,
            traffic_handler,
            Some(http_handler),
            Some(echo_handler),
            None,
            frag_config,
            metrics,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_rpc_handler(
        bus_subscriber: Arc<dyn IEventSubscriber>,
        ethereum_handler: Arc<EthereumHandler>,
        traffic_handler: Arc<TrafficHandler>,
        http_handler: Arc<HttpHandler>,
        echo_handler: Arc<EchoHandler>,
        rpc_handler: Arc<RpcHandler>,
        frag_config: FragmentationConfig,
        metrics: MetricsService,
    ) -> Self {
        Self::with_all_handlers(
            bus_subscriber,
            ethereum_handler,
            traffic_handler,
            Some(http_handler),
            Some(echo_handler),
            Some(rpc_handler),
            frag_config,
            metrics,
        )
    }

    /// Simulation mode: HTTP/Echo only, no Ethereum handler.
    pub fn simulation(
        bus_subscriber: Arc<dyn IEventSubscriber>,
        traffic_handler: Arc<TrafficHandler>,
        http_handler: Arc<HttpHandler>,
        echo_handler: Arc<EchoHandler>,
        metrics: MetricsService,
    ) -> Self {
        let frag_config = FragmentationConfig::default();
        let reassembler_config = ReassemblerConfig {
            max_buffer_bytes: frag_config.max_pending_bytes,
            max_concurrent_messages: frag_config.max_concurrent_messages,
            stale_timeout: Duration::from_secs(frag_config.timeout_seconds),
        };

        Self {
            bus_subscriber,
            ethereum_handler: None,
            traffic_handler,
            http_handler: Some(http_handler),
            echo_handler: Some(echo_handler),
            rpc_handler: None,
            reassembler: Arc::new(Mutex::new(Reassembler::new(reassembler_config))),
            prune_interval: Duration::from_secs(frag_config.prune_interval_seconds),
            stale_timeout: Duration::from_secs(frag_config.timeout_seconds),
            metrics,
            cancel_token: CancellationToken::new(),
            pending_replenishments: Arc::new(Mutex::new(HashMap::new())),
            surb_accumulator: Arc::new(Mutex::new(HashMap::new())),
            response_packer: Arc::new(ResponsePacker::new()),
            publisher: nox_core::NoopPublisher::arc(),
            workers: ExitWorkerConfig::default(),
        }
    }

    /// Like `simulation()` but adds RPC proxy support.
    pub fn simulation_with_rpc(
        bus_subscriber: Arc<dyn IEventSubscriber>,
        traffic_handler: Arc<TrafficHandler>,
        http_handler: Arc<HttpHandler>,
        echo_handler: Arc<EchoHandler>,
        rpc_handler: Arc<RpcHandler>,
        metrics: MetricsService,
    ) -> Self {
        let frag_config = FragmentationConfig::default();
        let reassembler_config = ReassemblerConfig {
            max_buffer_bytes: frag_config.max_pending_bytes,
            max_concurrent_messages: frag_config.max_concurrent_messages,
            stale_timeout: Duration::from_secs(frag_config.timeout_seconds),
        };

        Self {
            bus_subscriber,
            ethereum_handler: None,
            traffic_handler,
            http_handler: Some(http_handler),
            echo_handler: Some(echo_handler),
            rpc_handler: Some(rpc_handler),
            reassembler: Arc::new(Mutex::new(Reassembler::new(reassembler_config))),
            prune_interval: Duration::from_secs(frag_config.prune_interval_seconds),
            stale_timeout: Duration::from_secs(frag_config.timeout_seconds),
            metrics,
            cancel_token: CancellationToken::new(),
            pending_replenishments: Arc::new(Mutex::new(HashMap::new())),
            surb_accumulator: Arc::new(Mutex::new(HashMap::new())),
            response_packer: Arc::new(ResponsePacker::new()),
            publisher: nox_core::NoopPublisher::arc(),
            workers: ExitWorkerConfig::default(),
        }
    }

    pub fn with_fragmentation_config(
        bus_subscriber: Arc<dyn IEventSubscriber>,
        ethereum_handler: Arc<EthereumHandler>,
        traffic_handler: Arc<TrafficHandler>,
        http_handler: Option<Arc<HttpHandler>>,
        echo_handler: Option<Arc<EchoHandler>>,
        frag_config: FragmentationConfig,
        metrics: MetricsService,
    ) -> Self {
        let reassembler_config = ReassemblerConfig {
            max_buffer_bytes: frag_config.max_pending_bytes,
            max_concurrent_messages: frag_config.max_concurrent_messages,
            stale_timeout: Duration::from_secs(frag_config.timeout_seconds),
        };

        Self {
            bus_subscriber,
            ethereum_handler: Some(ethereum_handler),
            traffic_handler,
            http_handler,
            echo_handler,
            rpc_handler: None,
            reassembler: Arc::new(Mutex::new(Reassembler::new(reassembler_config))),
            prune_interval: Duration::from_secs(frag_config.prune_interval_seconds),
            stale_timeout: Duration::from_secs(frag_config.timeout_seconds),
            metrics,
            cancel_token: CancellationToken::new(),
            pending_replenishments: Arc::new(Mutex::new(HashMap::new())),
            surb_accumulator: Arc::new(Mutex::new(HashMap::new())),
            response_packer: Arc::new(ResponsePacker::new()),
            publisher: nox_core::NoopPublisher::arc(),
            workers: ExitWorkerConfig::default(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_all_handlers(
        bus_subscriber: Arc<dyn IEventSubscriber>,
        ethereum_handler: Arc<EthereumHandler>,
        traffic_handler: Arc<TrafficHandler>,
        http_handler: Option<Arc<HttpHandler>>,
        echo_handler: Option<Arc<EchoHandler>>,
        rpc_handler: Option<Arc<RpcHandler>>,
        frag_config: FragmentationConfig,
        metrics: MetricsService,
    ) -> Self {
        let reassembler_config = ReassemblerConfig {
            max_buffer_bytes: frag_config.max_pending_bytes,
            max_concurrent_messages: frag_config.max_concurrent_messages,
            stale_timeout: Duration::from_secs(frag_config.timeout_seconds),
        };

        Self {
            bus_subscriber,
            ethereum_handler: Some(ethereum_handler),
            traffic_handler,
            http_handler,
            echo_handler,
            rpc_handler,
            reassembler: Arc::new(Mutex::new(Reassembler::new(reassembler_config))),
            prune_interval: Duration::from_secs(frag_config.prune_interval_seconds),
            stale_timeout: Duration::from_secs(frag_config.timeout_seconds),
            metrics,
            cancel_token: CancellationToken::new(),
            pending_replenishments: Arc::new(Mutex::new(HashMap::new())),
            surb_accumulator: Arc::new(Mutex::new(HashMap::new())),
            response_packer: Arc::new(ResponsePacker::new()),
            publisher: nox_core::NoopPublisher::arc(),
            workers: ExitWorkerConfig::default(),
        }
    }

    #[must_use]
    pub fn with_worker_config(mut self, workers: ExitWorkerConfig) -> Self {
        self.workers = workers;
        self
    }

    #[must_use]
    pub fn with_publisher(mut self, publisher: Arc<dyn IEventPublisher>) -> Self {
        self.publisher = publisher;
        self
    }

    #[must_use]
    pub fn with_pending_replenishments(mut self, map: PendingReplenishments) -> Self {
        self.pending_replenishments = map;
        self
    }

    #[must_use]
    pub fn with_surb_accumulator(mut self, acc: SurbAccumulator) -> Self {
        self.surb_accumulator = acc;
        self
    }

    /// Create a closure that stashes remaining response bytes and drains pre-emptive SURBs.
    pub fn make_stash_closure(
        pending: PendingReplenishments,
        accumulator: SurbAccumulator,
        packer: Arc<ResponsePacker>,
        publisher: Arc<dyn IEventPublisher>,
    ) -> StashRemainingFn {
        Arc::new(move |request_id, state| {
            continue_or_stash(
                &pending,
                &accumulator,
                &packer,
                publisher.as_ref(),
                request_id,
                state,
                Vec::new(),
            );
        })
    }

    #[must_use]
    pub fn new_surb_accumulator() -> SurbAccumulator {
        Arc::new(Mutex::new(HashMap::new()))
    }

    #[must_use]
    pub fn new_pending_map() -> PendingReplenishments {
        Arc::new(Mutex::new(HashMap::new()))
    }

    #[must_use]
    pub fn with_cancel_token(mut self, token: CancellationToken) -> Self {
        self.cancel_token = token;
        self
    }

    pub async fn run(&self) {
        info!(
            paid = self.workers.paid_concurrency,
            quote = self.workers.quote_concurrency,
            proxy = self.workers.proxy_concurrency,
            control = self.workers.control_concurrency,
            queue = self.workers.queue_capacity,
            "Exit Service active."
        );

        let mut rx = self.bus_subscriber.subscribe();
        let mut prune_timer = tokio::time::interval(self.prune_interval);
        let lanes = self.start_lanes();

        loop {
            tokio::select! {
                event_result = rx.recv() => {
                    match event_result {
                        Ok(NoxEvent::PayloadDecrypted { packet_id, payload, .. }) => {
                            if let Some(command) = self.decode_command(&packet_id, &payload).await {
                                self.route(&lanes, packet_id, command).await;
                            }
                        }
                        Ok(_) => {
                            // Ignore other event types
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            self.metrics
                                .event_bus_subscriber_lag_total
                                .get_or_create(&vec![("subscriber".to_string(), "exit".to_string())])
                                .inc_by(n);
                            warn!("Exit Service bus lagged by {} events, continuing.", n);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            warn!("Event bus closed, Exit Service shutting down.");
                            break;
                        }
                    }
                }

                _ = prune_timer.tick() => {
                    self.prune_stale_fragments().await;
                    self.prune_stale_replenishments();
                }

                () = self.cancel_token.cancelled() => {
                    info!("Exit Service shutting down (cancellation token).");
                    break;
                }
            }
        }
    }

    /// Starts one bounded queue and worker per lane. Workers stop with the cancel token.
    fn start_lanes(&self) -> [mpsc::Sender<LaneJob>; 4] {
        let service = Arc::new(self.clone());
        let queue_capacity = self.workers.queue_capacity.max(1);
        ExitLane::ALL.map(|lane| {
            let (sender, receiver) = mpsc::channel(queue_capacity);
            let concurrency = lane.concurrency(&self.workers).max(1);
            tokio::spawn(Self::run_lane(
                service.clone(),
                lane,
                receiver,
                concurrency,
                self.cancel_token.clone(),
            ));
            sender
        })
    }

    /// Takes a permit first, then a job, so waiting jobs stay in the bounded queue.
    async fn run_lane(
        service: Arc<Self>,
        lane: ExitLane,
        mut receiver: mpsc::Receiver<LaneJob>,
        concurrency: usize,
        cancel: CancellationToken,
    ) {
        let semaphore = Arc::new(Semaphore::new(concurrency));
        let inflight = service
            .metrics
            .exit_lane_inflight
            .get_or_create(&vec![("lane".to_string(), lane.as_str().to_string())])
            .clone();
        loop {
            let permit = tokio::select! {
                permit = semaphore.clone().acquire_owned() => match permit {
                    Ok(permit) => permit,
                    Err(_) => break,
                },
                () = cancel.cancelled() => break,
            };
            let job = tokio::select! {
                job = receiver.recv() => job,
                () = cancel.cancelled() => break,
            };
            let Some((packet_id, command)) = job else {
                break;
            };
            let service = service.clone();
            let inflight = inflight.clone();
            inflight.inc();
            tokio::spawn(async move {
                service.dispatch_payload(&packet_id, command).await;
                inflight.dec();
                drop(permit);
            });
        }
        debug!(lane = lane.as_str(), "Exit lane stopped");
    }

    async fn route(
        &self,
        lanes: &[mpsc::Sender<LaneJob>; 4],
        packet_id: String,
        command: RelayerPayload,
    ) {
        let lane = match classify_payload(&command) {
            ExitDispatch::Inline => {
                self.dispatch_payload(&packet_id, command).await;
                return;
            }
            ExitDispatch::Lane(lane) => lane,
        };
        let reason = match lanes[lane.index()].try_send((packet_id, command)) {
            Ok(()) => return,
            Err(mpsc::error::TrySendError::Full(_)) => "queue_full",
            Err(mpsc::error::TrySendError::Closed(_)) => "lane_closed",
        };
        self.metrics
            .exit_payloads_dropped_total
            .get_or_create(&vec![
                ("lane".to_string(), lane.as_str().to_string()),
                ("reason".to_string(), reason.to_string()),
            ])
            .inc();
        debug!(
            lane = lane.as_str(),
            reason, "Exit payload dropped before dispatch"
        );
    }

    async fn prune_stale_fragments(&self) {
        let mut reassembler = self.reassembler.lock();
        let pruned = reassembler.prune_stale(self.stale_timeout);
        self.metrics
            .exit_reassembler_pending
            .set(reassembler.pending_count() as i64);
        if pruned > 0 {
            warn!(
                count = pruned,
                buffered_bytes = reassembler.buffered_bytes(),
                pending_messages = reassembler.pending_count(),
                "Pruned stale fragmented sessions"
            );
        }
    }

    fn prune_stale_replenishments(&self) {
        prune_replenishment_maps(&self.pending_replenishments, &self.surb_accumulator);
    }

    /// Decodes a decrypted payload and completes fragment reassembly. Returns the command to
    /// dispatch, or `None` while fragments are still buffered or the payload is invalid.
    async fn decode_command(
        &self,
        packet_id: &str,
        payload_bytes: &[u8],
    ) -> Option<RelayerPayload> {
        let command: RelayerPayload =
            match decode_padded_relayer_payload_limited(payload_bytes, MAX_SINGLE_PAYLOAD_SIZE) {
                Ok(cmd) => cmd,
                Err(e) => {
                    debug!(
                        packet_id = %packet_id,
                        error = %e,
                        payload_len = payload_bytes.len(),
                        "Payload decode failed (likely SURB-encrypted reply or garbage)"
                    );
                    return None;
                }
            };

        match command {
            RelayerPayload::Fragment { frag } => {
                self.try_reassemble(packet_id.to_string(), frag).await
            }
            other => Some(other),
        }
    }

    async fn try_reassemble(
        &self,
        packet_id: String,
        fragment: Fragment,
    ) -> Option<RelayerPayload> {
        let message_id = fragment.message_id;
        let sequence = fragment.sequence;
        let total = fragment.total_fragments;

        debug!(
            packet_id = %packet_id,
            message_id = message_id,
            sequence = sequence,
            total = total,
            "Received fragment"
        );

        let reassembled_data = {
            let mut reassembler = self.reassembler.lock();
            match reassembler.add_fragment(fragment) {
                Ok(Some(data)) => {
                    self.metrics
                        .exit_reassembly_total
                        .get_or_create(&vec![("result".to_string(), "complete".to_string())])
                        .inc();
                    debug!(
                        message_id = message_id,
                        total_bytes = data.len(),
                        pending = reassembler.pending_count(),
                        "Message reassembly complete"
                    );
                    Some(data)
                }
                Ok(None) => {
                    self.metrics
                        .exit_reassembly_total
                        .get_or_create(&vec![("result".to_string(), "buffered".to_string())])
                        .inc();
                    debug!(
                        message_id = message_id,
                        progress = %format!("{}/{}", sequence + 1, total),
                        "Fragment buffered, awaiting more"
                    );
                    None
                }
                Err(e) => {
                    self.metrics
                        .exit_reassembly_total
                        .get_or_create(&vec![("result".to_string(), "rejected".to_string())])
                        .inc();
                    if matches!(e, FragmentationError::DuplicateDataMismatch { .. }) {
                        self.metrics.reassembly_conflict_total.inc();
                    }
                    debug!(
                        message_id = message_id,
                        error = %e,
                        "Fragment rejected"
                    );
                    None
                }
            }
        };

        let data = reassembled_data?;

        match decode_payload_limited::<RelayerPayload>(&data, MAX_REASSEMBLED_PAYLOAD_SIZE) {
            Ok(inner_payload) => {
                if matches!(inner_payload, RelayerPayload::Fragment { .. }) {
                    debug!(
                        message_id = message_id,
                        "Reassembled payload is itself a Fragment - dropping to prevent loop"
                    );
                    return None;
                }

                debug!(
                    message_id = message_id,
                    packet_id = %packet_id,
                    "Re-injecting reassembled payload"
                );
                Some(inner_payload)
            }
            Err(e) => {
                debug!(
                    message_id = message_id,
                    size = data.len(),
                    error = %e,
                    "Reassembled garbage payload - deserialization failed"
                );
                None
            }
        }
    }

    async fn dispatch_payload(&self, packet_id: &str, command: RelayerPayload) {
        match command {
            RelayerPayload::SubmitTransaction { .. } => {
                self.metrics
                    .exit_payloads_dispatched_total
                    .get_or_create(&vec![(
                        "handler".to_string(),
                        "legacy_rejected".to_string(),
                    )])
                    .inc();
                debug!(
                    packet_id = %packet_id,
                    "Legacy SubmitTransaction payload rejected: paid execution requires PaidTransactionV2"
                );
            }
            RelayerPayload::Dummy { .. } | RelayerPayload::Heartbeat { .. } => {
                self.metrics
                    .exit_payloads_dispatched_total
                    .get_or_create(&vec![("handler".to_string(), "traffic".to_string())])
                    .inc();
                if let Err(e) = self.traffic_handler.handle(packet_id, &command).await {
                    debug!("Traffic handler failed for {}: {}", packet_id, e);
                }
            }
            RelayerPayload::Fragment { .. } => {
                warn!("dispatch_payload called with an unreassembled Fragment; dropping it");
            }
            RelayerPayload::AnonymousRequest { inner, reply_surbs } => {
                match decode_payload_limited::<ServiceRequest>(&inner, MAX_REASSEMBLED_PAYLOAD_SIZE)
                {
                    Ok(ServiceRequest::HttpRequest { .. }) => {
                        self.metrics
                            .exit_payloads_dispatched_total
                            .get_or_create(&vec![("handler".to_string(), "http".to_string())])
                            .inc();
                        if let Some(ref handler) = self.http_handler {
                            let payload = RelayerPayload::AnonymousRequest {
                                inner: inner.clone(),
                                reply_surbs: reply_surbs.clone(),
                            };
                            if let Err(e) = handler.handle(packet_id, &payload).await {
                                debug!(
                                    packet_id = %packet_id,
                                    error = %e,
                                    "HTTP handler failed"
                                );
                            }
                        } else {
                            debug!(
                                packet_id = %packet_id,
                                "HTTP request received but no HTTP handler configured"
                            );
                        }
                    }
                    Ok(ServiceRequest::Echo { .. }) => {
                        self.metrics
                            .exit_payloads_dispatched_total
                            .get_or_create(&vec![("handler".to_string(), "echo".to_string())])
                            .inc();
                        if let Some(ref handler) = self.echo_handler {
                            let payload = RelayerPayload::AnonymousRequest {
                                inner: inner.clone(),
                                reply_surbs: reply_surbs.clone(),
                            };
                            if let Err(e) = handler.handle(packet_id, &payload).await {
                                debug!(
                                    packet_id = %packet_id,
                                    error = %e,
                                    "Echo handler failed"
                                );
                            }
                        } else {
                            debug!(
                                packet_id = %packet_id,
                                "Echo request received but no Echo handler configured"
                            );
                        }
                    }
                    Ok(ServiceRequest::RpcRequest { .. }) => {
                        self.metrics
                            .exit_payloads_dispatched_total
                            .get_or_create(&vec![("handler".to_string(), "rpc".to_string())])
                            .inc();
                        if let Some(ref handler) = self.rpc_handler {
                            let payload = RelayerPayload::AnonymousRequest {
                                inner: inner.clone(),
                                reply_surbs: reply_surbs.clone(),
                            };
                            if let Err(e) = handler.handle(packet_id, &payload).await {
                                debug!(
                                    packet_id = %packet_id,
                                    error = %e,
                                    "RPC handler failed"
                                );
                            }
                        } else {
                            debug!(
                                packet_id = %packet_id,
                                "RPC request received but no RPC handler configured"
                            );
                        }
                    }
                    Ok(ServiceRequest::SubmitTransaction { .. }) => {
                        self.metrics
                            .exit_payloads_dispatched_total
                            .get_or_create(&vec![(
                                "handler".to_string(),
                                "legacy_rejected".to_string(),
                            )])
                            .inc();
                        debug!(
                            packet_id = %packet_id,
                            "Legacy SubmitTransaction request rejected: paid execution requires PaidTransactionV2"
                        );
                        if reply_surbs.is_empty() {
                            return;
                        }
                        let Some(ref echo) = self.echo_handler else {
                            return;
                        };
                        let response_data = format!(
                            "tx_error:{}",
                            crate::services::handlers::ethereum::legacy_submission_rejection()
                                .public_detail()
                        )
                        .into_bytes();
                        let inner = match encode_payload(&ServiceRequest::Echo {
                            data: response_data,
                        }) {
                            Ok(bytes) => bytes,
                            Err(e) => {
                                debug!(
                                    packet_id = %packet_id,
                                    error = %e,
                                    "Failed to encode legacy submission rejection"
                                );
                                return;
                            }
                        };
                        let echo_payload = RelayerPayload::AnonymousRequest { inner, reply_surbs };
                        if let Err(e) = echo.handle(packet_id, &echo_payload).await {
                            debug!(
                                packet_id = %packet_id,
                                error = %e,
                                "Failed to send legacy submission rejection via SURBs"
                            );
                        }
                    }
                    Ok(ServiceRequest::PaidTransactionV2(request)) => {
                        self.metrics
                            .exit_payloads_dispatched_total
                            .get_or_create(&vec![(
                                "handler".to_string(),
                                "ethereum_v2".to_string(),
                            )])
                            .inc();
                        let outcome = match &self.ethereum_handler {
                            Some(handler) => {
                                handler.handle_paid_transaction_v2(request.clone()).await
                            }
                            None => nox_core::PaidTransactionOutcomeV2::Rejected {
                                execution_id: Some(request.execution_id),
                                code: nox_core::PaidTransactionRejectionCodeV2::SubmissionFailure,
                                retryable: true,
                                detail: "paid execution handler unavailable".to_string(),
                            },
                        };
                        if !reply_surbs.is_empty() {
                            if let Some(ref echo) = self.echo_handler {
                                let response_data = match encode_payload(&outcome) {
                                    Ok(bytes) => bytes,
                                    Err(error) => {
                                        debug!(
                                            packet_id = %packet_id,
                                            error = %error,
                                            "Failed to encode paid v2 outcome"
                                        );
                                        return;
                                    }
                                };
                                let inner = match encode_payload(&ServiceRequest::Echo {
                                    data: response_data,
                                }) {
                                    Ok(bytes) => bytes,
                                    Err(error) => {
                                        debug!(
                                            packet_id = %packet_id,
                                            error = %error,
                                            "Failed to encode paid v2 SURB response"
                                        );
                                        return;
                                    }
                                };
                                let response =
                                    RelayerPayload::AnonymousRequest { inner, reply_surbs };
                                if let Err(error) = echo.handle(packet_id, &response).await {
                                    debug!(
                                        packet_id = %packet_id,
                                        error = %error,
                                        "Failed to send paid v2 response via SURBs"
                                    );
                                }
                            }
                        }
                    }
                    Ok(ServiceRequest::PaidQuoteRequestV2(request)) => {
                        if reply_surbs.is_empty() {
                            debug!(
                                packet_id = %packet_id,
                                "Paid quote request has no reply SURB; rejecting before reservation"
                            );
                            return;
                        }
                        let Some(ref echo) = self.echo_handler else {
                            debug!(
                                packet_id = %packet_id,
                                "Paid quote response handler unavailable; rejecting before reservation"
                            );
                            return;
                        };
                        self.metrics
                            .exit_payloads_dispatched_total
                            .get_or_create(&vec![("handler".to_string(), "quote_v2".to_string())])
                            .inc();
                        let outcome = match &self.ethereum_handler {
                            Some(handler) => handler.handle_paid_quote_v2(request).await,
                            None => nox_core::PaidQuoteOutcomeV2::Rejected {
                                code: nox_core::PaidTransactionRejectionCodeV2::SubmissionFailure,
                                retryable: true,
                                detail: "paid quote handler unavailable".to_string(),
                            },
                        };
                        let response_data = match encode_payload(&outcome) {
                            Ok(bytes) => bytes,
                            Err(error) => {
                                debug!(
                                    packet_id = %packet_id,
                                    error = %error,
                                    "Failed to encode paid quote outcome"
                                );
                                return;
                            }
                        };
                        let inner = match encode_payload(&ServiceRequest::Echo {
                            data: response_data,
                        }) {
                            Ok(bytes) => bytes,
                            Err(error) => {
                                debug!(
                                    packet_id = %packet_id,
                                    error = %error,
                                    "Failed to encode paid quote SURB response"
                                );
                                return;
                            }
                        };
                        let response = RelayerPayload::AnonymousRequest { inner, reply_surbs };
                        if let Err(error) = echo.handle(packet_id, &response).await {
                            debug!(
                                packet_id = %packet_id,
                                error = %error,
                                "Failed to send paid quote response via SURBs"
                            );
                        }
                    }
                    Ok(ServiceRequest::BroadcastSignedTransaction {
                        signed_tx,
                        rpc_url,
                        rpc_method,
                    }) => {
                        self.metrics
                            .exit_payloads_dispatched_total
                            .get_or_create(&vec![("handler".to_string(), "broadcast".to_string())])
                            .inc();

                        let Some(ref eth_handler) = self.ethereum_handler else {
                            debug!(
                                packet_id = %packet_id,
                                "BroadcastSignedTransaction received but no Ethereum handler (simulation mode) -- dropping"
                            );
                            return;
                        };

                        debug!(
                            packet_id = %packet_id,
                            signed_tx_len = signed_tx.len(),
                            custom_url = rpc_url.is_some(),
                            custom_method = rpc_method.is_some(),
                            "Exit: deserialized ServiceRequest::BroadcastSignedTransaction"
                        );
                        let tx_result = eth_handler
                            .handle_broadcast(packet_id, signed_tx, rpc_url, rpc_method)
                            .await;

                        if !reply_surbs.is_empty() {
                            if let Some(ref echo) = self.echo_handler {
                                let response_data = match &tx_result {
                                    Ok(bytes) => bytes.clone(),
                                    Err(e) => format!("tx_error:{e}").into_bytes(),
                                };
                                let inner = match encode_payload(&ServiceRequest::Echo {
                                    data: response_data,
                                }) {
                                    Ok(bytes) => bytes,
                                    Err(e) => {
                                        debug!(
                                            packet_id = %packet_id,
                                            error = %e,
                                            "Failed to encode broadcast response for SURB delivery"
                                        );
                                        return;
                                    }
                                };
                                let echo_payload =
                                    RelayerPayload::AnonymousRequest { inner, reply_surbs };
                                if let Err(e) = echo.handle(packet_id, &echo_payload).await {
                                    debug!(
                                        packet_id = %packet_id,
                                        error = %e,
                                        "Failed to send broadcast response via SURBs"
                                    );
                                }
                            }
                        }

                        if let Err(e) = tx_result {
                            debug!(
                                packet_id = %packet_id,
                                error = %e,
                                "Broadcast signed transaction handler failed"
                            );
                        }
                    }
                    Ok(ServiceRequest::ReplenishSurbs { request_id, surbs }) => {
                        // Lock order everywhere: accumulator, then pending. Neither lock is
                        // held while packing.
                        let stashed = {
                            let mut acc = self.surb_accumulator.lock();
                            let stashed = self.pending_replenishments.lock().remove(&request_id);
                            if let Some(state) = stashed {
                                let mut all_surbs = acc.remove(&request_id).unwrap_or_default();
                                all_surbs.extend(surbs);
                                Some((state, all_surbs))
                            } else {
                                let count = surbs.len();
                                acc.entry(request_id).or_default().extend(surbs);
                                debug!(
                                    packet_id = %packet_id,
                                    request_id = request_id,
                                    accumulated_surbs = count,
                                    "Pre-emptive ReplenishSurbs -- accumulated for future use"
                                );
                                None
                            }
                        };
                        if let Some((pending_state, all_surbs)) = stashed {
                            debug!(
                                packet_id = %packet_id,
                                request_id = request_id,
                                surbs = all_surbs.len(),
                                remaining_bytes = pending_state.remaining_data.len(),
                                seq_offset = pending_state.continuation.fragments_already_sent,
                                original_total = pending_state.continuation.original_total_fragments,
                                "Resuming partial response delivery with fresh SURBs (continuation)"
                            );
                            continue_or_stash(
                                &self.pending_replenishments,
                                &self.surb_accumulator,
                                &self.response_packer,
                                self.publisher.as_ref(),
                                request_id,
                                pending_state,
                                all_surbs,
                            );
                        }
                    }
                    Err(e) => {
                        debug!(
                            packet_id = %packet_id,
                            error = %e,
                            inner_len = inner.len(),
                            "Unknown AnonymousRequest - deserialization failed"
                        );
                    }
                }
            }
            RelayerPayload::ServiceResponse {
                request_id,
                fragment,
            } => {
                debug!(
                    packet_id = %packet_id,
                    request_id = request_id,
                    sequence = fragment.sequence,
                    "Received ServiceResponse - intended for client"
                );
            }
            RelayerPayload::NeedMoreSurbs {
                request_id,
                fragments_remaining,
            } => {
                debug!(
                    packet_id = %packet_id,
                    request_id = request_id,
                    fragments_remaining = fragments_remaining,
                    "Received NeedMoreSurbs at exit node (routing anomaly) -- dropping"
                );
            }
        }
    }
}

/// Sends as much of a pending response as the given and accumulated SURBs allow, then
/// stashes what is left. Locks are taken in the order accumulator, then pending, and are not
/// held while packing. SURBs that arrive while packing are picked up before stashing.
#[allow(clippy::too_many_arguments)]
fn continue_or_stash(
    pending: &PendingReplenishments,
    accumulator: &SurbAccumulator,
    packer: &ResponsePacker,
    publisher: &dyn IEventPublisher,
    request_id: u64,
    mut state: PendingResponseState,
    mut surbs: Vec<Surb>,
) {
    loop {
        if !surbs.is_empty() {
            match packer.pack_continuation(request_id, &state, std::mem::take(&mut surbs)) {
                Ok(result) => {
                    for packed in &result.packets {
                        let _ = publisher.publish(NoxEvent::SendPacket {
                            packet_id: reply_wire_id(&packed.surb_id),
                            next_hop_peer_id: packed.first_hop.clone(),
                            data: packed.packet_bytes.clone(),
                            reply_handle: packed.reply_handle(),
                            origin: PacketOrigin::Originated,
                        });
                    }
                    match result.remaining {
                        Some(remaining) => {
                            debug!(
                                request_id = request_id,
                                remaining_bytes = remaining.remaining_data.len(),
                                seq_offset = remaining.continuation.fragments_already_sent,
                                "Partial response delivery -- stashing for next round"
                            );
                            state = remaining;
                        }
                        None => return,
                    }
                }
                Err(e) => {
                    debug!(
                        request_id = request_id,
                        error = %e,
                        "Response continuation packing failed"
                    );
                }
            }
        }
        let mut acc = accumulator.lock();
        match acc.remove(&request_id) {
            Some(more) if !more.is_empty() => surbs = more,
            _ => {
                pending.lock().insert(request_id, state);
                return;
            }
        }
    }
}

/// Caps both replenishment maps. The two locks are never held together.
fn prune_replenishment_maps(pending: &PendingReplenishments, accumulator: &SurbAccumulator) {
    {
        let mut pending = pending.lock();
        if pending.len() > 100 {
            let excess = pending.len() - 50;
            let keys: Vec<u64> = pending.keys().take(excess).copied().collect();
            for k in keys {
                pending.remove(&k);
            }
            debug!(pruned = excess, "Pruned stale pending replenishments");
        }
    }
    let mut acc = accumulator.lock();
    if acc.len() > 100 {
        let excess = acc.len() - 50;
        let keys: Vec<u64> = acc.keys().take(excess).copied().collect();
        for k in keys {
            acc.remove(&k);
        }
        debug!(pruned = excess, "Pruned stale SURB accumulator entries");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nox_core::{PaidQuoteRequestV2, PaidTransactionRequestV2};

    fn anonymous(request: &ServiceRequest) -> RelayerPayload {
        RelayerPayload::AnonymousRequest {
            inner: encode_payload(request).unwrap_or_default(),
            reply_surbs: Vec::new(),
        }
    }

    fn quote_request() -> PaidQuoteRequestV2 {
        PaidQuoteRequestV2 {
            chain_id: 1,
            entry_point: [1; 20],
            client_intent_id: [2; 32],
            payment_adapter: [3; 20],
            payment_id: [4; 32],
            fee_asset: [5; 20],
            payment_gas_limit: 1,
            action_target: [6; 20],
            action_calldata_hash: [7; 32],
            action_gas_limit: 1,
            tracked_assets_hash: [8; 32],
            maximum_transaction_gas: 1,
            return_data_limit: 0,
            valid_until_unix: 1,
        }
    }

    #[test]
    fn service_requests_map_to_their_lanes() {
        let cases = [
            (
                ServiceRequest::Echo { data: vec![1] },
                ExitDispatch::Lane(ExitLane::Control),
            ),
            (
                ServiceRequest::HttpRequest {
                    method: "GET".into(),
                    url: "https://example.com".into(),
                    headers: Vec::new(),
                    body: Vec::new(),
                },
                ExitDispatch::Lane(ExitLane::Proxy),
            ),
            (
                ServiceRequest::RpcRequest {
                    method: "eth_blockNumber".into(),
                    params: Vec::new(),
                    id: 1,
                    rpc_url: None,
                },
                ExitDispatch::Lane(ExitLane::Proxy),
            ),
            (
                ServiceRequest::SubmitTransaction {
                    to: [1; 20],
                    data: Vec::new(),
                },
                ExitDispatch::Lane(ExitLane::Paid),
            ),
            (
                ServiceRequest::BroadcastSignedTransaction {
                    signed_tx: vec![1],
                    rpc_url: None,
                    rpc_method: None,
                },
                ExitDispatch::Lane(ExitLane::Proxy),
            ),
            (
                ServiceRequest::ReplenishSurbs {
                    request_id: 1,
                    surbs: Vec::new(),
                },
                ExitDispatch::Inline,
            ),
            (
                ServiceRequest::PaidTransactionV2(PaidTransactionRequestV2 {
                    chain_id: 1,
                    entry_point: [1; 20],
                    calldata: Vec::new(),
                    execution_id: [2; 32],
                    valid_until_unix: 1,
                }),
                ExitDispatch::Lane(ExitLane::Paid),
            ),
            (
                ServiceRequest::PaidQuoteRequestV2(quote_request()),
                ExitDispatch::Lane(ExitLane::Quote),
            ),
        ];
        for (request, expected) in cases {
            assert_eq!(
                classify_payload(&anonymous(&request)),
                expected,
                "{request:?}"
            );
        }
    }

    #[test]
    fn service_request_tags_match_the_wire_layout() {
        let tag = |request: &ServiceRequest| {
            let encoded = encode_payload(request).unwrap_or_default();
            u32::from_le_bytes([encoded[1], encoded[2], encoded[3], encoded[4]])
        };
        assert_eq!(
            tag(&ServiceRequest::ReplenishSurbs {
                request_id: 1,
                surbs: Vec::new()
            }),
            SERVICE_REQUEST_REPLENISH_SURBS
        );
        assert_eq!(
            tag(&ServiceRequest::PaidQuoteRequestV2(quote_request())),
            SERVICE_REQUEST_PAID_QUOTE_V2
        );
    }

    #[test]
    fn relayer_payloads_map_to_their_lanes() {
        assert_eq!(
            classify_payload(&RelayerPayload::SubmitTransaction {
                to: [1; 20],
                data: Vec::new()
            }),
            ExitDispatch::Lane(ExitLane::Paid)
        );
        assert_eq!(
            classify_payload(&RelayerPayload::Dummy {
                padding: Vec::new()
            }),
            ExitDispatch::Lane(ExitLane::Control)
        );
        assert_eq!(
            classify_payload(&RelayerPayload::Heartbeat {
                id: 1,
                timestamp: 1
            }),
            ExitDispatch::Lane(ExitLane::Control)
        );
        assert_eq!(
            classify_payload(&RelayerPayload::NeedMoreSurbs {
                request_id: 1,
                fragments_remaining: 1
            }),
            ExitDispatch::Inline
        );
    }

    #[test]
    fn malformed_or_unknown_requests_are_handled_inline() {
        for inner in [
            Vec::new(),
            vec![nox_core::models::payloads::PAYLOAD_VERSION],
            vec![nox_core::models::payloads::PAYLOAD_VERSION + 1, 1, 0, 0, 0],
            vec![nox_core::models::payloads::PAYLOAD_VERSION, 99, 0, 0, 0],
        ] {
            assert_eq!(
                classify_payload(&RelayerPayload::AnonymousRequest {
                    inner,
                    reply_surbs: Vec::new()
                }),
                ExitDispatch::Inline
            );
        }
    }

    fn pending_state() -> PendingResponseState {
        PendingResponseState {
            remaining_data: vec![1; 64],
            continuation: crate::services::response_packer::ContinuationState {
                original_total_fragments: 2,
                fragments_already_sent: 1,
                original_data_len: 128,
            },
        }
    }

    #[test]
    fn stash_without_surbs_keeps_the_pending_state() {
        let pending = ExitService::new_pending_map();
        let accumulator = ExitService::new_surb_accumulator();
        accumulator.lock().insert(7, Vec::new());
        let stash = ExitService::make_stash_closure(
            pending.clone(),
            accumulator.clone(),
            Arc::new(ResponsePacker::new()),
            nox_core::NoopPublisher::arc(),
        );
        stash(7, pending_state());
        assert!(pending.lock().contains_key(&7));
        assert!(!accumulator.lock().contains_key(&7));
    }

    #[test]
    fn stash_and_prune_run_concurrently_without_blocking() {
        let pending = ExitService::new_pending_map();
        let accumulator = ExitService::new_surb_accumulator();
        let stash = ExitService::make_stash_closure(
            pending.clone(),
            accumulator.clone(),
            Arc::new(ResponsePacker::new()),
            nox_core::NoopPublisher::arc(),
        );
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let rounds = 20_000u64;

        let mut threads = Vec::new();
        for worker in 0..2u64 {
            let stash = stash.clone();
            let accumulator = accumulator.clone();
            let done_tx = done_tx.clone();
            threads.push(std::thread::spawn(move || {
                for i in 0..rounds {
                    let id = worker * rounds + i;
                    accumulator.lock().insert(id + 1_000_000, Vec::new());
                    stash(id, pending_state());
                }
                let _ = done_tx.send(());
            }));
        }
        {
            let pending = pending.clone();
            let accumulator = accumulator.clone();
            let done_tx = done_tx.clone();
            threads.push(std::thread::spawn(move || {
                for _ in 0..rounds {
                    prune_replenishment_maps(&pending, &accumulator);
                }
                let _ = done_tx.send(());
            }));
        }
        drop(done_tx);

        for _ in 0..threads.len() {
            done_rx
                .recv_timeout(Duration::from_secs(30))
                .expect("stash and prune must not block each other");
        }
        for thread in threads {
            thread.join().expect("worker thread panicked");
        }
    }
}
