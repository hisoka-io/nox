//! Exit service: reassembles fragmented messages and routes to handlers.

use crate::config::FragmentationConfig;
use crate::services::handlers::echo::EchoHandler;
use crate::services::handlers::ethereum::EthereumHandler;
use crate::services::handlers::http::HttpHandler;
use crate::services::handlers::rpc::RpcHandler;
use crate::services::handlers::traffic::TrafficHandler;
use crate::services::response_packer::ResponsePacker;
use crate::telemetry::metrics::MetricsService;
use ethers::types::{Address, Bytes};
use nox_core::events::NoxEvent;
use nox_core::models::payloads::{
    decode_payload_limited, encode_payload, RelayerPayload, ServiceRequest,
};
use nox_core::protocol::fragmentation::{
    Fragment, Reassembler, ReassemblerConfig, MAX_MESSAGE_SIZE,
};
use nox_core::traits::service::ServiceHandler;
use nox_core::traits::IEventSubscriber;
use nox_core::IEventPublisher;
use nox_crypto::sphinx::surb::Surb;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
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
        }
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
            let pre_surbs = accumulator.lock().remove(&request_id);
            if let Some(surbs) = pre_surbs {
                if !surbs.is_empty() {
                    match packer.pack_continuation(request_id, &state, surbs) {
                        Ok(result) => {
                            for packed in &result.packets {
                                let _ = publisher.publish(NoxEvent::SendPacket {
                                    packet_id: format!(
                                        "preemptive-{}-{}",
                                        request_id,
                                        hex::encode(packed.surb_id)
                                    ),
                                    next_hop_peer_id: packed.first_hop.clone(),
                                    data: packed.packet_bytes.clone(),
                                });
                            }
                            if let Some(remaining) = result.remaining {
                                pending.lock().insert(request_id, remaining);
                            }
                            return;
                        }
                        Err(_e) => {}
                    }
                }
            }
            pending.lock().insert(request_id, state);
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
        info!("Exit Service active.");

        let mut rx = self.bus_subscriber.subscribe();
        let mut prune_timer = tokio::time::interval(self.prune_interval);

        loop {
            tokio::select! {
                event_result = rx.recv() => {
                    match event_result {
                        Ok(NoxEvent::PayloadDecrypted { packet_id, payload }) => {
                            self.handle_payload(packet_id, payload).await;
                        }
                        Ok(_) => {
                            // Ignore other event types
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
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
        let mut pending = self.pending_replenishments.lock();
        if pending.len() > 100 {
            let excess = pending.len() - 50;
            let keys: Vec<u64> = pending.keys().take(excess).copied().collect();
            for k in keys {
                pending.remove(&k);
            }
            debug!(pruned = excess, "Pruned stale pending replenishments");
        }

        let mut acc = self.surb_accumulator.lock();
        if acc.len() > 100 {
            let excess = acc.len() - 50;
            let keys: Vec<u64> = acc.keys().take(excess).copied().collect();
            for k in keys {
                acc.remove(&k);
            }
            debug!(pruned = excess, "Pruned stale SURB accumulator entries");
        }
    }

    async fn handle_payload(&self, packet_id: String, payload_bytes: Vec<u8>) {
        let command: RelayerPayload =
            match decode_payload_limited(&payload_bytes, MAX_SINGLE_PAYLOAD_SIZE) {
                Ok(cmd) => cmd,
                Err(e) => {
                    debug!(
                        packet_id = %packet_id,
                        error = %e,
                        payload_len = payload_bytes.len(),
                        "Payload decode failed (likely SURB-encrypted reply or garbage)"
                    );
                    return;
                }
            };

        match command {
            RelayerPayload::Fragment { frag } => {
                if let Some(reassembled_payload) =
                    self.try_reassemble(packet_id.clone(), frag).await
                {
                    self.dispatch_payload(&packet_id, reassembled_payload).await;
                }
            }
            other => {
                self.dispatch_payload(&packet_id, other).await;
            }
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
                    info!(
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
                    warn!(
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
                    warn!(
                        message_id = message_id,
                        "Reassembled payload is itself a Fragment - dropping to prevent loop"
                    );
                    return None;
                }

                info!(
                    message_id = message_id,
                    packet_id = %packet_id,
                    "Re-injecting reassembled payload"
                );
                Some(inner_payload)
            }
            Err(e) => {
                warn!(
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
                    .get_or_create(&vec![("handler".to_string(), "ethereum".to_string())])
                    .inc();
                if let Some(ref handler) = self.ethereum_handler {
                    if let Err(e) = handler.handle(packet_id, &command).await {
                        warn!("Ethereum handler failed for {}: {}", packet_id, e);
                    }
                } else {
                    warn!(
                        packet_id = %packet_id,
                        "SubmitTransaction received but no Ethereum handler (simulation mode) -- dropping"
                    );
                }
            }
            RelayerPayload::Dummy { .. } | RelayerPayload::Heartbeat { .. } => {
                self.metrics
                    .exit_payloads_dispatched_total
                    .get_or_create(&vec![("handler".to_string(), "traffic".to_string())])
                    .inc();
                if let Err(e) = self.traffic_handler.handle(packet_id, &command).await {
                    warn!("Traffic handler failed for {}: {}", packet_id, e);
                }
            }
            RelayerPayload::Fragment { .. } => {
                warn!(packet_id = %packet_id, "dispatch_payload called with Fragment - bug");
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
                                warn!(
                                    packet_id = %packet_id,
                                    error = %e,
                                    "HTTP handler failed"
                                );
                            }
                        } else {
                            warn!(
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
                                warn!(
                                    packet_id = %packet_id,
                                    error = %e,
                                    "Echo handler failed"
                                );
                            }
                        } else {
                            warn!(
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
                                warn!(
                                    packet_id = %packet_id,
                                    error = %e,
                                    "RPC handler failed"
                                );
                            }
                        } else {
                            warn!(
                                packet_id = %packet_id,
                                "RPC request received but no RPC handler configured"
                            );
                        }
                    }
                    Ok(ServiceRequest::SubmitTransaction { to, data }) => {
                        self.metrics
                            .exit_payloads_dispatched_total
                            .get_or_create(&vec![("handler".to_string(), "ethereum".to_string())])
                            .inc();

                        let Some(ref eth_handler) = self.ethereum_handler else {
                            warn!(
                                packet_id = %packet_id,
                                "Paid SubmitTransaction received but no Ethereum handler (simulation mode) -- dropping"
                            );
                            return;
                        };

                        let to_addr = Address::from(to);
                        info!(
                            packet_id = %packet_id,
                            to_raw = ?to,
                            to_addr = ?to_addr,
                            data_len = data.len(),
                            "Exit: deserialized ServiceRequest::SubmitTransaction"
                        );
                        let data_bytes = Bytes::from(data);
                        let tx_result = eth_handler
                            .handle_paid_transaction(packet_id, to_addr, data_bytes)
                            .await;

                        if !reply_surbs.is_empty() {
                            if let Some(ref echo) = self.echo_handler {
                                let response_data = match &tx_result {
                                    Ok(tx_hash) => tx_hash.as_bytes().to_vec(),
                                    Err(e) => format!("tx_error:{e}").into_bytes(),
                                };
                                let inner = match encode_payload(&ServiceRequest::Echo {
                                    data: response_data,
                                }) {
                                    Ok(bytes) => bytes,
                                    Err(e) => {
                                        warn!(
                                            packet_id = %packet_id,
                                            error = %e,
                                            "Failed to encode tx response for SURB delivery"
                                        );
                                        return;
                                    }
                                };
                                let echo_payload =
                                    RelayerPayload::AnonymousRequest { inner, reply_surbs };
                                if let Err(e) = echo.handle(packet_id, &echo_payload).await {
                                    warn!(
                                        packet_id = %packet_id,
                                        error = %e,
                                        "Failed to send tx response via SURBs"
                                    );
                                }
                            }
                        }

                        if let Err(e) = tx_result {
                            warn!(
                                packet_id = %packet_id,
                                error = %e,
                                "Paid transaction handler failed"
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
                            warn!(
                                packet_id = %packet_id,
                                "BroadcastSignedTransaction received but no Ethereum handler (simulation mode) -- dropping"
                            );
                            return;
                        };

                        info!(
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
                                        warn!(
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
                                    warn!(
                                        packet_id = %packet_id,
                                        error = %e,
                                        "Failed to send broadcast response via SURBs"
                                    );
                                }
                            }
                        }

                        if let Err(e) = tx_result {
                            warn!(
                                packet_id = %packet_id,
                                error = %e,
                                "Broadcast signed transaction handler failed"
                            );
                        }
                    }
                    Ok(ServiceRequest::ReplenishSurbs { request_id, surbs }) => {
                        let stashed = self.pending_replenishments.lock().remove(&request_id);
                        if let Some(pending_state) = stashed {
                            let mut all_surbs = {
                                let mut acc = self.surb_accumulator.lock();
                                acc.remove(&request_id).unwrap_or_default()
                            };
                            all_surbs.extend(surbs);

                            debug!(
                                packet_id = %packet_id,
                                request_id = request_id,
                                surbs = all_surbs.len(),
                                remaining_bytes = pending_state.remaining_data.len(),
                                seq_offset = pending_state.continuation.fragments_already_sent,
                                original_total = pending_state.continuation.original_total_fragments,
                                "Resuming partial response delivery with fresh SURBs (continuation)"
                            );
                            match self.response_packer.pack_continuation(
                                request_id,
                                &pending_state,
                                all_surbs,
                            ) {
                                Ok(result) => {
                                    for packed in &result.packets {
                                        let _ = self.publisher.publish(NoxEvent::SendPacket {
                                            packet_id: format!(
                                                "replenish-{}-{}",
                                                request_id,
                                                hex::encode(packed.surb_id)
                                            ),
                                            next_hop_peer_id: packed.first_hop.clone(),
                                            data: packed.packet_bytes.clone(),
                                        });
                                    }
                                    if let Some(remaining) = result.remaining {
                                        debug!(
                                            request_id = request_id,
                                            remaining_bytes = remaining.remaining_data.len(),
                                            seq_offset =
                                                remaining.continuation.fragments_already_sent,
                                            "Replenishment partial -- re-stashing for next round"
                                        );
                                        self.pending_replenishments
                                            .lock()
                                            .insert(request_id, remaining);
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        packet_id = %packet_id,
                                        request_id = request_id,
                                        error = %e,
                                        "Replenishment pack_continuation failed"
                                    );
                                }
                            }
                        } else {
                            let count = surbs.len();
                            self.surb_accumulator
                                .lock()
                                .entry(request_id)
                                .or_default()
                                .extend(surbs);
                            debug!(
                                packet_id = %packet_id,
                                request_id = request_id,
                                accumulated_surbs = count,
                                "Pre-emptive ReplenishSurbs -- accumulated for future use"
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
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
