use parking_lot::Mutex;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::Registry;
use std::sync::atomic::AtomicI64;
use std::sync::Arc;

/// Exit dispatch lanes, used as the `lane` label.
pub const EXIT_LANES: [&str; 4] = ["paid", "quote", "proxy", "control"];
/// Reasons an exit payload is dropped before dispatch, used as the `reason` label.
pub const EXIT_DROP_REASONS: [&str; 2] = ["queue_full", "lane_closed"];

/// Prometheus metrics for all NOX subsystems.
#[derive(Clone)]
pub struct MetricsService {
    registry: Arc<Mutex<Registry>>,
    /// Features this node supports, reported in `/metrics/json` as `capabilities`.
    capabilities: Arc<Mutex<std::collections::BTreeSet<String>>>,

    pub packets_received: Family<Vec<(String, String)>, Counter>,
    pub packets_forwarded: Family<Vec<(String, String)>, Counter>,
    pub dummy_packets_dropped: Family<Vec<(String, String)>, Counter>,

    pub eth_simulation_reverts: Family<Vec<(String, String)>, Counter>,
    pub eth_unprofitable_drops: Family<Vec<(String, String)>, Counter>,
    pub eth_transactions_submitted: Family<Vec<(String, String)>, Counter>,

    pub peers_connected: Family<Vec<(String, String)>, Counter>,
    pub peers_disconnected: Family<Vec<(String, String)>, Counter>,

    pub active_peers: Gauge<i64, AtomicI64>,

    pub processing_duration: Family<Vec<(String, String)>, Histogram>,
    pub mix_delay_seconds: Histogram,

    pub ingest_dropped_total: Family<Vec<(String, String)>, Counter>,
    /// Outbound packet identifiers by kind (`fresh`, `legacy_handle`, `passthrough`).
    pub wire_ids_total: Family<Vec<(String, String)>, Counter>,
    /// Reply handles not passed on to the next hop, by reason.
    pub wire_handle_dropped_total: Family<Vec<(String, String)>, Counter>,
    /// Packets carrying the format 2 reply flag, by `hop` (`relay`, `final`, `final_not_p2p`).
    pub reply_v2_packets_total: Family<Vec<(String, String)>, Counter>,
    /// Replies stored in the response buffer, by `key` (`handle`, `delivery`).
    pub response_store_total: Family<Vec<(String, String)>, Counter>,
    /// Replies removed from or refused by the response buffer without being
    /// claimed, by `key` and `reason`.
    pub response_evicted_total: Family<Vec<(String, String)>, Counter>,
    /// Bytes held in the response buffer, by `key`.
    pub response_buffer_bytes: Family<Vec<(String, String)>, Gauge<i64, AtomicI64>>,
    /// Format of the replies this exit sends, by `format` (`v1`, `v2`).
    pub reply_format_total: Family<Vec<(String, String)>, Counter>,
    pub relayer_worker_queue_depth: Gauge<i64, AtomicI64>,
    pub relayer_mix_queue_depth: Gauge<i64, AtomicI64>,
    pub relayer_egress_queue_depth: Gauge<i64, AtomicI64>,
    pub sphinx_processing_errors_total: Family<Vec<(String, String)>, Counter>,
    pub egress_routed_total: Family<Vec<(String, String)>, Counter>,
    pub node_start_time_seconds: Gauge<i64, AtomicI64>,
    pub ingress_http_requests_total: Family<Vec<(String, String)>, Counter>,
    pub ingress_response_buffer_entries: Gauge<i64, AtomicI64>,
    pub ingress_responses_pruned_total: Counter,
    pub p2p_rate_limit_total: Family<Vec<(String, String)>, Counter>,
    pub p2p_rate_limit_disconnects_total: Counter,
    pub replay_checks_total: Family<Vec<(String, String)>, Counter>,
    pub replay_bloom_rotations_total: Counter,
    pub event_bus_lag_total: Counter,
    pub event_bus_events_total: Family<Vec<(String, String)>, Counter>,
    pub event_bus_publish_errors_total: Family<Vec<(String, String)>, Counter>,

    pub profitability_outcomes_total: Family<Vec<(String, String)>, Counter>,
    pub profitability_margin_ratio: Histogram,
    pub tx_authorized_revenue_usd: Histogram,
    pub tx_planned_cost_usd: Histogram,
    pub tx_maximum_cost_usd: Histogram,
    pub cumulative_authorized_revenue_usd: Counter,
    pub cumulative_cost_usd: Counter,
    pub cumulative_maximum_cost_usd: Counter,
    pub eth_tx_gas_used: Histogram,
    pub eth_tx_outcomes_total: Family<Vec<(String, String)>, Counter>,
    pub chain_observer_last_block: Gauge<i64, AtomicI64>,
    pub chain_observer_errors_total: Family<Vec<(String, String)>, Counter>,
    pub chain_events_processed_total: Family<Vec<(String, String)>, Counter>,
    pub eth_tx_pending: Gauge<i64, AtomicI64>,
    pub oracle_fetch_total: Family<Vec<(String, String)>, Counter>,
    /// Paid quote and execution outcomes: `kind`, `result`, `code`.
    pub paid_outcomes_total: Family<Vec<(String, String)>, Counter>,
    pub eth_submission_blocked: Gauge<i64, AtomicI64>,
    pub eth_wallet_balance_gwei: Gauge<i64, AtomicI64>,
    pub eth_wallet_balance_low: Gauge<i64, AtomicI64>,
    pub quote_outstanding: Gauge<i64, AtomicI64>,
    pub quote_pending_sponsored_gas: Gauge<i64, AtomicI64>,
    pub quote_rolling_loss_gwei: Gauge<i64, AtomicI64>,
    pub storage_degraded: Gauge<i64, AtomicI64>,
    pub exit_payloads_dropped_total: Family<Vec<(String, String)>, Counter>,
    pub exit_lane_inflight: Family<Vec<(String, String)>, Gauge<i64, AtomicI64>>,
    pub event_bus_subscriber_lag_total: Family<Vec<(String, String)>, Counter>,

    pub cover_traffic_generated_total: Family<Vec<(String, String)>, Counter>,
    pub cover_traffic_errors_total: Family<Vec<(String, String)>, Counter>,
    pub cover_traffic_degraded: Family<Vec<(String, String)>, Gauge<i64, AtomicI64>>,
    pub cover_loop_sent_total: Family<Vec<(String, String)>, Counter>,
    pub cover_loop_returned_total: Family<Vec<(String, String)>, Counter>,
    pub cover_loop_lost_total: Family<Vec<(String, String)>, Counter>,
    pub cover_loop_outcomes_total: Family<Vec<(String, String)>, Counter>,
    pub cover_loop_rtt_seconds: Histogram,
    pub p2p_admission_total: Family<Vec<(String, String)>, Counter>,
    pub topology_reconcile_total: Family<Vec<(String, String)>, Counter>,
    pub topology_membership_verified: Gauge<i64, AtomicI64>,
    pub rpc_requests_total: Family<Vec<(String, String)>, Counter>,
    pub rpc_rate_limited_total: Counter,
    pub rpc_ssrf_blocks_total: Counter,
    pub http_proxy_requests_total: Family<Vec<(String, String)>, Counter>,
    pub fec_operations_total: Family<Vec<(String, String)>, Counter>,
    pub response_pack_total: Family<Vec<(String, String)>, Counter>,
    pub exit_payloads_dispatched_total: Family<Vec<(String, String)>, Counter>,
    pub exit_reassembly_total: Family<Vec<(String, String)>, Counter>,
    pub reassembly_conflict_total: Counter,
    pub exit_reassembler_pending: Gauge<i64, AtomicI64>,
    pub topology_nodes: Family<Vec<(String, String)>, Gauge<i64, AtomicI64>>,
    pub topology_bootstrap_total: Family<Vec<(String, String)>, Counter>,

    pub process_resident_memory_bytes: Gauge<i64, AtomicI64>,
    pub process_virtual_memory_bytes: Gauge<i64, AtomicI64>,
    pub process_open_fds: Gauge<i64, AtomicI64>,
    pub build_info: Family<Vec<(String, String)>, Gauge<i64, AtomicI64>>,
    pub health_status: Gauge<i64, AtomicI64>,
    pub uptime_seconds: Gauge<i64, AtomicI64>,
}

impl MetricsService {
    #[must_use]
    pub fn new() -> Self {
        let mut registry = Registry::default();

        let packets_received = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_packets_received_total",
            "Total packets received by P2P layer",
            packets_received.clone(),
        );

        let packets_forwarded = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_packets_forwarded_total",
            "Total packets forwarded by Relayer layer",
            packets_forwarded.clone(),
        );

        let dummy_packets_dropped = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_dummy_packets_dropped",
            "Total dummy packets dropped at exit",
            dummy_packets_dropped.clone(),
        );

        let eth_simulation_reverts = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_eth_simulation_reverts",
            "Transactions dropped due to simulation failure (invalid proof/state)",
            eth_simulation_reverts.clone(),
        );

        let eth_unprofitable_drops = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_eth_unprofitable_drops",
            "Transactions dropped due to unprofitability",
            eth_unprofitable_drops.clone(),
        );

        let eth_transactions_submitted = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_eth_transactions_submitted",
            "Transactions successfully submitted to mempool",
            eth_transactions_submitted.clone(),
        );

        let peers_connected = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_peers_connected_total",
            "Total peer connection events",
            peers_connected.clone(),
        );

        let peers_disconnected = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_peers_disconnected_total",
            "Total peer disconnection events",
            peers_disconnected.clone(),
        );

        let active_peers = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "nox_active_peers",
            "Current number of connected peers",
            active_peers.clone(),
        );

        let processing_duration =
            Family::<Vec<(String, String)>, Histogram>::new_with_constructor(|| {
                Histogram::new(exponential_buckets(0.005, 2.0, 10))
            });
        registry.register(
            "nox_packet_processing_duration_seconds",
            "Time spent peeling and processing a packet",
            processing_duration.clone(),
        );

        let mix_delay_seconds = Histogram::new(exponential_buckets(0.005, 2.0, 10));
        registry.register(
            "nox_mix_delay_seconds",
            "Actual delay applied to packets in the mix loop",
            mix_delay_seconds.clone(),
        );

        let ingest_dropped_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_relayer_ingest_dropped_total",
            "Packets dropped at ingest stage by reason",
            ingest_dropped_total.clone(),
        );

        let wire_ids_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_wire_ids",
            "Outbound packet identifiers by kind",
            wire_ids_total.clone(),
        );

        let wire_handle_dropped_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_wire_handle_dropped",
            "Reply handles not passed on to the next hop, by reason",
            wire_handle_dropped_total.clone(),
        );

        let reply_v2_packets_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_reply_v2_packets",
            "Packets carrying the format 2 reply flag, by hop",
            reply_v2_packets_total.clone(),
        );

        let response_store_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_response_store",
            "Replies stored in the response buffer, by key kind",
            response_store_total.clone(),
        );

        let response_evicted_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_response_evicted",
            "Replies removed from or refused by the response buffer, by key kind and reason",
            response_evicted_total.clone(),
        );

        let response_buffer_bytes =
            Family::<Vec<(String, String)>, Gauge<i64, AtomicI64>>::default();
        registry.register(
            "nox_response_buffer_bytes",
            "Bytes held in the response buffer, by key kind",
            response_buffer_bytes.clone(),
        );

        let reply_format_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_reply_format",
            "Replies sent by this exit, by format",
            reply_format_total.clone(),
        );

        let relayer_worker_queue_depth = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "nox_relayer_worker_queue_depth",
            "Current depth of the ingest-to-worker channel",
            relayer_worker_queue_depth.clone(),
        );

        let relayer_mix_queue_depth = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "nox_relayer_mix_queue_depth",
            "Current depth of the mix delay queue",
            relayer_mix_queue_depth.clone(),
        );

        let relayer_egress_queue_depth = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "nox_relayer_egress_queue_depth",
            "Current depth of the mix-to-egress channel",
            relayer_egress_queue_depth.clone(),
        );

        let sphinx_processing_errors_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_sphinx_processing_errors_total",
            "Sphinx packet processing failures by reason",
            sphinx_processing_errors_total.clone(),
        );

        let egress_routed_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_relayer_egress_routed_total",
            "Packets routed by egress stage by type",
            egress_routed_total.clone(),
        );

        let node_start_time_seconds = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "nox_node_start_time_seconds",
            "Unix epoch timestamp when the node started",
            node_start_time_seconds.clone(),
        );

        let ingress_http_requests_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_ingress_http_requests_total",
            "HTTP ingress requests by endpoint and status",
            ingress_http_requests_total.clone(),
        );

        let ingress_response_buffer_entries = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "nox_ingress_response_buffer_entries",
            "Current entries in the SURB response buffer",
            ingress_response_buffer_entries.clone(),
        );

        let ingress_responses_pruned_total = Counter::default();
        registry.register(
            "nox_ingress_responses_pruned_total",
            "Total expired responses pruned from the buffer",
            ingress_responses_pruned_total.clone(),
        );

        let p2p_rate_limit_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_p2p_rate_limit_total",
            "P2P rate limit decisions by result",
            p2p_rate_limit_total.clone(),
        );

        let p2p_rate_limit_disconnects_total = Counter::default();
        registry.register(
            "nox_p2p_rate_limit_disconnects_total",
            "Peers disconnected due to rate limit abuse",
            p2p_rate_limit_disconnects_total.clone(),
        );

        let replay_checks_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_replay_checks_total",
            "Replay protection checks by result",
            replay_checks_total.clone(),
        );

        let replay_bloom_rotations_total = Counter::default();
        registry.register(
            "nox_replay_bloom_rotations_total",
            "Bloom filter rotations in replay protection",
            replay_bloom_rotations_total.clone(),
        );

        let event_bus_lag_total = Counter::default();
        registry.register(
            "nox_event_bus_lag_total",
            "Event bus lag events (subscriber fell behind)",
            event_bus_lag_total.clone(),
        );

        let event_bus_events_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_event_bus_events_total",
            "Events processed by the event bus by type",
            event_bus_events_total.clone(),
        );

        let event_bus_publish_errors_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_event_bus_publish_errors_total",
            "Event bus publish failures by event type and caller",
            event_bus_publish_errors_total.clone(),
        );

        let profitability_outcomes_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_profitability_outcomes_total",
            "Profitability analysis outcomes by result",
            profitability_outcomes_total.clone(),
        );

        let profitability_margin_ratio =
            Histogram::new([0.0, 0.5, 1.0, 1.1, 1.5, 2.0, 5.0, 10.0, 50.0].into_iter());
        registry.register(
            "nox_profitability_margin_ratio",
            "Distribution of profitability margin ratios",
            profitability_margin_ratio.clone(),
        );

        let tx_authorized_revenue_usd =
            Histogram::new([0.01, 0.1, 0.5, 1.0, 5.0, 10.0, 50.0, 100.0].into_iter());
        registry.register(
            "nox_tx_authorized_revenue_usd",
            "Authorized per-transaction revenue in USD",
            tx_authorized_revenue_usd.clone(),
        );

        let tx_planned_cost_usd =
            Histogram::new([0.01, 0.1, 0.5, 1.0, 5.0, 10.0, 50.0, 100.0].into_iter());
        registry.register(
            "nox_tx_planned_cost_usd",
            "Per-transaction planned initial cost in USD",
            tx_planned_cost_usd.clone(),
        );

        let tx_maximum_cost_usd =
            Histogram::new([0.01, 0.1, 0.5, 1.0, 5.0, 10.0, 50.0, 100.0].into_iter());
        registry.register(
            "nox_tx_maximum_cost_usd",
            "Per-transaction maximum authorized cost in USD",
            tx_maximum_cost_usd.clone(),
        );

        let cumulative_authorized_revenue_usd = Counter::default();
        registry.register(
            "nox_cumulative_authorized_revenue_usd",
            "Cumulative authorized revenue in USD",
            cumulative_authorized_revenue_usd.clone(),
        );

        let cumulative_cost_usd = Counter::default();
        registry.register(
            "nox_cumulative_cost_usd",
            "Cumulative cost in USD",
            cumulative_cost_usd.clone(),
        );

        let cumulative_maximum_cost_usd = Counter::default();
        registry.register(
            "nox_cumulative_maximum_cost_usd",
            "Cumulative maximum authorized cost in USD",
            cumulative_maximum_cost_usd.clone(),
        );

        let eth_tx_gas_used = Histogram::new(
            [
                50_000.0,
                100_000.0,
                200_000.0,
                500_000.0,
                1_000_000.0,
                2_000_000.0,
                5_000_000.0,
                10_000_000.0,
            ]
            .into_iter(),
        );
        registry.register(
            "nox_eth_tx_gas_used",
            "Gas used per Ethereum transaction",
            eth_tx_gas_used.clone(),
        );

        let eth_tx_outcomes_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_eth_tx_outcomes_total",
            "Transaction outcomes by type and result",
            eth_tx_outcomes_total.clone(),
        );

        let chain_observer_last_block = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "nox_chain_observer_last_block",
            "Last block number processed by chain observer",
            chain_observer_last_block.clone(),
        );

        let chain_observer_errors_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_chain_observer_errors_total",
            "Chain observer errors by type",
            chain_observer_errors_total.clone(),
        );

        let chain_events_processed_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_chain_events_processed_total",
            "Chain events processed by type",
            chain_events_processed_total.clone(),
        );

        let eth_tx_pending = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "nox_eth_tx_pending",
            "Current count of pending Ethereum transactions",
            eth_tx_pending.clone(),
        );

        let oracle_fetch_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_oracle_fetch_total",
            "Oracle price fetch outcomes by result",
            oracle_fetch_total.clone(),
        );

        let paid_outcomes_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_paid_outcomes",
            "Paid quote and execution outcomes by kind, result and rejection code",
            paid_outcomes_total.clone(),
        );

        let eth_submission_blocked = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "nox_eth_submission_blocked",
            "1 while paid submission is paused by an unresolved outbox transaction",
            eth_submission_blocked.clone(),
        );

        let eth_wallet_balance_gwei = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "nox_eth_wallet_balance_gwei",
            "Exit wallet native balance in gwei",
            eth_wallet_balance_gwei.clone(),
        );

        let eth_wallet_balance_low = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "nox_eth_wallet_balance_low",
            "1 while the exit wallet balance is below min_gas_balance",
            eth_wallet_balance_low.clone(),
        );

        let quote_outstanding = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "nox_quote_outstanding",
            "Paid quotes that are reserved and not yet terminal",
            quote_outstanding.clone(),
        );

        let quote_pending_sponsored_gas = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "nox_quote_pending_sponsored_gas",
            "Gas reserved by quotes that are not yet terminal",
            quote_pending_sponsored_gas.clone(),
        );

        let quote_rolling_loss_gwei = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "nox_quote_rolling_loss_gwei",
            "Unreimbursed sponsored loss in the current rolling window, in gwei",
            quote_rolling_loss_gwei.clone(),
        );

        let storage_degraded = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "nox_storage_degraded",
            "1 while durable storage writes are failing",
            storage_degraded.clone(),
        );

        let exit_payloads_dropped_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_exit_payloads_dropped",
            "Exit payloads dropped before dispatch, by lane and reason",
            exit_payloads_dropped_total.clone(),
        );

        let exit_lane_inflight = Family::<Vec<(String, String)>, Gauge<i64, AtomicI64>>::default();
        registry.register(
            "nox_exit_lane_inflight",
            "Exit payloads currently being handled, by lane",
            exit_lane_inflight.clone(),
        );

        let event_bus_subscriber_lag_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_event_bus_subscriber_lagged",
            "Events skipped because a subscriber fell behind, by subscriber",
            event_bus_subscriber_lag_total.clone(),
        );

        let cover_traffic_generated_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_cover_traffic_generated_total",
            "Cover traffic packets generated by type",
            cover_traffic_generated_total.clone(),
        );

        let cover_traffic_errors_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_cover_traffic_errors_total",
            "Cover traffic generation errors by type and reason",
            cover_traffic_errors_total.clone(),
        );

        let cover_traffic_degraded =
            Family::<Vec<(String, String)>, Gauge<i64, AtomicI64>>::default();
        registry.register(
            "nox_cover_traffic_degraded",
            "Cover traffic degraded state per type (0=ok, 1=degraded)",
            cover_traffic_degraded.clone(),
        );

        let cover_loop_sent_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_cover_loop_sent_total",
            "Self-addressed loop cover packets sent, by first and second hop address",
            cover_loop_sent_total.clone(),
        );

        let cover_loop_returned_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_cover_loop_returned_total",
            "Loop cover packets that came back to this node, by first and second hop address",
            cover_loop_returned_total.clone(),
        );

        let cover_loop_lost_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_cover_loop_lost_total",
            "Loop cover packets that did not come back in time, by first and second hop address",
            cover_loop_lost_total.clone(),
        );

        let cover_loop_outcomes_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_cover_loop_outcomes_total",
            "Loop cover packets by outcome (sent, returned, lost), across all paths",
            cover_loop_outcomes_total.clone(),
        );

        let cover_loop_rtt_seconds = Histogram::new(exponential_buckets(0.05, 2.0, 12));
        registry.register(
            "nox_cover_loop_rtt_seconds",
            "Round-trip time of returned loop cover packets",
            cover_loop_rtt_seconds.clone(),
        );

        let p2p_admission_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_p2p_admission_total",
            "P2P admission decisions for peers outside the registry, by stage and result",
            p2p_admission_total.clone(),
        );

        let topology_reconcile_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_topology_reconcile_total",
            "Registry reconcile runs by result",
            topology_reconcile_total.clone(),
        );

        let topology_membership_verified = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "nox_topology_membership_verified",
            "1 while the node set matches the registry fingerprint and count, else 0",
            topology_membership_verified.clone(),
        );

        let rpc_requests_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_rpc_requests_total",
            "RPC handler requests by method and result",
            rpc_requests_total.clone(),
        );

        let rpc_rate_limited_total = Counter::default();
        registry.register(
            "nox_rpc_rate_limited_total",
            "RPC requests blocked by rate limiter",
            rpc_rate_limited_total.clone(),
        );

        let rpc_ssrf_blocks_total = Counter::default();
        registry.register(
            "nox_rpc_ssrf_blocks_total",
            "RPC requests blocked by SSRF protection",
            rpc_ssrf_blocks_total.clone(),
        );

        let http_proxy_requests_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_http_proxy_requests_total",
            "HTTP proxy requests by result",
            http_proxy_requests_total.clone(),
        );

        let fec_operations_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_fec_operations_total",
            "FEC encode/decode operations by type and result",
            fec_operations_total.clone(),
        );

        let response_pack_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_response_pack_total",
            "Response packing outcomes by result",
            response_pack_total.clone(),
        );

        let exit_payloads_dispatched_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_exit_payloads_dispatched_total",
            "Exit payloads dispatched by handler type",
            exit_payloads_dispatched_total.clone(),
        );

        let exit_reassembly_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_exit_reassembly_total",
            "Exit reassembly outcomes by result",
            exit_reassembly_total.clone(),
        );

        let reassembly_conflict_total = Counter::default();
        registry.register(
            "nox_reassembly_conflict_total",
            "Reassembly buffers discarded after a conflicting fragment",
            reassembly_conflict_total.clone(),
        );

        let exit_reassembler_pending = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "nox_exit_reassembler_pending",
            "Pending fragments in exit reassembler",
            exit_reassembler_pending.clone(),
        );

        let topology_nodes = Family::<Vec<(String, String)>, Gauge<i64, AtomicI64>>::default();
        registry.register(
            "nox_topology_nodes",
            "Node count per topology layer",
            topology_nodes.clone(),
        );

        let topology_bootstrap_total = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "nox_topology_bootstrap_total",
            "Topology bootstrap outcomes by result",
            topology_bootstrap_total.clone(),
        );

        let process_resident_memory_bytes = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "process_resident_memory_bytes",
            "Resident memory size in bytes",
            process_resident_memory_bytes.clone(),
        );

        let process_virtual_memory_bytes = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "process_virtual_memory_bytes",
            "Virtual memory size in bytes",
            process_virtual_memory_bytes.clone(),
        );

        let process_open_fds = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "process_open_fds",
            "Number of open file descriptors",
            process_open_fds.clone(),
        );

        let build_info = Family::<Vec<(String, String)>, Gauge<i64, AtomicI64>>::default();
        registry.register(
            "nox_build_info",
            "Build information (version, commit, role)",
            build_info.clone(),
        );

        let health_status = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "nox_health_status",
            "Node health: 0=unhealthy, 1=degraded, 2=healthy",
            health_status.clone(),
        );

        let uptime_seconds = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "nox_uptime_seconds",
            "Node uptime in seconds",
            uptime_seconds.clone(),
        );

        Self {
            registry: Arc::new(Mutex::new(registry)),
            capabilities: Arc::default(),
            packets_received,
            packets_forwarded,
            dummy_packets_dropped,
            eth_simulation_reverts,
            eth_unprofitable_drops,
            eth_transactions_submitted,
            peers_connected,
            peers_disconnected,
            active_peers,
            processing_duration,
            mix_delay_seconds,
            ingest_dropped_total,
            wire_ids_total,
            wire_handle_dropped_total,
            reply_v2_packets_total,
            response_store_total,
            response_evicted_total,
            response_buffer_bytes,
            reply_format_total,
            relayer_worker_queue_depth,
            relayer_mix_queue_depth,
            relayer_egress_queue_depth,
            sphinx_processing_errors_total,
            egress_routed_total,
            node_start_time_seconds,
            ingress_http_requests_total,
            ingress_response_buffer_entries,
            ingress_responses_pruned_total,
            p2p_rate_limit_total,
            p2p_rate_limit_disconnects_total,
            replay_checks_total,
            replay_bloom_rotations_total,
            event_bus_lag_total,
            event_bus_events_total,
            event_bus_publish_errors_total,
            profitability_outcomes_total,
            profitability_margin_ratio,
            tx_authorized_revenue_usd,
            tx_planned_cost_usd,
            tx_maximum_cost_usd,
            cumulative_authorized_revenue_usd,
            cumulative_cost_usd,
            cumulative_maximum_cost_usd,
            eth_tx_gas_used,
            eth_tx_outcomes_total,
            chain_observer_last_block,
            chain_observer_errors_total,
            chain_events_processed_total,
            eth_tx_pending,
            oracle_fetch_total,
            paid_outcomes_total,
            eth_submission_blocked,
            eth_wallet_balance_gwei,
            eth_wallet_balance_low,
            quote_outstanding,
            quote_pending_sponsored_gas,
            quote_rolling_loss_gwei,
            storage_degraded,
            exit_payloads_dropped_total,
            exit_lane_inflight,
            event_bus_subscriber_lag_total,
            cover_traffic_generated_total,
            cover_traffic_errors_total,
            cover_traffic_degraded,
            cover_loop_sent_total,
            cover_loop_returned_total,
            cover_loop_lost_total,
            cover_loop_outcomes_total,
            cover_loop_rtt_seconds,
            p2p_admission_total,
            topology_reconcile_total,
            topology_membership_verified,
            rpc_requests_total,
            rpc_rate_limited_total,
            rpc_ssrf_blocks_total,
            http_proxy_requests_total,
            fec_operations_total,
            response_pack_total,
            exit_payloads_dispatched_total,
            exit_reassembly_total,
            reassembly_conflict_total,
            exit_reassembler_pending,
            topology_nodes,
            topology_bootstrap_total,
            process_resident_memory_bytes,
            process_virtual_memory_bytes,
            process_open_fds,
            build_info,
            health_status,
            uptime_seconds,
        }
    }

    pub fn peer_connected(&self) {
        self.active_peers.inc();
    }

    pub fn peer_disconnected(&self) {
        self.active_peers.dec();
    }

    pub fn record_mix_delay(&self, delay_secs: f64) {
        self.mix_delay_seconds.observe(delay_secs);
    }

    #[must_use]
    pub fn get_registry(&self) -> Arc<Mutex<Registry>> {
        self.registry.clone()
    }

    /// Adds a capability to the `capabilities` list in `/metrics/json`.
    pub fn add_capability(&self, capability: &str) {
        self.capabilities.lock().insert(capability.to_string());
    }

    /// Capabilities reported in `/metrics/json`, sorted.
    #[must_use]
    pub fn capabilities(&self) -> Vec<String> {
        self.capabilities.lock().iter().cloned().collect()
    }

    /// Flat JSON for dashboard indexers (labeled metrics flattened by label value).
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let fc =
            |family: &Family<Vec<(String, String)>, Counter>, labels: &[(&str, &str)]| -> u64 {
                let label_set: Vec<(String, String)> = labels
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect();
                family.get_or_create(&label_set).get()
            };

        let fg = |family: &Family<Vec<(String, String)>, Gauge<i64, AtomicI64>>,
                  labels: &[(&str, &str)]|
         -> i64 {
            let label_set: Vec<(String, String)> = labels
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect();
            family.get_or_create(&label_set).get()
        };

        let fc0 = |family: &Family<Vec<(String, String)>, Counter>| -> u64 {
            family.get_or_create(&vec![]).get()
        };

        let mut m = serde_json::Map::new();

        m.insert("capabilities".into(), self.capabilities().into());

        m.insert("packetsReceived".into(), fc0(&self.packets_received).into());
        m.insert(
            "packetsForwarded".into(),
            fc0(&self.packets_forwarded).into(),
        );
        m.insert(
            "dummyPacketsDropped".into(),
            fc0(&self.dummy_packets_dropped).into(),
        );

        m.insert("activePeers".into(), self.active_peers.get().into());
        m.insert(
            "peersConnectedTotal".into(),
            fc0(&self.peers_connected).into(),
        );
        m.insert(
            "peersDisconnectedTotal".into(),
            fc0(&self.peers_disconnected).into(),
        );

        m.insert(
            "workerQueueDepth".into(),
            self.relayer_worker_queue_depth.get().into(),
        );
        m.insert(
            "mixQueueDepth".into(),
            self.relayer_mix_queue_depth.get().into(),
        );
        m.insert(
            "egressQueueDepth".into(),
            self.relayer_egress_queue_depth.get().into(),
        );
        m.insert(
            "ingestDropped".into(),
            fc0(&self.ingest_dropped_total).into(),
        );
        m.insert(
            "ingestDroppedBackpressure".into(),
            fc(&self.ingest_dropped_total, &[("reason", "backpressure")]).into(),
        );
        m.insert(
            "ingestDroppedPow".into(),
            fc(&self.ingest_dropped_total, &[("reason", "pow_invalid")]).into(),
        );
        m.insert(
            "ingestDroppedReplay".into(),
            fc(&self.ingest_dropped_total, &[("reason", "replay")]).into(),
        );
        m.insert(
            "egressForwarded".into(),
            fc(&self.egress_routed_total, &[("type", "forward")]).into(),
        );
        m.insert(
            "egressExited".into(),
            fc(&self.egress_routed_total, &[("type", "exit")]).into(),
        );

        m.insert(
            "sphinxErrors".into(),
            fc0(&self.sphinx_processing_errors_total).into(),
        );

        m.insert(
            "replayNew".into(),
            fc(&self.replay_checks_total, &[("result", "new")]).into(),
        );
        m.insert(
            "replayDuplicate".into(),
            fc(&self.replay_checks_total, &[("result", "duplicate")]).into(),
        );
        m.insert(
            "replayBloomRotations".into(),
            self.replay_bloom_rotations_total.get().into(),
        );

        m.insert(
            "coverLoopGenerated".into(),
            fc(&self.cover_traffic_generated_total, &[("type", "loop")]).into(),
        );
        m.insert(
            "coverDropGenerated".into(),
            fc(&self.cover_traffic_generated_total, &[("type", "drop")]).into(),
        );
        m.insert(
            "coverLoopDegraded".into(),
            fg(&self.cover_traffic_degraded, &[("type", "loop")]).into(),
        );
        m.insert(
            "coverDropDegraded".into(),
            fg(&self.cover_traffic_degraded, &[("type", "drop")]).into(),
        );
        m.insert(
            "coverErrors".into(),
            fc0(&self.cover_traffic_errors_total).into(),
        );
        m.insert(
            "coverLoopSent".into(),
            fc(&self.cover_loop_outcomes_total, &[("outcome", "sent")]).into(),
        );
        m.insert(
            "coverLoopReturned".into(),
            fc(&self.cover_loop_outcomes_total, &[("outcome", "returned")]).into(),
        );
        m.insert(
            "coverLoopLost".into(),
            fc(&self.cover_loop_outcomes_total, &[("outcome", "lost")]).into(),
        );
        m.insert(
            "topologyMembershipVerified".into(),
            self.topology_membership_verified.get().into(),
        );

        m.insert(
            "cumulativeAuthorizedRevenueUsd".into(),
            serde_json::Value::from(
                self.cumulative_authorized_revenue_usd.get() as f64 / 1_000_000.0,
            ),
        );
        m.insert(
            "cumulativeCostUsd".into(),
            serde_json::Value::from(self.cumulative_cost_usd.get() as f64 / 1_000_000.0),
        );
        m.insert(
            "cumulativeMaximumCostUsd".into(),
            serde_json::Value::from(self.cumulative_maximum_cost_usd.get() as f64 / 1_000_000.0),
        );
        m.insert(
            "profitableCount".into(),
            fc(
                &self.profitability_outcomes_total,
                &[("result", "accepted")],
            )
            .into(),
        );
        m.insert(
            "unprofitableCount".into(),
            fc(
                &self.profitability_outcomes_total,
                &[("result", "UNPROFITABLE")],
            )
            .into(),
        );

        m.insert("ethPending".into(), self.eth_tx_pending.get().into());
        m.insert(
            "ethSubmissionBlocked".into(),
            self.eth_submission_blocked.get().into(),
        );
        m.insert(
            "exitPayloadsDropped".into(),
            EXIT_LANES
                .iter()
                .flat_map(|lane| EXIT_DROP_REASONS.iter().map(move |reason| (*lane, *reason)))
                .map(|(lane, reason)| {
                    fc(
                        &self.exit_payloads_dropped_total,
                        &[("lane", lane), ("reason", reason)],
                    )
                })
                .sum::<u64>()
                .into(),
        );
        m.insert(
            "ethSimulationReverts".into(),
            fc0(&self.eth_simulation_reverts).into(),
        );
        m.insert(
            "ethUnprofitableDrops".into(),
            fc0(&self.eth_unprofitable_drops).into(),
        );
        m.insert(
            "ethTransactionsSubmitted".into(),
            ["paid", "paid_v2", "broadcast"]
                .iter()
                .map(|kind| fc(&self.eth_transactions_submitted, &[("type", kind)]))
                .sum::<u64>()
                .into(),
        );

        m.insert(
            "chainLastBlock".into(),
            self.chain_observer_last_block.get().into(),
        );
        m.insert(
            "chainErrors".into(),
            fc(&self.chain_observer_errors_total, &[("type", "rpc_error")]).into(),
        );
        // Sum all labeled variants of chain events
        let chain_events_sum = fc(
            &self.chain_events_processed_total,
            &[("type", "relayer_registered")],
        ) + fc(
            &self.chain_events_processed_total,
            &[("type", "privileged_registered")],
        ) + fc(
            &self.chain_events_processed_total,
            &[("type", "relayer_removed")],
        ) + fc(&self.chain_events_processed_total, &[("type", "unstaked")]);
        m.insert("chainEventsProcessed".into(), chain_events_sum.into());

        // Per-handler breakdown (labeled counter -- fc0 reads empty labels which is always 0)
        let exit_echo = fc(&self.exit_payloads_dispatched_total, &[("handler", "echo")]);
        let exit_http = fc(&self.exit_payloads_dispatched_total, &[("handler", "http")]);
        let exit_rpc = fc(&self.exit_payloads_dispatched_total, &[("handler", "rpc")]);
        let exit_broadcast = fc(
            &self.exit_payloads_dispatched_total,
            &[("handler", "broadcast")],
        );
        let exit_ethereum = fc(
            &self.exit_payloads_dispatched_total,
            &[("handler", "ethereum")],
        );
        let exit_traffic = fc(
            &self.exit_payloads_dispatched_total,
            &[("handler", "traffic")],
        );
        m.insert(
            "exitPayloadsDispatched".into(),
            (exit_echo + exit_http + exit_rpc + exit_broadcast + exit_ethereum + exit_traffic)
                .into(),
        );
        m.insert("exitEcho".into(), exit_echo.into());
        m.insert("exitHttp".into(), exit_http.into());
        m.insert("exitRpc".into(), exit_rpc.into());
        m.insert("exitBroadcast".into(), exit_broadcast.into());
        m.insert("exitEthereum".into(), exit_ethereum.into());
        m.insert("exitTraffic".into(), exit_traffic.into());
        m.insert(
            "exitReassemblerPending".into(),
            self.exit_reassembler_pending.get().into(),
        );

        m.insert(
            "httpProxySuccess".into(),
            fc(&self.http_proxy_requests_total, &[("result", "success")]).into(),
        );
        m.insert(
            "httpProxyError".into(),
            fc(&self.http_proxy_requests_total, &[("result", "error")]).into(),
        );
        m.insert(
            "httpProxySsrfBlocked".into(),
            fc(
                &self.http_proxy_requests_total,
                &[("result", "ssrf_blocked")],
            )
            .into(),
        );

        m.insert(
            "rpcRateLimited".into(),
            self.rpc_rate_limited_total.get().into(),
        );
        m.insert(
            "rpcSsrfBlocked".into(),
            self.rpc_ssrf_blocks_total.get().into(),
        );

        m.insert(
            "fecEncodeSuccess".into(),
            fc(
                &self.fec_operations_total,
                &[("type", "encode"), ("result", "success")],
            )
            .into(),
        );
        m.insert(
            "fecEncodeError".into(),
            fc(
                &self.fec_operations_total,
                &[("type", "encode"), ("result", "error")],
            )
            .into(),
        );
        m.insert(
            "fecDecodeSuccess".into(),
            fc(
                &self.fec_operations_total,
                &[("type", "decode"), ("result", "success")],
            )
            .into(),
        );
        m.insert(
            "fecDecodeError".into(),
            fc(
                &self.fec_operations_total,
                &[("type", "decode"), ("result", "error")],
            )
            .into(),
        );

        m.insert(
            "responsePackSuccess".into(),
            fc(&self.response_pack_total, &[("result", "success")]).into(),
        );
        m.insert(
            "responsePackError".into(),
            fc(&self.response_pack_total, &[("result", "error")]).into(),
        );

        m.insert(
            "ingressResponseBuffer".into(),
            self.ingress_response_buffer_entries.get().into(),
        );
        m.insert(
            "ingressResponsesPruned".into(),
            self.ingress_responses_pruned_total.get().into(),
        );

        m.insert(
            "p2pRateLimitAllowed".into(),
            fc(&self.p2p_rate_limit_total, &[("result", "allowed")]).into(),
        );
        m.insert(
            "p2pRateLimitDenied".into(),
            fc(&self.p2p_rate_limit_total, &[("result", "denied")]).into(),
        );
        m.insert(
            "p2pRateLimitDisconnects".into(),
            self.p2p_rate_limit_disconnects_total.get().into(),
        );

        m.insert(
            "topologyLayer0".into(),
            fg(&self.topology_nodes, &[("layer", "0")]).into(),
        );
        m.insert(
            "topologyLayer1".into(),
            fg(&self.topology_nodes, &[("layer", "1")]).into(),
        );
        m.insert(
            "topologyLayer2".into(),
            fg(&self.topology_nodes, &[("layer", "2")]).into(),
        );

        m.insert(
            "oracleFetchSuccess".into(),
            fc(&self.oracle_fetch_total, &[("result", "success")]).into(),
        );
        m.insert(
            "oracleFetchError".into(),
            fc(&self.oracle_fetch_total, &[("result", "error")]).into(),
        );
        m.insert(
            "oracleFetchStale".into(),
            fc(&self.oracle_fetch_total, &[("result", "stale")]).into(),
        );

        m.insert("eventBusLag".into(), self.event_bus_lag_total.get().into());
        m.insert(
            "eventBusPacketReceived".into(),
            fc(&self.event_bus_events_total, &[("type", "packet_received")]).into(),
        );
        m.insert(
            "eventBusSendPacket".into(),
            fc(&self.event_bus_events_total, &[("type", "send_packet")]).into(),
        );
        m.insert(
            "eventBusPacketProcessed".into(),
            fc(
                &self.event_bus_events_total,
                &[("type", "packet_processed")],
            )
            .into(),
        );
        m.insert(
            "eventBusPayloadDecrypted".into(),
            fc(
                &self.event_bus_events_total,
                &[("type", "payload_decrypted")],
            )
            .into(),
        );
        m.insert(
            "eventBusPeerConnected".into(),
            fc(&self.event_bus_events_total, &[("type", "peer_connected")]).into(),
        );
        m.insert(
            "eventBusPeerDisconnected".into(),
            fc(
                &self.event_bus_events_total,
                &[("type", "peer_disconnected")],
            )
            .into(),
        );
        m.insert(
            "eventBusPublishErrors".into(),
            fc0(&self.event_bus_publish_errors_total).into(),
        );

        m.insert("uptimeSeconds".into(), self.uptime_seconds.get().into());
        m.insert("healthStatus".into(), self.health_status.get().into());
        m.insert(
            "processMem".into(),
            self.process_resident_memory_bytes.get().into(),
        );
        m.insert(
            "processVmem".into(),
            self.process_virtual_memory_bytes.get().into(),
        );
        m.insert("openFds".into(), self.process_open_fds.get().into());
        m.insert(
            "nodeStartTime".into(),
            self.node_start_time_seconds.get().into(),
        );

        serde_json::Value::Object(m)
    }
}

impl Default for MetricsService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_projection_uses_typed_profitability_labels() {
        let metrics = MetricsService::new();
        metrics
            .profitability_outcomes_total
            .get_or_create(&vec![("result".into(), "accepted".into())])
            .inc();
        metrics
            .profitability_outcomes_total
            .get_or_create(&vec![("result".into(), "UNPROFITABLE".into())])
            .inc();
        metrics.cumulative_maximum_cost_usd.inc_by(1_250_000);

        let projection = metrics.to_json();
        assert_eq!(projection["profitableCount"], 1);
        assert_eq!(projection["unprofitableCount"], 1);
        assert_eq!(projection["cumulativeMaximumCostUsd"], 1.25);
    }

    #[test]
    fn dashboard_projection_sums_submissions_and_exit_drops() {
        let metrics = MetricsService::new();
        for kind in ["paid_v2", "paid_v2", "broadcast"] {
            metrics
                .eth_transactions_submitted
                .get_or_create(&vec![("type".into(), kind.into())])
                .inc();
        }
        metrics
            .exit_payloads_dropped_total
            .get_or_create(&vec![
                ("lane".into(), "quote".into()),
                ("reason".into(), "queue_full".into()),
            ])
            .inc();
        metrics.eth_submission_blocked.set(1);

        let projection = metrics.to_json();

        assert_eq!(projection["ethTransactionsSubmitted"], 3);
        assert_eq!(projection["exitPayloadsDropped"], 1);
        assert_eq!(projection["ethSubmissionBlocked"], 1);
    }

    #[test]
    fn new_counters_are_not_double_suffixed() {
        let metrics = MetricsService::new();
        metrics
            .paid_outcomes_total
            .get_or_create(&vec![
                ("kind".into(), "quote".into()),
                ("result".into(), "issued".into()),
                ("code".into(), "none".into()),
            ])
            .inc();
        let mut encoded = String::new();
        prometheus_client::encoding::text::encode(&mut encoded, &metrics.get_registry().lock())
            .unwrap_or_default();
        assert!(encoded.contains("nox_paid_outcomes_total{"));
        assert!(!encoded.contains("nox_paid_outcomes_total_total"));
        assert!(!encoded.contains("nox_exit_payloads_dropped_total_total"));
        assert!(!encoded.contains("nox_event_bus_subscriber_lagged_total_total"));
    }

    #[test]
    fn wire_id_counters_have_their_documented_names() {
        let metrics = MetricsService::new();
        metrics
            .wire_ids_total
            .get_or_create(&vec![("kind".into(), "fresh".into())])
            .inc();
        metrics
            .wire_handle_dropped_total
            .get_or_create(&vec![("reason".into(), "unknown_layer".into())])
            .inc();
        let mut encoded = String::new();
        prometheus_client::encoding::text::encode(&mut encoded, &metrics.get_registry().lock())
            .unwrap_or_default();
        assert!(encoded.contains("nox_wire_ids_total{kind=\"fresh\"} 1"));
        assert!(encoded.contains("nox_wire_handle_dropped_total{reason=\"unknown_layer\"} 1"));
    }

    #[test]
    fn capabilities_are_reported_in_json() {
        let metrics = MetricsService::new();
        assert_eq!(metrics.to_json()["capabilities"], serde_json::json!([]));
        metrics.add_capability("surb_v2");
        metrics.add_capability("paid_v2");
        metrics.add_capability("surb_v2");
        assert_eq!(
            metrics.to_json()["capabilities"],
            serde_json::json!(["paid_v2", "surb_v2"])
        );
    }
}
