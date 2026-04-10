use parking_lot::Mutex;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::Registry;
use std::sync::atomic::AtomicI64;
use std::sync::Arc;

/// Prometheus metrics for all NOX subsystems.
#[derive(Clone)]
pub struct MetricsService {
    registry: Arc<Mutex<Registry>>,

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
    pub tx_revenue_usd: Histogram,
    pub tx_cost_usd: Histogram,
    pub cumulative_revenue_usd: Counter,
    pub cumulative_cost_usd: Counter,
    pub eth_tx_gas_used: Histogram,
    pub eth_tx_outcomes_total: Family<Vec<(String, String)>, Counter>,
    pub chain_observer_last_block: Gauge<i64, AtomicI64>,
    pub chain_observer_errors_total: Family<Vec<(String, String)>, Counter>,
    pub chain_events_processed_total: Family<Vec<(String, String)>, Counter>,
    pub eth_tx_pending: Gauge<i64, AtomicI64>,
    pub oracle_fetch_total: Family<Vec<(String, String)>, Counter>,

    pub cover_traffic_generated_total: Family<Vec<(String, String)>, Counter>,
    pub cover_traffic_errors_total: Family<Vec<(String, String)>, Counter>,
    pub cover_traffic_degraded: Family<Vec<(String, String)>, Gauge<i64, AtomicI64>>,
    pub rpc_requests_total: Family<Vec<(String, String)>, Counter>,
    pub rpc_rate_limited_total: Counter,
    pub rpc_ssrf_blocks_total: Counter,
    pub http_proxy_requests_total: Family<Vec<(String, String)>, Counter>,
    pub fec_operations_total: Family<Vec<(String, String)>, Counter>,
    pub response_pack_total: Family<Vec<(String, String)>, Counter>,
    pub exit_payloads_dispatched_total: Family<Vec<(String, String)>, Counter>,
    pub exit_reassembly_total: Family<Vec<(String, String)>, Counter>,
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

        let tx_revenue_usd =
            Histogram::new([0.01, 0.1, 0.5, 1.0, 5.0, 10.0, 50.0, 100.0].into_iter());
        registry.register(
            "nox_tx_revenue_usd",
            "Per-transaction revenue in USD",
            tx_revenue_usd.clone(),
        );

        let tx_cost_usd = Histogram::new([0.01, 0.1, 0.5, 1.0, 5.0, 10.0, 50.0, 100.0].into_iter());
        registry.register(
            "nox_tx_cost_usd",
            "Per-transaction cost in USD",
            tx_cost_usd.clone(),
        );

        let cumulative_revenue_usd = Counter::default();
        registry.register(
            "nox_cumulative_revenue_usd",
            "Cumulative revenue in USD",
            cumulative_revenue_usd.clone(),
        );

        let cumulative_cost_usd = Counter::default();
        registry.register(
            "nox_cumulative_cost_usd",
            "Cumulative cost in USD",
            cumulative_cost_usd.clone(),
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
            tx_revenue_usd,
            tx_cost_usd,
            cumulative_revenue_usd,
            cumulative_cost_usd,
            eth_tx_gas_used,
            eth_tx_outcomes_total,
            chain_observer_last_block,
            chain_observer_errors_total,
            chain_events_processed_total,
            eth_tx_pending,
            oracle_fetch_total,
            cover_traffic_generated_total,
            cover_traffic_errors_total,
            cover_traffic_degraded,
            rpc_requests_total,
            rpc_rate_limited_total,
            rpc_ssrf_blocks_total,
            http_proxy_requests_total,
            fec_operations_total,
            response_pack_total,
            exit_payloads_dispatched_total,
            exit_reassembly_total,
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
            "cumulativeRevenueUsd".into(),
            serde_json::Value::from(self.cumulative_revenue_usd.get() as f64 / 1_000_000.0),
        );
        m.insert(
            "cumulativeCostUsd".into(),
            serde_json::Value::from(self.cumulative_cost_usd.get() as f64 / 1_000_000.0),
        );
        m.insert(
            "profitableCount".into(),
            fc(
                &self.profitability_outcomes_total,
                &[("result", "profitable")],
            )
            .into(),
        );
        m.insert(
            "unprofitableCount".into(),
            fc(
                &self.profitability_outcomes_total,
                &[("result", "unprofitable")],
            )
            .into(),
        );

        m.insert("ethPending".into(), self.eth_tx_pending.get().into());
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
            fc0(&self.eth_transactions_submitted).into(),
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
