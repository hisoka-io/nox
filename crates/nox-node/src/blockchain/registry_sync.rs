//! Periodic reconciliation of the node set against `NoxRegistry`.
//!
//! The chain observer applies registry logs as they arrive, but an update can
//! still be lost (a full event bus, a profile read that failed). The reconciler
//! re-reads every known member's profile at the observer's topology block and
//! compares the node set with `topologyFingerprint()` and `relayerCount()`.
//! While both match, membership counts as verified, which is what P2P admission
//! waits for before refusing peers outside the registry.

use crate::blockchain::executor::build_ethers_http1_provider;
use crate::blockchain::observer::{
    read_registry_profile, NoxRegistryContract, ObservedChain, PrivilegedRelayerRegisteredFilter,
    RelayerRegisteredFilter,
};
use crate::config::NoxConfig;
use crate::services::network_manager::{RegistryProfile, TopologyManager};
use crate::telemetry::metrics::MetricsService;
use ethers::contract::EthEvent;
use ethers::prelude::*;
use nox_core::traits::InfrastructureError;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Blocks per `eth_getLogs` call during a membership discovery scan.
const DISCOVERY_BLOCK_RANGE: u64 = 10_000;
/// Minimum spacing between two discovery scans (each walks the whole registry history).
const DISCOVERY_MIN_INTERVAL: Duration = Duration::from_mins(10);
/// Retry delay while the chain observer has no position yet.
const NOT_POSITIONED_RETRY: Duration = Duration::from_secs(15);
/// Passes run back to back when registry logs keep landing during the reads.
const MAX_ATTEMPTS: usize = 3;
/// Consecutive failed passes before membership is marked unverified, so one
/// transient RPC error does not toggle enforcement.
const ERRORS_BEFORE_UNVERIFIED: u32 = 2;

/// Result of one reconcile pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileOutcome {
    /// The observer has not scanned any block yet.
    NotPositioned,
    /// Node set and profiles already matched the registry.
    InSync,
    /// Profiles or members were corrected and the node set now matches.
    Repaired,
    /// The node set still differs from the registry.
    Mismatch,
    /// Registry logs kept arriving while profiles were read; nothing was
    /// applied and the verification state was left as it was.
    Superseded,
}

impl ReconcileOutcome {
    fn label(self) -> &'static str {
        match self {
            Self::NotPositioned => "not_positioned",
            Self::InSync => "in_sync",
            Self::Repaired => "repaired",
            Self::Mismatch => "mismatch",
            Self::Superseded => "superseded",
        }
    }
}

pub struct RegistryReconciler<M: Middleware = Provider<Http>> {
    contract: NoxRegistryContract<M>,
    topology: Arc<TopologyManager>,
    observed: Arc<ObservedChain>,
    interval: Duration,
    chain_start_block: u64,
    metrics: MetricsService,
    cancel_token: CancellationToken,
    last_discovery: Option<Instant>,
}

impl RegistryReconciler<Provider<Http>> {
    pub fn new(
        config: &NoxConfig,
        topology: Arc<TopologyManager>,
        observed: Arc<ObservedChain>,
        metrics: MetricsService,
    ) -> Result<Self, InfrastructureError> {
        let provider = build_ethers_http1_provider(&config.eth_rpc_url)?;
        let registry = config
            .registry_contract_address
            .parse::<Address>()
            .map_err(|e| {
                InfrastructureError::Blockchain(format!("Invalid Registry Address: {e}"))
            })?;
        let contract = NoxRegistryContract::new(registry, Arc::new(provider));
        Ok(Self::with_contract(
            contract,
            topology,
            observed,
            metrics,
            Duration::from_secs(config.topology_reconcile_interval_secs.max(1)),
            config.chain_start_block,
        ))
    }
}

impl<M: Middleware + 'static> RegistryReconciler<M> {
    pub(crate) fn with_contract(
        contract: NoxRegistryContract<M>,
        topology: Arc<TopologyManager>,
        observed: Arc<ObservedChain>,
        metrics: MetricsService,
        interval: Duration,
        chain_start_block: u64,
    ) -> Self {
        Self {
            contract,
            topology,
            observed,
            interval,
            chain_start_block,
            metrics,
            cancel_token: CancellationToken::new(),
            last_discovery: None,
        }
    }

    #[must_use]
    pub fn with_cancel_token(mut self, token: CancellationToken) -> Self {
        self.cancel_token = token;
        self
    }

    pub async fn run(mut self) {
        info!(
            interval_secs = self.interval.as_secs(),
            "Registry reconciler started"
        );
        let resync = self.topology.resync_signal();
        let mut wait = Duration::ZERO;
        let mut consecutive_errors = 0u32;
        loop {
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = resync.notified() => {
                    debug!("Registry resync requested");
                }
                () = self.cancel_token.cancelled() => {
                    info!("Registry reconciler shutting down (cancellation token).");
                    return;
                }
            }
            let result = self.reconcile_once().await;
            if result.is_ok() {
                consecutive_errors = 0;
            }
            wait = match result {
                Ok(ReconcileOutcome::NotPositioned | ReconcileOutcome::Superseded) => {
                    NOT_POSITIONED_RETRY
                }
                Ok(_) => self.interval,
                Err(e) => {
                    consecutive_errors = consecutive_errors.saturating_add(1);
                    if consecutive_errors >= ERRORS_BEFORE_UNVERIFIED {
                        warn!(error = %e, "Registry reconcile failed; membership left unverified");
                        self.topology.set_membership_verified(false);
                        self.metrics.topology_membership_verified.set(0);
                    } else {
                        warn!(error = %e, "Registry reconcile failed; retrying");
                    }
                    self.metrics
                        .topology_reconcile_total
                        .get_or_create(&vec![("result".into(), "error".into())])
                        .inc();
                    NOT_POSITIONED_RETRY.min(self.interval)
                }
            };
        }
    }

    /// One pass: refresh every member's profile, then compare the node set with
    /// the registry. All reads are pinned to one block at or after the newest
    /// registry log the observer has seen. If the observer records a newer log
    /// while the profiles are read, nothing is applied and the pass runs again
    /// at the new position, so a stale read never overrides a newer log.
    pub async fn reconcile_once(&mut self) -> Result<ReconcileOutcome, InfrastructureError> {
        for _ in 0..MAX_ATTEMPTS {
            if let Some(outcome) = self.reconcile_at_current_position().await? {
                return Ok(outcome);
            }
        }
        debug!("Registry logs kept arriving during reconcile; retrying later");
        self.metrics
            .topology_reconcile_total
            .get_or_create(&vec![(
                "result".into(),
                ReconcileOutcome::Superseded.label().into(),
            )])
            .inc();
        Ok(ReconcileOutcome::Superseded)
    }

    /// `None` when a newer registry log arrived before the reads were applied.
    async fn reconcile_at_current_position(
        &mut self,
    ) -> Result<Option<ReconcileOutcome>, InfrastructureError> {
        // Members first, then the block: every member in the list was added by
        // a log the observer recorded at or before `block`.
        let members = self.topology.member_addresses();
        // Trails the head a little (never behind the newest registry log), so
        // load-balanced providers that lag by a few blocks can serve the reads.
        let block = self.observed.topology_block();
        if block == 0 {
            return Ok(Some(ReconcileOutcome::NotPositioned));
        }

        let reads = self.read_profiles(members, block).await?;
        let Some(mut repaired) = self.apply_reads(block, reads).await else {
            return Ok(None);
        };
        let mut in_sync = self.matches_chain(block).await?;
        if !in_sync && self.discovery_due() {
            let Some(added) = self.discover_members(block).await? else {
                return Ok(None);
            };
            repaired |= added;
            in_sync = self.matches_chain(block).await?;
        }

        // Logs the observer applied after the reads were applied are newer;
        // run again at the new position so the comparison uses them too.
        if self.superseded(block) {
            self.topology.request_resync();
        }

        let outcome = match (in_sync, repaired) {
            (true, false) => ReconcileOutcome::InSync,
            (true, true) => ReconcileOutcome::Repaired,
            (false, _) => ReconcileOutcome::Mismatch,
        };
        self.topology.set_membership_verified(in_sync);
        self.metrics
            .topology_membership_verified
            .set(i64::from(in_sync));
        self.metrics
            .topology_reconcile_total
            .get_or_create(&vec![("result".into(), outcome.label().into())])
            .inc();
        match outcome {
            ReconcileOutcome::Repaired => {
                info!(block, "Registry reconcile repaired the node set");
            }
            ReconcileOutcome::Mismatch => warn!(
                block,
                members = self.topology.member_count(),
                "Node set does not match registry fingerprint/count; P2P admission stays permissive"
            ),
            _ => debug!(block, "Registry reconcile: in sync"),
        }
        Ok(Some(outcome))
    }

    /// The observer recorded a registry log newer than `block`.
    fn superseded(&self, block: u64) -> bool {
        self.observed.last_registry_log_block() > block
    }

    /// Reads the profile of each address at `block` (`None` = not registered).
    async fn read_profiles(
        &self,
        addresses: Vec<String>,
        block: u64,
    ) -> Result<Vec<(String, Option<RegistryProfile>)>, InfrastructureError> {
        let mut reads = Vec::with_capacity(addresses.len());
        for address in addresses {
            let relayer = address.parse::<Address>().map_err(|e| {
                InfrastructureError::Blockchain(format!("Invalid member address {address}: {e}"))
            })?;
            let profile = read_registry_profile(&self.contract, relayer, Some(block)).await?;
            reads.push((address, profile));
        }
        Ok(reads)
    }

    /// Applies profiles read at `block`; an unregistered address is removed.
    /// Returns `None` without applying anything if a newer registry log was
    /// recorded meanwhile, otherwise whether anything changed.
    async fn apply_reads(
        &self,
        block: u64,
        reads: Vec<(String, Option<RegistryProfile>)>,
    ) -> Option<bool> {
        if self.superseded(block) {
            return None;
        }
        let mut changed = false;
        for (address, profile) in reads {
            if let Some(profile) = profile {
                changed |= self.topology.apply_profile(profile).await;
            } else {
                info!(address = %address, block, "Member no longer registered; removing");
                self.topology.handle_removal(address).await;
                changed = true;
            }
        }
        Some(changed)
    }

    async fn matches_chain(&self, block: u64) -> Result<bool, InfrastructureError> {
        let at = BlockId::Number(BlockNumber::Number(block.into()));
        let fingerprint = self
            .contract
            .topology_fingerprint()
            .block(at)
            .call()
            .await
            .map_err(|e| {
                InfrastructureError::Blockchain(format!("topologyFingerprint() at {block}: {e}"))
            })?;
        let count = self
            .contract
            .relayer_count()
            .block(at)
            .call()
            .await
            .map_err(|e| {
                InfrastructureError::Blockchain(format!("relayerCount() at {block}: {e}"))
            })?;
        Ok(fingerprint == self.topology.get_current_fingerprint()
            && count == U256::from(self.topology.member_count()))
    }

    fn discovery_due(&self) -> bool {
        self.chain_start_block > 0
            && self
                .last_discovery
                .is_none_or(|at| at.elapsed() >= DISCOVERY_MIN_INTERVAL)
    }

    /// Finds members the node never learned about: walks registration logs from
    /// `chain_start_block` and reads the current profile of every unknown
    /// address. Only current state is applied, never historical event data.
    /// `None` when a newer registry log arrived before the reads were applied.
    async fn discover_members(&mut self, block: u64) -> Result<Option<bool>, InfrastructureError> {
        self.last_discovery = Some(Instant::now());
        let topics = vec![
            RelayerRegisteredFilter::signature(),
            PrivilegedRelayerRegisteredFilter::signature(),
        ];
        let mut candidates = HashSet::new();
        let mut from = self.chain_start_block;
        while from <= block {
            let to = block.min(from.saturating_add(DISCOVERY_BLOCK_RANGE - 1));
            let filter = Filter::new()
                .address(self.contract.address())
                .topic0(topics.clone())
                .from_block(from)
                .to_block(to);
            let logs = self
                .contract
                .client()
                .get_logs(&filter)
                .await
                .map_err(|e| {
                    InfrastructureError::Blockchain(format!(
                        "registration log scan {from}..={to}: {e}"
                    ))
                })?;
            for log in logs {
                if let Some(topic) = log.topics.get(1) {
                    candidates.insert(Address::from(*topic));
                }
            }
            from = to + 1;
        }

        let known: HashSet<String> = self.topology.member_addresses().into_iter().collect();
        let unknown: Vec<String> = candidates
            .into_iter()
            .map(|relayer| format!("{relayer:?}"))
            .filter(|address| !known.contains(address))
            .collect();
        // Only registered nodes are applied here; removals are left to the
        // member refresh, which reads the same addresses on the next pass.
        let found: Vec<_> = self
            .read_profiles(unknown, block)
            .await?
            .into_iter()
            .filter(|(_, profile)| profile.is_some())
            .collect();
        for (address, _) in &found {
            info!(address = %address, "Discovered registered member missing from topology");
        }
        Ok(self.apply_reads(block, found).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::{event_bus::TokioEventBus, storage::SledRepository};
    use ethers::abi::Token;
    use nox_core::IEventSubscriber;

    const A: &str = "0x74486dc1ac551e5cd3f4eef80727cc9d50d3abe9";
    const B: &str = "0x8c9fb3e9fe537067c8430480f80a4a5b9a12be1a";
    const BLOCK: u64 = 1_000;

    struct Chain {
        mock: MockProvider,
        reconciler: RegistryReconciler<Provider<MockProvider>>,
        topology: Arc<TopologyManager>,
        observed: Arc<ObservedChain>,
        _dir: tempfile::TempDir,
    }

    fn chain() -> Chain {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(SledRepository::new(dir.path()).expect("storage"));
        let bus = Arc::new(TokioEventBus::new(8));
        let subscriber: Arc<dyn IEventSubscriber> = bus;
        let topology = Arc::new(TopologyManager::new(storage, subscriber, None));
        let observed = Arc::new(ObservedChain::default());
        observed.resume_at(BLOCK);
        let (provider, mock) = Provider::mocked();
        let contract = NoxRegistryContract::new(Address::zero(), Arc::new(provider));
        let reconciler = RegistryReconciler::with_contract(
            contract,
            topology.clone(),
            observed.clone(),
            MetricsService::new(),
            Duration::from_mins(1),
            0,
        );
        Chain {
            mock,
            reconciler,
            topology,
            observed,
            _dir: dir,
        }
    }

    fn profile(address: &str, url: &str) -> RegistryProfile {
        RegistryProfile {
            address: address.to_string(),
            sphinx_key: "11".repeat(32),
            url: url.to_string(),
            ingress_url: Some("https://nox.example".to_string()),
            metadata_url: None,
            stake: "7".to_string(),
            role: 2,
            frozen: false,
        }
    }

    fn relayers_output(profile: Option<&RegistryProfile>) -> Bytes {
        let (key, url, ingress, stake, frozen, registered) = match profile {
            Some(p) => (
                hex::decode(&p.sphinx_key).expect("hex"),
                p.url.clone(),
                p.ingress_url.clone().unwrap_or_default(),
                U256::from_dec_str(&p.stake).expect("stake"),
                p.frozen,
                true,
            ),
            None => (
                vec![0; 32],
                String::new(),
                String::new(),
                U256::zero(),
                false,
                false,
            ),
        };
        ethers::abi::encode(&[
            Token::FixedBytes(key),
            Token::String(url),
            Token::String(ingress),
            Token::String(String::new()),
            Token::Uint(stake),
            Token::Uint(U256::zero()),
            Token::Bool(registered),
            Token::Uint(U256::from(u8::from(registered))),
            Token::Bool(frozen),
        ])
        .into()
    }

    fn uint(value: u64) -> Bytes {
        ethers::abi::encode(&[Token::Uint(U256::from(value))]).into()
    }

    fn fingerprint(addresses: &[&str]) -> Bytes {
        let owned: Vec<String> = addresses.iter().map(ToString::to_string).collect();
        ethers::abi::encode(&[Token::FixedBytes(
            TopologyManager::compute_topology_fingerprint(&owned).to_vec(),
        )])
        .into()
    }

    /// Queues eth_call results in call order (the mock pops the newest first).
    fn respond(mock: &MockProvider, results: Vec<Bytes>) {
        for result in results.into_iter().rev() {
            mock.push::<Bytes, _>(result).expect("push");
        }
    }

    #[tokio::test]
    async fn matching_registry_marks_membership_verified() {
        let mut chain = chain();
        let member = profile(A, "/ip4/10.0.0.1/tcp/15000");
        chain.topology.apply_profile(member.clone()).await;
        respond(
            &chain.mock,
            vec![
                relayers_output(Some(&member)),
                uint(2),
                fingerprint(&[A]),
                uint(1),
            ],
        );
        let outcome = chain.reconciler.reconcile_once().await.expect("reconcile");
        assert_eq!(outcome, ReconcileOutcome::InSync);
        assert!(chain.topology.membership_verified());
    }

    #[tokio::test]
    async fn stale_profile_and_freeze_are_repaired_from_the_registry() {
        let mut chain = chain();
        chain
            .topology
            .apply_profile(profile(A, "/ip4/10.0.0.1/tcp/15000"))
            .await;
        let mut on_chain = profile(A, "/ip4/10.0.0.9/tcp/15000");
        on_chain.frozen = true;
        respond(
            &chain.mock,
            vec![
                relayers_output(Some(&on_chain)),
                uint(2),
                fingerprint(&[A]),
                uint(1),
            ],
        );
        let outcome = chain.reconciler.reconcile_once().await.expect("reconcile");
        assert_eq!(outcome, ReconcileOutcome::Repaired);
        assert_eq!(
            chain.topology.lookup_by_address(A).expect("member").url,
            "/ip4/10.0.0.9/tcp/15000"
        );
        assert!(chain.topology.is_frozen(A));
        assert!(chain.topology.membership_verified());
    }

    #[tokio::test]
    async fn deregistered_member_is_removed() {
        let mut chain = chain();
        chain
            .topology
            .apply_profile(profile(A, "/ip4/10.0.0.1/tcp/15000"))
            .await;
        let b = profile(B, "/ip4/10.0.0.2/tcp/15000");
        chain.topology.apply_profile(b.clone()).await;
        // Member order follows the address index; answer per address.
        let mut results = Vec::new();
        for address in chain.topology.member_addresses() {
            if address == A {
                results.push(relayers_output(None));
            } else {
                results.push(relayers_output(Some(&b)));
                results.push(uint(2));
            }
        }
        results.push(fingerprint(&[B]));
        results.push(uint(1));
        respond(&chain.mock, results);

        let outcome = chain.reconciler.reconcile_once().await.expect("reconcile");
        assert_eq!(outcome, ReconcileOutcome::Repaired);
        assert!(chain.topology.lookup_by_address(A).is_none());
        assert!(chain.topology.membership_verified());
    }

    #[tokio::test]
    async fn unknown_member_leaves_membership_unverified() {
        let mut chain = chain();
        let member = profile(A, "/ip4/10.0.0.1/tcp/15000");
        chain.topology.apply_profile(member.clone()).await;
        chain.topology.set_membership_verified(true);
        // The registry has a second node this one never saw.
        respond(
            &chain.mock,
            vec![
                relayers_output(Some(&member)),
                uint(2),
                fingerprint(&[A, B]),
                uint(2),
            ],
        );
        let outcome = chain.reconciler.reconcile_once().await.expect("reconcile");
        assert_eq!(outcome, ReconcileOutcome::Mismatch);
        assert!(!chain.topology.membership_verified());
    }

    #[tokio::test]
    async fn registration_applied_during_the_reads_is_not_undone() {
        let chain = chain();
        // B registered at BLOCK + 1; the observer recorded and applied that log
        // after the member list was taken, while its profile was read at BLOCK.
        let b = profile(B, "/ip4/10.0.0.2/tcp/15000");
        chain.topology.apply_profile(b).await;
        respond(&chain.mock, vec![relayers_output(None)]);
        let reads = chain
            .reconciler
            .read_profiles(vec![B.to_string()], BLOCK)
            .await
            .expect("read");
        assert!(reads[0].1.is_none(), "B is not registered at BLOCK");

        chain.observed.record_registry_log(BLOCK + 1);
        assert_eq!(chain.reconciler.apply_reads(BLOCK, reads).await, None);
        assert!(chain.topology.lookup_by_address(B).is_some());
    }

    #[tokio::test]
    async fn pass_reads_at_the_newest_registry_log_block() {
        let mut chain = chain();
        let member = profile(A, "/ip4/10.0.0.1/tcp/15000");
        chain.topology.apply_profile(member.clone()).await;
        // The pass reads at the newest registry log even when the head is
        // further ahead, and the result is applied because nothing newer came.
        chain.observed.scanned(BLOCK + 100);
        chain.observed.record_registry_log(BLOCK + 90);
        assert_eq!(chain.observed.topology_block(), BLOCK + 90);
        respond(
            &chain.mock,
            vec![
                relayers_output(Some(&member)),
                uint(2),
                fingerprint(&[A]),
                uint(1),
            ],
        );
        let outcome = chain.reconciler.reconcile_once().await.expect("reconcile");
        assert_eq!(outcome, ReconcileOutcome::InSync);
        assert!(chain.topology.membership_verified());
    }

    #[tokio::test]
    async fn no_chain_position_skips_the_pass() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(SledRepository::new(dir.path()).expect("storage"));
        let bus = Arc::new(TokioEventBus::new(8));
        let subscriber: Arc<dyn IEventSubscriber> = bus;
        let topology = Arc::new(TopologyManager::new(storage, subscriber, None));
        let (provider, _mock) = Provider::mocked();
        let mut reconciler = RegistryReconciler::with_contract(
            NoxRegistryContract::new(Address::zero(), Arc::new(provider)),
            topology,
            Arc::new(ObservedChain::default()),
            MetricsService::new(),
            Duration::from_mins(1),
            0,
        );
        assert_eq!(
            reconciler.reconcile_once().await.expect("reconcile"),
            ReconcileOutcome::NotPositioned
        );
    }
}
