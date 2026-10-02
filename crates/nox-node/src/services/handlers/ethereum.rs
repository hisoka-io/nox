//! Ethereum TX handler: simulate, profitability-check, and submit on-chain.

use crate::blockchain::executor::{
    build_pinned_ethers_http1_provider, public_rpc_error, ChainExecutor,
};
use crate::blockchain::tx_manager::{SubmitError, TransactionManager};
use crate::infra::storage::QuoteStoreError;
use crate::price::client::FixedPriceSource;
use crate::services::profitability::{ProfitabilityCalculator, ProfitabilityError};
use crate::services::quotes::{execution_quote_digest, u256_word, QuotePolicy};
use crate::services::security;
use crate::services::token_registry::TokenRegistry;
use crate::telemetry::metrics::MetricsService;
use async_trait::async_trait;
use ethers::prelude::*;
use ethers::utils::keccak256;
use nox_core::models::payloads::RelayerPayload;
use nox_core::traits::service::{ServiceError, ServiceHandler};
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{info, warn};

/// Max RPC timeout for broadcast operations (matches RPC handler timeout).
const BROADCAST_RPC_TIMEOUT: Duration = Duration::from_secs(15);

const DEFAULT_BROADCAST_METHOD: &str = "eth_sendRawTransaction";
pub const MAX_PUBLIC_DETAIL_BYTES: usize = 256;
const PAID_EXECUTION_SETTLED_SIGNATURE: &[u8] = b"PaidExecutionSettled(bytes32,bytes32,address,address,uint256,uint256,address,bool,uint256,bytes32)";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaidOutcome {
    Submitted {
        execution_id: nox_core::ExecutionId,
        transaction_hash: H256,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedDetail(String);

impl fmt::Display for BoundedDetail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl BoundedDetail {
    #[must_use]
    pub fn from_public_message(message: &str) -> Self {
        let sanitized: String = message
            .chars()
            .map(|character| {
                if character.is_control() {
                    ' '
                } else {
                    character
                }
            })
            .collect();
        let collapsed = sanitized.split_whitespace().collect::<Vec<_>>().join(" ");
        let mut boundary = collapsed.len().min(MAX_PUBLIC_DETAIL_BYTES);
        while !collapsed.is_char_boundary(boundary) {
            boundary -= 1;
        }
        Self(collapsed[..boundary].to_string())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PaidRejection {
    #[error("simulation rejected: {detail}")]
    Simulation { detail: BoundedDetail },
    #[error("no committed payment")]
    PaymentMissing,
    #[error("price unavailable for {asset_id}: {detail}")]
    PriceUnavailable {
        asset_id: String,
        detail: BoundedDetail,
    },
    #[error("payment value {revenue_value_e8} is below maximum cost {maximum_cost_value_e8}")]
    Unprofitable {
        revenue_value_e8: U256,
        maximum_cost_value_e8: U256,
    },
    #[error("gas plan rejected: {detail}")]
    GasPlan { detail: BoundedDetail },
    #[error("execution {execution_id:?} conflicts with transaction {transaction_hash:?}")]
    Duplicate {
        execution_id: nox_core::ExecutionId,
        transaction_hash: H256,
    },
    #[error("submission failed: {detail}")]
    Submission { detail: BoundedDetail },
}

impl PaidRejection {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Simulation { .. } => "SIMULATION",
            Self::PaymentMissing => "PAYMENT_MISSING",
            Self::PriceUnavailable { .. } => "PRICE_UNAVAILABLE",
            Self::Unprofitable { .. } => "UNPROFITABLE",
            Self::GasPlan { .. } => "GAS_PLAN",
            Self::Duplicate { .. } => "DUPLICATE",
            Self::Submission { .. } => "SUBMISSION",
        }
    }

    #[must_use]
    pub fn public_detail(&self) -> String {
        format!(
            "{}:{}",
            self.code(),
            BoundedDetail::from_public_message(&self.to_string())
        )
    }
}

/// Rejection returned for the legacy `SubmitTransaction` surface, which exit nodes
/// no longer execute. Clients must use `PaidTransactionV2`.
#[must_use]
pub fn legacy_submission_rejection() -> PaidRejection {
    PaidRejection::Submission {
        detail: BoundedDetail::from_public_message(
            "legacy SubmitTransaction is disabled; use PaidTransactionV2",
        ),
    }
}

pub struct EthereumHandler {
    chain_executor: Arc<ChainExecutor>,
    tx_manager: Arc<TransactionManager>,
    profit_calc: ProfitabilityCalculator,
    metrics: MetricsService,
    max_broadcast_tx_size: usize,
    gas_limit_buffer_bps: u32,
    initial_fee_buffer_bps: u32,
    nox_entry_point_address: Address,
    quote_policy: Option<QuotePolicy>,
}

impl EthereumHandler {
    pub fn new(
        chain_executor: Arc<ChainExecutor>,
        tx_manager: Arc<TransactionManager>,
        metrics: MetricsService,
        min_profit_margin_percent: u64,
        price_client: Arc<dyn FixedPriceSource>,
        nox_reward_pool_address: Address,
        max_broadcast_tx_size: usize,
    ) -> Self {
        Self {
            chain_executor,
            tx_manager,
            metrics,
            profit_calc: ProfitabilityCalculator::new(
                min_profit_margin_percent,
                price_client,
                nox_reward_pool_address,
            ),
            max_broadcast_tx_size,
            gas_limit_buffer_bps: crate::config::DEFAULT_GAS_LIMIT_BUFFER_BPS,
            initial_fee_buffer_bps: crate::config::DEFAULT_INITIAL_FEE_BUFFER_BPS,
            nox_entry_point_address: Address::zero(),
            quote_policy: None,
        }
    }

    pub fn register_token(&mut self, address: Address, symbol: &str, decimals: u8, price_id: &str) {
        self.profit_calc
            .register_token(address, symbol, decimals, price_id);
    }

    pub fn with_quote_policy(
        mut self,
        config: &crate::config::NoxConfig,
    ) -> Result<Self, ServiceError> {
        self.quote_policy = Some(QuotePolicy::from_config(config).map_err(|error| {
            ServiceError::ProcessingFailed(format!("invalid paid quote policy: {error}"))
        })?);
        Ok(self)
    }

    pub async fn handle_paid_quote_v2(
        &self,
        request: nox_core::PaidQuoteRequestV2,
    ) -> nox_core::PaidQuoteOutcomeV2 {
        let Some(policy) = &self.quote_policy else {
            return paid_quote_rejection(
                nox_core::PaidTransactionRejectionCodeV2::UnsupportedPaymentAdapter,
                false,
                "paid quote policy unavailable",
            );
        };
        let wall_timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(_) => {
                return paid_quote_rejection(
                    nox_core::PaidTransactionRejectionCodeV2::MalformedRequest,
                    false,
                    "system clock is before Unix epoch",
                );
            }
        };
        let chain_timestamp = match self.chain_executor.latest_block_timestamp().await {
            Ok(timestamp) => timestamp,
            Err(_) => {
                return paid_quote_rejection(
                    nox_core::PaidTransactionRejectionCodeV2::SubmissionFailure,
                    true,
                    "latest chain timestamp unavailable",
                );
            }
        };
        let (maximum_transaction_gas, valid_until_unix) = match policy.validate_request(
            &request,
            self.chain_executor.chain_id(),
            self.nox_entry_point_address,
            chain_timestamp,
        ) {
            Ok(validated) => validated,
            Err(code) => return paid_quote_rejection(code, false, "paid quote request rejected"),
        };
        let network_fee_per_gas = match self.chain_executor.get_gas_price().await {
            Ok(price) => price,
            Err(_) => {
                return paid_quote_rejection(
                    nox_core::PaidTransactionRejectionCodeV2::StalePrice,
                    true,
                    "network gas price unavailable",
                );
            }
        };
        let initial_fee_per_gas = match crate::blockchain::transaction_plan::buffered(
            network_fee_per_gas,
            self.initial_fee_buffer_bps,
            "initial_fee_per_gas",
        ) {
            Ok(price) => price,
            Err(_) => {
                return paid_quote_rejection(
                    nox_core::PaidTransactionRejectionCodeV2::GasCapExceeded,
                    false,
                    "initial gas price overflow",
                );
            }
        };
        let maximum_fee_per_gas = match crate::blockchain::transaction_plan::buffered(
            initial_fee_per_gas,
            policy.replacement_step_bps,
            "maximum_fee_per_gas",
        ) {
            Ok(price) => price,
            Err(_) => {
                return paid_quote_rejection(
                    nox_core::PaidTransactionRejectionCodeV2::GasCapExceeded,
                    false,
                    "maximum gas price overflow",
                );
            }
        };
        let exit_fee = match self
            .profit_calc
            .quote_exit_fee(
                Address::from(request.fee_asset),
                U256::from(maximum_transaction_gas),
                maximum_fee_per_gas,
            )
            .await
        {
            Ok(fee) => fee,
            Err(error) => {
                let (code, retryable) = paid_v2_profit_error(&error);
                return paid_quote_rejection(code, retryable, "quote fee calculation failed");
            }
        };
        let network_fee = match quote_network_fee(exit_fee, policy.network_fee_bps) {
            Some(fee) => fee,
            None => {
                return paid_quote_rejection(
                    nox_core::PaidTransactionRejectionCodeV2::GasCapExceeded,
                    false,
                    "network fee arithmetic overflow",
                );
            }
        };
        let storage = self.tx_manager.quote_storage();
        let nonce = match storage.next_quote_nonce_durably().await {
            Ok(nonce) => nonce,
            Err(_) => {
                return paid_quote_rejection(
                    nox_core::PaidTransactionRejectionCodeV2::SubmissionFailure,
                    true,
                    "quote nonce persistence failed",
                );
            }
        };
        let quote = nox_core::ExecutionQuoteV1 {
            quote_version: 1,
            chain_id: u256_word(U256::from(request.chain_id)),
            entry_point: request.entry_point,
            exit_address: self.chain_executor.address().0,
            client_intent_id: request.client_intent_id,
            payment_adapter: request.payment_adapter,
            payment_id: request.payment_id,
            fee_asset: request.fee_asset,
            exit_fee: u256_word(exit_fee),
            network_fee: u256_word(network_fee),
            payment_gas_limit: u256_word(U256::from(request.payment_gas_limit)),
            action_target: request.action_target,
            action_calldata_hash: request.action_calldata_hash,
            action_gas_limit: u256_word(U256::from(request.action_gas_limit)),
            tracked_assets_hash: request.tracked_assets_hash,
            maximum_transaction_gas: u256_word(U256::from(maximum_transaction_gas)),
            maximum_fee_per_gas: u256_word(maximum_fee_per_gas),
            return_data_limit: u256_word(U256::from(request.return_data_limit)),
            valid_after_unix: chain_timestamp,
            valid_until_unix,
            quote_nonce: u256_word(U256::from(nonce)),
        };
        let digest = execution_quote_digest(&quote);
        let signature = match self.chain_executor.sign_execution_digest(digest) {
            Ok(signature) => signature,
            Err(_) => {
                return paid_quote_rejection(
                    nox_core::PaidTransactionRejectionCodeV2::SubmissionFailure,
                    true,
                    "quote signing failed",
                );
            }
        };
        let record = nox_core::StoredQuoteV2 {
            schema: 1,
            request,
            quote: quote.clone(),
            execution_id: digest.0,
            exit_signature: signature.clone(),
            pending_sponsored_gas: maximum_transaction_gas,
            rolling_loss_window_secs: policy.rolling_loss_window_secs,
            status: nox_core::QuoteStatusV2::Outstanding,
        };
        if let Err(error) = storage
            .create_quote_durably(
                &record,
                policy.maximum_outstanding,
                policy.maximum_pending_sponsored_gas,
                policy.rolling_loss_limit_native,
                policy.rolling_loss_window_secs,
                wall_timestamp,
            )
            .await
        {
            let (code, retryable) = match error {
                QuoteStoreError::DuplicateIdentity => (
                    nox_core::PaidTransactionRejectionCodeV2::DuplicateExecution,
                    false,
                ),
                QuoteStoreError::PendingLossLimit => (
                    nox_core::PaidTransactionRejectionCodeV2::PendingLossLimit,
                    false,
                ),
                QuoteStoreError::OutstandingCapacity | QuoteStoreError::PendingGasCapacity => (
                    nox_core::PaidTransactionRejectionCodeV2::QuoteCapacityExceeded,
                    true,
                ),
                QuoteStoreError::Unknown
                | QuoteStoreError::Expired
                | QuoteStoreError::NotOutstanding
                | QuoteStoreError::Storage(_) => (
                    nox_core::PaidTransactionRejectionCodeV2::SubmissionFailure,
                    true,
                ),
            };
            return paid_quote_rejection(code, retryable, "quote reservation failed");
        }
        nox_core::PaidQuoteOutcomeV2::Issued {
            quote,
            execution_id: digest.0,
            exit_signature: signature,
        }
    }

    pub(crate) fn clear_tokens(&mut self) {
        self.profit_calc.clear_tokens();
    }

    /// In-process entry point for the legacy paid path. Not reachable from the
    /// mixnet: exit nodes reject `SubmitTransaction` (see [`legacy_submission_rejection`]).
    pub async fn handle_paid_transaction(
        &self,
        packet_id: &str,
        to: Address,
        data: Bytes,
    ) -> Result<PaidOutcome, PaidRejection> {
        let outcome = self.execute_paid_transaction(packet_id, to, data).await;
        if let Err(rejection) = &outcome {
            self.metrics
                .profitability_outcomes_total
                .get_or_create(&vec![("result".into(), rejection.code().into())])
                .inc();
        }
        outcome
    }

    pub async fn handle_paid_transaction_v2(
        &self,
        request: nox_core::PaidTransactionRequestV2,
    ) -> nox_core::PaidTransactionOutcomeV2 {
        let wall_timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(_) => {
                return paid_v2_rejection(
                    Some(request.execution_id),
                    nox_core::PaidTransactionRejectionCodeV2::MalformedRequest,
                    false,
                    "system clock is before Unix epoch",
                );
            }
        };
        let chain_timestamp = match self.chain_executor.latest_block_timestamp().await {
            Ok(timestamp) => timestamp,
            Err(_) => {
                return paid_v2_rejection(
                    Some(request.execution_id),
                    nox_core::PaidTransactionRejectionCodeV2::SubmissionFailure,
                    true,
                    "latest chain timestamp unavailable",
                );
            }
        };
        if let Err(code) = validate_paid_v2_request(
            &request,
            self.chain_executor.chain_id(),
            self.nox_entry_point_address,
            chain_timestamp,
            self.max_broadcast_tx_size,
        ) {
            if code == nox_core::PaidTransactionRejectionCodeV2::ExpiredQuote {
                let storage = self.tx_manager.quote_storage();
                match storage.load_quote(request.execution_id).await {
                    Ok(Some(quote))
                        if quote.status == nox_core::QuoteStatusV2::Outstanding
                            && quote.quote.valid_until_unix <= chain_timestamp =>
                    {
                        if storage
                            .finalize_quote_durably(
                                request.execution_id,
                                nox_core::QuoteStatusV2::Expired,
                                U256::zero(),
                                wall_timestamp,
                            )
                            .await
                            .is_err()
                        {
                            return paid_v2_rejection(
                                Some(request.execution_id),
                                nox_core::PaidTransactionRejectionCodeV2::SubmissionFailure,
                                true,
                                "expired quote release failed",
                            );
                        }
                    }
                    Ok(_) => {}
                    Err(_) => {
                        return paid_v2_rejection(
                            Some(request.execution_id),
                            nox_core::PaidTransactionRejectionCodeV2::SubmissionFailure,
                            true,
                            "quote storage lookup failed",
                        );
                    }
                }
            }
            return paid_v2_rejection(
                Some(request.execution_id),
                code,
                false,
                "paid request validation failed",
            );
        }
        let quote_storage = self.tx_manager.quote_storage();
        let stored_quote = match quote_storage.load_quote(request.execution_id).await {
            Ok(Some(quote)) if quote.status != nox_core::QuoteStatusV2::Outstanding => {
                return paid_v2_rejection(
                    Some(request.execution_id),
                    nox_core::PaidTransactionRejectionCodeV2::DuplicateExecution,
                    false,
                    "quote execution is already consumed or terminal",
                );
            }
            Ok(Some(quote)) if quote.quote.valid_until_unix <= chain_timestamp => {
                if quote_storage
                    .finalize_quote_durably(
                        request.execution_id,
                        nox_core::QuoteStatusV2::Expired,
                        U256::zero(),
                        wall_timestamp,
                    )
                    .await
                    .is_err()
                {
                    return paid_v2_rejection(
                        Some(request.execution_id),
                        nox_core::PaidTransactionRejectionCodeV2::SubmissionFailure,
                        true,
                        "expired quote release failed",
                    );
                }
                return paid_v2_rejection(
                    Some(request.execution_id),
                    nox_core::PaidTransactionRejectionCodeV2::ExpiredQuote,
                    false,
                    "quote expired before submission",
                );
            }
            Ok(Some(quote)) => quote,
            Ok(None) => {
                return paid_v2_rejection(
                    Some(request.execution_id),
                    nox_core::PaidTransactionRejectionCodeV2::UnknownQuote,
                    false,
                    "quote execution ID is unknown",
                );
            }
            Err(_) => {
                return paid_v2_rejection(
                    Some(request.execution_id),
                    nox_core::PaidTransactionRejectionCodeV2::SubmissionFailure,
                    true,
                    "quote storage lookup failed",
                );
            }
        };
        if stored_quote.quote.entry_point != request.entry_point
            || stored_quote.quote.valid_until_unix != request.valid_until_unix
        {
            return paid_v2_rejection(
                Some(request.execution_id),
                nox_core::PaidTransactionRejectionCodeV2::MalformedRequest,
                false,
                "request does not match stored quote",
            );
        }

        let target = Address::from(request.entry_point);
        let calldata = Bytes::from(request.calldata.clone());
        let evidence = match self
            .chain_executor
            .simulate_transaction_evidence(target, calldata.clone())
            .await
        {
            Ok(evidence) => evidence,
            Err(_) => {
                return paid_v2_rejection(
                    Some(request.execution_id),
                    nox_core::PaidTransactionRejectionCodeV2::SimulationFailure,
                    true,
                    "entry point simulation failed",
                );
            }
        };
        let settlement =
            match parse_paid_v2_settlement(&request, self.chain_executor.address(), &evidence.logs)
            {
                Ok(settlement) => settlement,
                Err(code) => {
                    return paid_v2_rejection(
                        Some(request.execution_id),
                        code,
                        false,
                        "entry point settlement evidence rejected",
                    );
                }
            };
        if settlement.fee_asset != Address::from(stored_quote.quote.fee_asset)
            || settlement.exit_fee != U256::from_big_endian(&stored_quote.quote.exit_fee)
        {
            return paid_v2_rejection(
                Some(request.execution_id),
                nox_core::PaidTransactionRejectionCodeV2::PaymentMissing,
                false,
                "settlement fee does not match stored quote",
            );
        }
        let candidate = match self
            .chain_executor
            .build_cost_candidate(
                target,
                calldata.clone(),
                self.gas_limit_buffer_bps,
                self.initial_fee_buffer_bps,
            )
            .await
        {
            Ok(candidate) => candidate,
            Err(_) => {
                return paid_v2_rejection(
                    Some(request.execution_id),
                    nox_core::PaidTransactionRejectionCodeV2::GasCapExceeded,
                    true,
                    "exact transaction gas plan unavailable",
                );
            }
        };
        let quoted_gas = U256::from_big_endian(&stored_quote.quote.maximum_transaction_gas);
        let quoted_fee_per_gas = U256::from_big_endian(&stored_quote.quote.maximum_fee_per_gas);
        if let Err(violation) =
            validate_initial_plan_caps(&candidate, quoted_gas, quoted_fee_per_gas)
        {
            match violation {
                QuotePlanCapViolation::GasLimit { actual, maximum } => warn!(
                    execution_id = %hex::encode(request.execution_id),
                    actual = %actual,
                    maximum = %maximum,
                    "Actual gas limit exceeds signed quote maximum"
                ),
                QuotePlanCapViolation::InitialFeePerGas { actual, maximum } => warn!(
                    execution_id = %hex::encode(request.execution_id),
                    actual = %actual,
                    maximum = %maximum,
                    "Initial fee per gas exceeds signed quote maximum"
                ),
            }
            return paid_v2_rejection(
                Some(request.execution_id),
                nox_core::PaidTransactionRejectionCodeV2::GasCapExceeded,
                false,
                "initial transaction plan exceeds signed quote",
            );
        }
        let authorization = match self
            .profit_calc
            .authorize_fee_with_maximum_fee_per_gas(
                candidate,
                settlement.fee_asset,
                settlement.exit_fee,
                quoted_fee_per_gas,
            )
            .await
        {
            Ok(authorization) => authorization,
            Err(error) => {
                let (code, retryable) = paid_v2_profit_error(&error);
                return paid_v2_rejection(
                    Some(request.execution_id),
                    code,
                    retryable,
                    "profit authorization rejected",
                );
            }
        };
        let quote_reservation = self
            .tx_manager
            .quote_storage()
            .take_quote_durably(request.execution_id, chain_timestamp)
            .await;
        if let Err(error) = quote_reservation {
            return match error {
                QuoteStoreError::Expired => {
                    let _ = self
                        .tx_manager
                        .quote_storage()
                        .finalize_quote_durably(
                            request.execution_id,
                            nox_core::QuoteStatusV2::Expired,
                            U256::zero(),
                            wall_timestamp,
                        )
                        .await;
                    paid_v2_rejection(
                        Some(request.execution_id),
                        nox_core::PaidTransactionRejectionCodeV2::ExpiredQuote,
                        false,
                        "quote expired before reservation",
                    )
                }
                QuoteStoreError::NotOutstanding => paid_v2_rejection(
                    Some(request.execution_id),
                    nox_core::PaidTransactionRejectionCodeV2::DuplicateExecution,
                    false,
                    "quote is no longer outstanding",
                ),
                QuoteStoreError::Unknown => paid_v2_rejection(
                    Some(request.execution_id),
                    nox_core::PaidTransactionRejectionCodeV2::UnknownQuote,
                    false,
                    "quote execution ID is unknown",
                ),
                QuoteStoreError::Storage(_) => paid_v2_rejection(
                    Some(request.execution_id),
                    nox_core::PaidTransactionRejectionCodeV2::SubmissionFailure,
                    true,
                    "quote reservation storage failed",
                ),
                QuoteStoreError::DuplicateIdentity
                | QuoteStoreError::OutstandingCapacity
                | QuoteStoreError::PendingGasCapacity
                | QuoteStoreError::PendingLossLimit => paid_v2_rejection(
                    Some(request.execution_id),
                    nox_core::PaidTransactionRejectionCodeV2::SubmissionFailure,
                    false,
                    "quote reservation state is invalid",
                ),
            };
        }
        let submission = self
            .tx_manager
            .submit_planned(
                request.execution_id,
                target,
                calldata,
                authorization.plan.clone(),
            )
            .await;
        let submitted = match submission {
            Ok(submitted) => submitted,
            Err(
                SubmitError::AmbiguousBroadcast {
                    transaction_hash, ..
                }
                | SubmitError::Duplicate {
                    transaction_hash, ..
                },
            ) => crate::blockchain::tx_manager::SubmittedTransaction {
                execution_id: request.execution_id,
                transaction_hash,
            },
            Err(error @ (SubmitError::GasPlan { .. } | SubmitError::Signing { .. })) => {
                let _ = self
                    .tx_manager
                    .quote_storage()
                    .finalize_quote_durably(
                        request.execution_id,
                        nox_core::QuoteStatusV2::Rejected,
                        U256::zero(),
                        wall_timestamp,
                    )
                    .await;
                return paid_v2_rejection(
                    Some(request.execution_id),
                    paid_v2_submit_error(&map_submit_error(error)),
                    false,
                    "transaction rejected before outbox creation",
                );
            }
            Err(error @ (SubmitError::Persistence { .. } | SubmitError::Broadcast { .. })) => {
                match self
                    .tx_manager
                    .quote_storage()
                    .load_outbox_by_execution(request.execution_id)
                    .await
                {
                    Ok(Some(outbox)) => crate::blockchain::tx_manager::SubmittedTransaction {
                        execution_id: request.execution_id,
                        transaction_hash: match H256::from_str(&outbox.tx_hash) {
                            Ok(hash) => hash,
                            Err(_) => {
                                return paid_v2_rejection(
                                    Some(request.execution_id),
                                    nox_core::PaidTransactionRejectionCodeV2::SubmissionFailure,
                                    false,
                                    "stored outbox hash is invalid",
                                );
                            }
                        },
                    },
                    Ok(None) if matches!(error, SubmitError::Persistence { .. }) => {
                        let _ = self
                            .tx_manager
                            .quote_storage()
                            .finalize_quote_durably(
                                request.execution_id,
                                nox_core::QuoteStatusV2::Rejected,
                                U256::zero(),
                                wall_timestamp,
                            )
                            .await;
                        return paid_v2_rejection(
                            Some(request.execution_id),
                            nox_core::PaidTransactionRejectionCodeV2::SubmissionFailure,
                            false,
                            "outbox was not created",
                        );
                    }
                    Ok(None) | Err(_) => {
                        return paid_v2_rejection(
                            Some(request.execution_id),
                            nox_core::PaidTransactionRejectionCodeV2::SubmissionFailure,
                            false,
                            "submission outcome unresolved; quote remains inflight",
                        );
                    }
                }
            }
        };
        if let Err(error) = self
            .tx_manager
            .quote_storage()
            .mark_quote_submitted_durably(request.execution_id)
            .await
        {
            warn!(error = %error, "Submitted transaction quote status remains inflight");
        }
        record_accepted_economics(&self.metrics, &authorization);
        nox_core::PaidTransactionOutcomeV2::Submitted {
            execution_id: submitted.execution_id,
            transaction_hash: submitted.transaction_hash.0,
        }
    }

    async fn execute_paid_transaction(
        &self,
        packet_id: &str,
        to: Address,
        data: Bytes,
    ) -> Result<PaidOutcome, PaidRejection> {
        let evidence = self
            .chain_executor
            .simulate_legacy_paid_transaction(to, data.clone())
            .await
            .map_err(|_| PaidRejection::Simulation {
                detail: BoundedDetail::from_public_message(
                    "legacy committed simulation evidence unavailable",
                ),
            })?;
        let logs = committed_payment_logs(&evidence)?;
        let candidate = self
            .chain_executor
            .build_cost_candidate(
                to,
                data.clone(),
                self.gas_limit_buffer_bps,
                self.initial_fee_buffer_bps,
            )
            .await
            .map_err(|_| PaidRejection::GasPlan {
                detail: BoundedDetail::from_public_message("exact gas estimation failed"),
            })?;
        let authorization = self
            .profit_calc
            .authorize(candidate, logs)
            .await
            .map_err(map_profit_error)?;
        let execution_id =
            legacy_execution_id(self.chain_executor.chain_id(), packet_id, to, &data)?;
        let submitted = resolve_submission(
            execution_id,
            self.tx_manager
                .submit_planned(execution_id, to, data, authorization.plan.clone())
                .await,
        )?;
        record_accepted_economics(&self.metrics, &authorization);
        self.metrics
            .eth_transactions_submitted
            .get_or_create(&vec![("type".into(), "paid".into())])
            .inc();
        self.metrics
            .eth_tx_outcomes_total
            .get_or_create(&vec![
                ("type".into(), "paid".into()),
                ("result".into(), "submitted".into()),
            ])
            .inc();
        self.metrics
            .eth_tx_gas_used
            .observe(evidence.gas_used as f64);
        Ok(PaidOutcome::Submitted {
            execution_id: submitted.execution_id,
            transaction_hash: submitted.transaction_hash,
        })
    }

    /// No simulation or profitability check -- user pays their own gas.
    pub async fn handle_broadcast(
        &self,
        packet_id: &str,
        signed_tx: Vec<u8>,
        rpc_url: Option<String>,
        rpc_method: Option<String>,
    ) -> Result<Vec<u8>, ServiceError> {
        let method = rpc_method.as_deref().unwrap_or(DEFAULT_BROADCAST_METHOD);

        if signed_tx.is_empty() {
            return Err(ServiceError::ProcessingFailed(
                "Empty signed transaction".into(),
            ));
        }
        if signed_tx.len() > self.max_broadcast_tx_size {
            return Err(ServiceError::ProcessingFailed(format!(
                "Signed TX too large: {} bytes (max {})",
                signed_tx.len(),
                self.max_broadcast_tx_size
            )));
        }

        let response_bytes = if let Some(ref url) = rpc_url {
            let (resolved_ip, validated_url) =
                security::validate_url_ssrf(url, false).await.map_err(|e| {
                    warn!(
                        packet_id,
                        error = %e,
                        "SSRF check blocked broadcast RPC URL"
                    );
                    ServiceError::ProcessingFailed(format!("RPC URL blocked: {e}"))
                })?;

            // Pinned to the validated address with redirects disabled, so neither
            // DNS rebinding nor an upstream redirect can reach another host.
            let user_provider = build_pinned_ethers_http1_provider(&validated_url, resolved_ip)
                .map_err(|e| {
                    ServiceError::ProcessingFailed(format!(
                        "Failed to create provider for user-supplied RPC URL: {e}"
                    ))
                })?;

            info!(
                packet_id,
                rpc_url = url,
                rpc_method = method,
                signed_tx_len = signed_tx.len(),
                "Broadcast via custom RPC URL"
            );

            let hex_tx = format!("0x{}", hex::encode(&signed_tx));
            let rpc_result = tokio::time::timeout(
                BROADCAST_RPC_TIMEOUT,
                user_provider.request::<_, serde_json::Value>(method, [hex_tx]),
            )
            .await;

            match rpc_result {
                Ok(Ok(value)) => serde_json::to_vec(&value).map_err(|e| {
                    ServiceError::ProcessingFailed(format!("Failed to serialize RPC response: {e}"))
                })?,
                Ok(Err(e)) => {
                    warn!(packet_id, error = %e, "Custom URL broadcast rejected");
                    return Err(ServiceError::ProcessingFailed(format!(
                        "Broadcast rejected: {}",
                        public_rpc_error(&e)
                    )));
                }
                Err(_) => {
                    warn!(packet_id, "Custom URL broadcast timed out");
                    return Err(ServiceError::ProcessingFailed("Broadcast timed out".into()));
                }
            }
        } else if method != DEFAULT_BROADCAST_METHOD {
            warn!(
                packet_id,
                rpc_method = method,
                "Broadcast rejected: custom RPC method requires rpc_url"
            );
            return Err(ServiceError::ProcessingFailed(format!(
                "Custom RPC method '{method}' requires rpc_url (use BroadcastOptions with rpc_url)"
            )));
        } else {
            info!(
                packet_id,
                signed_tx_len = signed_tx.len(),
                "Broadcast via default provider (eth_sendRawTransaction)"
            );

            let broadcast_result = tokio::time::timeout(
                BROADCAST_RPC_TIMEOUT,
                self.chain_executor.broadcast_raw_signed_tx(&signed_tx),
            )
            .await;

            let tx_hash = match broadcast_result {
                Ok(Ok(hash)) => hash,
                Ok(Err(e)) => {
                    warn!(
                        packet_id,
                        error = %e,
                        "Broadcast signed TX rejected by RPC"
                    );
                    return Err(ServiceError::ProcessingFailed(format!(
                        "Broadcast rejected: {e}"
                    )));
                }
                Err(_) => {
                    warn!(packet_id, "Broadcast signed TX timed out");
                    return Err(ServiceError::ProcessingFailed("Broadcast timed out".into()));
                }
            };

            match self.chain_executor.get_transaction_receipt(tx_hash).await {
                Ok(Some(receipt)) => {
                    info!(
                        packet_id,
                        %tx_hash,
                        status = ?receipt.status,
                        gas_used = ?receipt.gas_used,
                        logs = receipt.logs.len(),
                        block = ?receipt.block_number,
                        "Broadcast TX receipt"
                    );
                }
                Ok(None) => {
                    info!(
                        packet_id,
                        %tx_hash,
                        "Broadcast TX in mempool (receipt not yet available)"
                    );
                }
                Err(e) => {
                    warn!(packet_id, %tx_hash, error = %e, "Broadcast TX receipt fetch failed");
                }
            }

            tx_hash.as_bytes().to_vec()
        };

        info!(
            packet_id,
            response_len = response_bytes.len(),
            rpc_method = method,
            custom_url = rpc_url.is_some(),
            "Broadcast signed transaction complete"
        );

        self.metrics
            .eth_transactions_submitted
            .get_or_create(&vec![("type".into(), "broadcast".into())])
            .inc();
        self.metrics
            .eth_tx_outcomes_total
            .get_or_create(&vec![
                ("type".into(), "broadcast".into()),
                ("result".into(), "submitted".into()),
            ])
            .inc();

        Ok(response_bytes)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_config(
        chain_executor: Arc<ChainExecutor>,
        tx_manager: Arc<TransactionManager>,
        metrics: MetricsService,
        min_profit_margin_percent: u64,
        price_client: Arc<dyn FixedPriceSource>,
        nox_reward_pool_address_str: &str,
        max_broadcast_tx_size: usize,
        native_asset_price_id: &str,
        native_asset_decimals: u8,
        gas_limit_buffer_bps: u32,
        initial_fee_buffer_bps: u32,
        nox_entry_point_address_str: &str,
    ) -> Result<Self, ServiceError> {
        let nox_reward_pool_address =
            Address::from_str(nox_reward_pool_address_str).map_err(|_| {
                ServiceError::ProcessingFailed(format!(
                    "Invalid nox_reward_pool_address in config: {nox_reward_pool_address_str}"
                ))
            })?;
        let nox_entry_point_address =
            Address::from_str(nox_entry_point_address_str).map_err(|_| {
                ServiceError::ProcessingFailed(format!(
                    "Invalid nox_entry_point_address in config: {nox_entry_point_address_str}"
                ))
            })?;

        let margin_bps = u128::from(min_profit_margin_percent)
            .checked_mul(100)
            .ok_or_else(|| {
                ServiceError::ProcessingFailed("profit margin conversion overflow".to_string())
            })?;
        Ok(Self {
            chain_executor,
            tx_manager,
            metrics,
            profit_calc: ProfitabilityCalculator::with_economics(
                margin_bps,
                price_client,
                nox_reward_pool_address,
                TokenRegistry::default(),
                native_asset_price_id.to_string(),
                native_asset_decimals,
            ),
            max_broadcast_tx_size,
            gas_limit_buffer_bps,
            initial_fee_buffer_bps,
            nox_entry_point_address,
            quote_policy: None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PaidV2Settlement {
    fee_asset: Address,
    exit_fee: U256,
}

fn validate_paid_v2_request(
    request: &nox_core::PaidTransactionRequestV2,
    expected_chain_id: u64,
    expected_entry_point: Address,
    now_unix: u64,
    maximum_calldata_bytes: usize,
) -> Result<(), nox_core::PaidTransactionRejectionCodeV2> {
    if request.chain_id != expected_chain_id {
        return Err(nox_core::PaidTransactionRejectionCodeV2::WrongChain);
    }
    if Address::from(request.entry_point) != expected_entry_point || expected_entry_point.is_zero()
    {
        return Err(nox_core::PaidTransactionRejectionCodeV2::WrongEntryPoint);
    }
    if request.valid_until_unix <= now_unix {
        return Err(nox_core::PaidTransactionRejectionCodeV2::ExpiredQuote);
    }
    if request.execution_id == [0_u8; 32] {
        return Err(nox_core::PaidTransactionRejectionCodeV2::MalformedRequest);
    }
    if request.calldata.len() > maximum_calldata_bytes {
        return Err(nox_core::PaidTransactionRejectionCodeV2::GasCapExceeded);
    }
    Ok(())
}

fn parse_paid_v2_settlement(
    request: &nox_core::PaidTransactionRequestV2,
    expected_exit: Address,
    logs: &[Log],
) -> Result<PaidV2Settlement, nox_core::PaidTransactionRejectionCodeV2> {
    let event_topic = H256::from(keccak256(PAID_EXECUTION_SETTLED_SIGNATURE));
    let matching: Vec<&Log> = logs
        .iter()
        .filter(|log| {
            log.address == Address::from(request.entry_point)
                && log.topics.first() == Some(&event_topic)
        })
        .collect();
    let [log] = matching.as_slice() else {
        return Err(nox_core::PaidTransactionRejectionCodeV2::PaymentMissing);
    };
    if log.topics.len() != 4 || log.data.len() != 224 {
        return Err(nox_core::PaidTransactionRejectionCodeV2::MalformedRequest);
    }
    if log.topics[1] != H256::from(request.execution_id) || log.topics[2] == H256::zero() {
        return Err(nox_core::PaidTransactionRejectionCodeV2::PaymentMissing);
    }
    let exit_topic = log.topics[3].as_bytes();
    if exit_topic[..12] != [0_u8; 12] || Address::from_slice(&exit_topic[12..]) != expected_exit {
        return Err(nox_core::PaidTransactionRejectionCodeV2::PaymentMissing);
    }
    let words = log.data.as_ref();
    if words[..12] != [0_u8; 12]
        || words[96..108] != [0_u8; 12]
        || words[128..159] != [0_u8; 31]
        || words[159] > 1
    {
        return Err(nox_core::PaidTransactionRejectionCodeV2::MalformedRequest);
    }
    let exit_fee = U256::from_big_endian(&words[32..64]);
    if exit_fee.is_zero() {
        return Err(nox_core::PaidTransactionRejectionCodeV2::PaymentMissing);
    }
    Ok(PaidV2Settlement {
        fee_asset: Address::from_slice(&words[12..32]),
        exit_fee,
    })
}

fn paid_v2_rejection(
    execution_id: Option<[u8; 32]>,
    code: nox_core::PaidTransactionRejectionCodeV2,
    retryable: bool,
    detail: &str,
) -> nox_core::PaidTransactionOutcomeV2 {
    nox_core::PaidTransactionOutcomeV2::Rejected {
        execution_id,
        code,
        retryable,
        detail: BoundedDetail::from_public_message(detail)
            .as_str()
            .to_string(),
    }
}

fn paid_quote_rejection(
    code: nox_core::PaidTransactionRejectionCodeV2,
    retryable: bool,
    detail: &str,
) -> nox_core::PaidQuoteOutcomeV2 {
    nox_core::PaidQuoteOutcomeV2::Rejected {
        code,
        retryable,
        detail: BoundedDetail::from_public_message(detail)
            .as_str()
            .to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum QuotePlanCapViolation {
    GasLimit { actual: U256, maximum: U256 },
    InitialFeePerGas { actual: U256, maximum: U256 },
}

fn validate_initial_plan_caps(
    candidate: &crate::blockchain::transaction_plan::CostCandidate,
    maximum_transaction_gas: U256,
    maximum_fee_per_gas: U256,
) -> Result<(), QuotePlanCapViolation> {
    if candidate.gas_limit > maximum_transaction_gas {
        return Err(QuotePlanCapViolation::GasLimit {
            actual: candidate.gas_limit,
            maximum: maximum_transaction_gas,
        });
    }
    if candidate.initial_fee_per_gas > maximum_fee_per_gas {
        return Err(QuotePlanCapViolation::InitialFeePerGas {
            actual: candidate.initial_fee_per_gas,
            maximum: maximum_fee_per_gas,
        });
    }
    Ok(())
}

fn quote_network_fee(exit_fee: U256, network_fee_bps: u32) -> Option<U256> {
    exit_fee
        .checked_mul(U256::from(network_fee_bps))?
        .checked_add(U256::from(9_999))
        .map(|value| value / U256::from(10_000))
}

fn paid_v2_profit_error(
    error: &ProfitabilityError,
) -> (nox_core::PaidTransactionRejectionCodeV2, bool) {
    match error {
        ProfitabilityError::PaymentMissing => (
            nox_core::PaidTransactionRejectionCodeV2::PaymentMissing,
            false,
        ),
        ProfitabilityError::PriceUnavailable { .. } => {
            (nox_core::PaidTransactionRejectionCodeV2::StalePrice, true)
        }
        ProfitabilityError::Unprofitable { .. } => (
            nox_core::PaidTransactionRejectionCodeV2::Unprofitable,
            false,
        ),
        ProfitabilityError::Arithmetic { .. } => (
            nox_core::PaidTransactionRejectionCodeV2::GasCapExceeded,
            false,
        ),
    }
}

fn paid_v2_submit_error(rejection: &PaidRejection) -> nox_core::PaidTransactionRejectionCodeV2 {
    match rejection {
        PaidRejection::Duplicate { .. } => {
            nox_core::PaidTransactionRejectionCodeV2::DuplicateExecution
        }
        PaidRejection::PaymentMissing => nox_core::PaidTransactionRejectionCodeV2::PaymentMissing,
        PaidRejection::PriceUnavailable { .. } => {
            nox_core::PaidTransactionRejectionCodeV2::StalePrice
        }
        PaidRejection::Unprofitable { .. } => {
            nox_core::PaidTransactionRejectionCodeV2::Unprofitable
        }
        PaidRejection::GasPlan { .. } => nox_core::PaidTransactionRejectionCodeV2::GasCapExceeded,
        PaidRejection::Simulation { .. } => {
            nox_core::PaidTransactionRejectionCodeV2::SimulationFailure
        }
        PaidRejection::Submission { .. } => {
            nox_core::PaidTransactionRejectionCodeV2::SubmissionFailure
        }
    }
}

fn legacy_execution_id(
    chain_id: u64,
    packet_id: &str,
    target: Address,
    data: &[u8],
) -> Result<nox_core::ExecutionId, PaidRejection> {
    let packet_len = u32::try_from(packet_id.len()).map_err(|_| PaidRejection::GasPlan {
        detail: BoundedDetail::from_public_message("packet identifier exceeds u32 length"),
    })?;
    let mut preimage = Vec::with_capacity(32 + packet_id.len() + data.len().min(32));
    preimage.extend_from_slice(b"hisoka.nox.legacy-execution.v1");
    preimage.extend_from_slice(&chain_id.to_be_bytes());
    preimage.extend_from_slice(&packet_len.to_be_bytes());
    preimage.extend_from_slice(packet_id.as_bytes());
    preimage.extend_from_slice(target.as_bytes());
    preimage.extend_from_slice(&keccak256(data));
    Ok(keccak256(preimage))
}

fn map_profit_error(error: ProfitabilityError) -> PaidRejection {
    match error {
        ProfitabilityError::PaymentMissing => PaidRejection::PaymentMissing,
        ProfitabilityError::PriceUnavailable { asset_id, .. } => PaidRejection::PriceUnavailable {
            asset_id,
            detail: BoundedDetail::from_public_message("fresh validated price unavailable"),
        },
        ProfitabilityError::Unprofitable {
            revenue_value_e8,
            maximum_cost_value_e8,
        } => PaidRejection::Unprofitable {
            revenue_value_e8,
            maximum_cost_value_e8,
        },
        ProfitabilityError::Arithmetic { .. } => PaidRejection::GasPlan {
            detail: BoundedDetail::from_public_message("profitability arithmetic failed"),
        },
    }
}

fn committed_payment_logs(
    evidence: &crate::blockchain::executor::SimulationEvidence,
) -> Result<&[Log], PaidRejection> {
    evidence
        .legacy_payment_logs()
        .ok_or(PaidRejection::PaymentMissing)
}

fn record_accepted_economics(
    metrics: &MetricsService,
    authorization: &crate::services::profitability::ProfitAuthorization,
) {
    const E8_SCALE: f64 = 100_000_000.0;
    const E8_PER_USD_MICRO: u64 = 100;

    let to_usd = |value: U256| value.to_string().parse::<f64>().unwrap_or(f64::MAX) / E8_SCALE;
    let to_usd_micro = |value: U256| {
        let scaled = value / U256::from(E8_PER_USD_MICRO);
        if scaled > U256::from(u64::MAX) {
            u64::MAX
        } else {
            scaled.as_u64()
        }
    };

    let authorized_revenue_usd = to_usd(authorization.revenue_value_e8);
    let planned_cost_usd = to_usd(authorization.planned_initial_cost_value_e8);
    let maximum_cost_usd = to_usd(authorization.maximum_cost_value_e8);
    metrics
        .tx_authorized_revenue_usd
        .observe(authorized_revenue_usd);
    metrics.tx_planned_cost_usd.observe(planned_cost_usd);
    metrics.tx_maximum_cost_usd.observe(maximum_cost_usd);
    if planned_cost_usd > 0.0 {
        metrics
            .profitability_margin_ratio
            .observe(authorized_revenue_usd / planned_cost_usd);
    }
    metrics
        .cumulative_authorized_revenue_usd
        .inc_by(to_usd_micro(authorization.revenue_value_e8));
    metrics
        .cumulative_cost_usd
        .inc_by(to_usd_micro(authorization.planned_initial_cost_value_e8));
    metrics
        .cumulative_maximum_cost_usd
        .inc_by(to_usd_micro(authorization.maximum_cost_value_e8));
    metrics
        .profitability_outcomes_total
        .get_or_create(&vec![("result".into(), "accepted".into())])
        .inc();
}

fn resolve_submission(
    execution_id: nox_core::ExecutionId,
    submission: Result<crate::blockchain::tx_manager::SubmittedTransaction, SubmitError>,
) -> Result<crate::blockchain::tx_manager::SubmittedTransaction, PaidRejection> {
    match submission {
        Ok(submitted) => Ok(submitted),
        Err(SubmitError::AmbiguousBroadcast {
            transaction_hash, ..
        }) => Ok(crate::blockchain::tx_manager::SubmittedTransaction {
            execution_id,
            transaction_hash,
        }),
        Err(error) => Err(map_submit_error(error)),
    }
}

fn map_submit_error(error: SubmitError) -> PaidRejection {
    match error {
        SubmitError::Duplicate {
            execution_id,
            transaction_hash,
        } => PaidRejection::Duplicate {
            execution_id,
            transaction_hash,
        },
        SubmitError::GasPlan { .. } => PaidRejection::GasPlan {
            detail: BoundedDetail::from_public_message("transaction plan rejected"),
        },
        SubmitError::Persistence { .. } => PaidRejection::Submission {
            detail: BoundedDetail::from_public_message("durable outbox persistence failed"),
        },
        SubmitError::Signing { .. } => PaidRejection::Submission {
            detail: BoundedDetail::from_public_message("transaction signing failed"),
        },
        SubmitError::Broadcast { .. } => PaidRejection::Submission {
            detail: BoundedDetail::from_public_message("transaction broadcast failed"),
        },
        SubmitError::AmbiguousBroadcast { .. } => PaidRejection::Submission {
            detail: BoundedDetail::from_public_message(
                "transaction broadcast outcome is ambiguous",
            ),
        },
    }
}

#[async_trait]
impl ServiceHandler for EthereumHandler {
    fn name(&self) -> &'static str {
        "ethereum"
    }

    /// Paid execution is only reachable through `PaidTransactionV2`; a legacy
    /// `SubmitTransaction` payload is rejected without simulation or submission.
    async fn handle(&self, packet_id: &str, payload: &RelayerPayload) -> Result<(), ServiceError> {
        match payload {
            RelayerPayload::SubmitTransaction { .. } => {
                warn!(packet_id, "Legacy SubmitTransaction payload rejected");
                Err(ServiceError::ProcessingFailed(
                    legacy_submission_rejection().public_detail(),
                ))
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod paid_control_flow_tests {
    use super::*;
    use crate::blockchain::executor::{SimulationEvidence, SimulationSource};
    use crate::blockchain::transaction_plan::TransactionPlan;
    use crate::services::profitability::ProfitAuthorization;

    #[test]
    fn flat_payment_log_maps_to_payment_missing() {
        let evidence = SimulationEvidence {
            gas_used: 1,
            logs: vec![Log {
                address: Address::from_low_u64_be(1),
                topics: vec![H256::from(keccak256(
                    b"RewardsDeposited(address,address,uint256)",
                ))],
                ..Default::default()
            }],
            source: SimulationSource::FlatSimulation,
        };
        assert!(evidence.legacy_payment_logs().is_none());
        assert_eq!(
            committed_payment_logs(&evidence),
            Err(PaidRejection::PaymentMissing)
        );
        assert_eq!(
            map_profit_error(ProfitabilityError::PaymentMissing),
            PaidRejection::PaymentMissing
        );
    }

    #[test]
    fn bounded_detail_removes_controls_and_respects_utf8_boundary() {
        let message = format!("line\n{}é", "x".repeat(MAX_PUBLIC_DETAIL_BYTES));
        let detail = BoundedDetail::from_public_message(&message);
        assert!(detail.as_str().len() <= MAX_PUBLIC_DETAIL_BYTES);
        assert!(!detail.as_str().chars().any(char::is_control));
    }

    #[test]
    fn ambiguous_durable_outcome_returns_original_submitted_identity() {
        let execution_id = [3; 32];
        let transaction_hash = H256::from_low_u64_be(4);
        let submitted = resolve_submission(
            execution_id,
            Err(SubmitError::AmbiguousBroadcast {
                transaction_hash,
                detail: "post-broadcast durable status unavailable".to_string(),
            }),
        )
        .unwrap();
        assert_eq!(submitted.execution_id, execution_id);
        assert_eq!(submitted.transaction_hash, transaction_hash);
    }

    #[test]
    fn accepted_economics_records_planned_and_maximum_cost_once() {
        let metrics = MetricsService::new();
        let authorization = ProfitAuthorization {
            plan: TransactionPlan {
                gas_limit: U256::from(21_000),
                initial_fee_per_gas: U256::from(10),
                maximum_fee_per_gas: U256::from(12),
                chain_data_fee_native: U256::zero(),
            },
            revenue_value_e8: U256::from(250_000_000_u64),
            planned_initial_cost_value_e8: U256::from(100_000_000_u64),
            maximum_cost_value_e8: U256::from(120_000_000_u64),
        };

        record_accepted_economics(&metrics, &authorization);

        assert_eq!(metrics.cumulative_authorized_revenue_usd.get(), 2_500_000);
        assert_eq!(metrics.cumulative_cost_usd.get(), 1_000_000);
        assert_eq!(metrics.cumulative_maximum_cost_usd.get(), 1_200_000);
        assert_eq!(
            metrics
                .profitability_outcomes_total
                .get_or_create(&vec![("result".into(), "accepted".into())])
                .get(),
            1,
        );
    }

    fn paid_v2_request() -> nox_core::PaidTransactionRequestV2 {
        nox_core::PaidTransactionRequestV2 {
            chain_id: 421_614,
            entry_point: [0x11; 20],
            calldata: vec![1, 2, 3],
            execution_id: [0x22; 32],
            valid_until_unix: 1_800_000_000,
        }
    }

    #[test]
    fn paid_v2_request_validation_precedes_simulation() {
        let request = paid_v2_request();
        let entry_point = Address::from_slice(&request.entry_point);
        assert!(
            validate_paid_v2_request(&request, 421_614, entry_point, 1_799_999_999, 64).is_ok()
        );

        let mut wrong_chain = request.clone();
        wrong_chain.chain_id += 1;
        assert_eq!(
            validate_paid_v2_request(&wrong_chain, 421_614, entry_point, 1_799_999_999, 64),
            Err(nox_core::PaidTransactionRejectionCodeV2::WrongChain),
        );
        let mut expired = request.clone();
        expired.valid_until_unix = 1_799_999_999;
        assert_eq!(
            validate_paid_v2_request(&expired, 421_614, entry_point, 1_799_999_999, 64),
            Err(nox_core::PaidTransactionRejectionCodeV2::ExpiredQuote),
        );
    }

    #[test]
    fn initial_plan_must_fit_both_signed_quote_caps() {
        let candidate = crate::blockchain::transaction_plan::CostCandidate {
            gas_limit: U256::from(100),
            initial_fee_per_gas: U256::from(10),
            chain_data_fee_native: U256::zero(),
        };
        assert!(validate_initial_plan_caps(&candidate, U256::from(100), U256::from(10)).is_ok());
        assert_eq!(
            validate_initial_plan_caps(&candidate, U256::from(99), U256::from(10)),
            Err(QuotePlanCapViolation::GasLimit {
                actual: U256::from(100),
                maximum: U256::from(99),
            })
        );
        assert_eq!(
            validate_initial_plan_caps(&candidate, U256::from(100), U256::from(9)),
            Err(QuotePlanCapViolation::InitialFeePerGas {
                actual: U256::from(10),
                maximum: U256::from(9),
            })
        );
    }

    #[test]
    fn entry_point_settlement_binds_execution_exit_and_exit_fee() {
        let request = paid_v2_request();
        let exit = Address::from_low_u64_be(9);
        let fee_asset = Address::from_low_u64_be(10);
        let mut fee_asset_word = [0_u8; 32];
        fee_asset_word[12..].copy_from_slice(fee_asset.as_bytes());
        let mut exit_topic = [0_u8; 32];
        exit_topic[12..].copy_from_slice(exit.as_bytes());
        let mut data = vec![0_u8; 224];
        data[..32].copy_from_slice(&fee_asset_word);
        U256::from(77).to_big_endian(&mut data[32..64]);
        U256::from(23).to_big_endian(&mut data[64..96]);
        data[127] = 1;
        data[159] = 1;
        let log = Log {
            address: Address::from_slice(&request.entry_point),
            topics: vec![
                H256::from(keccak256(PAID_EXECUTION_SETTLED_SIGNATURE)),
                H256::from(request.execution_id),
                H256::from_low_u64_be(1),
                H256::from(exit_topic),
            ],
            data: Bytes::from(data),
            ..Default::default()
        };

        let settlement = parse_paid_v2_settlement(&request, exit, &[log]).unwrap();
        assert_eq!(settlement.fee_asset, fee_asset);
        assert_eq!(settlement.exit_fee, U256::from(77));
    }
}
