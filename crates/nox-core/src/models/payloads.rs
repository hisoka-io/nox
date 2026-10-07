use serde::{Deserialize, Serialize};

use crate::protocol::fragmentation::Fragment;
use nox_crypto::sphinx::surb::Surb;

/// Current payload wire version. Prepended as a 1-byte prefix to all bincode payloads.
pub const PAYLOAD_VERSION: u8 = 1;

/// Encode a value for wire transport: `[version: u8][bincode body: ...]`.
pub fn encode_payload<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let body = bincode::serialize(value).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(PAYLOAD_VERSION);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode a versioned wire payload back into `T`.
pub fn decode_payload<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, String> {
    use bincode::Options;
    match bytes.split_first() {
        None => Err("empty payload bytes".into()),
        Some((&ver, body)) => {
            if ver != PAYLOAD_VERSION {
                return Err(format!("unsupported payload version {ver}"));
            }
            bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .reject_trailing_bytes()
                .deserialize(body)
                .map_err(|e| e.to_string())
        }
    }
}

/// Like `decode_payload` but with a bincode size limit to prevent OOM from malicious packets.
pub fn decode_payload_limited<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    max_bytes: u64,
) -> Result<T, String> {
    use bincode::Options;
    match bytes.split_first() {
        None => Err("empty payload bytes".into()),
        Some((&ver, body)) => {
            if ver != PAYLOAD_VERSION {
                return Err(format!("unsupported payload version {ver}"));
            }
            bincode::DefaultOptions::new()
                .with_limit(max_bytes)
                .with_fixint_encoding()
                .deserialize(body)
                .map_err(|e| e.to_string())
        }
    }
}

pub fn decode_padded_relayer_payload_limited(
    bytes: &[u8],
    max_bytes: u64,
) -> Result<RelayerPayload, String> {
    use bincode::Options;
    if u64::try_from(bytes.len()).map_or(true, |length| length > max_bytes) {
        return Err(format!(
            "padded relayer payload exceeds {max_bytes}-byte limit"
        ));
    }
    let (&version, body) = bytes
        .split_first()
        .ok_or_else(|| "empty payload bytes".to_string())?;
    if version != PAYLOAD_VERSION {
        return Err(format!("unsupported payload version {version}"));
    }
    let mut cursor = std::io::Cursor::new(body);
    let payload = bincode::DefaultOptions::new()
        .with_limit(max_bytes.saturating_sub(1))
        .with_fixint_encoding()
        .deserialize_from(&mut cursor)
        .map_err(|error| error.to_string())?;
    let consumed = usize::try_from(cursor.position())
        .map_err(|_| "decoded relayer payload length exceeds usize".to_string())?;
    if !body
        .get(consumed..)
        .ok_or_else(|| "decoded relayer payload length exceeds input".to_string())?
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err("padded relayer payload has nonzero trailing bytes".to_string());
    }
    Ok(payload)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelayerPayload {
    /// `to` is raw 20-byte Ethereum address (no hex encoding overhead on wire).
    SubmitTransaction {
        to: [u8; 20],
        data: Vec<u8>,
    },
    Dummy {
        padding: Vec<u8>,
    },
    Heartbeat {
        id: u64,
        timestamp: u64,
    },
    Fragment {
        frag: Fragment,
    },
    AnonymousRequest {
        inner: Vec<u8>,
        reply_surbs: Vec<Surb>,
    },
    ServiceResponse {
        request_id: u64,
        fragment: Fragment,
    },
    /// Exit node exhausted reply SURBs; sent in the last available SURB so the
    /// client can deliver a fresh batch for the exit to resume sending.
    NeedMoreSurbs {
        request_id: u64,
        fragments_remaining: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaidTransactionRequestV2 {
    pub chain_id: u64,
    pub entry_point: [u8; 20],
    pub calldata: Vec<u8>,
    pub execution_id: [u8; 32],
    pub valid_until_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaidQuoteRequestV2 {
    pub chain_id: u64,
    pub entry_point: [u8; 20],
    pub client_intent_id: [u8; 32],
    pub payment_adapter: [u8; 20],
    pub payment_id: [u8; 32],
    pub fee_asset: [u8; 20],
    pub payment_gas_limit: u64,
    pub action_target: [u8; 20],
    pub action_calldata_hash: [u8; 32],
    pub action_gas_limit: u64,
    pub tracked_assets_hash: [u8; 32],
    pub maximum_transaction_gas: u64,
    pub return_data_limit: u32,
    pub valid_until_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionQuoteV1 {
    pub quote_version: u8,
    pub chain_id: [u8; 32],
    pub entry_point: [u8; 20],
    pub exit_address: [u8; 20],
    pub client_intent_id: [u8; 32],
    pub payment_adapter: [u8; 20],
    pub payment_id: [u8; 32],
    pub fee_asset: [u8; 20],
    pub exit_fee: [u8; 32],
    pub network_fee: [u8; 32],
    pub payment_gas_limit: [u8; 32],
    pub action_target: [u8; 20],
    pub action_calldata_hash: [u8; 32],
    pub action_gas_limit: [u8; 32],
    pub tracked_assets_hash: [u8; 32],
    pub maximum_transaction_gas: [u8; 32],
    pub maximum_fee_per_gas: [u8; 32],
    pub return_data_limit: [u8; 32],
    pub valid_after_unix: u64,
    pub valid_until_unix: u64,
    pub quote_nonce: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "bincode wire layout is frozen across Rust and TypeScript"
)]
pub enum PaidQuoteOutcomeV2 {
    Issued {
        quote: ExecutionQuoteV1,
        execution_id: [u8; 32],
        exit_signature: Vec<u8>,
    },
    Rejected {
        code: PaidTransactionRejectionCodeV2,
        retryable: bool,
        detail: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PaidTransactionRejectionCodeV2 {
    MalformedRequest,
    WrongChain,
    WrongEntryPoint,
    UnknownQuote,
    ExpiredQuote,
    DuplicateExecution,
    SimulationFailure,
    PaymentMissing,
    PaymentReverted,
    UnsupportedFeeAsset,
    StalePrice,
    Unprofitable,
    GasCapExceeded,
    SubmissionFailure,
    UnsupportedPaymentAdapter,
    QuoteCapacityExceeded,
    PendingLossLimit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PaidTransactionOutcomeV2 {
    Submitted {
        execution_id: [u8; 32],
        transaction_hash: [u8; 32],
    },
    Rejected {
        execution_id: Option<[u8; 32]>,
        code: PaidTransactionRejectionCodeV2,
        retryable: bool,
        detail: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceRequest {
    Echo {
        data: Vec<u8>,
    },
    HttpRequest {
        method: String,
        url: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    /// Anonymous JSON-RPC query. `rpc_url: None` uses node default (read-only whitelist enforced).
    RpcRequest {
        method: String,
        params: Vec<u8>,
        id: u64,
        rpc_url: Option<String>,
    },
    SubmitTransaction {
        to: [u8; 20],
        data: Vec<u8>,
    },
    /// Broadcast a pre-signed transaction. Client pays gas; no relayer signing or profitability check.
    BroadcastSignedTransaction {
        signed_tx: Vec<u8>,
        rpc_url: Option<String>,
        /// JSON-RPC method name (None = `eth_sendRawTransaction`)
        rpc_method: Option<String>,
    },
    /// Client sends fresh SURBs to let a stalled exit node resume response delivery.
    ReplenishSurbs {
        request_id: u64,
        surbs: Vec<nox_crypto::sphinx::surb::Surb>,
    },
    PaidTransactionV2(PaidTransactionRequestV2),
    PaidQuoteRequestV2(PaidQuoteRequestV2),
    /// One exchange on an end-to-end TLS tunnel. Exits advertise [`TUNNEL_V1_CAPABILITY`].
    TunnelV1(TunnelRequestV1),
}

/// Capability an exit lists in `/metrics/json` when it accepts [`ServiceRequest::TunnelV1`].
pub const TUNNEL_V1_CAPABILITY: &str = "tunnel_v1";
/// Length of the client-chosen tunnel ID.
pub const TUNNEL_ID_LEN: usize = 16;
/// Most `data` bytes in one [`TunnelReplyV1::Data`] part, sized so a part fits one SURB.
pub const TUNNEL_PART_MAX_DATA: usize = 30_656;
/// Most bytes of [`TunnelReplyV1::Rejected`] `detail`.
pub const TUNNEL_REJECT_DETAIL_MAX: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelRequestV1 {
    pub tunnel_id: [u8; TUNNEL_ID_LEN],
    /// 0 opens the tunnel; each new write or close adds one. A copy repeats the seq.
    pub seq: u32,
    /// Present exactly when `seq` is 0.
    pub open: Option<TunnelOpenV1>,
    /// Contiguous downstream bytes the client holds.
    pub ack_offset: u64,
    /// TLS records to write upstream, identical on every copy of one seq.
    pub data: Vec<u8>,
    /// Half-close the upstream write side after writing `data`.
    pub close: bool,
    /// How long the exit may hold this exchange's SURBs, clamped by the exit.
    pub hold_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelOpenV1 {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TunnelReplyV1 {
    Data {
        seq: u32,
        offset: u64,
        data: Vec<u8>,
        fin: Option<TunnelFinV1>,
    },
    Rejected {
        seq: u32,
        code: TunnelRejectCodeV1,
        retryable: bool,
        detail: String,
    },
}

/// Transport hint on a part. Response completeness comes from HTTP framing or TLS
/// `close_notify`, never from `Eof` alone.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TunnelFinV1 {
    /// The upstream closed and this part reaches its last byte.
    Eof,
    /// Bytes are waiting and this was the exchange's last SURB.
    NeedSurbs,
    /// The hold deadline passed; the remaining SURBs were dropped.
    Expired,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TunnelRejectCodeV1 {
    Malformed,
    Disabled,
    PortNotAllowed,
    HostNotAllowed,
    NotTls,
    DestinationBlocked,
    DnsFailed,
    ConnectFailed,
    SessionLimit,
    RateLimited,
    UnknownSession,
    OutOfOrder,
    ByteLimit,
    UpstreamClosed,
    Expired,
}

impl TunnelRejectCodeV1 {
    /// Whether the client may retry the same open on this or another exit.
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::DnsFailed | Self::ConnectFailed | Self::SessionLimit | Self::RateLimited
        )
    }

    /// Metric label for the code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Disabled => "disabled",
            Self::PortNotAllowed => "port_not_allowed",
            Self::HostNotAllowed => "host_not_allowed",
            Self::NotTls => "not_tls",
            Self::DestinationBlocked => "destination_blocked",
            Self::DnsFailed => "dns_failed",
            Self::ConnectFailed => "connect_failed",
            Self::SessionLimit => "session_limit",
            Self::RateLimited => "rate_limited",
            Self::UnknownSession => "unknown_session",
            Self::OutOfOrder => "out_of_order",
            Self::ByteLimit => "byte_limit",
            Self::UpstreamClosed => "upstream_closed",
            Self::Expired => "expired",
        }
    }

    pub const ALL: [Self; 15] = [
        Self::Malformed,
        Self::Disabled,
        Self::PortNotAllowed,
        Self::HostNotAllowed,
        Self::NotTls,
        Self::DestinationBlocked,
        Self::DnsFailed,
        Self::ConnectFailed,
        Self::SessionLimit,
        Self::RateLimited,
        Self::UnknownSession,
        Self::OutOfOrder,
        Self::ByteLimit,
        Self::UpstreamClosed,
        Self::Expired,
    ];
}

impl TunnelReplyV1 {
    /// A rejection whose `detail` is cut to [`TUNNEL_REJECT_DETAIL_MAX`] bytes on a char
    /// boundary.
    #[must_use]
    pub fn rejected(seq: u32, code: TunnelRejectCodeV1, detail: &str) -> Self {
        let mut end = detail.len().min(TUNNEL_REJECT_DETAIL_MAX);
        while !detail.is_char_boundary(end) {
            end -= 1;
        }
        Self::Rejected {
            seq,
            code,
            retryable: code.retryable(),
            detail: detail[..end].to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    pub id: u64,
    pub result: Result<Vec<u8>, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_broadcast_signed_transaction_roundtrip() {
        let fake_signed_tx = vec![0xf8, 0x65, 0x80, 0x84, 0x3b, 0x9a, 0xca, 0x00];
        let request = ServiceRequest::BroadcastSignedTransaction {
            signed_tx: fake_signed_tx.clone(),
            rpc_url: None,
            rpc_method: None,
        };

        let encoded = encode_payload(&request).expect("encode");
        assert_eq!(encoded[0], PAYLOAD_VERSION);

        let decoded: ServiceRequest = decode_payload(&encoded).expect("decode");

        match decoded {
            ServiceRequest::BroadcastSignedTransaction {
                signed_tx,
                rpc_url,
                rpc_method,
            } => {
                assert_eq!(signed_tx, fake_signed_tx);
                assert!(rpc_url.is_none());
                assert!(rpc_method.is_none());
            }
            other => panic!("expected BroadcastSignedTransaction, got {other:?}"),
        }
    }

    #[test]
    fn test_broadcast_with_custom_rpc_roundtrip() {
        let request = ServiceRequest::BroadcastSignedTransaction {
            signed_tx: vec![0xf8, 0x65],
            rpc_url: Some("https://rpc.ankr.com/eth".to_string()),
            rpc_method: Some("sendTransaction".to_string()),
        };

        let encoded = encode_payload(&request).expect("encode");
        let decoded: ServiceRequest = decode_payload(&encoded).expect("decode");

        match decoded {
            ServiceRequest::BroadcastSignedTransaction {
                signed_tx,
                rpc_url,
                rpc_method,
            } => {
                assert_eq!(signed_tx, vec![0xf8, 0x65]);
                assert_eq!(rpc_url.as_deref(), Some("https://rpc.ankr.com/eth"));
                assert_eq!(rpc_method.as_deref(), Some("sendTransaction"));
            }
            other => panic!("expected BroadcastSignedTransaction, got {other:?}"),
        }
    }

    #[test]
    fn test_relayer_payload_roundtrip() {
        let payload = RelayerPayload::Heartbeat {
            id: 42,
            timestamp: 1_700_000_000,
        };
        let encoded = encode_payload(&payload).expect("encode");
        assert_eq!(encoded[0], PAYLOAD_VERSION);
        let decoded: RelayerPayload = decode_payload(&encoded).expect("decode");
        match decoded {
            RelayerPayload::Heartbeat { id, timestamp } => {
                assert_eq!(id, 42);
                assert_eq!(timestamp, 1_700_000_000);
            }
            other => panic!("expected Heartbeat, got {other:?}"),
        }
    }

    #[test]
    fn test_decode_rejects_unsupported_version() {
        // Build a packet with a version byte of 99.
        let mut bad = vec![99u8];
        bad.extend_from_slice(
            &bincode::serialize(&ServiceRequest::Echo { data: vec![1] }).unwrap(),
        );
        let result: Result<ServiceRequest, _> = decode_payload(&bad);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unsupported payload version"));
    }

    #[test]
    fn test_decode_rejects_empty_bytes() {
        let result: Result<ServiceRequest, _> = decode_payload(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn paid_v2_request_is_append_only_after_legacy_ordinals() {
        let legacy = encode_payload(&ServiceRequest::ReplenishSurbs {
            request_id: 1,
            surbs: Vec::new(),
        })
        .unwrap();
        let request = PaidTransactionRequestV2 {
            chain_id: 421_614,
            entry_point: [1; 20],
            calldata: vec![2, 3],
            execution_id: [4; 32],
            valid_until_unix: 1_800_000_000,
        };
        let encoded = encode_payload(&ServiceRequest::PaidTransactionV2(request.clone())).unwrap();
        assert_eq!(
            hex::encode(&encoded),
            "0106000000ee6e060000000000010101010101010101010101010101010101010102000000000000000203040404040404040404040404040404040404040404040404040404040404040400d2496b00000000",
        );

        assert_eq!(&legacy[1..5], 5_u32.to_le_bytes().as_slice());
        assert_eq!(&encoded[1..5], 6_u32.to_le_bytes().as_slice());
        let decoded: ServiceRequest = decode_payload(&encoded).unwrap();
        assert!(matches!(
            decoded,
            ServiceRequest::PaidTransactionV2(decoded) if decoded == request
        ));
    }

    #[test]
    fn paid_v2_outcome_roundtrips_typed_rejection() {
        let outcome = PaidTransactionOutcomeV2::Rejected {
            execution_id: Some([7; 32]),
            code: PaidTransactionRejectionCodeV2::WrongChain,
            retryable: false,
            detail: "request chain does not match exit chain".to_string(),
        };
        let encoded = encode_payload(&outcome).unwrap();
        let decoded: PaidTransactionOutcomeV2 = decode_payload(&encoded).unwrap();
        assert_eq!(decoded, outcome);
    }

    #[test]
    fn paid_quote_request_is_append_only_at_ordinal_seven() {
        let request = PaidQuoteRequestV2 {
            chain_id: 421_614,
            entry_point: [1; 20],
            client_intent_id: [2; 32],
            payment_adapter: [3; 20],
            payment_id: [4; 32],
            fee_asset: [5; 20],
            payment_gas_limit: 500_000,
            action_target: [6; 20],
            action_calldata_hash: [7; 32],
            action_gas_limit: 700_000,
            tracked_assets_hash: [8; 32],
            maximum_transaction_gas: 1_500_000,
            return_data_limit: 256,
            valid_until_unix: 1_800_000_000,
        };
        let encoded = encode_payload(&ServiceRequest::PaidQuoteRequestV2(request.clone())).unwrap();
        assert_eq!(
            hex::encode(&encoded),
            "0107000000ee6e0600000000000101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020203030303030303030303030303030303030303030404040404040404040404040404040404040404040404040404040404040404050505050505050505050505050505050505050520a10700000000000606060606060606060606060606060606060606070707070707070707070707070707070707070707070707070707070707070760ae0a0000000000080808080808080808080808080808080808080808080808080808080808080860e31600000000000001000000d2496b00000000",
        );
        assert_eq!(&encoded[1..5], 7_u32.to_le_bytes().as_slice());
        let decoded: ServiceRequest = decode_payload(&encoded).unwrap();
        assert!(
            matches!(decoded, ServiceRequest::PaidQuoteRequestV2(decoded) if decoded == request)
        );
    }

    #[test]
    fn paid_quote_rejection_has_a_pinned_wire_vector() {
        let outcome = PaidQuoteOutcomeV2::Rejected {
            code: PaidTransactionRejectionCodeV2::WrongChain,
            retryable: false,
            detail: "wrong chain".to_string(),
        };
        let encoded = encode_payload(&outcome).unwrap();
        assert_eq!(
            hex::encode(&encoded),
            "010100000001000000000b0000000000000077726f6e6720636861696e",
        );
        let decoded: PaidQuoteOutcomeV2 = decode_payload(&encoded).unwrap();
        assert_eq!(decoded, outcome);
    }

    #[test]
    fn paid_quote_issued_has_a_pinned_wire_vector() {
        let word = |value: u64| {
            let mut encoded = [0_u8; 32];
            encoded[24..].copy_from_slice(&value.to_be_bytes());
            encoded
        };
        let quote = ExecutionQuoteV1 {
            quote_version: 1,
            chain_id: word(421_614),
            entry_point: [0x11; 20],
            exit_address: [0x22; 20],
            client_intent_id: [0x33; 32],
            payment_adapter: [0x44; 20],
            payment_id: [0x55; 32],
            fee_asset: [0x66; 20],
            exit_fee: word(77),
            network_fee: word(8),
            payment_gas_limit: word(500_000),
            action_target: [0x77; 20],
            action_calldata_hash: [0x88; 32],
            action_gas_limit: word(700_000),
            tracked_assets_hash: [0x99; 32],
            maximum_transaction_gas: word(1_450_000),
            maximum_fee_per_gas: word(123),
            return_data_limit: word(256),
            valid_after_unix: 1_799_999_900,
            valid_until_unix: 1_800_000_000,
            quote_nonce: word(1),
        };
        let outcome = PaidQuoteOutcomeV2::Issued {
            quote,
            execution_id: [0xab; 32],
            exit_signature: vec![0xcd; 65],
        };
        let encoded = encode_payload(&outcome).unwrap();
        assert_eq!(
            hex::encode(&encoded),
            "0100000000010000000000000000000000000000000000000000000000000000000000066eee111111111111111111111111111111111111111122222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333444444444444444444444444444444444444444455555555555555555555555555555555555555555555555555555555555555556666666666666666666666666666666666666666000000000000000000000000000000000000000000000000000000000000004d0000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000007a1207777777777777777777777777777777777777777888888888888888888888888888888888888888888888888888888888888888800000000000000000000000000000000000000000000000000000000000aae6099999999999999999999999999999999999999999999999999999999999999990000000000000000000000000000000000000000000000000000000000162010000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000001009cd1496b0000000000d2496b000000000000000000000000000000000000000000000000000000000000000000000001abababababababababababababababababababababababababababababababab4100000000000000cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        );
        let decoded: PaidQuoteOutcomeV2 = decode_payload(&encoded).unwrap();
        assert_eq!(decoded, outcome);
    }

    #[test]
    fn paid_v2_wire_rejects_trailing_bytes() {
        let mut transaction = encode_payload(&ServiceRequest::PaidTransactionV2(
            PaidTransactionRequestV2 {
                chain_id: 1,
                entry_point: [1; 20],
                calldata: Vec::new(),
                execution_id: [2; 32],
                valid_until_unix: 3,
            },
        ))
        .unwrap();
        transaction.push(0xff);
        assert!(decode_payload::<ServiceRequest>(&transaction).is_err());
        assert!(decode_payload_limited::<ServiceRequest>(&transaction, 1_024).is_err());

        let mut quote = encode_payload(&ServiceRequest::PaidQuoteRequestV2(PaidQuoteRequestV2 {
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
            maximum_transaction_gas: 2,
            return_data_limit: 0,
            valid_until_unix: 3,
        }))
        .unwrap();
        quote.push(0xff);
        assert!(decode_payload::<ServiceRequest>(&quote).is_err());
        assert!(decode_payload_limited::<ServiceRequest>(&quote, 1_024).is_err());
    }

    fn tunnel_id() -> [u8; TUNNEL_ID_LEN] {
        std::array::from_fn(|i| i as u8)
    }

    #[test]
    fn tunnel_requests_have_pinned_wire_vectors() {
        let open = ServiceRequest::TunnelV1(TunnelRequestV1 {
            tunnel_id: tunnel_id(),
            seq: 0,
            open: Some(TunnelOpenV1 {
                host: "rpc.example".to_string(),
                port: 443,
            }),
            ack_offset: 0,
            data: vec![0x16, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00],
            close: false,
            hold_ms: 20_000,
        });
        let close = ServiceRequest::TunnelV1(TunnelRequestV1 {
            tunnel_id: tunnel_id(),
            seq: 3,
            open: None,
            ack_offset: 5_123,
            data: Vec::new(),
            close: true,
            hold_ms: 20_000,
        });
        for (request, expected) in [
            (
                &open,
                "0108000000000102030405060708090a0b0c0d0e0f00000000010b000000000000007270632e6578616d706c65bb01000000000000000007000000000000001603010002010000204e0000",
            ),
            (
                &close,
                "0108000000000102030405060708090a0b0c0d0e0f03000000000314000000000000000000000000000001204e0000",
            ),
        ] {
            let encoded = encode_payload(request).unwrap();
            assert_eq!(hex::encode(&encoded), expected);
            assert_eq!(&encoded[1..5], 8_u32.to_le_bytes().as_slice());
            let decoded: ServiceRequest = decode_payload(&encoded).unwrap();
            assert!(matches!(
                (decoded, request),
                (ServiceRequest::TunnelV1(a), ServiceRequest::TunnelV1(b)) if a == *b
            ));
        }
    }

    #[test]
    fn tunnel_replies_have_pinned_wire_vectors() {
        for (reply, expected) in [
            (
                TunnelReplyV1::Data {
                    seq: 1,
                    offset: 4_096,
                    data: vec![0x17, 0x03, 0x03, 0x00, 0x01, 0x55],
                    fin: Some(TunnelFinV1::Eof),
                },
                "010000000001000000001000000000000006000000000000001703030001550100000000",
            ),
            (
                TunnelReplyV1::Data {
                    seq: 2,
                    offset: 0,
                    data: vec![0x16, 0x03, 0x03, 0x00, 0x02],
                    fin: None,
                },
                "01000000000200000000000000000000000500000000000000160303000200",
            ),
            (
                TunnelReplyV1::rejected(0, TunnelRejectCodeV1::DestinationBlocked, "blocked"),
                "01010000000000000005000000000700000000000000626c6f636b6564",
            ),
        ] {
            let encoded = encode_payload(&reply).unwrap();
            assert_eq!(hex::encode(&encoded), expected);
            assert_eq!(decode_payload::<TunnelReplyV1>(&encoded).unwrap(), reply);
        }
    }

    #[test]
    fn tunnel_reply_decoding_rejects_trailing_bytes_and_unknown_indices() {
        let mut encoded = encode_payload(&TunnelReplyV1::Data {
            seq: 2,
            offset: 0,
            data: vec![1],
            fin: None,
        })
        .unwrap();
        encoded.push(0);
        assert!(decode_payload::<TunnelReplyV1>(&encoded).is_err());

        let unknown_variant = hex::decode("0102000000").unwrap();
        assert!(decode_payload::<TunnelReplyV1>(&unknown_variant).is_err());

        let mut unknown_fin = encode_payload(&TunnelReplyV1::Data {
            seq: 1,
            offset: 0,
            data: Vec::new(),
            fin: Some(TunnelFinV1::Eof),
        })
        .unwrap();
        let fin_index = unknown_fin.len() - 4;
        unknown_fin[fin_index] = 3;
        assert!(decode_payload::<TunnelReplyV1>(&unknown_fin).is_err());

        let mut unknown_code =
            encode_payload(&TunnelReplyV1::rejected(0, TunnelRejectCodeV1::Expired, "")).unwrap();
        unknown_code[9] = 15;
        assert!(decode_payload::<TunnelReplyV1>(&unknown_code).is_err());
        unknown_code[9] = 14;
        assert!(decode_payload::<TunnelReplyV1>(&unknown_code).is_ok());
    }

    #[test]
    fn tunnel_reject_detail_is_cut_on_a_char_boundary() {
        let detail = "é".repeat(TUNNEL_REJECT_DETAIL_MAX);
        let TunnelReplyV1::Rejected {
            detail, retryable, ..
        } = TunnelReplyV1::rejected(0, TunnelRejectCodeV1::RateLimited, &detail)
        else {
            panic!("expected a rejection");
        };
        assert_eq!(detail.len(), TUNNEL_REJECT_DETAIL_MAX);
        assert!(retryable);
    }

    #[test]
    fn outer_relayer_payload_accepts_only_zero_sphinx_padding() {
        let payload = RelayerPayload::AnonymousRequest {
            inner: encode_payload(&ServiceRequest::Echo { data: vec![1, 2] }).unwrap(),
            reply_surbs: Vec::new(),
        };
        let mut encoded = encode_payload(&payload).unwrap();
        encoded.resize(1_024, 0);
        assert_eq!(
            encode_payload(&decode_padded_relayer_payload_limited(&encoded, 1_024).unwrap())
                .unwrap(),
            encode_payload(&payload).unwrap(),
        );
        *encoded.last_mut().unwrap() = 1;
        assert!(decode_padded_relayer_payload_limited(&encoded, 1_024).is_err());
    }

    /// Verify TS SDK bincode encoding matches Rust (cross-language parity).
    #[test]
    fn test_ts_sdk_anonymous_request_decode() {
        let ts_bytes: Vec<u8> = vec![
            0x01, 0x04, 0x00, 0x00, 0x00, 0x46, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x45,
            0x54, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x74, 0x74, 0x70, 0x73,
            0x3a, 0x2f, 0x2f, 0x68, 0x74, 0x74, 0x70, 0x62, 0x69, 0x6e, 0x2e, 0x6f, 0x72, 0x67,
            0x2f, 0x62, 0x79, 0x74, 0x65, 0x73, 0x2f, 0x31, 0x30, 0x32, 0x34, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(ts_bytes.len(), 91);

        // Rust's own encoding of the same value
        let rust_inner = encode_payload(&ServiceRequest::HttpRequest {
            method: "GET".to_string(),
            url: "https://httpbin.org/bytes/1024".to_string(),
            headers: vec![],
            body: vec![],
        })
        .unwrap();
        let rust_bytes = encode_payload(&RelayerPayload::AnonymousRequest {
            inner: rust_inner,
            reply_surbs: vec![],
        })
        .unwrap();

        assert_eq!(ts_bytes, rust_bytes, "TS SDK / Rust encoding mismatch");

        // Decode and verify the payload structure
        let payload = decode_payload_limited::<RelayerPayload>(&ts_bytes, 65536)
            .expect("TS SDK bytes must decode successfully");
        match payload {
            RelayerPayload::AnonymousRequest { inner, reply_surbs } => {
                assert!(reply_surbs.is_empty());
                let sr = decode_payload_limited::<ServiceRequest>(&inner, 65536)
                    .expect("inner ServiceRequest must decode");
                match sr {
                    ServiceRequest::HttpRequest {
                        method,
                        url,
                        headers,
                        body,
                    } => {
                        assert_eq!(method, "GET");
                        assert_eq!(url, "https://httpbin.org/bytes/1024");
                        assert!(headers.is_empty());
                        assert!(body.is_empty());
                    }
                    other => panic!(
                        "expected HttpRequest, got variant {:?}",
                        std::mem::discriminant(&other)
                    ),
                }
            }
            other => panic!(
                "expected AnonymousRequest, got variant {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }
}
