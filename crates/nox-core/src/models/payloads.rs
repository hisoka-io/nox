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
    match bytes.split_first() {
        None => Err("empty payload bytes".into()),
        Some((&ver, body)) => {
            if ver != PAYLOAD_VERSION {
                return Err(format!("unsupported payload version {ver}"));
            }
            bincode::deserialize(body).map_err(|e| e.to_string())
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
                .allow_trailing_bytes()
                .deserialize(body)
                .map_err(|e| e.to_string())
        }
    }
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
