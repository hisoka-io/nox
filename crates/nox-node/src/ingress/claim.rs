//! Claim protocol v2: request options and response encodings for
//! `POST /api/v1/responses/claim` (see `docs/claim-api.md`).
//!
//! Every v2 option is an optional field of the JSON request body, so a v1
//! client (which sends only `surb_ids`) gets exactly the v1 behaviour: a JSON
//! array of `{"data":[numbers],"id":...}` items and delete-on-claim. A v2
//! client talking to a v1 node gets that same v1 answer, which it recognises
//! by its `Content-Type`.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tokio::sync::Semaphore;

use super::response_buffer::ClaimedReply;

/// `Content-Type` of the binary claim batch.
pub const CLAIM_BATCH_CONTENT_TYPE: &str = "application/vnd.nox.claim-batch";
/// Version byte at the start of a binary claim batch.
pub const CLAIM_BATCH_VERSION: u8 = 1;
/// Per-item flag in the binary batch: a retaining claim returned this reply
/// before.
pub const CLAIM_ITEM_FLAG_RECLAIMED: u8 = 0x01;
/// Response header naming the claim protocol version the node speaks.
pub const CLAIM_VERSION_HEADER: &str = "x-nox-claim-version";
/// Claim protocol version this node speaks.
pub const CLAIM_VERSION: &str = "2";
/// Response header with the longest `wait_ms` the node honours.
pub const CLAIM_WAIT_MAX_HEADER: &str = "x-nox-claim-wait-max-ms";
/// Response header listing the optional claim features this node supports.
pub const CLAIM_FEATURES_HEADER: &str = "x-nox-claim-features";
/// Optional claim features this node supports: `max-replies` (the
/// `max_replies` field) and `ack-ahead` (an ack for a reply that has not
/// arrived yet drops it when it arrives).
pub const CLAIM_FEATURES: &str = "max-replies, ack-ahead";

/// Default longest long-poll a claim may ask for.
pub const DEFAULT_CLAIM_WAIT_MAX_MS: u64 = 20_000;
/// Default number of claims that may long-poll at once.
pub const DEFAULT_CLAIM_WAIT_MAX_CONCURRENT: usize = 256;

/// How the claimed replies are written in the response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClaimEncoding {
    /// v1: `[{"data":[0..255,...],"id":"..."}]`, `application/json`.
    #[default]
    Json,
    /// `[{"id":"...","data_b64":"...","reclaimed":false}]`, `application/json`.
    Base64,
    /// Length-prefixed binary batch, [`CLAIM_BATCH_CONTENT_TYPE`].
    Binary,
}

impl ClaimEncoding {
    /// Reads the `encoding` field. Unknown values fall back to JSON, which
    /// every client understands, so a newer client never gets an error here.
    #[must_use]
    pub fn from_field(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "binary" => Self::Binary,
            "base64" => Self::Base64,
            _ => Self::Json,
        }
    }

    /// Picks the encoding from an `Accept` header value: binary when it names
    /// [`CLAIM_BATCH_CONTENT_TYPE`], JSON otherwise.
    #[must_use]
    pub fn from_accept(accept: &str) -> Self {
        let names_batch = accept.split(',').any(|range| {
            range.split(';').next().is_some_and(|essence| {
                essence
                    .trim()
                    .eq_ignore_ascii_case(CLAIM_BATCH_CONTENT_TYPE)
            })
        });
        if names_batch {
            Self::Binary
        } else {
            Self::Json
        }
    }

    /// Metric label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Base64 => "base64",
            Self::Binary => "binary",
        }
    }
}

/// Body of `POST /api/v1/responses/claim`. Unknown fields are ignored.
#[derive(Debug, Deserialize)]
pub struct ClaimRequest {
    /// SURB IDs to claim, each exactly 32 hex characters.
    pub surb_ids: Vec<String>,
    /// `json` (default), `base64` or `binary`. Takes precedence over `Accept`.
    #[serde(default)]
    pub encoding: Option<String>,
    /// Keep the returned replies until acked or until the claim grace has
    /// passed, so a cut-off transfer can be claimed again.
    #[serde(default)]
    pub retain: bool,
    /// IDs of replies the client has; removed before the claim runs.
    #[serde(default)]
    pub ack: Vec<String>,
    /// Hold the request until at least one reply is available or this many
    /// milliseconds have passed (capped by the node). Honoured only with
    /// `retain`, so a reply is never lost to a client that left mid-wait.
    #[serde(default)]
    pub wait_ms: u64,
    /// Return at most this many replies, the ones that arrived first; the
    /// rest stay for a later claim. Absent or 0: no limit.
    #[serde(default)]
    pub max_replies: Option<usize>,
}

impl ClaimRequest {
    /// Largest number of replies to return.
    #[must_use]
    pub fn reply_limit(&self) -> usize {
        match self.max_replies {
            None | Some(0) => usize::MAX,
            Some(n) => n,
        }
    }
}

/// Long-poll limits shared by every claim.
#[derive(Debug, Clone)]
pub struct ClaimSettings {
    /// Longest `wait_ms` honoured.
    pub wait_max: Duration,
    /// One permit per claim that is long-polling.
    pub wait_slots: Arc<Semaphore>,
}

impl ClaimSettings {
    #[must_use]
    pub fn new(wait_max: Duration, max_concurrent_waits: usize) -> Self {
        Self {
            wait_max,
            wait_slots: Arc::new(Semaphore::new(max_concurrent_waits)),
        }
    }
}

impl Default for ClaimSettings {
    fn default() -> Self {
        Self::new(
            Duration::from_millis(DEFAULT_CLAIM_WAIT_MAX_MS),
            DEFAULT_CLAIM_WAIT_MAX_CONCURRENT,
        )
    }
}

/// Binary claim batch (all integers big-endian):
///
/// ```text
/// u8  version (= 1)
/// u16 item count
/// per item:
///   u8  flags (bit 0: reclaimed)
///   u16 id length, then the id (ASCII)
///   u32 data length, then the data
/// ```
///
/// Items whose id or data do not fit their length field are left out; the
/// node's ids are at most a few dozen bytes and a reply is one Sphinx
/// payload, so this never happens with replies the node stores.
#[must_use]
pub fn encode_batch(replies: &[ClaimedReply]) -> Vec<u8> {
    let fits = |reply: &&ClaimedReply| {
        u16::try_from(reply.id.len()).is_ok() && u32::try_from(reply.data.len()).is_ok()
    };
    let items: Vec<&ClaimedReply> = replies
        .iter()
        .filter(fits)
        .take(usize::from(u16::MAX))
        .collect();
    let size = 3 + items
        .iter()
        .map(|reply| 1 + 2 + reply.id.len() + 4 + reply.data.len())
        .sum::<usize>();
    let mut out = Vec::with_capacity(size);
    out.push(CLAIM_BATCH_VERSION);
    out.extend_from_slice(&(items.len() as u16).to_be_bytes());
    for reply in items {
        out.push(if reply.reclaimed {
            CLAIM_ITEM_FLAG_RECLAIMED
        } else {
            0
        });
        out.extend_from_slice(&(reply.id.len() as u16).to_be_bytes());
        out.extend_from_slice(reply.id.as_bytes());
        out.extend_from_slice(&(reply.data.len() as u32).to_be_bytes());
        out.extend_from_slice(&reply.data);
    }
    out
}

/// v1 JSON items: `{"id":"...","data":[...]}`, built exactly as v1 nodes build them.
#[must_use]
pub fn encode_json(replies: &[ClaimedReply]) -> serde_json::Value {
    serde_json::Value::Array(
        replies
            .iter()
            .map(|reply| serde_json::json!({ "id": reply.id, "data": reply.data }))
            .collect(),
    )
}

/// Base64 JSON items: `{"id":"...","data_b64":"...","reclaimed":bool}`.
#[must_use]
pub fn encode_base64_json(replies: &[ClaimedReply]) -> serde_json::Value {
    serde_json::Value::Array(replies.iter().map(base64_item).collect())
}

/// One reply as a base64 JSON object (also used by the SSE and WebSocket
/// streams when a client asks for `encoding=base64`).
#[must_use]
pub fn base64_item(reply: &ClaimedReply) -> serde_json::Value {
    serde_json::json!({
        "id": reply.id,
        "data_b64": base64_encode(&reply.data),
        "reclaimed": reply.reclaimed,
    })
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 (RFC 4648 §4) with `=` padding.
#[must_use]
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        let sextet = |shift: u32| char::from(BASE64_ALPHABET[((n >> shift) & 0x3f) as usize]);
        out.push(sextet(18));
        out.push(sextet(12));
        out.push(if chunk.len() > 1 { sextet(6) } else { '=' });
        out.push(if chunk.len() > 2 { sextet(0) } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(id: &str, data: &[u8], reclaimed: bool) -> ClaimedReply {
        ClaimedReply {
            id: id.to_string(),
            data: data.to_vec(),
            reclaimed,
        }
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(input.as_bytes()), expected, "{input:?}");
        }
        assert_eq!(base64_encode(&[0xfb, 0xff, 0xbf]), "+/+/");
    }

    #[test]
    fn batch_layout_is_exact() {
        let batch = encode_batch(&[reply("ab", &[1, 2, 3], false), reply("c", &[], true)]);
        assert_eq!(
            batch,
            vec![
                1, 0, 2, // version, count
                0, 0, 2, b'a', b'b', 0, 0, 0, 3, 1, 2, 3, // item 1
                1, 0, 1, b'c', 0, 0, 0, 0, // item 2, reclaimed
            ]
        );
        assert_eq!(encode_batch(&[]), vec![1, 0, 0]);
    }

    #[test]
    fn json_encoding_is_the_v1_shape() {
        // Key order follows serde_json's `preserve_order` feature, so compare values.
        let json = encode_json(&[reply("reply-0-aa", &[7, 255], true)]);
        assert_eq!(
            json,
            serde_json::json!([{ "id": "reply-0-aa", "data": [7, 255] }])
        );
        let json = encode_base64_json(&[reply("reply-0-aa", &[7, 255], true)]);
        assert_eq!(
            json,
            serde_json::json!([{ "id": "reply-0-aa", "data_b64": "B/8=", "reclaimed": true }])
        );
    }

    #[test]
    fn encoding_negotiation() {
        assert_eq!(ClaimEncoding::from_field("binary"), ClaimEncoding::Binary);
        assert_eq!(ClaimEncoding::from_field("BASE64"), ClaimEncoding::Base64);
        assert_eq!(ClaimEncoding::from_field("json"), ClaimEncoding::Json);
        assert_eq!(ClaimEncoding::from_field("zstd"), ClaimEncoding::Json);
        assert_eq!(
            ClaimEncoding::from_accept("application/json, application/vnd.nox.claim-batch;q=0.9"),
            ClaimEncoding::Binary
        );
        assert_eq!(
            ClaimEncoding::from_accept("Application/Vnd.Nox.Claim-Batch"),
            ClaimEncoding::Binary
        );
        assert_eq!(ClaimEncoding::from_accept("*/*"), ClaimEncoding::Json);
        assert_eq!(
            ClaimEncoding::from_accept("application/vnd.nox.claim-batchx"),
            ClaimEncoding::Json
        );
    }

    #[test]
    fn v1_bodies_parse_with_v1_defaults() {
        let req: ClaimRequest =
            serde_json::from_str(r#"{"surb_ids":["00"],"future_field":1}"#).expect("parses");
        assert!(req.encoding.is_none());
        assert!(!req.retain);
        assert!(req.ack.is_empty());
        assert_eq!(req.wait_ms, 0);
    }
}
