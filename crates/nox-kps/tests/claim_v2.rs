//! Claim protocol v2 through nox-kps: long-poll caps and slots, the extended
//! upstream timeout, `Accept` negotiation for the binary batch, the claim
//! headers relayed from the node, and the v2 body checks.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

mod common;

use std::time::{Duration, Instant};

use common::{
    dial, exchange, packet, packet_request, request, TestServer, Transport,
    MOCK_NODE_CLAIM_WAIT_MAX_MS, SURB_ID,
};

fn claim_body(fields: serde_json::Value) -> Vec<u8> {
    let mut body = serde_json::json!({ "surb_ids": [SURB_ID] });
    if let (Some(out), Some(extra)) = (body.as_object_mut(), fields.as_object()) {
        for (k, v) in extra {
            out.insert(k.clone(), v.clone());
        }
    }
    serde_json::to_vec(&body).unwrap()
}

fn claim_with(certhash: &str, fields: serde_json::Value, extra: &[(&str, &str)]) -> Vec<u8> {
    let mut headers = vec![("Content-Type", "application/json")];
    headers.extend_from_slice(extra);
    request(
        "POST",
        "/api/v1/responses/claim",
        certhash,
        &headers,
        &claim_body(fields),
    )
}

fn sent_body(t: &TestServer) -> serde_json::Value {
    serde_json::from_slice(&t.upstream.last().body).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn long_poll_is_capped_relayed_and_outlives_the_claim_timeout() {
    let t = TestServer::start(|raw| {
        raw.limits.claim_wait_max_ms = 600;
        raw.limits.upstream_claim_timeout_ms = 300;
    })
    .await;
    t.upstream.behaviour.lock().unwrap().claims_wait_then_empty = true;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let ch = t.certhash();

    let started = Instant::now();
    let res = exchange(
        conn.as_ref(),
        &claim_with(
            &ch,
            serde_json::json!({ "retain": true, "wait_ms": 60_000, "encoding": "binary" }),
            &[],
        ),
    )
    .await;
    let elapsed = started.elapsed();
    assert_eq!(res.status, 204, "{}", res.text());
    assert!(
        elapsed >= Duration::from_millis(590),
        "held for the capped wait: {elapsed:?}"
    );
    let sent = sent_body(&t);
    assert_eq!(sent["wait_ms"], 600, "capped to limits.claim_wait_max_ms");
    assert_eq!(sent["encoding"], "binary", "other fields relayed untouched");
    assert_eq!(sent["retain"], true);
    assert_eq!(res.header("x-nox-claim-version"), Some("2"));
    assert_eq!(
        res.header("x-nox-claim-wait-max-ms"),
        Some("600"),
        "lowered from the node's {MOCK_NODE_CLAIM_WAIT_MAX_MS} to the relay's cap"
    );
    let metrics = t.metrics_text().await;
    assert!(
        metrics.contains(r#"nox_kps_claim_waits_total{result="granted"} 1"#),
        "{metrics}"
    );
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn waits_without_retain_or_with_waits_off_are_not_held() {
    let t = TestServer::start(|raw| {
        raw.limits.claim_wait_max_ms = 0;
    })
    .await;
    t.upstream.behaviour.lock().unwrap().claims_wait_then_empty = true;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let ch = t.certhash();

    let res = exchange(
        conn.as_ref(),
        &claim_with(&ch, serde_json::json!({ "wait_ms": 5_000 }), &[]),
    )
    .await;
    assert_eq!(res.status, 204);
    assert_eq!(
        sent_body(&t)["wait_ms"],
        5_000,
        "no retain: relayed as sent, the node ignores it"
    );

    let started = Instant::now();
    let res = exchange(
        conn.as_ref(),
        &claim_with(
            &ch,
            serde_json::json!({ "retain": true, "wait_ms": 5_000 }),
            &[],
        ),
    )
    .await;
    assert_eq!(res.status, 204);
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(
        sent_body(&t)["wait_ms"],
        0,
        "long-polling off: rewritten to 0"
    );
    assert!(t
        .metrics_text()
        .await
        .contains(r#"nox_kps_claim_waits_total{result="off"} 1"#));
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn long_polls_use_their_own_slots() {
    let t = TestServer::start(|raw| {
        raw.limits.claim_wait_max_ms = 2_000;
        raw.limits.max_concurrent_claim_waits = 1;
        raw.limits.max_inflight_upstream = 1;
    })
    .await;
    t.upstream.behaviour.lock().unwrap().claims_wait_then_empty = true;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let ch = t.certhash();

    let held = {
        let conn = dial(&t.addr(), Transport::Quic).await;
        let req = claim_with(
            &ch,
            serde_json::json!({ "retain": true, "wait_ms": 2_000 }),
            &[],
        );
        tokio::spawn(async move { exchange(conn.as_ref(), &req).await.status })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The held long-poll takes neither the only in-flight slot ...
    let res = exchange(conn.as_ref(), &packet_request(&ch, &packet(1))).await;
    assert_eq!(res.status, 202, "{}", res.text());
    // ... nor leaves room for a second long-poll, which answers at once.
    let started = Instant::now();
    let res = exchange(
        conn.as_ref(),
        &claim_with(
            &ch,
            serde_json::json!({ "retain": true, "wait_ms": 2_000 }),
            &[],
        ),
    )
    .await;
    assert_eq!(res.status, 204);
    assert!(started.elapsed() < Duration::from_millis(1_500));
    assert_eq!(sent_body(&t)["wait_ms"], 0);
    assert_eq!(held.await.unwrap(), 204);
    let metrics = t.metrics_text().await;
    assert!(metrics.contains(r#"nox_kps_claim_waits_total{result="busy"} 1"#));
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accept_for_the_binary_batch_reaches_the_node() {
    let t = TestServer::start(|_| {}).await;
    let conn = dial(&t.addr(), Transport::WebRtc).await;
    let ch = t.certhash();

    let res = exchange(
        conn.as_ref(),
        &claim_with(
            &ch,
            serde_json::json!({}),
            &[(
                "Accept",
                "application/json, application/vnd.nox.claim-batch",
            )],
        ),
    )
    .await;
    assert_eq!(res.status, 200);
    assert_eq!(
        t.upstream.last().headers["accept"],
        "application/vnd.nox.claim-batch"
    );

    let res = exchange(
        conn.as_ref(),
        &claim_with(&ch, serde_json::json!({}), &[("Accept", "*/*")]),
    )
    .await;
    assert_eq!(res.status, 200);
    assert!(
        t.upstream.last().headers.get("accept").is_none(),
        "other Accept values are not relayed"
    );
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v2_fields_are_checked() {
    let t = TestServer::start(|raw| {
        raw.limits.claim_max_surb_ids = 2;
        raw.limits.claim_response_max_bytes = nox_kps::config::max_claim_response_bytes(2);
    })
    .await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let ch = t.certhash();
    let before = t.upstream.count();
    for (fields, needle) in [
        (serde_json::json!({ "ack": ["zz"] }), "ack[0]"),
        (
            serde_json::json!({ "ack": [SURB_ID, SURB_ID, SURB_ID] }),
            "at most 2 ack",
        ),
        (serde_json::json!({ "retain": "yes" }), "claim body must be"),
        (serde_json::json!({ "wait_ms": -1 }), "claim body must be"),
        (
            serde_json::json!({ "encoding": "x".repeat(40) }),
            "encoding is at most",
        ),
    ] {
        let res = exchange(conn.as_ref(), &claim_with(&ch, fields.clone(), &[])).await;
        assert_eq!(res.status, 400, "{fields}");
        assert!(res.text().contains(needle), "{fields}: {}", res.text());
    }
    assert_eq!(t.upstream.count(), before, "nothing reached the node");

    let res = exchange(
        conn.as_ref(),
        &claim_with(
            &ch,
            serde_json::json!({ "ack": [SURB_ID], "encoding": "base64", "future": 1 }),
            &[],
        ),
    )
    .await;
    assert_eq!(res.status, 200, "{}", res.text());
    assert_eq!(sent_body(&t)["future"], 1, "unknown fields pass through");
    t.stop().await;
}
