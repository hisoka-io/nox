//! The anon-rpc `kps:` bundle-resolver profile (SPEC §4.2), exercised the way
//! the reference harness fetches: one GET per stream with `Host` = certhash
//! and `Accept-Encoding`, `closeWrite`, read to EOF, decode, keccak check.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

mod common;

use std::io::Read;
use std::path::Path;
use std::time::Duration;

use common::{dial, eventually, exchange, raw_request, request, TestServer, Transport, T};
use nox_kps::bundles::keccak256_hex;

fn bundle_bytes() -> Vec<u8> {
    // Bundle-like content: compressible text, a few hundred KiB.
    let mut js = String::from("(()=>{\"use strict\";");
    for i in 0..20_000 {
        js.push_str(&format!("var v{i}=\"anon-rpc nox worker {}\";", i % 97));
    }
    js.push_str("})();\n");
    js.into_bytes()
}

fn publish(dir: &Path, bytes: &[u8]) -> String {
    let hash = keccak256_hex(bytes);
    std::fs::create_dir_all(dir.join(&hash[..2])).unwrap();
    std::fs::write(dir.join(&hash[..2]).join(&hash[2..]), bytes).unwrap();
    hash
}

fn harness_get(path: &str, certhash: &str, accept_encoding: Option<&str>) -> Vec<u8> {
    let mut headers = vec![("Host", certhash)];
    if let Some(ae) = accept_encoding {
        headers.push(("Accept-Encoding", ae));
    }
    raw_request("GET", path, &headers, b"")
}

fn bundle_config(raw: &mut nox_kps::RawConfig, dir: String, gzip: bool) {
    raw.keccak_dir = dir;
    raw.limits.bundle_gzip = gzip;
    raw.limits.bundle_rate_per_ip = 1000;
    raw.limits.bundle_burst = 1000;
}

async fn serves_bundles(transport: Transport) {
    let bundles = tempfile::tempdir().unwrap();
    let bytes = bundle_bytes();
    let hash = publish(bundles.path(), &bytes);
    // A file whose bytes do not match its name is never served.
    let fake = keccak256_hex(b"what the name promises");
    std::fs::create_dir_all(bundles.path().join(&fake[..2])).unwrap();
    std::fs::write(
        bundles.path().join(&fake[..2]).join(&fake[2..]),
        b"something else",
    )
    .unwrap();

    let dir = bundles.path().to_string_lossy().into_owned();
    let t = TestServer::start(|raw| bundle_config(raw, dir, false)).await;
    let conn = dial(&t.addr(), transport).await;
    let ch = t.certhash();
    let path = format!("/keccak/{}/{}", &hash[..2], &hash[2..]);

    // v1 serves identity bytes even to a harness that lists gzip.
    let res = exchange(
        conn.as_ref(),
        &harness_get(&path, &ch, Some("zstd, br, gzip, deflate")),
    )
    .await;
    assert_eq!(res.status, 200, "{}", transport.name());
    assert!(res.header("content-encoding").is_none());
    assert_eq!(
        res.header("cache-control"),
        Some("public, max-age=31536000, immutable")
    );
    assert_eq!(res.header("content-type"), Some("text/javascript"));
    assert_eq!(keccak256_hex(&res.body), hash, "bytes hash to the name");

    // Harness without decoders: identity bytes.
    let res = exchange(conn.as_ref(), &harness_get(&path, &ch, None)).await;
    assert_eq!(res.status, 200);
    assert!(res.header("content-encoding").is_none());
    assert_eq!(keccak256_hex(&res.body), hash);

    // HEAD: headers only.
    let res = exchange(
        conn.as_ref(),
        &raw_request("HEAD", &path, &[("Host", ch.as_str())], b""),
    )
    .await;
    assert_eq!(res.status, 200);
    assert!(res.body.is_empty());

    for (missing, want) in [
        (format!("/keccak/{}/{}", &fake[..2], &fake[2..]), 404),
        (format!("/keccak/{}/{}", &hash[..2], &hash[2..63]), 404),
        (format!("/keccak/{}", hash), 404),
        (
            format!(
                "/keccak/{}/{}",
                hash[..2].to_uppercase().replace(char::is_numeric, "A"),
                &hash[2..]
            ),
            404,
        ),
        (format!("/keccak/{}/{}/x", &hash[..2], &hash[2..]), 404),
    ] {
        let res = exchange(conn.as_ref(), &harness_get(&missing, &ch, Some("gzip"))).await;
        assert_eq!(res.status, want, "{missing}");
    }
    let res = exchange(conn.as_ref(), &request("POST", &path, &ch, &[], b"x")).await;
    assert_eq!(res.status, 405);

    let res = exchange(
        conn.as_ref(),
        &request("GET", "/metadata.json", &ch, &[], b""),
    )
    .await;
    let doc: serde_json::Value = serde_json::from_slice(&res.body).unwrap();
    assert!(doc["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c == "worker-bundles"));
    assert_eq!(t.upstream.count(), 0, "bundles are served locally");
    let metrics = t.metrics_text().await;
    assert!(metrics.contains("nox_kps_bundles_loaded 1"), "{metrics}");
    assert!(
        metrics.contains("nox_kps_bundle_requests_total{result=\"hit\"} 3"),
        "{metrics}"
    );
    assert!(
        metrics.contains("nox_kps_bundle_requests_total{result=\"miss\"} 5"),
        "{metrics}"
    );
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gzip_is_served_when_enabled() {
    let bundles = tempfile::tempdir().unwrap();
    let bytes = bundle_bytes();
    let hash = publish(bundles.path(), &bytes);
    let dir = bundles.path().to_string_lossy().into_owned();
    let t = TestServer::start(|raw| bundle_config(raw, dir, true)).await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let path = format!("/keccak/{}/{}", &hash[..2], &hash[2..]);
    let res = exchange(
        conn.as_ref(),
        &harness_get(&path, &t.certhash(), Some("gzip")),
    )
    .await;
    assert_eq!(res.status, 200);
    assert_eq!(res.header("content-encoding"), Some("gzip"));
    assert_eq!(res.header("vary"), Some("accept-encoding"));
    assert!(res.body.len() < bytes.len(), "compressed on the wire");
    let mut decoded = Vec::new();
    flate2::read::GzDecoder::new(res.body.as_slice())
        .read_to_end(&mut decoded)
        .unwrap();
    assert_eq!(
        keccak256_hex(&decoded),
        hash,
        "decoded bytes hash to the name"
    );
    let res = exchange(conn.as_ref(), &harness_get(&path, &t.certhash(), None)).await;
    assert!(res.header("content-encoding").is_none());
    assert_eq!(keccak256_hex(&res.body), hash);
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bundle_requests_are_rate_limited_per_ip() {
    let bundles = tempfile::tempdir().unwrap();
    let hash = publish(bundles.path(), b"rate limited bundle");
    let dir = bundles.path().to_string_lossy().into_owned();
    let t = TestServer::start(|raw| raw.keccak_dir = dir).await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let path = format!("/keccak/{}/{}", &hash[..2], &hash[2..]);
    let mut statuses = Vec::new();
    for _ in 0..7 {
        statuses.push(
            exchange(conn.as_ref(), &harness_get(&path, &t.certhash(), None))
                .await
                .status,
        );
    }
    assert_eq!(
        statuses,
        [200, 200, 200, 200, 200, 429, 429],
        "default burst of 5"
    );
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_missing_keccak_dir_stops_startup() {
    let upstream = common::MockUpstream::start().await;
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("kps.key");
    nox_kps::identity::init(&key).unwrap();
    let mut raw = common::base_config(&upstream, &key);
    raw.keccak_dir = dir.path().join("absent").to_string_lossy().into_owned();
    let err = nox_kps::start(raw.validate().unwrap()).await.unwrap_err();
    assert!(err.to_string().contains("keccak_dir"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn serves_bundles_over_quic() {
    serves_bundles(Transport::Quic).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn serves_bundles_over_webrtc() {
    serves_bundles(Transport::WebRtc).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rescans_pick_up_published_and_removed_bundles() {
    let bundles = tempfile::tempdir().unwrap();
    let first = publish(bundles.path(), b"first bundle");
    let dir = bundles.path().to_string_lossy().into_owned();
    let t = TestServer::start(|raw| {
        bundle_config(raw, dir, false);
        raw.limits.bundle_rescan_secs = 1;
    })
    .await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let ch = t.certhash();
    let get =
        |hash: &str| harness_get(&format!("/keccak/{}/{}", &hash[..2], &hash[2..]), &ch, None);

    assert_eq!(exchange(conn.as_ref(), &get(&first)).await.status, 200);
    let second = publish(bundles.path(), b"second bundle");
    std::fs::remove_file(bundles.path().join(&first[..2]).join(&first[2..])).unwrap();

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let a = exchange(conn.as_ref(), &get(&second)).await.status;
        let b = exchange(conn.as_ref(), &get(&first)).await.status;
        if a == 200 && b == 404 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "rescan did not apply (second {a}, first {b})"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(eventually(T, || true).await);
    t.stop().await;
}
