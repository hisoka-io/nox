//! Golden vectors for the Sphinx builders, and the final-hop padding checks.
//!
//! `zero_fill.json` pins what clients built before final-hop padding was
//! random (they left the unused routing bytes zero); `random_fill.json` pins
//! the current builders. Both are built from seeded RNGs. Regenerate with
//! `NOX_WRITE_SPHINX_VECTORS=1 cargo test -p nox-crypto vectors -- --ignored`.

use super::surb::{Surb, SurbRecovery};
use super::{
    apply_stream_cipher, build_multi_hop_packet_with_rng, derive_keys, into_result, zero_fill,
    PathHop, ProcessResult, SphinxHeader, FINAL_PADDING_OFFSET, MAX_PATH_HOPS, ROUTING_INFO_SIZE,
    SHIFT_SIZE,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

const ZERO_FILL: &str = include_str!("../../tests/vectors/zero_fill.json");
const RANDOM_FILL: &str = include_str!("../../tests/vectors/random_fill.json");

const FORWARD_PAYLOAD: &[u8] = b"nox final-hop padding vector";
const REPLY_MESSAGE: &[u8] = b"reply vector";
const SURB_ID: [u8; 16] = [0x11; 16];
const SURB_HOPS: [usize; 2] = [1, 3];

#[derive(Clone, Copy, PartialEq)]
enum Fill {
    Zero,
    Random,
}

fn hop_secret(i: usize) -> X25519SecretKey {
    X25519SecretKey::from([0x40 + i as u8; 32])
}

fn vector_path(hops: usize) -> (Vec<X25519SecretKey>, Vec<PathHop>) {
    let sks: Vec<X25519SecretKey> = (0..hops).map(hop_secret).collect();
    let path = sks
        .iter()
        .enumerate()
        .map(|(i, sk)| PathHop {
            public_key: X25519PublicKey::from(sk),
            address: format!("hop-{i}"),
        })
        .collect();
    (sks, path)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn forward_packet(fill: Fill, hops: usize, seed: u64) -> Vec<u8> {
    let (_, path) = vector_path(hops);
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    match fill {
        Fill::Zero => {
            zero_fill::build_multi_hop_packet_with_rng(&path, FORWARD_PAYLOAD, 0, &mut rng)
        }
        Fill::Random => build_multi_hop_packet_with_rng(&path, FORWARD_PAYLOAD, 0, &mut rng),
    }
    .expect("build forward packet")
}

fn surb(fill: Fill, v2: bool, hops: usize, seed: u64) -> (Surb, SurbRecovery) {
    let (_, path) = vector_path(hops);
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    match (fill, v2) {
        (Fill::Zero, false) => zero_fill::surb_with_rng(&path, SURB_ID, 0, &mut rng),
        (Fill::Zero, true) => zero_fill::surb_v2_with_rng(&path, 0, &mut rng),
        (Fill::Random, false) => Surb::new_with_rng(&path, SURB_ID, 0, &mut rng),
        (Fill::Random, true) => Surb::new_v2_with_rng(&path, 0, &mut rng),
    }
    .expect("build SURB")
}

fn sealed_reply(surb: &Surb) -> Vec<u8> {
    if surb.is_v2() {
        surb.encapsulate_v2(REPLY_MESSAGE)
    } else {
        surb.encapsulate(REPLY_MESSAGE)
    }
    .expect("seal reply")
    .into_bytes()
}

/// Every vector for one fill, in the layout of the JSON files.
fn vectors(fill: Fill) -> Value {
    let forward: Vec<Value> = (1..=MAX_PATH_HOPS)
        .map(|hops| {
            let seed = 1000 + hops as u64;
            let packet = forward_packet(fill, hops, seed);
            json!({
                "hops": hops,
                "seed": seed,
                "header": hex::encode(&packet[..super::HEADER_SIZE]),
                "packet_sha256": sha256_hex(&packet),
            })
        })
        .collect();
    let surbs: Vec<Value> = [false, true]
        .into_iter()
        .flat_map(|v2| SURB_HOPS.into_iter().map(move |hops| (v2, hops)))
        .map(|(v2, hops)| {
            let seed = if v2 { 3000 } else { 2000 } + hops as u64;
            let (surb, recovery) = surb(fill, v2, hops, seed);
            json!({
                "format": if v2 { 2 } else { 1 },
                "hops": hops,
                "seed": seed,
                "header": hex::encode(surb.header.to_bytes(&[])),
                "recovery_id": hex::encode(recovery.id),
                "reply_sha256": sha256_hex(&sealed_reply(&surb)),
            })
        })
        .collect();
    json!({
        "node_secret": "byte 0x40 + hop index, repeated 32 times",
        "addresses": "hop-<index>",
        "forward_payload": hex::encode(FORWARD_PAYLOAD),
        "surb_id": hex::encode(SURB_ID),
        "reply_message": hex::encode(REPLY_MESSAGE),
        "rng": "ChaCha20Rng::seed_from_u64(seed)",
        "forward": forward,
        "surbs": surbs,
    })
}

fn pinned(json: &str) -> Value {
    serde_json::from_str(json).expect("vector file is JSON")
}

#[test]
fn zero_fill_builders_match_pinned_vectors() {
    assert_eq!(vectors(Fill::Zero), pinned(ZERO_FILL));
}

#[test]
fn random_fill_builders_match_pinned_vectors() {
    assert_eq!(vectors(Fill::Random), pinned(RANDOM_FILL));
}

#[test]
#[ignore = "writes the vector files"]
fn write_vectors() {
    if std::env::var_os("NOX_WRITE_SPHINX_VECTORS").is_none() {
        return;
    }
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    std::fs::create_dir_all(&dir).expect("vector dir");
    for (name, fill) in [
        ("zero_fill.json", Fill::Zero),
        ("random_fill.json", Fill::Random),
    ] {
        let text = serde_json::to_string_pretty(&vectors(fill)).expect("json");
        std::fs::write(dir.join(name), text + "\n").expect("write vectors");
    }
}

/// The final hop's decrypted routing info, as the final hop sees it.
fn final_hop_view(header: &SphinxHeader, sk: &X25519SecretKey) -> [u8; ROUTING_INFO_SIZE] {
    let shared = sk.diffie_hellman(&header.ephemeral_key);
    let (rho, _, _, _) = derive_keys(shared.as_bytes());
    let mut routing = header.routing_info;
    apply_stream_cipher(&rho, &[0u8; 12], &mut routing);
    routing
}

/// Processes `packet` through every hop of `sks`, checking each forward
/// address, and returns the final hop's header and the delivered body.
fn walk(mut packet: Vec<u8>, sks: &[X25519SecretKey]) -> (SphinxHeader, Vec<u8>) {
    for (i, sk) in sks.iter().enumerate() {
        let (header, body) = SphinxHeader::from_bytes(&packet).expect("parse");
        match into_result(header.process(sk, body.to_vec()).expect("hop MAC verifies")) {
            ProcessResult::Forward {
                next_hop,
                next_packet,
                processed_body,
            } => {
                assert_eq!(next_hop, format!("hop-{}", i + 1));
                packet = next_packet.to_bytes(&processed_body);
            }
            ProcessResult::Exit { payload } => {
                assert_eq!(i + 1, sks.len(), "only the last hop delivers");
                return (header, payload);
            }
        }
    }
    panic!("path ended without delivery")
}

/// Bytes between the flag and the filler, which no hop reads.
fn padding(view: &[u8; ROUTING_INFO_SIZE], hops: usize) -> &[u8] {
    &view[FINAL_PADDING_OFFSET..ROUTING_INFO_SIZE - (hops - 1) * SHIFT_SIZE]
}

#[test]
fn both_fills_reach_the_exit_on_every_path_length() {
    for hops in 1..=MAX_PATH_HOPS {
        let (sks, _) = vector_path(hops);
        for fill in [Fill::Zero, Fill::Random] {
            let packet = forward_packet(fill, hops, 7 + hops as u64);
            let (final_header, payload) = walk(packet, &sks);
            assert_eq!(&payload[..FORWARD_PAYLOAD.len()], FORWARD_PAYLOAD);
            let view = final_hop_view(&final_header, &sks[hops - 1]);
            assert_eq!(view[0], 0x01);
            assert_eq!(view[1], 0x00, "no format 2 flag on a forward packet");
            let pad = padding(&view, hops);
            match fill {
                Fill::Zero => assert!(pad.iter().all(|&b| b == 0)),
                Fill::Random => assert!(pad.iter().any(|&b| b != 0)),
            }
        }
    }
}

#[test]
fn both_fills_deliver_surb_replies() {
    for hops in 1..=MAX_PATH_HOPS {
        let (sks, _) = vector_path(hops);
        for fill in [Fill::Zero, Fill::Random] {
            for v2 in [false, true] {
                let (surb, recovery) = surb(fill, v2, hops, 50 + hops as u64);
                let (final_header, body) = walk(sealed_reply(&surb), &sks);
                assert_eq!(
                    recovery.decrypt(&body).expect("reply decrypts"),
                    REPLY_MESSAGE
                );
                let view = final_hop_view(&final_header, &sks[hops - 1]);
                assert_eq!(view[1], if v2 { super::REPLY_V2_FLAG } else { 0 });
                let verified = final_header.verify(&sks[hops - 1]).expect("verify");
                assert_eq!(verified.reply_v2_flag(), v2);
                if v2 {
                    assert_eq!(verified.delivery_id(), recovery.id);
                }
                let pad = padding(&view, hops);
                assert_eq!(fill == Fill::Random, pad.iter().any(|&b| b != 0));
            }
        }
    }
}

/// With zero padding, the final hop finds the filler where the zeros end, and
/// the filler is `SHIFT_SIZE` bytes per earlier hop. With random padding the
/// whole region past the flag looks alike for every path length.
#[test]
fn final_hop_cannot_find_the_filler_boundary() {
    let zero_run = |view: &[u8; ROUTING_INFO_SIZE]| {
        view[FINAL_PADDING_OFFSET..]
            .iter()
            .take_while(|&&b| b == 0)
            .count()
    };
    for hops in 1..=2 {
        let (sks, _) = vector_path(hops);
        let (old_header, _) = walk(forward_packet(Fill::Zero, hops, 90), &sks);
        let old_view = final_hop_view(&old_header, &sks[hops - 1]);
        let leaked = zero_run(&old_view);
        let filler = (hops - 1) * SHIFT_SIZE;
        assert!(leaked >= ROUTING_INFO_SIZE - FINAL_PADDING_OFFSET - filler);

        for seed in 0..64 {
            let (header, _) = walk(forward_packet(Fill::Random, hops, 100 + seed), &sks);
            let view = final_hop_view(&header, &sks[hops - 1]);
            assert!(
                zero_run(&view) < 8,
                "{hops} hops, seed {seed}: padding starts with a zero run"
            );
            let zeros = view[FINAL_PADDING_OFFSET..]
                .iter()
                .map(|&b| usize::from(b == 0))
                .sum::<usize>();
            assert!(zeros < 16, "{hops} hops, seed {seed}: {zeros} zero bytes");
        }
    }
}

#[test]
fn padding_draws_differ_between_packets() {
    let (sks, _) = vector_path(1);
    let a = final_hop_view(&walk(forward_packet(Fill::Random, 1, 1), &sks).0, &sks[0]);
    let b = final_hop_view(&walk(forward_packet(Fill::Random, 1, 2), &sks).0, &sks[0]);
    assert_ne!(padding(&a, 1), padding(&b, 1));
}
