//! Format 2 replies through the relayer pipeline and the response router.
//!
//! Each node runs its real ingest, worker, mix and egress stages on its own
//! event bus. Packets are handed in as `PacketReceived`, the way the P2P layer
//! (`prev_peer` set) and HTTP ingress (`prev_peer` unset) hand them in.

use nox_core::models::wire_id::ReplyHandle;
use nox_core::{IEventPublisher, IEventSubscriber, NoxEvent};
use nox_crypto::{PathHop, Surb, SurbRecovery};
use nox_node::config::SurbFormats;
use nox_node::infra::persistence::rotational_bloom::RotationalBloomFilter;
use nox_node::ingress::{ResponseBuffer, ResponseRouter};
use nox_node::services::mixing::NoMixStrategy;
use nox_node::services::relayer::RelayerService;
use nox_node::telemetry::metrics::MetricsService;
use nox_node::{NoxConfig, TokioEventBus};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use x25519_dalek::{PublicKey, StaticSecret};

const PLANTED: ReplyHandle = [0x5a; 16];

struct Node {
    publisher: Arc<dyn IEventPublisher>,
    events: broadcast::Receiver<NoxEvent>,
    buffer: Arc<ResponseBuffer>,
}

async fn start_node(sk: &StaticSecret, surb_formats: SurbFormats) -> Node {
    let bus = TokioEventBus::new(256);
    let publisher: Arc<dyn IEventPublisher> = Arc::new(bus.clone());
    let subscriber: Arc<dyn IEventSubscriber> = Arc::new(bus.clone());
    let events = subscriber.subscribe();

    let mut config = NoxConfig::default();
    config.relayer.worker_count = 1;
    config.relayer.queue_size = 16;
    config.relayer.surb_formats = surb_formats;
    config.routing_private_key = hex::encode(sk.to_bytes());

    let metrics = MetricsService::new();
    let replay = Arc::new(RotationalBloomFilter::new(
        1_000,
        0.001,
        Duration::from_mins(1),
    ));
    let service = RelayerService::new(
        config,
        subscriber.clone(),
        publisher.clone(),
        replay,
        Arc::new(NoMixStrategy),
        metrics.clone(),
    );
    service.run().await.expect("relayer");

    let buffer = Arc::new(ResponseBuffer::new());
    let router = ResponseRouter::new(subscriber, buffer.clone(), 60, metrics);
    tokio::spawn(async move { router.run().await });
    tokio::time::sleep(Duration::from_millis(50)).await;

    Node {
        publisher,
        events,
        buffer,
    }
}

fn keypair() -> (StaticSecret, PublicKey) {
    let sk = StaticSecret::random_from_rng(rand::thread_rng());
    let pk = PublicKey::from(&sk);
    (sk, pk)
}

fn hop(pk: PublicKey, address: &str) -> PathHop {
    PathHop {
        public_key: pk,
        address: address.into(),
    }
}

fn receive(node: &Node, data: Vec<u8>, reply_handle: Option<ReplyHandle>, prev_peer: Option<&str>) {
    node.publisher
        .publish(NoxEvent::PacketReceived {
            packet_id: "local".into(),
            size_bytes: data.len(),
            data,
            reply_handle,
            prev_peer: prev_peer.map(str::to_string),
        })
        .expect("publish");
}

/// Waits for the next event matching `pick`.
async fn next_event<T>(node: &mut Node, mut pick: impl FnMut(NoxEvent) -> Option<T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let event = node.events.recv().await.expect("bus open");
            if let Some(found) = pick(event) {
                return found;
            }
        }
    })
    .await
    .expect("event in time")
}

/// Waits until the node has decrypted `n` packets, then gives the response
/// router time to file them.
async fn delivered(node: &mut Node, n: usize) {
    for _ in 0..n {
        next_event(node, |event| match event {
            NoxEvent::PayloadDecrypted { .. } => Some(()),
            _ => None,
        })
        .await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// A format 2 reply sealed for the path `[mix, entry]`.
fn v2_reply(mix: PublicKey, entry: PublicKey, message: &[u8]) -> (Vec<u8>, SurbRecovery) {
    let (surb, recovery) =
        Surb::new_v2(&[hop(mix, "mix"), hop(entry, "entry")], 0).expect("v2 SURB");
    let packet = surb.encapsulate_v2(message).expect("seal");
    (packet.into_bytes(), recovery)
}

#[tokio::test]
async fn relay_strips_a_handle_from_a_v2_reply() {
    let (mix_sk, mix_pk) = keypair();
    let (_, entry_pk) = keypair();
    let mut mix = start_node(&mix_sk, SurbFormats::Both).await;
    let (packet, _) = v2_reply(mix_pk, entry_pk, b"reply");

    receive(&mix, packet, Some(PLANTED), Some("exit-peer"));
    let (handle, next_hop) = next_event(&mut mix, |event| match event {
        NoxEvent::SendPacket {
            reply_handle,
            next_hop_peer_id,
            ..
        } => Some((reply_handle, next_hop_peer_id)),
        _ => None,
    })
    .await;
    assert_eq!(next_hop, "entry");
    assert_eq!(handle, None, "a v2 reply leaves the relay without a handle");
}

#[tokio::test]
async fn relay_keeps_a_v1_reply_handle() {
    let (mix_sk, mix_pk) = keypair();
    let (_, entry_pk) = keypair();
    let mut mix = start_node(&mix_sk, SurbFormats::Both).await;
    let (surb, _) =
        Surb::new(&[hop(mix_pk, "mix"), hop(entry_pk, "entry")], PLANTED, 0).expect("SURB");
    let packet = surb.encapsulate(b"reply").expect("seal").into_bytes();

    receive(&mix, packet, Some(PLANTED), Some("exit-peer"));
    let handle = next_event(&mut mix, |event| match event {
        NoxEvent::SendPacket { reply_handle, .. } => Some(reply_handle),
        _ => None,
    })
    .await;
    assert_eq!(handle, Some(PLANTED));
}

#[tokio::test]
async fn entry_files_a_p2p_v2_reply_under_the_delivery_id_only() {
    let (mix_sk, mix_pk) = keypair();
    let (entry_sk, entry_pk) = keypair();
    let mut mix = start_node(&mix_sk, SurbFormats::Both).await;
    let mut entry = start_node(&entry_sk, SurbFormats::Both).await;
    let (packet, recovery) = v2_reply(mix_pk, entry_pk, b"the reply");

    receive(&mix, packet, None, Some("exit-peer"));
    let forwarded = next_event(&mut mix, |event| match event {
        NoxEvent::SendPacket { data, .. } => Some(data),
        _ => None,
    })
    .await;

    // A handle planted on the way in must not become a second key.
    receive(&entry, forwarded, Some(PLANTED), Some("mix-peer"));
    delivered(&mut entry, 1).await;

    assert_eq!(entry.buffer.delivery_len(), 1);
    assert!(entry.buffer.claim_by_surb_ids(&[PLANTED]).is_empty());
    let claimed = entry.buffer.claim_by_surb_ids(&[recovery.id]);
    assert_eq!(claimed.len(), 1);
    assert_eq!(
        claimed[0].0,
        format!("reply-0-{}", hex::encode(recovery.id))
    );
    assert_eq!(
        recovery.decrypt(&claimed[0].1).expect("tag verifies"),
        b"the reply"
    );
    assert!(entry.buffer.is_empty());
}

#[tokio::test]
async fn http_ingested_packets_are_never_stored() {
    let (entry_sk, entry_pk) = keypair();
    let mut entry = start_node(&entry_sk, SurbFormats::Both).await;

    // One-hop format 2 reply addressed to the entry, plus format 1 replies
    // with and without a handle, all handed in the way HTTP ingress does.
    let (surb, _) = Surb::new_v2(&[hop(entry_pk, "entry")], 0).expect("v2 SURB");
    receive(
        &entry,
        surb.encapsulate_v2(b"x").expect("seal").into_bytes(),
        None,
        None,
    );
    let (surb, _) = Surb::new_v2(&[hop(entry_pk, "entry")], 0).expect("v2 SURB");
    receive(
        &entry,
        surb.encapsulate_v2(b"x").expect("seal").into_bytes(),
        Some(PLANTED),
        None,
    );
    let (surb, _) = Surb::new(&[hop(entry_pk, "entry")], [1; 16], 0).expect("SURB");
    receive(
        &entry,
        surb.encapsulate(b"x").expect("seal").into_bytes(),
        None,
        None,
    );
    delivered(&mut entry, 3).await;

    assert!(entry.buffer.is_empty());
}

#[tokio::test]
async fn v1_mode_ignores_the_flag() {
    let (entry_sk, entry_pk) = keypair();
    let mut entry = start_node(&entry_sk, SurbFormats::V1).await;
    let (surb, recovery) = Surb::new_v2(&[hop(entry_pk, "entry")], 0).expect("v2 SURB");
    receive(
        &entry,
        surb.encapsulate_v2(b"x").expect("seal").into_bytes(),
        Some(PLANTED),
        Some("mix-peer"),
    );
    delivered(&mut entry, 1).await;

    assert_eq!(entry.buffer.delivery_len(), 0);
    assert!(entry.buffer.claim_by_surb_ids(&[recovery.id]).is_empty());
    assert_eq!(entry.buffer.claim_by_surb_ids(&[PLANTED]).len(), 1);
}
