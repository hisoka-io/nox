//! Packets from clients that leave the final hop's routing padding zero and
//! from clients that fill it with random bytes, through the relayer pipeline.
//!
//! Each node runs its real ingest, worker, mix and egress stages on its own
//! event bus, as in `reply_v2.rs`. Forward packets cross entry, mix and exit;
//! replies cross mix and entry and are filed by the entry's response router.

use nox_core::models::wire_id::ReplyHandle;
use nox_core::{IEventPublisher, IEventSubscriber, NoxEvent};
use nox_crypto::sphinx::zero_fill;
use nox_crypto::{build_multi_hop_packet_with_rng, PathHop, Surb, SurbRecovery};
use nox_node::config::SurbFormats;
use nox_node::infra::persistence::rotational_bloom::RotationalBloomFilter;
use nox_node::ingress::{ResponseBuffer, ResponseRouter};
use nox_node::services::mixing::NoMixStrategy;
use nox_node::services::relayer::RelayerService;
use nox_node::telemetry::metrics::MetricsService;
use nox_node::{NoxConfig, TokioEventBus};
use rand::rngs::OsRng;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use x25519_dalek::{PublicKey, StaticSecret};

const SURB_ID: ReplyHandle = [0x3c; 16];

#[derive(Clone, Copy, Debug)]
enum Client {
    /// Zero padding, as clients built before random padding.
    Old,
    /// Random padding.
    New,
}

struct Node {
    publisher: Arc<dyn IEventPublisher>,
    events: broadcast::Receiver<NoxEvent>,
    buffer: Arc<ResponseBuffer>,
}

async fn start_node(sk: &StaticSecret) -> Node {
    let bus = TokioEventBus::new(256);
    let publisher: Arc<dyn IEventPublisher> = Arc::new(bus.clone());
    let subscriber: Arc<dyn IEventSubscriber> = Arc::new(bus.clone());
    let events = subscriber.subscribe();

    let mut config = NoxConfig::default();
    config.relayer.worker_count = 1;
    config.relayer.queue_size = 16;
    config.relayer.surb_formats = SurbFormats::Both;
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

fn receive(node: &Node, data: Vec<u8>, reply_handle: Option<ReplyHandle>, prev_peer: &str) {
    node.publisher
        .publish(NoxEvent::PacketReceived {
            packet_id: "local".into(),
            size_bytes: data.len(),
            data,
            reply_handle,
            prev_peer: Some(prev_peer.to_string()),
        })
        .expect("publish");
}

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

/// Hands `data` to `node` and returns what it forwards, checking the next hop.
async fn forward(node: &mut Node, data: Vec<u8>, handle: Option<ReplyHandle>, to: &str) -> Vec<u8> {
    receive(node, data, handle, "prev-peer");
    let (next_hop, data) = next_event(node, |event| match event {
        NoxEvent::SendPacket {
            next_hop_peer_id,
            data,
            ..
        } => Some((next_hop_peer_id, data)),
        _ => None,
    })
    .await;
    assert_eq!(next_hop, to);
    data
}

/// Hands `data` to `node` as its final hop and returns the delivered body.
async fn deliver(node: &mut Node, data: Vec<u8>, handle: Option<ReplyHandle>) -> Vec<u8> {
    receive(node, data, handle, "prev-peer");
    let payload = next_event(node, |event| match event {
        NoxEvent::PayloadDecrypted { payload, .. } => Some(payload),
        _ => None,
    })
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    payload
}

fn forward_packet(client: Client, path: &[PathHop], payload: &[u8]) -> Vec<u8> {
    match client {
        Client::Old => zero_fill::build_multi_hop_packet_with_rng(path, payload, 0, &mut OsRng),
        Client::New => build_multi_hop_packet_with_rng(path, payload, 0, &mut OsRng),
    }
    .expect("build packet")
}

fn surb(client: Client, v2: bool, path: &[PathHop]) -> (Surb, SurbRecovery) {
    match (client, v2) {
        (Client::Old, false) => zero_fill::surb_with_rng(path, SURB_ID, 0, &mut OsRng),
        (Client::Old, true) => zero_fill::surb_v2_with_rng(path, 0, &mut OsRng),
        (Client::New, false) => Surb::new_with_rng(path, SURB_ID, 0, &mut OsRng),
        (Client::New, true) => Surb::new_v2_with_rng(path, 0, &mut OsRng),
    }
    .expect("build SURB")
}

#[tokio::test]
async fn forward_packets_from_old_and_new_clients_reach_the_exit() {
    let (entry_sk, entry_pk) = keypair();
    let (mix_sk, mix_pk) = keypair();
    let (exit_sk, exit_pk) = keypair();
    let mut entry = start_node(&entry_sk).await;
    let mut mix = start_node(&mix_sk).await;
    let mut exit = start_node(&exit_sk).await;

    let three = [
        hop(entry_pk, "entry"),
        hop(mix_pk, "mix"),
        hop(exit_pk, "exit"),
    ];
    for client in [Client::Old, Client::New, Client::Old, Client::New] {
        let message = format!("{client:?} client, three hops");
        let packet = forward_packet(client, &three, message.as_bytes());
        let packet = forward(&mut entry, packet, None, "mix").await;
        let packet = forward(&mut mix, packet, None, "exit").await;
        let payload = deliver(&mut exit, packet, None).await;
        assert_eq!(&payload[..message.len()], message.as_bytes(), "{client:?}");
    }

    // A one-hop packet leaves the most padding for the final hop to see.
    for client in [Client::Old, Client::New] {
        let message = format!("{client:?} client, one hop");
        let packet = forward_packet(client, &[hop(exit_pk, "exit")], message.as_bytes());
        let payload = deliver(&mut exit, packet, None).await;
        assert_eq!(&payload[..message.len()], message.as_bytes(), "{client:?}");
    }
}

#[tokio::test]
async fn replies_from_old_and_new_surbs_are_filed_at_the_entry() {
    let (mix_sk, mix_pk) = keypair();
    let (entry_sk, entry_pk) = keypair();
    let mut mix = start_node(&mix_sk).await;
    let mut entry = start_node(&entry_sk).await;
    let return_path = [hop(mix_pk, "mix"), hop(entry_pk, "entry")];

    for client in [Client::Old, Client::New] {
        // Format 2: filed under the delivery ID only the final hop derives.
        let (surb_v2, recovery) = surb(client, true, &return_path);
        let reply = surb_v2.encapsulate_v2(b"v2 reply").expect("seal");
        let packet = forward(&mut mix, reply.into_bytes(), None, "entry").await;
        deliver(&mut entry, packet, None).await;
        let claimed = entry.buffer.claim_by_surb_ids(&[recovery.id]);
        assert_eq!(claimed.len(), 1, "{client:?} v2 reply filed");
        assert_eq!(
            recovery.decrypt(&claimed[0].1).expect("tag verifies"),
            b"v2 reply"
        );

        // Format 1: filed under the handle the reply carries.
        let (surb_v1, recovery) = surb(client, false, &return_path);
        let reply = surb_v1.encapsulate(b"v1 reply").expect("seal");
        let packet = forward(&mut mix, reply.into_bytes(), Some(SURB_ID), "entry").await;
        deliver(&mut entry, packet, Some(SURB_ID)).await;
        let claimed = entry.buffer.claim_by_surb_ids(&[SURB_ID]);
        assert_eq!(claimed.len(), 1, "{client:?} v1 reply filed");
        assert_eq!(
            recovery.decrypt(&claimed[0].1).expect("padding verifies"),
            b"v1 reply"
        );
        assert!(entry.buffer.is_empty());
    }
}
