//! Wire bytes of the messages nodes exchange, pinned so that a change which
//! older nodes could not read fails here. `SystemMessage` travels as CBOR on
//! the `/nox/packet/1` request-response protocol; `RelayerPayload` is the
//! versioned bincode body of a Sphinx packet.

use libp2p::request_response::{self, Codec};
use libp2p::StreamProtocol;
use nox_core::models::payloads::{decode_payload, encode_payload};
use nox_core::models::topology::{TopologyLiveness, TopologyLivenessStatus};
use nox_core::{
    Capabilities, FecInfo, Fragment, Handshake, RelayerNode, RelayerPayload, TopologySnapshot,
};
use nox_node::network::behaviour::{NoxBehaviour, SphinxPacket, SystemMessage};

/// The codec `NoxBehaviour` sends `SystemMessage` with, named through the
/// behaviour's own field so the vectors follow a codec change.
fn wire_codec<C>(_: fn(&NoxBehaviour) -> &request_response::Behaviour<C>) -> C
where
    C: Codec<Protocol = StreamProtocol, Request = SystemMessage, Response = SystemMessage>
        + Default
        + Clone
        + Send
        + 'static,
{
    C::default()
}

async fn assert_system_message(message: SystemMessage, expected_hex: &str) {
    let protocol = StreamProtocol::new("/nox/packet/1");
    let mut codec = wire_codec(|behaviour| &behaviour.direct_message);

    let mut request = Vec::new();
    codec
        .write_request(&protocol, &mut request, message.clone())
        .await
        .unwrap();
    assert_eq!(hex::encode(&request), expected_hex, "{message:?}");

    let mut response = Vec::new();
    codec
        .write_response(&protocol, &mut response, message.clone())
        .await
        .unwrap();
    assert_eq!(response, request);

    let pinned = hex::decode(expected_hex).unwrap();
    assert_eq!(
        codec
            .read_request(&protocol, &mut pinned.as_slice())
            .await
            .unwrap(),
        message
    );
    assert_eq!(
        codec
            .read_response(&protocol, &mut pinned.as_slice())
            .await
            .unwrap(),
        message
    );
}

fn handshake() -> Handshake {
    Handshake {
        version: 5,
        capabilities: Capabilities::RELAY | Capabilities::EXIT_NODE,
        routing_key: "11".repeat(32),
        eth_address: Some(format!("0x{}", "22".repeat(20))),
        payload_version_min: 1,
        payload_version_max: 1,
        identity_sig: Some("33".repeat(65)),
    }
}

#[tokio::test]
async fn system_message_handshake_bytes() {
    assert_system_message(SystemMessage::Handshake(handshake()), "a16948616e647368616b65a76776657273696f6e056c6361706162696c6974696573036b726f7574696e675f6b65797840313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131316b6574685f61646472657373782a307832323232323232323232323232323232323232323232323232323232323232323232323232323232737061796c6f61645f76657273696f6e5f6d696e01737061796c6f61645f76657273696f6e5f6d6178016c6964656e746974795f736967788233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333").await;
}

#[tokio::test]
async fn system_message_handshake_ack_bytes() {
    assert_system_message(
        SystemMessage::HandshakeAck {
            accepted: true,
            reason: None,
            session_ticket: Some((0..32).collect()),
        },
        "a16c48616e647368616b6541636ba3686163636570746564f566726561736f6ef66e73657373696f6e5f7469636b65749820000102030405060708090a0b0c0d0e0f101112131415161718181819181a181b181c181d181e181f",
    )
    .await;
    assert_system_message(
        SystemMessage::HandshakeAck {
            accepted: false,
            reason: Some("Incompatible version".to_string()),
            session_ticket: None,
        },
        "a16c48616e647368616b6541636ba3686163636570746564f466726561736f6e74496e636f6d70617469626c652076657273696f6e6e73657373696f6e5f7469636b6574f6",
    )
    .await;
}

#[tokio::test]
async fn system_message_packet_and_session_bytes() {
    assert_system_message(
        SystemMessage::Packet(SphinxPacket {
            id: "packet_123".to_string(),
            data: vec![1, 2, 3, 4, 5],
        }),
        "a1665061636b6574a26269646a7061636b65745f3132336464617461850102030405",
    )
    .await;
    assert_system_message(
        SystemMessage::SessionResume {
            ticket: (0..32).collect(),
        },
        "a16d53657373696f6e526573756d65a1667469636b65749820000102030405060708090a0b0c0d0e0f101112131415161718181819181a181b181c181d181e181f",
    )
    .await;
    assert_system_message(SystemMessage::Ack, "6341636b").await;
}

#[tokio::test]
async fn system_message_topology_bytes() {
    assert_system_message(
        SystemMessage::TopologyRequest,
        "6f546f706f6c6f677952657175657374",
    )
    .await;
    let address = format!("0x{}", "aa".repeat(20));
    assert_system_message(
        SystemMessage::TopologyResponse(TopologySnapshot {
            nodes: vec![RelayerNode {
                address: address.clone(),
                sphinx_key: "bb".repeat(32),
                url: "/ip4/10.0.0.1/tcp/9000".to_string(),
                stake: "1000".to_string(),
                last_seen: 1_700_000_000,
                is_privileged: false,
                layer: 2,
                role: 2,
                ingress_url: Some("https://exit.example".to_string()),
                metadata_url: None,
            }],
            fingerprint: "cc".repeat(32),
            timestamp: 1_700_000_000,
            block_number: 12,
            pow_difficulty: 3,
            schema_version: 2,
            liveness: vec![TopologyLiveness {
                address,
                status: TopologyLivenessStatus::Online,
                observed_at_unix: 1_700_000_000,
            }],
        }),
        "a170546f706f6c6f6779526573706f6e7365a7656e6f64657381a96761646472657373782a3078616161616161616161616161616161616161616161616161616161616161616161616161616161616a737068696e785f6b65797840626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626375726c762f6970342f31302e302e302e312f7463702f39303030657374616b656431303030696c6173745f7365656e1a6553f1006d69735f70726976696c65676564f4656c617965720264726f6c65026b696e67726573735f75726c7468747470733a2f2f657869742e6578616d706c656b66696e6765727072696e747840636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636974696d657374616d701a6553f1006c626c6f636b5f6e756d6265720c6e706f775f646966666963756c7479036e736368656d615f76657273696f6e02686c6976656e65737381a36761646472657373782a30786161616161616161616161616161616161616161616161616161616161616161616161616161616166737461747573666f6e6c696e65706f627365727665645f61745f756e69781a6553f100",
    )
    .await;
}

fn assert_relayer_payload(payload: &RelayerPayload, expected_hex: &str) {
    let bytes = encode_payload(payload).unwrap();
    assert_eq!(hex::encode(&bytes), expected_hex, "{payload:?}");
    let decoded: RelayerPayload = decode_payload(&hex::decode(expected_hex).unwrap()).unwrap();
    assert_eq!(encode_payload(&decoded).unwrap(), bytes);
}

#[test]
fn relayer_payload_bytes() {
    let mut to = [0u8; 20];
    to[..2].copy_from_slice(&[0x01, 0x23]);
    assert_relayer_payload(
        &RelayerPayload::SubmitTransaction {
            to,
            data: vec![0xCA, 0xFE],
        },
        "010000000001230000000000000000000000000000000000000200000000000000cafe",
    );
    assert_relayer_payload(
        &RelayerPayload::Dummy {
            padding: vec![0; 4],
        },
        "0101000000040000000000000000000000",
    );
    assert_relayer_payload(
        &RelayerPayload::Heartbeat {
            id: 999,
            timestamp: 1_234_567_890,
        },
        "0102000000e703000000000000d202964900000000",
    );
    assert_relayer_payload(
        &RelayerPayload::Fragment {
            frag: Fragment::new(7, 3, 1, vec![0xAB; 4]).unwrap(),
        },
        "0103000000070000000000000003000000010000000400000000000000abababab00",
    );
    assert_relayer_payload(
        &RelayerPayload::AnonymousRequest {
            inner: vec![1, 2, 3],
            reply_surbs: Vec::new(),
        },
        "010400000003000000000000000102030000000000000000",
    );
    assert_relayer_payload(
        &RelayerPayload::ServiceResponse {
            request_id: 77,
            fragment: Fragment::new_with_fec(
                77,
                5,
                4,
                vec![0xCD; 4],
                FecInfo {
                    data_shard_count: 3,
                    original_data_len: 10,
                },
            )
            .unwrap(),
        },
        "01050000004d000000000000004d0000000000000005000000040000000400000000000000cdcdcdcd01030000000a00000000000000",
    );
    assert_relayer_payload(
        &RelayerPayload::NeedMoreSurbs {
            request_id: 77,
            fragments_remaining: 5,
        },
        "01060000004d0000000000000005000000",
    );
}
