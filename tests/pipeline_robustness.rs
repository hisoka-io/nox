use nox_core::RelayerPayload;

#[test]
fn test_payload_serialization_roundtrip() {
    let addr: [u8; 20] = [
        0x01, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let p1 = RelayerPayload::SubmitTransaction {
        to: addr,
        data: vec![0xCA, 0xFE],
    };
    let b1 = bincode::serialize(&p1).unwrap();
    let d1: RelayerPayload = bincode::deserialize(&b1).unwrap();

    match d1 {
        RelayerPayload::SubmitTransaction { to, data } => {
            assert_eq!(to, addr);
            assert_eq!(data, vec![0xCA, 0xFE]);
        }
        _ => panic!("Wrong variant for p1"),
    }

    let p2 = RelayerPayload::Dummy {
        padding: vec![0x00; 100],
    };
    let b2 = bincode::serialize(&p2).unwrap();
    let d2: RelayerPayload = bincode::deserialize(&b2).unwrap();
    match d2 {
        RelayerPayload::Dummy { padding } => assert_eq!(padding.len(), 100),
        _ => panic!("Wrong variant for p2"),
    }

    let p3 = RelayerPayload::Heartbeat {
        id: 999,
        timestamp: 1234567890,
    };
    let b3 = bincode::serialize(&p3).unwrap();
    let d3: RelayerPayload = bincode::deserialize(&b3).unwrap();
    match d3 {
        RelayerPayload::Heartbeat { id, timestamp } => {
            assert_eq!(id, 999);
            assert_eq!(timestamp, 1234567890);
        }
        _ => panic!("Wrong variant for p3"),
    }
}
