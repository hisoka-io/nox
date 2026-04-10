use tokio::sync::broadcast;
use tracing::warn;

use nox_core::{
    events::NoxEvent,
    traits::{EventBusError, IEventBus, IEventPublisher, IEventSubscriber},
};

#[derive(Clone)]
pub struct TokioEventBus {
    sender: broadcast::Sender<NoxEvent>,
    _capacity: usize,
}

impl TokioEventBus {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            _capacity: capacity,
        }
    }
}

impl IEventPublisher for TokioEventBus {
    fn publish(&self, event: NoxEvent) -> Result<usize, EventBusError> {
        match self.sender.send(event) {
            Ok(count) => Ok(count),
            Err(e) => {
                warn!("Event dropped -- no subscribers: {:?}", e.0);
                Ok(0)
            }
        }
    }
}

impl IEventSubscriber for TokioEventBus {
    fn subscribe(&self) -> broadcast::Receiver<NoxEvent> {
        self.sender.subscribe()
    }
}

impl IEventBus for TokioEventBus {}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;

    #[tokio::test]
    async fn test_lagging_receiver() {
        // Small capacity to force lag
        let bus = TokioEventBus::new(2);
        let mut rx = bus.subscribe();

        // Fill buffer + overflow
        bus.publish(NoxEvent::PacketProcessed {
            packet_id: "1".into(),
            duration_ms: 1,
        })
        .unwrap();
        bus.publish(NoxEvent::PacketProcessed {
            packet_id: "2".into(),
            duration_ms: 2,
        })
        .unwrap();
        bus.publish(NoxEvent::PacketProcessed {
            packet_id: "3".into(),
            duration_ms: 3,
        })
        .unwrap();

        // The receiver should have missed the oldest message (1)
        let result = rx.recv().await;

        // Tokio broadcast returns RecvError::Lagged
        assert!(result.is_err());

        // Next receive should be the oldest available (2 or 3 depending on impl details)
        // Usually it skips to latest available.
        let msg = rx.recv().await.unwrap();
        match msg {
            NoxEvent::PacketProcessed { duration_ms, .. } => assert!(duration_ms > 1),
            _ => panic!("Wrong event type"),
        }
    }

    #[tokio::test]
    async fn test_broadcast_to_multiple_subscribers() {
        let bus = TokioEventBus::new(10);
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        let event = NoxEvent::PeerConnected {
            peer_id: "123".into(),
        };
        bus.publish(event.clone()).unwrap();

        let msg1 = rx1.recv().await.unwrap();
        let msg2 = rx2.recv().await.unwrap();

        assert_eq!(msg1, event);
        assert_eq!(msg2, event);
    }

    #[tokio::test]
    async fn test_bus_capacity_lag() {
        // Small buffer to force lag
        let bus = TokioEventBus::new(1);
        let mut rx = bus.subscribe();

        // Fill and overflow buffer
        bus.publish(NoxEvent::PacketProcessed {
            packet_id: "1".into(),
            duration_ms: 1,
        })
        .unwrap();
        bus.publish(NoxEvent::PacketProcessed {
            packet_id: "2".into(),
            duration_ms: 2,
        })
        .unwrap();

        // First message should be lost (Lagged)
        let result = rx.recv().await;
        assert!(result.is_err(), "Receiver should have lagged error");

        // Should recover and get latest
        let msg = rx.recv().await.unwrap();
        match msg {
            NoxEvent::PacketProcessed { duration_ms, .. } => assert_eq!(duration_ms, 2),
            _ => panic!("Unexpected event"),
        }
    }

    #[tokio::test]
    async fn test_stress_publish() {
        let bus = TokioEventBus::new(10000);
        let mut rx = bus.subscribe();

        let n = 1000;
        for i in 0..n {
            bus.publish(NoxEvent::PacketProcessed {
                packet_id: format!("{}", i),
                duration_ms: i,
            })
            .unwrap();
        }

        let mut count = 0;
        while count < n {
            if timeout(Duration::from_millis(100), rx.recv()).await.is_ok() {
                count += 1;
            } else {
                break;
            }
        }
        assert_eq!(count, n, "Should receive all stress test messages");
    }
}
