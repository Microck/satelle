use satelle_core::SatelleEventBody;
use std::sync::Arc;
use tokio::sync::broadcast;

pub(crate) const LIVE_EVENT_QUEUE_CAPACITY: usize = 256;

pub(crate) struct LiveEventHub {
    sender: broadcast::Sender<Arc<SatelleEventBody>>,
}

impl LiveEventHub {
    pub(crate) fn new() -> Self {
        let (sender, _) = broadcast::channel(LIVE_EVENT_QUEUE_CAPACITY);
        Self { sender }
    }

    pub(crate) fn subscribe(&self) -> LiveEventSubscription {
        LiveEventSubscription {
            receiver: self.sender.subscribe(),
        }
    }

    pub(crate) fn publish(&self, event: SatelleEventBody) {
        // With no subscriber, dropping the live-only event is the contract.
        // With subscribers, broadcast::send is synchronous and never waits on
        // a slow receiver.
        let _no_receivers = self.sender.send(Arc::new(event));
    }
}

pub struct LiveEventSubscription {
    receiver: broadcast::Receiver<Arc<SatelleEventBody>>,
}

impl LiveEventSubscription {
    pub async fn recv(&mut self) -> Result<Arc<SatelleEventBody>, LiveEventReceiveError> {
        self.receiver.recv().await.map_err(map_receive_error)
    }

    pub fn try_recv(&mut self) -> Result<Arc<SatelleEventBody>, LiveEventReceiveError> {
        self.receiver.try_recv().map_err(|error| match error {
            broadcast::error::TryRecvError::Empty => LiveEventReceiveError::Empty,
            broadcast::error::TryRecvError::Lagged(dropped) => {
                LiveEventReceiveError::Lagged { dropped }
            }
            broadcast::error::TryRecvError::Closed => LiveEventReceiveError::Closed,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiveEventReceiveError {
    Empty,
    Lagged { dropped: u64 },
    Closed,
}

fn map_receive_error(error: broadcast::error::RecvError) -> LiveEventReceiveError {
    match error {
        broadcast::error::RecvError::Lagged(dropped) => LiveEventReceiveError::Lagged { dropped },
        broadcast::error::RecvError::Closed => LiveEventReceiveError::Closed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use satelle_core::{EventSource, EventType};

    #[test]
    fn bounded_live_event_receiver_reports_exact_lag_without_blocking_publishers() {
        let hub = LiveEventHub::new();
        let mut subscription = hub.subscribe();
        for index in 0..=LIVE_EVENT_QUEUE_CAPACITY {
            hub.publish(
                SatelleEventBody::new(
                    EventType::Readiness,
                    EventSource::HostDaemon,
                    time::OffsetDateTime::UNIX_EPOCH,
                    "host-test",
                    None,
                    "readiness observation",
                    serde_json::json!({"index": index}),
                )
                .expect("valid safe event"),
            );
        }

        assert_eq!(
            subscription.try_recv(),
            Err(LiveEventReceiveError::Lagged { dropped: 1 })
        );
    }

    #[test]
    fn subscribers_receive_only_events_published_after_they_subscribe() {
        let hub = LiveEventHub::new();
        let event = SatelleEventBody::new(
            EventType::Readiness,
            EventSource::HostDaemon,
            time::OffsetDateTime::UNIX_EPOCH,
            "host-test",
            None,
            "readiness observation",
            serde_json::json!({}),
        )
        .expect("valid safe event");

        hub.publish(event.clone());
        let mut existing_subscription = hub.subscribe();
        assert_eq!(
            existing_subscription.try_recv(),
            Err(LiveEventReceiveError::Empty)
        );

        hub.publish(event.clone());
        assert_eq!(existing_subscription.try_recv().as_deref(), Ok(&event));

        let mut later_subscription = hub.subscribe();
        assert_eq!(
            later_subscription.try_recv(),
            Err(LiveEventReceiveError::Empty)
        );
    }
}
