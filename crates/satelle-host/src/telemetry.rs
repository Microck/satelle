use satelle_core::telemetry::{
    TelemetryComponent, TelemetryConfig, TelemetryOutcome, TelemetryQueue, TelemetryResourceUsage,
    TelemetryStatus,
};
use satelle_core::{ErrorCode, SatelleError};
use std::path::PathBuf;
use std::sync::mpsc::{SyncSender, sync_channel};
use std::time::Duration;

#[derive(Clone, Debug)]
pub(crate) struct HostTelemetry {
    config: Option<TelemetryConfig>,
    queue: Option<TelemetryQueue>,
    delivery_wake: Option<SyncSender<()>>,
}

impl HostTelemetry {
    pub(crate) fn new(
        config: Option<TelemetryConfig>,
        state_root: Result<PathBuf, SatelleError>,
    ) -> Self {
        let queue = state_root
            .ok()
            .map(|root| TelemetryQueue::new(&root, TelemetryComponent::Host));
        let enabled = config.as_ref().is_some_and(|config| config.enabled);
        if !enabled && let Some(queue) = queue.as_ref() {
            let _ = queue.clear();
        }
        let delivery_wake = if enabled {
            config
                .as_ref()
                .cloned()
                .zip(queue.as_ref().cloned())
                .map(|(config, queue)| {
                    let (sender, receiver) = sync_channel(1);
                    std::thread::spawn(move || {
                        // Retry records retained from an earlier process before
                        // waiting for new request outcomes.
                        let _ = queue.deliver(&config, TelemetryComponent::Host);
                        while receiver.recv().is_ok() {
                            let _ = queue.deliver(&config, TelemetryComponent::Host);
                        }
                    });
                    sender
                })
        } else {
            None
        };
        Self {
            config,
            queue,
            delivery_wake,
        }
    }

    pub(crate) fn status(&self) -> Result<TelemetryStatus, SatelleError> {
        let config = self.config.as_ref().cloned().unwrap_or_default();
        let endpoint_origin = config.endpoint()?.map(|endpoint| endpoint.origin());
        let queue = self.queue.as_ref().ok_or_else(|| {
            SatelleError::config_error("the Host telemetry state directory is unavailable", None)
        })?;
        queue
            .status(TelemetryComponent::Host, config.enabled, endpoint_origin)
            .map_err(|error| {
                SatelleError::config_error(
                    "the private Host telemetry queue is unavailable",
                    Some(error.to_string()),
                )
            })
    }

    pub(crate) fn record(
        &self,
        duration: Duration,
        outcome: TelemetryOutcome,
        error_code: Option<ErrorCode>,
    ) {
        if !self.enabled() {
            return;
        }
        let Some(queue) = self.queue.as_ref() else {
            return;
        };
        if queue
            .enqueue(satelle_core::telemetry::TelemetryRecord::new(
                duration,
                outcome,
                error_code,
                0,
                TelemetryResourceUsage::current(),
            ))
            .is_err()
        {
            return;
        }
        if let Some(delivery_wake) = self.delivery_wake.as_ref() {
            // A capacity-one wake coalesces request bursts while the single
            // delivery worker drains the durable queue.
            let _ = delivery_wake.try_send(());
        }
    }

    pub(crate) fn enabled(&self) -> bool {
        self.config.as_ref().is_some_and(|config| config.enabled)
    }
}
