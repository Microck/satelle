use crate::{ExplicitDuration, QueueRequestId, SatelleError, SessionId, TurnId};
use serde::{Deserialize, Deserializer, Serialize};
use time::{OffsetDateTime, UtcOffset};

pub const QUEUE_STATUS_SCHEMA_VERSION: &str = "satelle.queue.status.v1";
pub const QUEUE_CANCEL_SCHEMA_VERSION: &str = "satelle.queue.cancel.v1";
pub const DEFAULT_QUEUE_MAX_DEPTH: u16 = 16;
pub const MAX_QUEUE_DEPTH: u16 = 256;
pub const DEFAULT_QUEUE_TTL_MS: u64 = 60 * 60 * 1_000;
pub const MAX_QUEUE_TTL_MS: u64 = 24 * 60 * 60 * 1_000;

/// User-owned queue policy. Optional fields preserve overlay intent while the
/// accessors expose the complete effective policy used by the Host.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueueConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_depth: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ttl: Option<ExplicitDuration>,
}

impl QueueConfig {
    pub const fn is_default(&self) -> bool {
        self.enabled.is_none() && self.max_depth.is_none() && self.ttl.is_none()
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self
            .max_depth
            .is_some_and(|depth| !(1..=MAX_QUEUE_DEPTH).contains(&depth))
        {
            return Err("queue.max_depth must be between 1 and 256");
        }
        if self
            .ttl
            .as_ref()
            .is_some_and(|ttl| ttl.milliseconds() == 0 || ttl.milliseconds() > MAX_QUEUE_TTL_MS)
        {
            return Err("queue.ttl must be positive and at most 24h");
        }
        Ok(())
    }

    pub fn enabled(&self) -> bool {
        self.enabled.unwrap_or(false)
    }

    pub fn max_depth(&self) -> u16 {
        self.max_depth.unwrap_or(DEFAULT_QUEUE_MAX_DEPTH)
    }

    pub fn ttl_ms(&self) -> u64 {
        self.ttl
            .as_ref()
            .map_or(DEFAULT_QUEUE_TTL_MS, ExplicitDuration::milliseconds)
    }

    pub fn apply_overlay(&mut self, overlay: &Self) {
        if overlay.enabled.is_some() {
            self.enabled = overlay.enabled;
        }
        if overlay.max_depth.is_some() {
            self.max_depth = overlay.max_depth;
        }
        if overlay.ttl.is_some() {
            self.ttl.clone_from(&overlay.ttl);
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueRequestStatus {
    Queued,
    Admitted,
    Cancelled,
    Expired,
    ValidationFailed,
}

impl QueueRequestStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Admitted => "admitted",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::ValidationFailed => "validation_failed",
        }
    }

    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Queued)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueueFailure {
    pub code: String,
    pub message: String,
}

impl From<&SatelleError> for QueueFailure {
    fn from(error: &SatelleError) -> Self {
        Self {
            code: error.code.as_str().to_string(),
            message: error.message.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueueStatus {
    pub schema_version: String,
    pub queue_request_id: QueueRequestId,
    pub status: QueueRequestStatus,
    pub position: Option<u16>,
    pub enqueued_at: String,
    pub expires_at: String,
    pub session_id: Option<SessionId>,
    pub turn_id: Option<TurnId>,
    pub failure: Option<QueueFailure>,
    pub state_revision: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QueueStatusWire {
    schema_version: String,
    queue_request_id: QueueRequestId,
    status: QueueRequestStatus,
    position: Option<u16>,
    enqueued_at: String,
    expires_at: String,
    session_id: Option<SessionId>,
    turn_id: Option<TurnId>,
    failure: Option<QueueFailure>,
    state_revision: u64,
}

impl<'de> Deserialize<'de> for QueueStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = QueueStatusWire::deserialize(deserializer)?;
        let status = Self {
            schema_version: wire.schema_version,
            queue_request_id: wire.queue_request_id,
            status: wire.status,
            position: wire.position,
            enqueued_at: wire.enqueued_at,
            expires_at: wire.expires_at,
            session_id: wire.session_id,
            turn_id: wire.turn_id,
            failure: wire.failure,
            state_revision: wire.state_revision,
        };
        status.validate().map_err(serde::de::Error::custom)?;
        Ok(status)
    }
}

impl QueueStatus {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        queue_request_id: QueueRequestId,
        status: QueueRequestStatus,
        position: Option<u16>,
        enqueued_at: OffsetDateTime,
        expires_at: OffsetDateTime,
        session_id: Option<SessionId>,
        turn_id: Option<TurnId>,
        failure: Option<QueueFailure>,
        state_revision: u64,
    ) -> Self {
        Self {
            schema_version: QUEUE_STATUS_SCHEMA_VERSION.to_string(),
            queue_request_id,
            status,
            position,
            enqueued_at: format_time(enqueued_at),
            expires_at: format_time(expires_at),
            session_id,
            turn_id,
            failure,
            state_revision,
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != QUEUE_STATUS_SCHEMA_VERSION || self.state_revision == 0 {
            return Err("the queue status schema or revision is invalid");
        }
        let enqueued_at = OffsetDateTime::parse(
            &self.enqueued_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| "the queue enqueue time is invalid")?;
        let expires_at = OffsetDateTime::parse(
            &self.expires_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| "the queue expiry time is invalid")?;
        if expires_at <= enqueued_at {
            return Err("the queue expiry must follow its enqueue time");
        }
        let shape_is_valid = match self.status {
            QueueRequestStatus::Queued => {
                self.position.is_some() && self.turn_id.is_none() && self.failure.is_none()
            }
            QueueRequestStatus::Admitted => {
                self.position.is_none()
                    && self.session_id.is_some()
                    && self.turn_id.is_some()
                    && self.failure.is_none()
            }
            QueueRequestStatus::Cancelled | QueueRequestStatus::Expired => {
                self.position.is_none() && self.turn_id.is_none() && self.failure.is_none()
            }
            QueueRequestStatus::ValidationFailed => {
                self.position.is_none() && self.turn_id.is_none() && self.failure.is_some()
            }
        };
        if !shape_is_valid {
            return Err("the queue status fields contradict its lifecycle state");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueCancelOutcome {
    Cancelled,
    AlreadyTerminal,
}

impl QueueCancelOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::AlreadyTerminal => "already_terminal",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueueCancelResult {
    pub schema_version: String,
    pub queue_request_id: QueueRequestId,
    pub outcome: QueueCancelOutcome,
    pub changed: bool,
    pub session_id: Option<SessionId>,
    pub turn_id: Option<TurnId>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QueueCancelWire {
    schema_version: String,
    queue_request_id: QueueRequestId,
    outcome: QueueCancelOutcome,
    changed: bool,
    session_id: Option<SessionId>,
    turn_id: Option<TurnId>,
}

impl<'de> Deserialize<'de> for QueueCancelResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = QueueCancelWire::deserialize(deserializer)?;
        let result = Self {
            schema_version: wire.schema_version,
            queue_request_id: wire.queue_request_id,
            outcome: wire.outcome,
            changed: wire.changed,
            session_id: wire.session_id,
            turn_id: wire.turn_id,
        };
        result.validate().map_err(serde::de::Error::custom)?;
        Ok(result)
    }
}

impl QueueCancelResult {
    pub fn cancelled(queue_request_id: QueueRequestId) -> Self {
        Self {
            schema_version: QUEUE_CANCEL_SCHEMA_VERSION.to_string(),
            queue_request_id,
            outcome: QueueCancelOutcome::Cancelled,
            changed: true,
            session_id: None,
            turn_id: None,
        }
    }

    pub fn already_terminal(status: &QueueStatus) -> Self {
        Self {
            schema_version: QUEUE_CANCEL_SCHEMA_VERSION.to_string(),
            queue_request_id: status.queue_request_id.clone(),
            outcome: QueueCancelOutcome::AlreadyTerminal,
            changed: false,
            session_id: status.session_id.clone(),
            turn_id: status.turn_id.clone(),
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != QUEUE_CANCEL_SCHEMA_VERSION
            || (self.turn_id.is_some() && self.session_id.is_none())
        {
            return Err("the queue cancellation schema or identity is invalid");
        }
        match self.outcome {
            QueueCancelOutcome::Cancelled
                if self.changed && self.session_id.is_none() && self.turn_id.is_none() =>
            {
                Ok(())
            }
            QueueCancelOutcome::AlreadyTerminal if !self.changed => Ok(()),
            _ => Err("the queue cancellation fields contradict its outcome"),
        }
    }
}

fn format_time(value: OffsetDateTime) -> String {
    value
        .to_offset(UtcOffset::UTC)
        .format(&time::format_description::well_known::Rfc3339)
        .expect("UTC queue timestamps are RFC 3339 representable")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_defaults_and_bounds_are_closed() {
        let defaults = QueueConfig::default();
        assert!(!defaults.enabled());
        assert_eq!(defaults.max_depth(), 16);
        assert_eq!(defaults.ttl_ms(), 3_600_000);

        for invalid in ["max_depth = 0", "max_depth = 257", "ttl = \"1500m\""] {
            let config = toml::from_str::<QueueConfig>(invalid).expect("parse queue syntax");
            assert!(config.validate().is_err());
        }
    }

    #[test]
    fn queue_identifier_and_status_contract_are_canonical() {
        let id = QueueRequestId::new();
        assert!(id.as_str().starts_with("rq_"));
        let status = QueueStatus::new(
            id.clone(),
            QueueRequestStatus::Queued,
            Some(1),
            OffsetDateTime::UNIX_EPOCH,
            OffsetDateTime::UNIX_EPOCH + time::Duration::HOUR,
            None,
            None,
            None,
            1,
        );
        let value = serde_json::to_value(status).expect("serialize queue status");
        assert_eq!(value["schema_version"], QUEUE_STATUS_SCHEMA_VERSION);
        assert_eq!(value["queue_request_id"], id.as_str());
    }
}
