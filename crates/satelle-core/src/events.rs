use crate::session::{SessionStateRevision, TurnStateRevision};
use crate::{SessionId, TurnId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::fmt;
use thiserror::Error;
use time::{OffsetDateTime, UtcOffset};

pub const EVENT_SCHEMA_VERSION: &str = "satelle.events.v2";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EventSchema;

impl Serialize for EventSchema {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(EVENT_SCHEMA_VERSION)
    }
}

impl<'de> Deserialize<'de> for EventSchema {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value == EVENT_SCHEMA_VERSION {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(
                "expected schema_version satelle.events.v2",
            ))
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    Preflight,
    Readiness,
    ProviderSmoke,
    TurnStarted,
    TurnProgress,
    ActionRequired,
    CommandFailed,
    TurnCompleted,
    TurnBlocked,
    TurnFailed,
    TurnStopped,
}

impl EventType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Preflight => "preflight",
            Self::Readiness => "readiness",
            Self::ProviderSmoke => "provider_smoke",
            Self::TurnStarted => "turn_started",
            Self::TurnProgress => "turn_progress",
            Self::ActionRequired => "action_required",
            Self::CommandFailed => "command_failed",
            Self::TurnCompleted => "turn_completed",
            Self::TurnBlocked => "turn_blocked",
            Self::TurnFailed => "turn_failed",
            Self::TurnStopped => "turn_stopped",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::CommandFailed
                | Self::TurnCompleted
                | Self::TurnBlocked
                | Self::TurnFailed
                | Self::TurnStopped
        )
    }

    pub const fn requires_turn_subject(self) -> bool {
        matches!(
            self,
            Self::TurnStarted
                | Self::TurnCompleted
                | Self::TurnBlocked
                | Self::TurnFailed
                | Self::TurnStopped
        )
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    Cli,
    HostDaemon,
    CodexAdapter,
}

impl EventSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::HostDaemon => "host_daemon",
            Self::CodexAdapter => "codex_adapter",
        }
    }
}

impl fmt::Display for EventSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EventStateSubject {
    Session {
        session_state_revision: SessionStateRevision,
    },
    Turn {
        session_state_revision: SessionStateRevision,
        turn_state_revision: TurnStateRevision,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventSubject {
    /// Session identity for an event that does not report committed state.
    SessionIdentity { session_id: SessionId },
    /// Session and Turn identity for an event that does not report committed state.
    TurnIdentity {
        session_id: SessionId,
        turn_id: TurnId,
    },
    Session {
        session_id: SessionId,
        session_state_revision: SessionStateRevision,
    },
    Turn {
        session_id: SessionId,
        turn_id: TurnId,
        session_state_revision: SessionStateRevision,
        turn_state_revision: TurnStateRevision,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct SatelleEventBody {
    event_type: EventType,
    source: EventSource,
    timestamp: OffsetDateTime,
    session_id: Option<SessionId>,
    turn_id: Option<TurnId>,
    host: String,
    state_subject: Option<EventStateSubject>,
    message: String,
    data: Value,
}

impl SatelleEventBody {
    pub fn new(
        event_type: EventType,
        source: EventSource,
        timestamp: OffsetDateTime,
        host: impl Into<String>,
        subject: Option<EventSubject>,
        message: impl Into<String>,
        data: Value,
    ) -> Result<Self, SatelleEventError> {
        let host = host.into();
        let message = message.into();
        if host.is_empty() {
            return Err(SatelleEventError::EmptyHost);
        }
        if message.is_empty() {
            return Err(SatelleEventError::EmptyMessage);
        }
        if !data.is_object() {
            return Err(SatelleEventError::DataMustBeObject);
        }
        if event_type.requires_turn_subject() && !matches!(subject, Some(EventSubject::Turn { .. }))
        {
            return Err(SatelleEventError::LifecycleEventRequiresTurn);
        }
        if event_type == EventType::CommandFailed && subject.is_some() {
            return Err(SatelleEventError::CommandFailedRequiresNoSubject);
        }
        let (session_id, turn_id, state_subject) = match subject {
            None => (None, None, None),
            Some(EventSubject::SessionIdentity { session_id }) => (Some(session_id), None, None),
            Some(EventSubject::TurnIdentity {
                session_id,
                turn_id,
            }) => (Some(session_id), Some(turn_id), None),
            Some(EventSubject::Session {
                session_id,
                session_state_revision,
            }) => (
                Some(session_id),
                None,
                Some(EventStateSubject::Session {
                    session_state_revision,
                }),
            ),
            Some(EventSubject::Turn {
                session_id,
                turn_id,
                session_state_revision,
                turn_state_revision,
            }) => (
                Some(session_id),
                Some(turn_id),
                Some(EventStateSubject::Turn {
                    session_state_revision,
                    turn_state_revision,
                }),
            ),
        };
        Ok(Self {
            event_type,
            source,
            timestamp: timestamp.to_offset(UtcOffset::UTC),
            session_id,
            turn_id,
            host,
            state_subject,
            message,
            data,
        })
    }

    pub const fn event_type(&self) -> EventType {
        self.event_type
    }

    pub const fn source(&self) -> EventSource {
        self.source
    }

    pub const fn timestamp(&self) -> OffsetDateTime {
        self.timestamp
    }

    pub const fn session_id(&self) -> Option<&SessionId> {
        self.session_id.as_ref()
    }

    pub const fn turn_id(&self) -> Option<&TurnId> {
        self.turn_id.as_ref()
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub const fn state_subject(&self) -> Option<&EventStateSubject> {
        self.state_subject.as_ref()
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub const fn data(&self) -> &Value {
        &self.data
    }

    pub fn with_host(mut self, host: impl Into<String>) -> Result<Self, SatelleEventError> {
        let host = host.into();
        if host.is_empty() {
            return Err(SatelleEventError::EmptyHost);
        }
        self.host = host;
        Ok(self)
    }

    pub fn with_seq(self, seq: u64) -> Result<SatelleEvent, SatelleEventError> {
        SatelleEvent::new(seq, self)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SatelleEvent {
    seq: u64,
    body: SatelleEventBody,
}

impl SatelleEvent {
    pub fn new(seq: u64, body: SatelleEventBody) -> Result<Self, SatelleEventError> {
        if seq == 0 {
            return Err(SatelleEventError::ZeroSequence);
        }
        Ok(Self { seq, body })
    }

    pub const fn event_type(&self) -> EventType {
        self.body.event_type()
    }

    pub const fn source(&self) -> EventSource {
        self.body.source()
    }

    pub const fn timestamp(&self) -> OffsetDateTime {
        self.body.timestamp()
    }

    pub const fn seq(&self) -> u64 {
        self.seq
    }

    pub const fn session_id(&self) -> Option<&SessionId> {
        self.body.session_id()
    }

    pub const fn turn_id(&self) -> Option<&TurnId> {
        self.body.turn_id()
    }

    pub fn host(&self) -> &str {
        self.body.host()
    }

    pub const fn state_subject(&self) -> Option<&EventStateSubject> {
        self.body.state_subject()
    }

    pub fn message(&self) -> &str {
        self.body.message()
    }

    pub const fn data(&self) -> &Value {
        self.body.data()
    }

    pub fn into_body(self) -> SatelleEventBody {
        self.body
    }
}

#[derive(Serialize)]
struct SatelleEventRef<'a> {
    schema_version: EventSchema,
    #[serde(rename = "type")]
    event_type: EventType,
    source: EventSource,
    #[serde(with = "time::serde::rfc3339")]
    timestamp: OffsetDateTime,
    seq: u64,
    session_id: Option<&'a SessionId>,
    turn_id: Option<&'a TurnId>,
    host: &'a str,
    state_subject: Option<&'a EventStateSubject>,
    message: &'a str,
    data: &'a Value,
}

impl Serialize for SatelleEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SatelleEventRef {
            schema_version: EventSchema,
            event_type: self.event_type(),
            source: self.source(),
            timestamp: self.timestamp(),
            seq: self.seq,
            session_id: self.session_id(),
            turn_id: self.turn_id(),
            host: self.host(),
            state_subject: self.state_subject(),
            message: self.message(),
            data: self.data(),
        }
        .serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SatelleEventOwned {
    #[serde(rename = "schema_version")]
    _schema_version: EventSchema,
    #[serde(rename = "type")]
    event_type: EventType,
    source: EventSource,
    #[serde(with = "time::serde::rfc3339")]
    timestamp: OffsetDateTime,
    seq: u64,
    #[serde(deserialize_with = "Option::deserialize")]
    session_id: Option<SessionId>,
    #[serde(deserialize_with = "Option::deserialize")]
    turn_id: Option<TurnId>,
    host: String,
    #[serde(deserialize_with = "Option::deserialize")]
    state_subject: Option<EventStateSubject>,
    message: String,
    data: Value,
}

impl<'de> Deserialize<'de> for SatelleEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SatelleEventOwned::deserialize(deserializer)?;
        let subject = match (wire.session_id, wire.turn_id, wire.state_subject) {
            (None, None, None) => None,
            (Some(session_id), None, None) => Some(EventSubject::SessionIdentity { session_id }),
            (Some(session_id), Some(turn_id), None) => Some(EventSubject::TurnIdentity {
                session_id,
                turn_id,
            }),
            (
                Some(session_id),
                None,
                Some(EventStateSubject::Session {
                    session_state_revision,
                }),
            ) => Some(EventSubject::Session {
                session_id,
                session_state_revision,
            }),
            (
                Some(session_id),
                Some(turn_id),
                Some(EventStateSubject::Turn {
                    session_state_revision,
                    turn_state_revision,
                }),
            ) => Some(EventSubject::Turn {
                session_id,
                turn_id,
                session_state_revision,
                turn_state_revision,
            }),
            _ => {
                return Err(serde::de::Error::custom(
                    "the Satelle Event identifiers contradict its state_subject",
                ));
            }
        };
        SatelleEventBody::new(
            wire.event_type,
            wire.source,
            wire.timestamp,
            wire.host,
            subject,
            wire.message,
            wire.data,
        )
        .and_then(|body| body.with_seq(wire.seq))
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SatelleEventError {
    #[error("a Satelle Event stream sequence must be positive")]
    ZeroSequence,
    #[error("a Satelle Event Host must not be empty")]
    EmptyHost,
    #[error("a Satelle Event message must not be empty")]
    EmptyMessage,
    #[error("Satelle Event data must be a JSON object")]
    DataMustBeObject,
    #[error("a committed Turn lifecycle Satelle Event requires a Turn state subject")]
    LifecycleEventRequiresTurn,
    #[error("a command_failed Satelle Event must not have a state subject")]
    CommandFailedRequiresNoSubject,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_event() -> Value {
        serde_json::json!({
            "schema_version": "satelle.events.v2",
            "type": "turn_completed",
            "source": "host_daemon",
            "timestamp": "2026-07-10T12:00:00Z",
            "seq": 7,
            "session_id": "rs_01890a5d-ac96-7b7c-8f89-37c3d0a66e11",
            "turn_id": "rt_01890a5d-ac96-7b7c-8f89-37c3d0a66e21",
            "host": "host-01890a5d-ac96-7b7c-8f89-37c3d0a66e31",
            "state_subject": {
                "kind": "turn",
                "session_state_revision": 3,
                "turn_state_revision": 3
            },
            "message": "completed Turn",
            "data": {"state": "completed"}
        })
    }

    fn valid_command_failed_event() -> Value {
        serde_json::json!({
            "schema_version": "satelle.events.v2",
            "type": "command_failed",
            "source": "cli",
            "timestamp": "2026-07-10T12:00:00Z",
            "seq": 1,
            "session_id": null,
            "turn_id": null,
            "host": "workstation",
            "state_subject": null,
            "message": "Host is unreachable",
            "data": {
                "code": "host-unreachable",
                "message": "Host is unreachable",
                "recovery_command": null,
                "source_detail": null,
                "details": {},
                "admission_phase": "not_admitted",
                "session_id": null,
                "turn_id": null
            }
        })
    }

    fn uncommitted_turn_progress_event() -> Value {
        serde_json::json!({
            "schema_version": "satelle.events.v2",
            "type": "turn_progress",
            "source": "codex_adapter",
            "timestamp": "2026-07-10T12:00:00Z",
            "seq": 2,
            "session_id": "rs_01890a5d-ac96-7b7c-8f89-37c3d0a66e11",
            "turn_id": "rt_01890a5d-ac96-7b7c-8f89-37c3d0a66e21",
            "host": "host-01890a5d-ac96-7b7c-8f89-37c3d0a66e31",
            "state_subject": null,
            "message": "Turn is making progress",
            "data": {"phase": "working"}
        })
    }

    #[test]
    fn command_failed_is_a_subjectless_terminal_event() {
        let wire = valid_command_failed_event();
        let event: SatelleEvent =
            serde_json::from_value(wire.clone()).expect("decode subjectless command failure");

        assert_eq!(event.event_type(), EventType::CommandFailed);
        assert!(event.event_type().is_terminal());
        assert!(!event.event_type().requires_turn_subject());
        assert_eq!(event.session_id(), None);
        assert_eq!(event.turn_id(), None);
        assert_eq!(event.state_subject(), None);
        assert_eq!(
            serde_json::to_value(event).expect("encode command failure"),
            wire
        );
    }

    #[test]
    fn satelle_event_v2_requires_nullable_subject_fields() {
        for field in ["session_id", "turn_id", "state_subject"] {
            let mut wire = valid_command_failed_event();
            let event = wire
                .as_object_mut()
                .expect("command_failed fixture is an Event object");
            assert!(
                event.remove(field).is_some(),
                "fixture must contain nullable field {field}"
            );
            assert!(!event.contains_key(field), "mutation must remove {field}");

            assert!(
                serde_json::from_value::<SatelleEvent>(wire).is_err(),
                "omitted nullable field {field} must be rejected"
            );
        }
    }

    #[test]
    fn command_failed_rejects_a_state_subject() {
        let mut turn_subject = valid_event();
        turn_subject["type"] = serde_json::json!("command_failed");

        let mut session_subject = turn_subject.clone();
        session_subject["turn_id"] = Value::Null;
        session_subject["state_subject"] = serde_json::json!({
            "kind": "session",
            "session_state_revision": 3
        });

        for wire in [session_subject, turn_subject] {
            let error = serde_json::from_value::<SatelleEvent>(wire)
                .expect_err("command failure with a state subject must be rejected");
            assert!(
                error
                    .to_string()
                    .contains("command_failed Satelle Event must not have a state subject")
            );
        }
    }

    #[test]
    fn non_lifecycle_events_keep_identity_without_claiming_committed_state() {
        let turn_wire = uncommitted_turn_progress_event();
        let turn_event: SatelleEvent = serde_json::from_value(turn_wire.clone())
            .expect("decode Turn identity without a committed state subject");
        assert!(turn_event.session_id().is_some());
        assert!(turn_event.turn_id().is_some());
        assert_eq!(turn_event.state_subject(), None);
        assert_eq!(
            serde_json::to_value(turn_event).expect("encode uncommitted Turn event"),
            turn_wire
        );

        let mut session_wire = uncommitted_turn_progress_event();
        session_wire["type"] = serde_json::json!("action_required");
        session_wire["turn_id"] = Value::Null;
        let session_event: SatelleEvent = serde_json::from_value(session_wire.clone())
            .expect("decode Session identity without a committed state subject");
        assert!(session_event.session_id().is_some());
        assert_eq!(session_event.turn_id(), None);
        assert_eq!(session_event.state_subject(), None);
        assert_eq!(
            serde_json::to_value(session_event).expect("encode uncommitted Session event"),
            session_wire
        );
    }

    #[test]
    fn turn_started_requires_committed_turn_revisions() {
        let mut wire = uncommitted_turn_progress_event();
        wire["type"] = serde_json::json!("turn_started");

        let error = serde_json::from_value::<SatelleEvent>(wire)
            .expect_err("turn_started without committed revisions must be rejected");
        assert!(
            error
                .to_string()
                .contains("committed Turn lifecycle Satelle Event requires a Turn state subject")
        );
    }

    #[test]
    fn turn_terminal_events_still_require_a_turn_subject() {
        let error = SatelleEventBody::new(
            EventType::TurnCompleted,
            EventSource::HostDaemon,
            OffsetDateTime::UNIX_EPOCH,
            "workstation",
            None,
            "completed Turn",
            serde_json::json!({"state": "completed"}),
        )
        .expect_err("Turn terminal event without a Turn subject must be rejected");

        assert_eq!(error, SatelleEventError::LifecycleEventRequiresTurn);
    }

    #[test]
    fn terminal_classification_distinguishes_stream_and_turn_requirements() {
        assert!(EventType::CommandFailed.is_terminal());
        assert!(!EventType::CommandFailed.requires_turn_subject());
        assert!(!EventType::TurnStarted.is_terminal());
        assert!(EventType::TurnStarted.requires_turn_subject());

        for event_type in [
            EventType::TurnCompleted,
            EventType::TurnBlocked,
            EventType::TurnFailed,
            EventType::TurnStopped,
        ] {
            assert!(event_type.is_terminal());
            assert!(event_type.requires_turn_subject());
        }

        for event_type in [
            EventType::Preflight,
            EventType::Readiness,
            EventType::ProviderSmoke,
            EventType::TurnProgress,
            EventType::ActionRequired,
        ] {
            assert!(!event_type.is_terminal());
            assert!(!event_type.requires_turn_subject());
        }
    }

    #[test]
    fn satelle_event_v2_is_closed_and_revision_bound() {
        let event: SatelleEvent =
            serde_json::from_value(valid_event()).expect("decode coherent event");
        assert_eq!(event.event_type(), EventType::TurnCompleted);
        assert_eq!(event.seq(), 7);

        let mutations: [fn(&mut Value); 5] = [
            |value| value["schema_version"] = serde_json::json!("satelle.events.v1"),
            |value| value["schema_version"] = serde_json::json!(1),
            |value| value["seq"] = serde_json::json!(0),
            |value| {
                value["state_subject"]["turn_state_revision"] = serde_json::Value::Null;
            },
            |value| value["extra"] = serde_json::json!(true),
        ];
        for mutation in mutations {
            let mut invalid = valid_event();
            mutation(&mut invalid);
            assert!(serde_json::from_value::<SatelleEvent>(invalid).is_err());
        }
    }
}
