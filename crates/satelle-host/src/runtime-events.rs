use super::{AdapterReadiness, RuntimeEngine};
use satelle_core::queue::QueueStatus;
use satelle_core::session::{Session, TurnState};
use satelle_core::{EventSource, EventSubject, EventType, SatelleEventBody, TurnId};
use serde_json::json;
use time::format_description::well_known::Rfc3339;

impl RuntimeEngine {
    pub(super) fn publish_queue_event(
        &self,
        event_type: EventType,
        status: &QueueStatus,
        message: &'static str,
    ) -> Result<(), satelle_core::SatelleError> {
        let host_identity = self.host_identity()?;
        let subject = match (&status.session_id, &status.turn_id) {
            (Some(session_id), Some(turn_id)) => Some(EventSubject::TurnIdentity {
                session_id: session_id.clone(),
                turn_id: turn_id.clone(),
            }),
            (Some(session_id), None) => Some(EventSubject::SessionIdentity {
                session_id: session_id.clone(),
            }),
            (None, Some(_)) => unreachable!("a queue Turn cannot exist without its Session"),
            (None, None) => None,
        };
        let event = SatelleEventBody::new(
            event_type,
            EventSource::HostDaemon,
            time::OffsetDateTime::now_utc(),
            host_identity.as_str(),
            subject,
            message,
            json!({
                "queue_request_id": status.queue_request_id,
                "status": status.status,
                "position": status.position,
                "enqueued_at": status.enqueued_at,
                "expires_at": status.expires_at,
                "session_id": status.session_id,
                "turn_id": status.turn_id,
                "failure": status.failure,
                "state_revision": status.state_revision,
            }),
        )
        .expect("a typed queue status produces a valid safe lifecycle event");
        self.live_events.publish(event);
        Ok(())
    }

    /// Publishes the successful native preflight before the admitted Turn so
    /// attached clients can distinguish native readiness from provider
    /// readiness without inferring either result from later execution events.
    pub(super) fn publish_native_readiness(
        &self,
        readiness: &AdapterReadiness,
        session: &Session,
        turn_id: &TurnId,
    ) -> SatelleEventBody {
        let turn = session
            .turn(turn_id)
            .expect("an admitted native preflight retains its Turn");
        let checks = readiness
            .checks()
            .iter()
            .map(|check| {
                json!({
                    "kind": check.kind().as_str(),
                    "status": check.status().as_str(),
                    "reason": check.reason(),
                })
            })
            .collect::<Vec<_>>();
        let event = SatelleEventBody::new(
            EventType::Readiness,
            EventSource::HostDaemon,
            time::OffsetDateTime::now_utc(),
            session.host_identity().as_str(),
            Some(EventSubject::Turn {
                session_id: session.id().clone(),
                turn_id: turn_id.clone(),
                session_state_revision: session.session_state_revision(),
                turn_state_revision: turn.turn_state_revision(),
            }),
            "native Computer Use preflight passed",
            json!({
                "status": "passed",
                "source": readiness.source().as_str(),
                "checks": checks,
            }),
        )
        .expect("typed native readiness produces a valid safe preflight event");
        self.live_events.publish(event.clone());
        event
    }

    /// Publishes one live observation of state that SQLite has already
    /// committed. Callers retain the storage mutex through this synchronous,
    /// nonblocking send so events preserve commit order across workers.
    pub(super) fn publish_committed_turn(
        &self,
        session: &Session,
        turn_id: &TurnId,
    ) -> SatelleEventBody {
        self.publish_committed_turn_with_failure_reason(session, turn_id, None)
    }

    /// Like `publish_committed_turn`, but a terminal failure also carries the
    /// adapter's closed failure reason. Remote attached clients only see this
    /// event, so it is their single source for why the Turn failed.
    pub(super) fn publish_committed_turn_with_failure_reason(
        &self,
        session: &Session,
        turn_id: &TurnId,
        failure_reason: Option<&str>,
    ) -> SatelleEventBody {
        let turn = session
            .turn(turn_id)
            .expect("a committed lifecycle mutation retains its Turn");
        let (event_type, message, state) = event_for_state(turn.state());
        let data = match failure_reason {
            Some(reason) if turn.state() == TurnState::Failed => {
                json!({"state": state, "reason": reason})
            }
            _ => json!({"state": state}),
        };
        let event = SatelleEventBody::new(
            event_type,
            EventSource::HostDaemon,
            turn.updated_at(),
            session.host_identity().as_str(),
            Some(EventSubject::Turn {
                session_id: session.id().clone(),
                turn_id: turn_id.clone(),
                session_state_revision: session.session_state_revision(),
                turn_state_revision: turn.turn_state_revision(),
            }),
            message,
            data,
        )
        .expect("a committed Session produces a valid safe lifecycle event");
        self.live_events.publish(event.clone());
        event
    }

    /// Publishes normalized provider preflight provenance without exposing the
    /// provider fingerprint, prompt, transcript, or desktop content.
    pub(super) fn publish_provider_smoke(
        &self,
        readiness: &AdapterReadiness,
        session: &Session,
        turn_id: &TurnId,
    ) -> Option<SatelleEventBody> {
        let evidence = readiness.provider_smoke_evidence()?;
        let binding = readiness
            .resolved_provider_binding()
            .expect("typed provider smoke evidence always carries its authorized binding");
        let turn = session
            .turn(turn_id)
            .expect("an admitted provider preflight retains its Turn");
        let now = time::OffsetDateTime::now_utc();
        let age_ms = (now - evidence.observed_at())
            .whole_milliseconds()
            .clamp(0, i128::from(u64::MAX)) as u64;
        let event = SatelleEventBody::new(
            EventType::ProviderSmoke,
            EventSource::HostDaemon,
            now,
            session.host_identity().as_str(),
            Some(EventSubject::Turn {
                session_id: session.id().clone(),
                turn_id: turn_id.clone(),
                session_state_revision: session.session_state_revision(),
                turn_state_revision: turn.turn_state_revision(),
            }),
            "provider Computer Use preflight passed",
            json!({
                "status": "passed",
                "source": evidence.source().as_str(),
                "resolved_codex_model": binding.model(),
                "resolved_model_provider": binding.model_provider(),
                "provider_binding_source": binding.source().as_str(),
                "experimental_provider_computer_use":
                    binding.experimental_provider_computer_use(),
                "binding_digest": binding.binding_digest(),
                "model_origin": binding.model_origin().map(|origin| origin.as_str()),
                "model_provider_origin": binding
                    .model_provider_origin()
                    .map(|origin| origin.as_str()),
                "observed_at": evidence.observed_at().format(&Rfc3339)
                    .expect("provider evidence timestamp is RFC 3339 representable"),
                "expires_at": evidence.expires_at().format(&Rfc3339)
                    .expect("provider evidence expiry is RFC 3339 representable"),
                "age_ms": age_ms,
            }),
        )
        .expect("typed provider evidence produces a valid safe preflight event");
        self.live_events.publish(event.clone());
        Some(event)
    }
}

fn event_for_state(state: TurnState) -> (EventType, &'static str, &'static str) {
    match state {
        TurnState::Starting => (EventType::TurnStarted, "admitted Turn", "starting"),
        TurnState::Running => (
            EventType::TurnProgress,
            "Turn execution is running",
            "running",
        ),
        TurnState::RecoveryPending => (
            EventType::ActionRequired,
            "Turn requires recovery",
            "recovery_pending",
        ),
        TurnState::Completed => (EventType::TurnCompleted, "completed Turn", "completed"),
        TurnState::Blocked => (EventType::TurnBlocked, "Turn was blocked", "blocked"),
        TurnState::Failed => (EventType::TurnFailed, "Turn failed", "failed"),
        TurnState::Stopped => (EventType::TurnStopped, "stopped Turn", "stopped"),
    }
}
