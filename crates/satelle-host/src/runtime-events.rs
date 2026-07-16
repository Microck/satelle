use super::{AdapterReadiness, RuntimeEngine};
use satelle_core::session::{Session, TurnState};
use satelle_core::{EventSource, EventSubject, EventType, SatelleEventBody, TurnId};
use serde_json::json;
use time::format_description::well_known::Rfc3339;

impl RuntimeEngine {
    /// Publishes one live observation of state that SQLite has already
    /// committed. Callers retain the storage mutex through this synchronous,
    /// nonblocking send so events preserve commit order across workers.
    pub(super) fn publish_committed_turn(&self, session: &Session, turn_id: &TurnId) {
        let turn = session
            .turn(turn_id)
            .expect("a committed lifecycle mutation retains its Turn");
        let (event_type, message, state) = event_for_state(turn.state());
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
            json!({"state": state}),
        )
        .expect("a committed Session produces a valid safe lifecycle event");
        self.live_events.publish(event);
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
