use super::RuntimeEngine;
use satelle_core::session::{Session, TurnState};
use satelle_core::{EventSource, EventSubject, EventType, SatelleEventBody, TurnId};
use serde_json::json;

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
