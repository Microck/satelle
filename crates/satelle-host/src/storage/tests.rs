use super::*;
use crate::TestStateDir as TempDir;
use rusqlite::{Connection, params};
use satelle_core::session::{
    ApprovalPolicy, DesktopBindingRef, DesktopTarget, EffectiveModelRef,
    ExperimentalFeatureChoices, FeatureChoice, ProviderBindingRef, SafeSummary, SandboxPolicy,
    SessionActivity, StopObservation, TerminalTurnState, TimeoutPolicy, TurnState,
    TurnStateRevision,
};
use std::fs;
use time::format_description::well_known::Rfc3339;

const SESSION_1: &str = "rs_01890a5d-ac96-7b7c-8f89-37c3d0a66e11";
const SESSION_2: &str = "rs_01890a5d-ac96-7b7c-8f89-37c3d0a66e12";
const TURN_1: &str = "rt_01890a5d-ac96-7b7c-8f89-37c3d0a66e21";
const TURN_2: &str = "rt_01890a5d-ac96-7b7c-8f89-37c3d0a66e22";
const TURN_3: &str = "rt_01890a5d-ac96-7b7c-8f89-37c3d0a66e23";

mod atomicity;
mod auth;
mod lifecycle;
mod logs;
mod security;

fn initial_session(storage: &Storage, session: &str, turn: &str, at: OffsetDateTime) -> Session {
    Session::start(
        session_id(session),
        storage.host_identity().expect("load Host Identity"),
        DesktopBindingRef::new("desktop-binding-1").unwrap(),
        turn_id(turn),
        policy(),
        at,
    )
    .unwrap()
}

fn policy() -> ExecutionPolicy {
    ExecutionPolicy::new(
        EffectiveModelRef::new("model-1").unwrap(),
        ProviderBindingRef::new("provider-1").unwrap(),
        DesktopTarget::new(DesktopBindingRef::new("desktop-binding-1").unwrap()),
        ApprovalPolicy::OnRequest,
        SandboxPolicy::WorkspaceWrite,
        TimeoutPolicy::bounded_seconds(120).unwrap(),
        ExperimentalFeatureChoices::new(FeatureChoice::Enabled, FeatureChoice::Disabled),
    )
}

fn admission(
    operation: IdempotentOperation,
    key: &str,
    request_token: &str,
    at: OffsetDateTime,
) -> AdmissionContext {
    AdmissionContext::new(
        LeaseOwner::new(
            format!("operation-{key}"),
            std::process::id(),
            "process-start-1",
            "boot-identity-1",
            at,
        )
        .unwrap(),
        idempotency(operation, key, at),
        PrivateRequestToken::new(request_token).unwrap(),
    )
}

fn idempotency(
    operation: IdempotentOperation,
    key: &str,
    created_at: OffsetDateTime,
) -> IdempotencyInput {
    IdempotencyInput::new(
        "principal-1",
        operation,
        key,
        format!("operation-{key}"),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        1,
        1,
        created_at,
        created_at + time::Duration::hours(24),
    )
    .unwrap()
}

fn record_upstream_refs(
    storage: &mut Storage,
    session_id: &SessionId,
    turn_id: &TurnId,
    thread: &str,
    turn: &str,
) {
    storage
        .record_upstream_ref(
            session_id,
            turn_id,
            &ObservedUpstreamRef::thread(thread).unwrap(),
        )
        .unwrap();
    storage
        .record_upstream_ref(
            session_id,
            turn_id,
            &ObservedUpstreamRef::turn(turn).unwrap(),
        )
        .unwrap();
}

fn revisions(session: &Session, turn: &str) -> ExpectedRevisions {
    ExpectedRevisions::new(
        session.session_state_revision(),
        session
            .turn(&turn_id(turn))
            .expect("Turn belongs to Session")
            .turn_state_revision(),
    )
}

fn session_id(value: &str) -> SessionId {
    SessionId::parse(value).unwrap()
}

fn turn_id(value: &str) -> TurnId {
    TurnId::parse(value).unwrap()
}

fn at(second: u8) -> OffsetDateTime {
    OffsetDateTime::parse(&format!("2026-01-02T03:04:{second:02}Z"), &Rfc3339).unwrap()
}

fn pragma_integer(connection: &Connection, name: &str) -> i64 {
    connection
        .query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))
        .unwrap()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

impl Storage {
    fn connection_for_test(&self) -> &Connection {
        &self.connection
    }

    fn checkpoint_for_test(&self) {
        self.connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .expect("checkpoint test database");
    }
}
