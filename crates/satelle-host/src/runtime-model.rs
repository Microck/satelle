use super::RequestIdentity;
use super::adapter::AdapterReadiness;
use crate::process_identity::{ProcessIdentity, ProcessIdentityError};
use crate::storage::{
    AdmissionContext, IDEMPOTENCY_RETENTION, IdempotencyInput, IdempotentOperation, LeaseOwner,
    LogEvent, LogSeverity, LogSource, PrivateRequestToken, RecoverySubject, StorageError,
    StorageErrorKind, StoredLogRecord,
};
use satelle_core::session::{
    ExecutionPolicy, ExpectedRevisions, RetainedOwnership, Session, TurnState,
};
use satelle_core::{
    ErrorCode, LOCAL_DEMO_HOST, LogEntry, SatelleError, SatelleEvent, SessionId, SessionRecord,
    StopResult, TurnId, TurnRecord, TurnStatus,
};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub(super) fn initial_session(
    session_id: SessionId,
    turn_id: TurnId,
    host_identity: satelle_core::session::HostIdentityRef,
    readiness: &AdapterReadiness,
    execution_policy: ExecutionPolicy,
    started_at: OffsetDateTime,
) -> Result<Session, SatelleError> {
    Session::start(
        session_id,
        host_identity,
        readiness.desktop_binding().clone(),
        turn_id,
        execution_policy,
        started_at,
    )
    .map_err(|_| runtime_failure("the Session could not be initialized"))
}

pub(super) fn validate_follow_up_bindings(
    session: &Session,
    readiness: &AdapterReadiness,
) -> Result<(), SatelleError> {
    if session.desktop_binding() != readiness.desktop_binding() {
        return Err(integrity_failure(
            "the adapter preflight does not match the stored Host binding",
        ));
    }
    Ok(())
}

pub(super) fn admission(
    operation: IdempotentOperation,
    requested_at: OffsetDateTime,
    identity: &RequestIdentity,
    process_identity: &ProcessIdentity,
) -> Result<AdmissionContext, SatelleError> {
    let operation_id = identity.key().to_string();
    let idempotency = idempotency(operation, identity, requested_at)?;
    let lease_owner = LeaseOwner::new(
        operation_id.clone(),
        process_identity.process_id(),
        process_identity.process_start_ref(),
        process_identity.boot_identity_ref(),
        requested_at,
    )
    .map_err(storage_failure)?;
    let request_token = PrivateRequestToken::new(operation_id).map_err(storage_failure)?;
    Ok(AdmissionContext::new(
        lease_owner,
        idempotency,
        request_token,
    ))
}

pub(super) fn process_identity_failure(error: ProcessIdentityError) -> SatelleError {
    SatelleError {
        code: ErrorCode::StorageIntegrityFailed,
        message:
            "the Host Daemon could not establish a stable process identity; no Turn was admitted"
                .to_string(),
        recovery_command: Some("satelle doctor --scope codex --json".to_string()),
        source_detail: Some(error.to_string()),
        details: std::collections::BTreeMap::new(),
    }
}

pub(super) fn stop_idempotency(
    requested_at: OffsetDateTime,
    identity: &RequestIdentity,
) -> Result<IdempotencyInput, SatelleError> {
    idempotency(IdempotentOperation::Stop, identity, requested_at)
}

pub(super) fn idempotency(
    operation: IdempotentOperation,
    identity: &RequestIdentity,
    requested_at: OffsetDateTime,
) -> Result<IdempotencyInput, SatelleError> {
    IdempotencyInput::new(
        identity.principal_ref().to_string(),
        operation,
        identity.key().to_string(),
        identity.key().to_string(),
        identity.request_digest().to_string(),
        identity.digest_schema_version(),
        identity.hmac_key_version(),
        requested_at,
        requested_at + IDEMPOTENCY_RETENTION,
    )
    .map_err(storage_failure)
}

pub(super) fn expected_revisions(
    session: &Session,
    turn_id: &TurnId,
) -> Result<ExpectedRevisions, SatelleError> {
    let turn = session
        .turn(turn_id)
        .ok_or_else(|| integrity_failure("stored Turn is missing"))?;
    Ok(ExpectedRevisions::new(
        session.session_state_revision(),
        turn.turn_state_revision(),
    ))
}

pub(super) fn monotonic_now(session: &Session) -> OffsetDateTime {
    OffsetDateTime::now_utc().max(session.updated_at())
}

pub(super) fn session_record(session: &Session) -> Result<SessionRecord, SatelleError> {
    let turns = session
        .turns()
        .map(|turn| {
            Ok(TurnRecord {
                turn_id: turn.id().clone(),
                status: turn_status(turn.state()),
                started_at: public_time(turn.started_at())?,
                completed_at: turn.terminal_at().map(public_time).transpose()?,
                summary: turn_summary(turn.state()).to_string(),
            })
        })
        .collect::<Result<Vec<_>, SatelleError>>()?;
    let status = turns
        .last()
        .map(|turn| turn.status.clone())
        .ok_or_else(|| integrity_failure("stored Session has no Turn history"))?;
    Ok(SessionRecord {
        session_id: session.id().clone(),
        host: LOCAL_DEMO_HOST.to_string(),
        status,
        created_at: public_time(session.created_at())?,
        updated_at: public_time(session.updated_at())?,
        turns,
    })
}

pub(super) fn turn_outcome(
    session: &Session,
    events: Vec<SatelleEvent>,
) -> Result<super::RuntimeTurnOutcome, SatelleError> {
    Ok(super::RuntimeTurnOutcome {
        session: session_record(session)?,
        events,
        public_session: session.to_public(),
    })
}

fn turn_status(state: TurnState) -> TurnStatus {
    match state {
        TurnState::Starting | TurnState::Running | TurnState::RecoveryPending => {
            TurnStatus::Started
        }
        TurnState::Completed => TurnStatus::Completed,
        TurnState::Blocked => TurnStatus::Blocked,
        TurnState::Failed => TurnStatus::Failed,
        TurnState::Stopped => TurnStatus::Stopped,
    }
}

fn turn_summary(state: TurnState) -> &'static str {
    match state {
        TurnState::Starting => "turn is starting",
        TurnState::Running => "turn is running",
        TurnState::RecoveryPending => "turn recovery is pending",
        TurnState::Completed => "fake computer-use turn completed",
        TurnState::Blocked => "turn was blocked by policy",
        TurnState::Failed => "turn execution failed",
        TurnState::Stopped => "turn was stopped by the user",
    }
}

pub(super) fn stored_log_entry(stored: StoredLogRecord) -> Result<LogEntry, SatelleError> {
    let record = stored.record();
    let source = match record.source() {
        LogSource::HostDaemon => "host_daemon",
        LogSource::Storage => "storage",
        LogSource::CodexAdapter => "codex_adapter",
    };
    let severity = match record.severity() {
        LogSeverity::Info => "info",
        LogSeverity::Warning => "warn",
        LogSeverity::Error => "error",
    };
    let (event, message) = match record.event() {
        LogEvent::SessionStarted => ("session_started", "created local demo session"),
        LogEvent::FollowUpStarted => ("follow_up_started", "appended local demo turn"),
        LogEvent::TurnStateCommitted => ("turn_state_committed", "committed local demo turn state"),
        LogEvent::StopConfirmed => ("stop_confirmed", "resolved local demo stop request"),
        LogEvent::StopNotConfirmed => ("stop_not_confirmed", "local demo stop was not confirmed"),
        LogEvent::RestartRecoveryPending => (
            "restart_recovery_pending",
            "local demo turn requires restart recovery",
        ),
        LogEvent::StoreOpened => ("store_opened", "opened local demo storage"),
    };
    let mut fields = std::collections::BTreeMap::from([
        ("cursor".to_string(), stored.cursor().to_string()),
        ("event".to_string(), event.to_string()),
    ]);
    let session_id = match record.subject() {
        crate::LogSubject::Host => None,
        crate::LogSubject::Turn {
            session_id,
            turn_id,
            session_state_revision,
            turn_state_revision,
        } => {
            fields.insert("turn_id".to_string(), turn_id.to_string());
            fields.insert(
                "session_state_revision".to_string(),
                session_state_revision.get().to_string(),
            );
            fields.insert(
                "turn_state_revision".to_string(),
                turn_state_revision.get().to_string(),
            );
            Some(session_id.clone())
        }
    };
    Ok(LogEntry {
        timestamp: public_time(record.recorded_at())?,
        source: source.to_string(),
        severity: severity.to_string(),
        host: LOCAL_DEMO_HOST.to_string(),
        session_id,
        message: message.to_string(),
        fields,
        redacted: true,
    })
}

pub(super) fn stop_result(
    commit: &crate::storage::StopCommit,
    session_id: &SessionId,
) -> Result<StopResult, SatelleError> {
    let turn_id = commit.turn_id().clone();
    match commit.outcome() {
        crate::storage::StopCommitOutcome::Stopped(previous_state) => {
            let turn = commit
                .session()
                .turn(&turn_id)
                .ok_or_else(|| integrity_failure("stopped Turn is missing"))?;
            let stopped_at = turn
                .terminal_at()
                .ok_or_else(|| integrity_failure("confirmed stop has no terminal timestamp"))?;
            StopResult::stopped(
                session_id.clone(),
                turn_id,
                *previous_state,
                public_time(stopped_at)?,
            )
            .map_err(|_| integrity_failure("invalid confirmed stop result"))
        }
        crate::storage::StopCommitOutcome::AlreadyTerminal(state) => {
            StopResult::already_terminal(session_id.clone(), turn_id, (*state).into())
                .map_err(|_| integrity_failure("invalid terminal stop result"))
        }
        crate::storage::StopCommitOutcome::NotConfirmed { ownership, changed } => Err(
            stop_not_confirmed(*ownership, *changed, session_id, &turn_id),
        ),
    }
}

pub(super) fn recovery_host_busy(subject: &RecoverySubject) -> SatelleError {
    let mut error = SatelleError::host_busy(LOCAL_DEMO_HOST, subject.session_id());
    error.details.insert(
        "reason".to_string(),
        Value::String("outcome_unknown".to_string()),
    );
    error.recovery_command = Some(format!("satelle status {} --json", subject.session_id()));
    error
}

fn stop_not_confirmed(
    ownership: RetainedOwnership,
    changed: bool,
    session_id: &SessionId,
    turn_id: &TurnId,
) -> SatelleError {
    let ownership = match ownership {
        RetainedOwnership::Active => "active",
        RetainedOwnership::RecoveryPending => "recovery_pending",
    };
    let mut details = std::collections::BTreeMap::new();
    details.insert(
        "session_id".to_string(),
        Value::String(session_id.to_string()),
    );
    details.insert("turn_id".to_string(), Value::String(turn_id.to_string()));
    details.insert(
        "ownership".to_string(),
        Value::String(ownership.to_string()),
    );
    details.insert("state_changed".to_string(), Value::Bool(changed));
    details.insert("retryable".to_string(), Value::Bool(true));
    SatelleError {
        code: ErrorCode::StopNotConfirmed,
        message: "stop was not confirmed; Satelle retained control of the Turn".to_string(),
        recovery_command: Some(format!("satelle status {session_id} --json")),
        source_detail: None,
        details,
    }
}

pub(super) fn storage_failure(error: StorageError) -> SatelleError {
    if let Some(session_id) = error.conflicting_session_id() {
        return SatelleError::host_busy(LOCAL_DEMO_HOST, session_id);
    }
    match error.kind() {
        StorageErrorKind::InvalidInput => SatelleError::invalid_usage(error.to_string()),
        StorageErrorKind::IdempotencyConflict => SatelleError {
            code: ErrorCode::IdempotencyKeyConflict,
            message: "the idempotency key was already used for a different request".to_string(),
            recovery_command: None,
            source_detail: None,
            details: std::collections::BTreeMap::new(),
        },
        StorageErrorKind::Busy => SatelleError::storage_busy(),
        StorageErrorKind::StoreInUse => SatelleError::store_in_use(),
        StorageErrorKind::StateConflict => SatelleError::state_conflict(),
        StorageErrorKind::UnsafeStatePath
        | StorageErrorKind::OpenFailed
        | StorageErrorKind::MigrationFailed
        | StorageErrorKind::MigrationIntegrity
        | StorageErrorKind::IntegrityCheckFailed
        | StorageErrorKind::InvalidStoredState
        | StorageErrorKind::PrivateReferenceConflict => integrity_failure(error.to_string()),
        _ => runtime_failure(error.to_string()),
    }
}

pub(super) fn storage_failure_for_session(
    error: StorageError,
    session_id: &SessionId,
) -> SatelleError {
    if error.kind() == StorageErrorKind::SessionNotFound {
        SatelleError::session_not_found(session_id)
    } else {
        storage_failure(error)
    }
}

pub(super) fn integrity_failure(message: impl Into<String>) -> SatelleError {
    SatelleError {
        code: ErrorCode::StorageIntegrityFailed,
        message: message.into(),
        recovery_command: Some(
            "preserve the state directory and run satelle doctor --scope storage --json"
                .to_string(),
        ),
        source_detail: None,
        details: std::collections::BTreeMap::new(),
    }
}

pub(super) fn background_execution_failure(error: std::io::Error) -> SatelleError {
    runtime_failure(format!(
        "the detached runtime worker could not start: {error}"
    ))
}

fn runtime_failure(message: impl Into<String>) -> SatelleError {
    SatelleError {
        code: ErrorCode::HostUnreachable,
        message: message.into(),
        recovery_command: Some("retry after verifying the Satelle state directory".to_string()),
        source_detail: None,
        details: std::collections::BTreeMap::new(),
    }
}

fn public_time(value: OffsetDateTime) -> Result<String, SatelleError> {
    value
        .format(&Rfc3339)
        .map_err(|_| integrity_failure("stored timestamp cannot be represented"))
}

#[cfg(test)]
mod storage_failure_tests {
    use super::*;

    #[test]
    fn sqlite_busy_is_preserved_as_a_typed_transient_error() {
        let error = storage_failure(StorageError::for_test(StorageErrorKind::Busy));

        assert_eq!(error.code, ErrorCode::StorageBusy);
        assert_eq!(error.code.as_str(), "storage-busy");
        assert_eq!(error.exit_code(), 74);
        assert!(!error.message.contains("SQLite"));
        assert!(error.source_detail.is_none());
    }

    #[test]
    fn store_ownership_conflict_is_preserved_as_a_typed_startup_error() {
        let error = storage_failure(StorageError::for_test(StorageErrorKind::StoreInUse));

        assert_eq!(error.code, ErrorCode::StoreInUse);
        assert_eq!(error.code.as_str(), "store-in-use");
        assert_eq!(error.exit_code(), 69);
        assert!(!error.message.contains("SQLite"));
        assert!(error.source_detail.is_none());
    }

    #[test]
    fn stale_revision_is_preserved_as_a_typed_transient_error() {
        let error = storage_failure(StorageError::for_test(StorageErrorKind::StateConflict));

        assert_eq!(error.code, ErrorCode::StateConflict);
        assert_eq!(error.code.as_str(), "state-conflict");
        assert_eq!(error.exit_code(), 75);
        assert!(!error.message.contains("SQLite"));
        assert!(error.source_detail.is_none());
    }

    #[test]
    fn migration_failure_is_typed_and_prescribes_non_destructive_repair() {
        let error = storage_failure(StorageError::for_test(StorageErrorKind::MigrationFailed));

        assert_eq!(error.code, ErrorCode::StorageIntegrityFailed);
        assert_eq!(error.code.as_str(), "storage-integrity-failed");
        assert_eq!(error.message, "the Satelle SQLite migration failed");
        assert_eq!(
            error.recovery_command.as_deref(),
            Some("preserve the state directory and run satelle doctor --scope storage --json")
        );
        assert!(error.source_detail.is_none());
    }
}
