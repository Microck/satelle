use super::{
    IdempotentOperation, LogEvent, LogSeverity, LogSource, PrivateRequestToken, SafeLogRecord,
    StopCommitOutcome, StorageError, StorageErrorKind, StoredLogRecord, sqlite_error,
};
use crate::LogSubject;
use rusqlite::{Connection, OptionalExtension, params};
use satelle_core::session::{
    ApprovalPolicy, DesktopBindingRef, DesktopTarget, EffectiveModelRef, ExecutionPolicy,
    ExperimentalFeatureChoices, FeatureChoice, HostIdentityRef, ProviderBindingRef,
    RetainedOwnership, SafeSummary, SandboxPolicy, Session, SessionSnapshot, SessionStateRevision,
    TerminalTurnState, TimeoutPolicy, TurnSnapshot, TurnState, TurnStateRevision,
};
use satelle_core::{SessionId, TurnId};
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

const MAX_PRIVATE_REFERENCE_BYTES: usize = 256;

pub(super) fn validated_private_reference(value: String) -> Result<String, StorageError> {
    if value.is_empty()
        || value.len() > MAX_PRIVATE_REFERENCE_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return Err(StorageError::new(StorageErrorKind::InvalidInput));
    }
    Ok(value)
}

#[derive(Debug)]
struct RawSessionRow {
    display_name: Option<String>,
    revision: String,
    host_identity_ref: String,
    desktop_binding_ref: String,
    created_at: String,
    updated_at: String,
}

#[derive(Debug)]
struct RawTurnRow {
    turn_id: String,
    revision: String,
    state: String,
    started_at: String,
    updated_at: String,
    terminal_at: Option<String>,
    safe_summary: Option<String>,
    request_token: String,
    effective_model_ref: String,
    provider_binding_ref: String,
    desktop_binding_ref: String,
    desktop_session_id: String,
    approval_policy: String,
    sandbox_policy: String,
    timeout_seconds: i64,
    computer_use_enabled: i64,
    provider_computer_use_enabled: i64,
}

#[derive(Debug)]
struct RawLogRow {
    cursor: i64,
    recorded_at: String,
    source: String,
    severity: String,
    event: String,
    session_id: Option<String>,
    turn_id: Option<String>,
    session_revision: Option<String>,
    turn_revision: Option<String>,
}

pub(super) fn load_session_from_connection(
    connection: &Connection,
    session_id: &SessionId,
) -> Result<Option<Session>, StorageError> {
    load_session(connection, session_id, None)
}

pub(super) fn load_session_at_operation_outcome(
    connection: &Connection,
    session_id: &SessionId,
    turn_id: &TurnId,
    session_revision: &str,
    session_updated_at: &str,
) -> Result<Session, StorageError> {
    load_session(
        connection,
        session_id,
        Some((turn_id, session_revision, session_updated_at)),
    )?
    .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))
}

fn load_session(
    connection: &Connection,
    session_id: &SessionId,
    operation_boundary: Option<(&TurnId, &str, &str)>,
) -> Result<Option<Session>, StorageError> {
    let row = connection
        .query_row(
            "SELECT s.display_name, s.session_state_revision, p.host_identity_ref, p.desktop_binding_ref, s.created_at, s.updated_at \
             FROM sessions s JOIN session_private_refs p ON p.session_id = s.session_id \
             WHERE s.session_id = ?1",
            [session_id.as_str()],
            |row| {
                Ok(RawSessionRow {
                    display_name: row.get(0)?,
                    revision: row.get(1)?,
                    host_identity_ref: row.get(2)?,
                    desktop_binding_ref: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            },
        )
        .optional()
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let mut row = row;
    if let Some((_, session_revision, session_updated_at)) = operation_boundary {
        row.revision = session_revision.to_string();
        row.updated_at = session_updated_at.to_string();
    }
    let mut statement = connection
        .prepare(
            "SELECT t.turn_id, t.turn_state_revision, t.state, t.started_at, t.updated_at, t.terminal_at, t.safe_summary, \
                    r.request_token, p.effective_model_ref, p.provider_binding_ref, p.desktop_binding_ref, p.desktop_session_id, \
                    p.approval_policy, p.sandbox_policy, p.timeout_seconds, p.computer_use_enabled, p.provider_computer_use_enabled \
             FROM turns t \
             JOIN turn_private_refs r ON r.turn_id = t.turn_id \
             JOIN turn_policies p ON p.turn_id = t.turn_id \
             WHERE t.session_id = ?1 \
               AND (?2 IS NULL OR t.ordinal <= ( \
                    SELECT boundary.ordinal FROM turns boundary \
                    WHERE boundary.session_id = ?1 AND boundary.turn_id = ?2 \
               )) \
             ORDER BY t.ordinal",
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    let boundary_turn_id = operation_boundary.map(|(turn_id, _, _)| turn_id.as_str());
    let turns = statement
        .query_map(params![session_id.as_str(), boundary_turn_id], |row| {
            Ok(RawTurnRow {
                turn_id: row.get(0)?,
                revision: row.get(1)?,
                state: row.get(2)?,
                started_at: row.get(3)?,
                updated_at: row.get(4)?,
                terminal_at: row.get(5)?,
                safe_summary: row.get(6)?,
                request_token: row.get(7)?,
                effective_model_ref: row.get(8)?,
                provider_binding_ref: row.get(9)?,
                desktop_binding_ref: row.get(10)?,
                desktop_session_id: row.get(11)?,
                approval_policy: row.get(12)?,
                sandbox_policy: row.get(13)?,
                timeout_seconds: row.get(14)?,
                computer_use_enabled: row.get(15)?,
                provider_computer_use_enabled: row.get(16)?,
            })
        })
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?
        .map(|turn| {
            turn.map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
                .and_then(parse_turn_row)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let snapshot = SessionSnapshot::new_with_display_name(
        session_id.clone(),
        row.display_name,
        parse_session_revision(&row.revision)?,
        HostIdentityRef::new(row.host_identity_ref)
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?,
        DesktopBindingRef::new(row.desktop_binding_ref)
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?,
        parse_time(&row.created_at)?,
        parse_time(&row.updated_at)?,
        turns,
    );
    Session::restore(snapshot)
        .map(Some)
        .map_err(|source| StorageError::with_source(StorageErrorKind::InvalidStoredState, source))
}

pub(super) fn load_required_session(
    connection: &Connection,
    session_id: &SessionId,
) -> Result<Session, StorageError> {
    load_session_from_connection(connection, session_id)?
        .ok_or_else(|| StorageError::new(StorageErrorKind::SessionNotFound))
}

#[cfg(test)]
pub(super) fn load_log_records(
    connection: &Connection,
    cursor: i64,
    limit: i64,
) -> Result<Vec<StoredLogRecord>, StorageError> {
    let mut statement = connection
        .prepare(
            "SELECT log_cursor, recorded_at, source, severity, event_kind, session_id, turn_id, session_state_revision, turn_state_revision FROM logs WHERE log_cursor > ?1 ORDER BY log_cursor LIMIT ?2",
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    let rows = statement
        .query_map(params![cursor, limit], |row| {
            Ok(RawLogRow {
                cursor: row.get(0)?,
                recorded_at: row.get(1)?,
                source: row.get(2)?,
                severity: row.get(3)?,
                event: row.get(4)?,
                session_id: row.get(5)?,
                turn_id: row.get(6)?,
                session_revision: row.get(7)?,
                turn_revision: row.get(8)?,
            })
        })
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    rows.map(|row| {
        row.map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
            .and_then(parse_log_row)
    })
    .collect()
}

pub(super) fn load_log_page_records(
    connection: &Connection,
    query: &crate::LogPageQuery,
    limit: usize,
) -> Result<Vec<StoredLogRecord>, StorageError> {
    let forward = i64::from(query.mode() == crate::LogPageMode::Forward);
    let cursor = i64::try_from(query.cursor().map_or(0, crate::LogCursor::position))
        .map_err(|_| StorageError::new(StorageErrorKind::InvalidInput))?;
    let session_id = query.session_id().map(SessionId::as_str);
    let since_nanos = query.since().map(OffsetDateTime::unix_timestamp_nanos);
    if since_nanos.is_some_and(|value| value > i128::from(i64::MAX)) {
        // SQLite stores Log timestamps as signed 64-bit nanoseconds. A valid RFC 3339 lower
        // bound beyond that representable range is newer than every storable entry, so it is a
        // successful empty query rather than invalid storage input.
        return Ok(Vec::new());
    }
    let since = since_nanos
        .map(|value| value.max(i128::from(i64::MIN)))
        .map(i64::try_from)
        .transpose()
        .expect("the Log query timestamp was bounded to SQLite's signed 64-bit range");
    let all_sources = i64::from(
        query.includes_source(crate::LogSource::HostDaemon)
            && query.includes_source(crate::LogSource::Storage)
            && query.includes_source(crate::LogSource::CodexAdapter),
    );
    let host_daemon = i64::from(query.includes_source(crate::LogSource::HostDaemon));
    let storage = i64::from(query.includes_source(crate::LogSource::Storage));
    let codex_adapter = i64::from(query.includes_source(crate::LogSource::CodexAdapter));
    let minimum_severity = i64::from(query.minimum_severity().rank());
    let limit =
        i64::try_from(limit).map_err(|_| StorageError::new(StorageErrorKind::InvalidInput))?;
    let mut statement = connection
        .prepare(
            "SELECT log_cursor, recorded_at, source, severity, event_kind, session_id, turn_id, session_state_revision, turn_state_revision
             FROM logs
             WHERE (?1 = 0 OR log_cursor > ?2)
               AND (?3 IS NULL OR session_id = ?3)
               AND (?4 IS NULL OR recorded_at_unix_nanos >= ?4)
               AND (
                    ?5 = 1
                    OR (?6 = 1 AND source = 'host_daemon')
                    OR (?7 = 1 AND source = 'storage')
                    OR (?8 = 1 AND source = 'codex_adapter')
               )
               AND CASE severity WHEN 'info' THEN 0 WHEN 'warning' THEN 1 WHEN 'error' THEN 2 END >= ?9
             ORDER BY
               CASE WHEN ?1 = 1 THEN log_cursor END ASC,
               CASE WHEN ?1 = 0 THEN log_cursor END DESC
             LIMIT ?10",
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    let rows = statement
        .query_map(
            params![
                forward,
                cursor,
                session_id,
                since,
                all_sources,
                host_daemon,
                storage,
                codex_adapter,
                minimum_severity,
                limit,
            ],
            |row| {
                Ok(RawLogRow {
                    cursor: row.get(0)?,
                    recorded_at: row.get(1)?,
                    source: row.get(2)?,
                    severity: row.get(3)?,
                    event: row.get(4)?,
                    session_id: row.get(5)?,
                    turn_id: row.get(6)?,
                    session_revision: row.get(7)?,
                    turn_revision: row.get(8)?,
                })
            },
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    rows.map(|row| {
        row.map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
            .and_then(parse_log_row)
    })
    .collect()
}

pub(super) fn log_retention_bounds(
    connection: &Connection,
) -> Result<(u64, Option<u64>, u64), StorageError> {
    let (expired_through, earliest, high_water) = connection
        .query_row(
            "SELECT r.expired_through_cursor, min(l.log_cursor), max(l.log_cursor)
             FROM log_retention_state r LEFT JOIN logs l ON true
             WHERE r.singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            },
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    let expired_through = u64::try_from(expired_through)
        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
    let earliest = earliest
        .map(u64::try_from)
        .transpose()
        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
    let high_water = high_water
        .map(u64::try_from)
        .transpose()
        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?
        .unwrap_or(expired_through);
    Ok((expired_through, earliest, high_water))
}

fn parse_turn_row(row: RawTurnRow) -> Result<TurnSnapshot, StorageError> {
    PrivateRequestToken::new(row.request_token)?;
    let timeout_seconds = u32::try_from(row.timeout_seconds)
        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
    let execution_policy = ExecutionPolicy::new(
        EffectiveModelRef::new(row.effective_model_ref)
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?,
        ProviderBindingRef::new(row.provider_binding_ref)
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?,
        DesktopTarget::new(
            DesktopBindingRef::new(row.desktop_binding_ref)
                .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?,
            row.desktop_session_id,
        ),
        parse_approval_policy(&row.approval_policy)?,
        parse_sandbox_policy(&row.sandbox_policy)?,
        TimeoutPolicy::bounded_seconds(timeout_seconds)
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?,
        ExperimentalFeatureChoices::new(
            parse_feature_choice(row.computer_use_enabled)?,
            parse_feature_choice(row.provider_computer_use_enabled)?,
        ),
    );
    Ok(TurnSnapshot::new(
        TurnId::parse(&row.turn_id)
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?,
        parse_turn_revision(&row.revision)?,
        parse_turn_state(&row.state)?,
        execution_policy,
        parse_time(&row.started_at)?,
        parse_time(&row.updated_at)?,
        row.terminal_at.as_deref().map(parse_time).transpose()?,
        row.safe_summary
            .as_deref()
            .map(parse_safe_summary)
            .transpose()?,
    ))
}

pub(super) fn stop_outcome_token(
    outcome: &StopCommitOutcome,
) -> Result<&'static str, StorageError> {
    Ok(match outcome {
        StopCommitOutcome::Stopped(TurnState::Starting) => "v1.stop.stopped_from_starting",
        StopCommitOutcome::Stopped(TurnState::Running) => "v1.stop.stopped_from_running",
        StopCommitOutcome::Stopped(TurnState::RecoveryPending) => {
            "v1.stop.stopped_from_recovery_pending"
        }
        StopCommitOutcome::Stopped(
            TurnState::Completed | TurnState::Blocked | TurnState::Failed | TurnState::Stopped,
        ) => return Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
        StopCommitOutcome::AlreadyTerminal(TerminalTurnState::Completed) => {
            "v1.stop.already_completed"
        }
        StopCommitOutcome::AlreadyTerminal(TerminalTurnState::Blocked) => "v1.stop.already_blocked",
        StopCommitOutcome::AlreadyTerminal(TerminalTurnState::Failed) => "v1.stop.already_failed",
        StopCommitOutcome::AlreadyTerminal(TerminalTurnState::Stopped) => "v1.stop.already_stopped",
        StopCommitOutcome::NotConfirmed {
            ownership: RetainedOwnership::Active,
            changed: true,
        } => "v1.stop.not_confirmed_active_changed",
        StopCommitOutcome::NotConfirmed {
            ownership: RetainedOwnership::Active,
            changed: false,
        } => "v1.stop.not_confirmed_active_unchanged",
        StopCommitOutcome::NotConfirmed {
            ownership: RetainedOwnership::RecoveryPending,
            changed: true,
        } => "v1.stop.not_confirmed_recovery_pending_changed",
        StopCommitOutcome::NotConfirmed {
            ownership: RetainedOwnership::RecoveryPending,
            changed: false,
        } => "v1.stop.not_confirmed_recovery_pending_unchanged",
    })
}

pub(super) fn parse_stop_outcome(value: &str) -> Result<StopCommitOutcome, StorageError> {
    match value {
        "v1.stop.stopped_from_starting" => Ok(StopCommitOutcome::Stopped(TurnState::Starting)),
        "v1.stop.stopped_from_running" => Ok(StopCommitOutcome::Stopped(TurnState::Running)),
        "v1.stop.stopped_from_recovery_pending" => {
            Ok(StopCommitOutcome::Stopped(TurnState::RecoveryPending))
        }
        "v1.stop.already_completed" => Ok(StopCommitOutcome::AlreadyTerminal(
            TerminalTurnState::Completed,
        )),
        "v1.stop.already_blocked" => Ok(StopCommitOutcome::AlreadyTerminal(
            TerminalTurnState::Blocked,
        )),
        "v1.stop.already_failed" => Ok(StopCommitOutcome::AlreadyTerminal(
            TerminalTurnState::Failed,
        )),
        "v1.stop.already_stopped" => Ok(StopCommitOutcome::AlreadyTerminal(
            TerminalTurnState::Stopped,
        )),
        "v1.stop.not_confirmed_active_changed" => Ok(StopCommitOutcome::NotConfirmed {
            ownership: RetainedOwnership::Active,
            changed: true,
        }),
        "v1.stop.not_confirmed_active_unchanged" => Ok(StopCommitOutcome::NotConfirmed {
            ownership: RetainedOwnership::Active,
            changed: false,
        }),
        "v1.stop.not_confirmed_recovery_pending_changed" => Ok(StopCommitOutcome::NotConfirmed {
            ownership: RetainedOwnership::RecoveryPending,
            changed: true,
        }),
        "v1.stop.not_confirmed_recovery_pending_unchanged" => Ok(StopCommitOutcome::NotConfirmed {
            ownership: RetainedOwnership::RecoveryPending,
            changed: false,
        }),
        _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
    }
}

pub(super) fn idempotent_operation_token(operation: IdempotentOperation) -> &'static str {
    match operation {
        IdempotentOperation::Run => "run",
        IdempotentOperation::Steer => "steer",
        IdempotentOperation::Stop => "stop",
        IdempotentOperation::Setup => "setup",
        IdempotentOperation::Repair => "repair",
        IdempotentOperation::HostUpdate => "host_update",
        IdempotentOperation::StorageMigration => "storage_migration",
        IdempotentOperation::DestructiveMaintenance => "destructive_maintenance",
    }
}

pub(super) fn turn_idempotency_token(state: TurnState) -> &'static str {
    match state {
        TurnState::Starting => "v1.turn.starting",
        TurnState::Running => "v1.turn.running",
        TurnState::RecoveryPending => "v1.turn.recovery_pending",
        TurnState::Completed => "v1.turn.completed",
        TurnState::Blocked => "v1.turn.blocked",
        TurnState::Failed => "v1.turn.failed",
        TurnState::Stopped => "v1.turn.stopped",
    }
}

pub(super) fn format_time(value: OffsetDateTime) -> Result<String, StorageError> {
    value
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|_| StorageError::new(StorageErrorKind::InvalidInput))
}

pub(super) fn unix_timestamp_nanos(value: OffsetDateTime) -> Result<i64, StorageError> {
    i64::try_from(value.unix_timestamp_nanos())
        .map_err(|_| StorageError::new(StorageErrorKind::InvalidInput))
}

pub(super) fn parse_time(value: &str) -> Result<OffsetDateTime, StorageError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
}

pub(super) fn format_revision(value: SessionStateRevision) -> String {
    format!("{:016x}", value.get())
}

pub(super) fn format_turn_revision(value: TurnStateRevision) -> String {
    format!("{:016x}", value.get())
}

fn parse_session_revision(value: &str) -> Result<SessionStateRevision, StorageError> {
    parse_revision(value).and_then(|value| {
        SessionStateRevision::new(value)
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
    })
}

fn parse_turn_revision(value: &str) -> Result<TurnStateRevision, StorageError> {
    parse_revision(value).and_then(|value| {
        TurnStateRevision::new(value)
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
    })
}

fn parse_revision(value: &str) -> Result<u64, StorageError> {
    if value.len() != 16 {
        return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
    }
    u64::from_str_radix(value, 16)
        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
}

pub(super) fn turn_state_token(value: TurnState) -> &'static str {
    match value {
        TurnState::Starting => "starting",
        TurnState::Running => "running",
        TurnState::RecoveryPending => "recovery_pending",
        TurnState::Completed => "completed",
        TurnState::Blocked => "blocked",
        TurnState::Failed => "failed",
        TurnState::Stopped => "stopped",
    }
}

fn parse_turn_state(value: &str) -> Result<TurnState, StorageError> {
    match value {
        "starting" => Ok(TurnState::Starting),
        "running" => Ok(TurnState::Running),
        "recovery_pending" => Ok(TurnState::RecoveryPending),
        "completed" => Ok(TurnState::Completed),
        "blocked" => Ok(TurnState::Blocked),
        "failed" => Ok(TurnState::Failed),
        "stopped" => Ok(TurnState::Stopped),
        _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
    }
}

pub(super) fn safe_summary_token(value: SafeSummary) -> &'static str {
    value.as_str()
}

fn parse_safe_summary(value: &str) -> Result<SafeSummary, StorageError> {
    match value {
        "task_completed" => Ok(SafeSummary::TaskCompleted),
        "blocked_by_policy" => Ok(SafeSummary::BlockedByPolicy),
        "execution_failed" => Ok(SafeSummary::ExecutionFailed),
        "daemon_restart_recovery_failed" => Ok(SafeSummary::DaemonRestartRecoveryFailed),
        _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
    }
}

pub(super) fn approval_policy_token(value: ApprovalPolicy) -> &'static str {
    match value {
        ApprovalPolicy::Untrusted => "untrusted",
        ApprovalPolicy::OnFailure => "on_failure",
        ApprovalPolicy::OnRequest => "on_request",
        ApprovalPolicy::Never => "never",
    }
}

fn parse_approval_policy(value: &str) -> Result<ApprovalPolicy, StorageError> {
    match value {
        "untrusted" => Ok(ApprovalPolicy::Untrusted),
        "on_failure" => Ok(ApprovalPolicy::OnFailure),
        "on_request" => Ok(ApprovalPolicy::OnRequest),
        "never" => Ok(ApprovalPolicy::Never),
        _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
    }
}

pub(super) fn sandbox_policy_token(value: SandboxPolicy) -> &'static str {
    match value {
        SandboxPolicy::ReadOnly => "read_only",
        SandboxPolicy::WorkspaceWrite => "workspace_write",
        SandboxPolicy::DangerFullAccess => "danger_full_access",
    }
}

fn parse_sandbox_policy(value: &str) -> Result<SandboxPolicy, StorageError> {
    match value {
        "read_only" => Ok(SandboxPolicy::ReadOnly),
        "workspace_write" => Ok(SandboxPolicy::WorkspaceWrite),
        "danger_full_access" => Ok(SandboxPolicy::DangerFullAccess),
        _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
    }
}

pub(super) fn feature_choice_integer(value: FeatureChoice) -> i64 {
    match value {
        FeatureChoice::Disabled => 0,
        FeatureChoice::Enabled => 1,
    }
}

fn parse_feature_choice(value: i64) -> Result<FeatureChoice, StorageError> {
    match value {
        0 => Ok(FeatureChoice::Disabled),
        1 => Ok(FeatureChoice::Enabled),
        _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
    }
}

pub(super) fn log_source_token(value: LogSource) -> &'static str {
    match value {
        LogSource::HostDaemon => "host_daemon",
        LogSource::Storage => "storage",
        LogSource::CodexAdapter => "codex_adapter",
    }
}

fn parse_log_source(value: &str) -> Result<LogSource, StorageError> {
    match value {
        "host_daemon" => Ok(LogSource::HostDaemon),
        "storage" => Ok(LogSource::Storage),
        "codex_adapter" => Ok(LogSource::CodexAdapter),
        _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
    }
}

pub(super) fn log_severity_token(value: LogSeverity) -> &'static str {
    match value {
        LogSeverity::Info => "info",
        LogSeverity::Warning => "warning",
        LogSeverity::Error => "error",
    }
}

fn parse_log_severity(value: &str) -> Result<LogSeverity, StorageError> {
    match value {
        "info" => Ok(LogSeverity::Info),
        "warning" => Ok(LogSeverity::Warning),
        "error" => Ok(LogSeverity::Error),
        _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
    }
}

pub(super) fn log_event_token(value: LogEvent) -> &'static str {
    match value {
        LogEvent::SessionStarted => "session_started",
        LogEvent::FollowUpStarted => "follow_up_started",
        LogEvent::TurnStateCommitted => "turn_state_committed",
        LogEvent::StopConfirmed => "stop_confirmed",
        LogEvent::StopNotConfirmed => "stop_not_confirmed",
        LogEvent::RestartRecoveryPending => "restart_recovery_pending",
        LogEvent::StoreOpened => "store_opened",
    }
}

fn parse_log_event(value: &str) -> Result<LogEvent, StorageError> {
    match value {
        "session_started" => Ok(LogEvent::SessionStarted),
        "follow_up_started" => Ok(LogEvent::FollowUpStarted),
        "turn_state_committed" => Ok(LogEvent::TurnStateCommitted),
        "stop_confirmed" => Ok(LogEvent::StopConfirmed),
        "stop_not_confirmed" => Ok(LogEvent::StopNotConfirmed),
        "restart_recovery_pending" => Ok(LogEvent::RestartRecoveryPending),
        "store_opened" => Ok(LogEvent::StoreOpened),
        _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
    }
}

fn parse_log_row(row: RawLogRow) -> Result<StoredLogRecord, StorageError> {
    let subject = match (
        row.session_id,
        row.turn_id,
        row.session_revision,
        row.turn_revision,
    ) {
        (None, None, None, None) => LogSubject::Host,
        (Some(session_id), Some(turn_id), Some(session_revision), Some(turn_revision)) => {
            LogSubject::Turn {
                session_id: SessionId::parse(&session_id)
                    .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?,
                turn_id: TurnId::parse(&turn_id)
                    .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?,
                session_state_revision: parse_session_revision(&session_revision)?,
                turn_state_revision: parse_turn_revision(&turn_revision)?,
            }
        }
        _ => return Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
    };
    let record = SafeLogRecord::new(
        parse_time(&row.recorded_at)?,
        parse_log_source(&row.source)?,
        parse_log_severity(&row.severity)?,
        parse_log_event(&row.event)?,
        subject,
    )
    .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
    Ok(StoredLogRecord {
        cursor: u64::try_from(row.cursor)
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?,
        record,
    })
}
