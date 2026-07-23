use super::codec::{
    approval_policy_token, feature_choice_integer, format_revision, format_time,
    format_turn_revision, idempotent_operation_token, load_required_session, log_event_token,
    log_severity_token, log_source_token, safe_summary_token, sandbox_policy_token,
    turn_idempotency_token, turn_state_token, unix_timestamp_nanos,
};
use super::logs::canonical_log;
use super::{
    IDEMPOTENCY_RETENTION, IdempotencyInput, IdempotentOperation, LeaseOwner, LogEvent,
    LogSeverity, ObservedUpstreamRef, PrivateRequestToken, PrivateUpstreamRef, RecoverySubject,
    SafeLogRecord, Storage, StorageError, StorageErrorKind, sqlite_error,
};
use crate::LogSubject;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use satelle_core::session::{
    DesktopBindingRef, ExpectedRevisions, HostIdentityRef, LifecycleError, LifecycleMutation,
    Session, SessionActivity, SessionStateRevision, TurnState, TurnStateRevision,
};
use satelle_core::{SessionId, TurnId};
use time::OffsetDateTime;

const DEFAULT_LOG_RETENTION: time::Duration = time::Duration::days(7);

#[derive(Debug)]
pub(super) struct StoredIdempotency {
    pub(super) request_digest: String,
    pub(super) digest_schema_version: i64,
    pub(super) hmac_key_version: i64,
    pub(super) status: String,
    pub(super) durable_outcome: String,
    pub(super) session_id: Option<String>,
    pub(super) turn_id: Option<String>,
    pub(super) result_session_state_revision: Option<String>,
    pub(super) result_session_updated_at: Option<String>,
}

pub(super) fn insert_safe_log(
    transaction: &Transaction<'_>,
    record: &SafeLogRecord,
) -> Result<u64, StorageError> {
    // Cursor order is the pagination order, so timestamps must not move
    // backwards when the wall clock is adjusted between writes.
    let requested_nanos = unix_timestamp_nanos(record.recorded_at)?;
    let prior_nanos = transaction
        .query_row(
            "SELECT recorded_at_unix_nanos FROM logs ORDER BY log_cursor DESC LIMIT 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    let effective_nanos = prior_nanos.map_or(requested_nanos, |prior| prior.max(requested_nanos));
    let effective_at = OffsetDateTime::from_unix_timestamp_nanos(i128::from(effective_nanos))
        .map_err(|_| StorageError::new(StorageErrorKind::InvalidInput))?;
    let (session_id, turn_id, session_revision, turn_revision) = match record.subject() {
        LogSubject::Host => (None, None, None, None),
        LogSubject::Turn {
            session_id,
            turn_id,
            session_state_revision,
            turn_state_revision,
        } => (
            Some(session_id.as_str()),
            Some(turn_id.as_str()),
            Some(format_revision(*session_state_revision)),
            Some(format_turn_revision(*turn_state_revision)),
        ),
    };
    transaction
        .execute(
            "INSERT INTO logs (recorded_at, recorded_at_unix_nanos, source, severity, event_kind, session_id, turn_id, session_state_revision, turn_state_revision) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                format_time(effective_at)?,
                effective_nanos,
                log_source_token(record.source),
                log_severity_token(record.severity),
                log_event_token(record.event),
                session_id,
                turn_id,
                session_revision,
                turn_revision,
            ],
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    let cursor = u64::try_from(transaction.last_insert_rowid())
        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
    prune_expired_logs(transaction, effective_at)?;
    Ok(cursor)
}

pub(super) fn prune_expired_logs(
    transaction: &Transaction<'_>,
    observed_at: OffsetDateTime,
) -> Result<(), StorageError> {
    let cutoff = observed_at
        .checked_sub(DEFAULT_LOG_RETENTION)
        .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidInput))?;
    let cutoff_nanos = unix_timestamp_nanos(cutoff)?;
    let first_retained = transaction
        .query_row(
            "SELECT min(log_cursor) FROM logs WHERE recorded_at_unix_nanos >= ?1",
            params![cutoff_nanos],
            |row| row.get::<_, Option<i64>>(0),
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    let expired_through = match first_retained {
        Some(first_retained) => first_retained
            .checked_sub(1)
            .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?,
        None => match transaction
            .query_row("SELECT max(log_cursor) FROM logs", [], |row| {
                row.get::<_, Option<i64>>(0)
            })
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?
        {
            Some(high_water) => high_water,
            None => return Ok(()),
        },
    };
    transaction
        .execute(
            "DELETE FROM logs WHERE log_cursor <= ?1",
            params![expired_through],
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    transaction
        .execute(
            "UPDATE log_retention_state SET expired_through_cursor = max(expired_through_cursor, ?1) WHERE singleton = 1",
            params![expired_through],
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    Ok(())
}

pub(super) fn logs_need_pruning(
    connection: &Connection,
    observed_at: OffsetDateTime,
) -> Result<bool, StorageError> {
    let cutoff = observed_at
        .checked_sub(DEFAULT_LOG_RETENTION)
        .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidInput))?;
    let cutoff_nanos = unix_timestamp_nanos(cutoff)?;
    connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM logs
                WHERE log_cursor = (SELECT min(log_cursor) FROM logs)
                  AND recorded_at_unix_nanos < ?1
            )",
            params![cutoff_nanos],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
}

pub(super) fn validate_initial_session(session: &Session) -> Result<(), StorageError> {
    let mut turns = session.turns();
    let Some(turn) = turns.next() else {
        return Err(StorageError::new(StorageErrorKind::InvalidInput));
    };
    if turns.next().is_some()
        || session.session_state_revision() != SessionStateRevision::initial()
        || session.created_at() != session.updated_at()
        || turn.turn_state_revision() != TurnStateRevision::initial()
        || turn.state() != TurnState::Starting
        || turn.started_at() != session.created_at()
        || turn.updated_at() != session.created_at()
        || turn.terminal_at().is_some()
        || turn.safe_summary().is_some()
    {
        return Err(StorageError::new(StorageErrorKind::InvalidInput));
    }
    Ok(())
}

pub(super) fn insert_initial_session(
    transaction: &Transaction<'_>,
    session: &Session,
    request_token: &PrivateRequestToken,
) -> Result<(), StorageError> {
    let existing_identity: Option<String> = transaction
        .query_row(
            "SELECT host_identity_ref FROM daemon_identity WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    match existing_identity {
        Some(identity) if identity != session.host_identity().as_str() => {
            return Err(StorageError::new(StorageErrorKind::InvalidInput));
        }
        Some(_) => {}
        None => return Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
    }
    transaction
        .execute(
            "INSERT INTO sessions (session_id, display_name, session_state_revision, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                session.id().as_str(),
                session.display_name(),
                format_revision(session.session_state_revision()),
                format_time(session.created_at())?,
                format_time(session.updated_at())?,
            ],
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    transaction
        .execute(
            "INSERT INTO session_private_refs (session_id, host_identity_ref, desktop_binding_ref) VALUES (?1, ?2, ?3)",
            params![
                session.id().as_str(),
                session.host_identity().as_str(),
                session.desktop_binding().as_str(),
            ],
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    let turn = session
        .turns()
        .next()
        .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidInput))?;
    insert_turn(transaction, session.id(), 0, turn, request_token)
}

pub(super) fn insert_turn(
    transaction: &Transaction<'_>,
    session_id: &SessionId,
    ordinal: usize,
    turn: &satelle_core::session::Turn,
    request_token: &PrivateRequestToken,
) -> Result<(), StorageError> {
    let ordinal =
        i64::try_from(ordinal).map_err(|_| StorageError::new(StorageErrorKind::InvalidInput))?;
    transaction
        .execute(
            "INSERT INTO turns (turn_id, session_id, ordinal, turn_state_revision, state, started_at, updated_at, terminal_at, safe_summary) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                turn.id().as_str(),
                session_id.as_str(),
                ordinal,
                format_turn_revision(turn.turn_state_revision()),
                turn_state_token(turn.state()),
                format_time(turn.started_at())?,
                format_time(turn.updated_at())?,
                turn.terminal_at().map(format_time).transpose()?,
                turn.safe_summary().copied().map(safe_summary_token),
            ],
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    transaction
        .execute(
            "INSERT INTO turn_private_refs (turn_id, request_token) VALUES (?1, ?2)",
            params![turn.id().as_str(), request_token.0.as_str()],
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    let policy = turn.execution_policy();
    transaction
        .execute(
            "INSERT INTO turn_policies (turn_id, effective_model_ref, provider_binding_ref, desktop_binding_ref, desktop_session_id, approval_policy, sandbox_policy, timeout_seconds, computer_use_enabled, provider_computer_use_enabled) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                turn.id().as_str(),
                policy.effective_model().as_str(),
                policy.provider_binding().as_str(),
                policy.desktop_target().binding().as_str(),
                policy.desktop_target().session_id(),
                approval_policy_token(policy.approval_policy()),
                sandbox_policy_token(policy.sandbox_policy()),
                i64::from(policy.timeout_policy().seconds()),
                feature_choice_integer(policy.experimental_features().computer_use()),
                feature_choice_integer(policy.experimental_features().provider_computer_use()),
            ],
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    Ok(())
}

pub(super) fn update_session_row(
    transaction: &Transaction<'_>,
    session: &Session,
    expected_revision: SessionStateRevision,
) -> Result<(), StorageError> {
    let changed = transaction
        .execute(
            "UPDATE sessions SET session_state_revision = ?1, updated_at = ?2 \
             WHERE session_id = ?3 AND session_state_revision = ?4",
            params![
                format_revision(session.session_state_revision()),
                format_time(session.updated_at())?,
                session.id().as_str(),
                format_revision(expected_revision),
            ],
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    if changed != 1 {
        return Err(StorageError::new(StorageErrorKind::StateConflict));
    }
    Ok(())
}

pub(super) fn persist_lifecycle_mutation(
    transaction: &Transaction<'_>,
    session: &Session,
    turn_id: &TurnId,
    expected: ExpectedRevisions,
) -> Result<(), StorageError> {
    update_session_row(transaction, session, expected.session())?;
    let turn = session
        .turn(turn_id)
        .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
    let changed = transaction
        .execute(
            "UPDATE turns SET turn_state_revision = ?1, state = ?2, updated_at = ?3, terminal_at = ?4, safe_summary = ?5 \
             WHERE turn_id = ?6 AND session_id = ?7 AND turn_state_revision = ?8",
            params![
                format_turn_revision(turn.turn_state_revision()),
                turn_state_token(turn.state()),
                format_time(turn.updated_at())?,
                turn.terminal_at().map(format_time).transpose()?,
                turn.safe_summary().copied().map(safe_summary_token),
                turn_id.as_str(),
                session.id().as_str(),
                format_turn_revision(expected.turn()),
            ],
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    if changed != 1 {
        return Err(StorageError::new(StorageErrorKind::StateConflict));
    }
    Ok(())
}

pub(super) fn merge_observed_reference(
    transaction: &Transaction<'_>,
    session_id: &SessionId,
    turn_id: &TurnId,
    observed: &ObservedUpstreamRef,
) -> Result<(), StorageError> {
    let belongs_to_session: i64 = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM turns WHERE session_id = ?1 AND turn_id = ?2)",
            params![session_id.as_str(), turn_id.as_str()],
            |row| row.get(0),
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    if belongs_to_session != 1 {
        return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
    }

    let changed = match observed {
        ObservedUpstreamRef::Thread(thread_ref) => transaction
            .execute(
                "UPDATE session_private_refs SET upstream_thread_ref = COALESCE(upstream_thread_ref, ?1) \
                 WHERE session_id = ?2 \
                   AND (upstream_thread_ref IS NULL OR upstream_thread_ref = ?1) \
                   AND NOT EXISTS ( \
                       SELECT 1 FROM session_private_refs AS existing \
                       WHERE existing.session_id <> ?2 AND existing.upstream_thread_ref = ?1 \
                   )",
                params![thread_ref.0.as_str(), session_id.as_str()],
            ),
        ObservedUpstreamRef::Turn(turn_ref) => transaction
            .execute(
                "UPDATE turn_private_refs SET upstream_turn_ref = COALESCE(upstream_turn_ref, ?1) \
                 WHERE turn_id = ?2 \
                   AND (upstream_turn_ref IS NULL OR upstream_turn_ref = ?1) \
                   AND NOT EXISTS ( \
                       SELECT 1 FROM turn_private_refs AS existing \
                       WHERE existing.turn_id <> ?2 AND existing.upstream_turn_ref = ?1 \
                   )",
                params![turn_ref.0.as_str(), turn_id.as_str()],
            ),
        ObservedUpstreamRef::Goal(goal_ref) => transaction
            .execute(
                "UPDATE session_private_refs SET upstream_goal_ref = COALESCE(upstream_goal_ref, ?1) \
                 WHERE session_id = ?2 \
                   AND (upstream_goal_ref IS NULL OR upstream_goal_ref = ?1) \
                   AND NOT EXISTS ( \
                       SELECT 1 FROM session_private_refs AS existing \
                       WHERE existing.session_id <> ?2 AND existing.upstream_goal_ref = ?1 \
                   )",
                params![goal_ref.0.as_str(), session_id.as_str()],
            ),
    }
    .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    if changed != 1 {
        return Err(StorageError::new(
            StorageErrorKind::PrivateReferenceConflict,
        ));
    }
    Ok(())
}

pub(super) fn ensure_control_lease_available(
    transaction: &Transaction<'_>,
    host_identity: &HostIdentityRef,
    desktop_binding: &DesktopBindingRef,
) -> Result<(), StorageError> {
    let maintenance_heartbeat: Option<String> = transaction
        .query_row(
            "SELECT heartbeat_at FROM maintenance_leases WHERE host_identity_ref = ?1",
            [host_identity.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    let control: Option<(String, Option<String>, String)> = transaction
        .query_row(
            "SELECT owner_kind, session_id, heartbeat_at FROM control_leases
             WHERE host_identity_ref = ?1 AND desktop_binding_ref = ?2",
            params![host_identity.as_str(), desktop_binding.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    if let Some(heartbeat_at) = maintenance_heartbeat {
        let _freshness =
            super::operational::classify_lease_freshness(&heartbeat_at, OffsetDateTime::now_utc())?;
        return Err(StorageError::new(StorageErrorKind::LeaseConflict));
    }
    if let Some((owner_kind, session_id, heartbeat_at)) = control {
        let _freshness =
            super::operational::classify_lease_freshness(&heartbeat_at, OffsetDateTime::now_utc())?;
        if matches!(owner_kind.as_str(), "provider_probe" | "native_probe") && session_id.is_none()
        {
            return Err(StorageError::new(StorageErrorKind::LeaseConflict));
        }
        let session_id = session_id
            .as_deref()
            .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))
            .and_then(|session_id| {
                SessionId::parse(session_id)
                    .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
            })?;
        return Err(StorageError::lease_conflict(session_id));
    }
    Ok(())
}

pub(super) fn insert_control_lease(
    transaction: &Transaction<'_>,
    session: &Session,
    turn_id: &TurnId,
    owner: &LeaseOwner,
) -> Result<(), StorageError> {
    transaction
        .execute(
            "INSERT INTO control_leases (host_identity_ref, desktop_binding_ref, operation_id, owner_process_id, owner_process_start_ref, owner_boot_identity_ref, acquired_at, heartbeat_at, lease_state, owner_kind, session_id, turn_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 'active', 'turn', ?8, ?9)",
            params![
                session.host_identity().as_str(),
                session.desktop_binding().as_str(),
                owner.operation_id.as_str(),
                i64::from(owner.process_id),
                owner.process_start_ref.as_str(),
                owner.boot_identity_ref.as_str(),
                format_time(owner.acquired_at)?,
                session.id().as_str(),
                turn_id.as_str(),
            ],
        )
        .map_err(|source| sqlite_error(StorageErrorKind::LeaseConflict, source))?;
    Ok(())
}

pub(super) fn synchronize_control_lease(
    transaction: &Transaction<'_>,
    session: &Session,
    turn_id: &TurnId,
) -> Result<(), StorageError> {
    let turn = session
        .turn(turn_id)
        .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
    if turn.state().is_terminal() {
        let changed = transaction
            .execute(
                "DELETE FROM control_leases WHERE session_id = ?1 AND turn_id = ?2",
                params![session.id().as_str(), turn_id.as_str()],
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if changed != 1 {
            return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
        }
    } else {
        let lease_state = if turn.state() == TurnState::RecoveryPending {
            "recovery_pending"
        } else {
            "active"
        };
        let changed = transaction
            .execute(
                "UPDATE control_leases SET lease_state = ?1 WHERE session_id = ?2 AND turn_id = ?3",
                params![lease_state, session.id().as_str(), turn_id.as_str()],
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if changed != 1 {
            return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
        }
    }
    Ok(())
}

pub(super) fn ensure_control_lease_absent(
    transaction: &Transaction<'_>,
    session_id: &SessionId,
    turn_id: &TurnId,
) -> Result<(), StorageError> {
    let exists: i64 = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM control_leases WHERE session_id = ?1 AND turn_id = ?2)",
            params![session_id.as_str(), turn_id.as_str()],
            |row| row.get(0),
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    if exists != 0 {
        return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
    }
    Ok(())
}

pub(super) fn ensure_control_lease_present(
    connection: &Connection,
    session_id: &SessionId,
    turn_id: &TurnId,
) -> Result<(), StorageError> {
    let exists: i64 = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM control_leases WHERE session_id = ?1 AND turn_id = ?2)",
            params![session_id.as_str(), turn_id.as_str()],
            |row| row.get(0),
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    if exists != 1 {
        return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
    }
    Ok(())
}

pub(super) fn ensure_no_pending_stop(
    connection: &Connection,
    session_id: &SessionId,
    turn_id: &TurnId,
) -> Result<(), StorageError> {
    let exists: i64 = connection
        .query_row(
            "SELECT EXISTS(\
                SELECT 1 FROM idempotency_records \
                WHERE operation = 'stop' \
                  AND session_id = ?1 \
                  AND turn_id = ?2 \
                  AND status = 'in_progress' \
                  AND durable_outcome = 'v1.stop.pending'\
            )",
            params![session_id.as_str(), turn_id.as_str()],
            |row| row.get(0),
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    if exists != 0 {
        return Err(StorageError::new(StorageErrorKind::StateConflict));
    }
    Ok(())
}

fn active_session_ids(transaction: &Transaction<'_>) -> Result<Vec<SessionId>, StorageError> {
    let mut statement = transaction
        .prepare(
            "SELECT DISTINCT session_id FROM turns WHERE state IN ('starting', 'running', 'recovery_pending') ORDER BY session_id",
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?
        .map(|row| {
            row.map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
                .and_then(|value| {
                    SessionId::parse(&value)
                        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
                })
        })
        .collect()
}

pub(super) fn load_recovery_subject(
    connection: &Connection,
    session: &Session,
    turn_id: &TurnId,
) -> Result<RecoverySubject, StorageError> {
    let turn = session
        .turn(turn_id)
        .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
    let (request_token, upstream_thread_ref, upstream_turn_ref, upstream_goal_ref): (
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = connection
        .query_row(
            "SELECT t.request_token, s.upstream_thread_ref, t.upstream_turn_ref, s.upstream_goal_ref \
             FROM turn_private_refs t \
             JOIN turns u ON u.turn_id = t.turn_id \
             JOIN session_private_refs s ON s.session_id = u.session_id \
             WHERE u.session_id = ?1 AND u.turn_id = ?2",
            params![session.id().as_str(), turn_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
    Ok(RecoverySubject {
        session_id: session.id().clone(),
        turn_id: turn_id.clone(),
        turn_state: turn.state(),
        expected_revisions: ExpectedRevisions::new(
            session.session_state_revision(),
            turn.turn_state_revision(),
        ),
        host_identity: session.host_identity().clone(),
        request_token: PrivateRequestToken::new(request_token)?,
        upstream_thread_ref: upstream_thread_ref
            .map(PrivateUpstreamRef::new)
            .transpose()?,
        upstream_turn_ref: upstream_turn_ref.map(PrivateUpstreamRef::new).transpose()?,
        upstream_goal_ref: upstream_goal_ref.map(PrivateUpstreamRef::new).transpose()?,
    })
}

pub(super) fn require_operation(
    input: &IdempotencyInput,
    expected: IdempotentOperation,
) -> Result<(), StorageError> {
    if input.operation != expected {
        return Err(StorageError::new(StorageErrorKind::InvalidInput));
    }
    Ok(())
}

pub(super) fn matching_idempotency(
    connection: &Connection,
    input: &IdempotencyInput,
) -> Result<Option<StoredIdempotency>, StorageError> {
    let record = connection
        .query_row(
            "SELECT request_digest, digest_schema_version, hmac_key_version, status, durable_outcome, session_id, turn_id, result_session_state_revision, result_session_updated_at \
             FROM idempotency_records \
             WHERE principal_ref = ?1 AND operation = ?2 AND idempotency_key = ?3",
            params![
                input.principal_ref.as_str(),
                idempotent_operation_token(input.operation),
                input.key.as_str(),
            ],
            |row| {
                Ok(StoredIdempotency {
                    request_digest: row.get(0)?,
                    digest_schema_version: row.get(1)?,
                    hmac_key_version: row.get(2)?,
                    status: row.get(3)?,
                    durable_outcome: row.get(4)?,
                    session_id: row.get(5)?,
                    turn_id: row.get(6)?,
                    result_session_state_revision: row.get(7)?,
                    result_session_updated_at: row.get(8)?,
                })
            },
        )
        .optional()
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    if let Some(record) = &record
        && (record.request_digest != input.request_digest
            || record.digest_schema_version != i64::from(input.digest_schema_version)
            || record.hmac_key_version != i64::from(input.hmac_key_version))
    {
        return Err(StorageError::new(StorageErrorKind::IdempotencyConflict));
    }
    Ok(record)
}

pub(super) fn ensure_record_handles(
    record: &StoredIdempotency,
    session_id: &SessionId,
    turn_id: &TurnId,
) -> Result<(), StorageError> {
    if record.session_id.as_deref() != Some(session_id.as_str())
        || record.turn_id.as_deref() != Some(turn_id.as_str())
    {
        return Err(StorageError::new(StorageErrorKind::IdempotencyConflict));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn insert_idempotency(
    transaction: &Transaction<'_>,
    input: &IdempotencyInput,
    status: &str,
    durable_outcome: &str,
    session_id: Option<&SessionId>,
    turn_id: Option<&TurnId>,
    completed_at: Option<OffsetDateTime>,
) -> Result<(), StorageError> {
    transaction
        .execute(
            "INSERT INTO idempotency_records (principal_ref, operation, idempotency_key, operation_id, request_digest, digest_schema_version, hmac_key_version, status, durable_outcome, session_id, turn_id, result_session_state_revision, result_session_updated_at, created_at, completed_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL, NULL, ?12, ?13, ?14)",
            params![
                input.principal_ref.as_str(),
                idempotent_operation_token(input.operation),
                input.key.as_str(),
                input.operation_id.as_str(),
                input.request_digest.as_str(),
                i64::from(input.digest_schema_version),
                i64::from(input.hmac_key_version),
                status,
                durable_outcome,
                session_id.map(SessionId::as_str),
                turn_id.map(TurnId::as_str),
                format_time(input.created_at)?,
                completed_at.map(format_time).transpose()?,
                format_time(input.expires_at)?,
            ],
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    Ok(())
}

pub(super) fn update_turn_idempotency(
    transaction: &Transaction<'_>,
    session: &Session,
    turn_id: &TurnId,
    at: OffsetDateTime,
) -> Result<(), StorageError> {
    let turn = session
        .turn(turn_id)
        .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
    let terminal = turn.state().is_terminal();
    let changed = transaction
        .execute(
            "UPDATE idempotency_records \
             SET status = ?1, durable_outcome = ?2, completed_at = ?3, \
                 result_session_state_revision = ?4, result_session_updated_at = ?5, \
                 expires_at = CASE WHEN ?1 = 'terminal' THEN ?6 ELSE expires_at END \
             WHERE session_id = ?7 AND turn_id = ?8 AND operation IN ('run', 'steer')",
            params![
                if terminal { "terminal" } else { "in_progress" },
                turn_idempotency_token(turn.state()),
                if terminal {
                    Some(format_time(at)?)
                } else {
                    None
                },
                terminal.then(|| format_revision(session.session_state_revision())),
                if terminal {
                    Some(format_time(session.updated_at())?)
                } else {
                    None
                },
                if terminal {
                    Some(format_time(at + IDEMPOTENCY_RETENTION)?)
                } else {
                    None
                },
                session.id().as_str(),
                turn_id.as_str(),
            ],
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    if changed != 1 {
        return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
    }
    Ok(())
}

pub(super) fn complete_stop_idempotency(
    transaction: &Transaction<'_>,
    input: &IdempotencyInput,
    durable_outcome: &str,
    session: &Session,
    at: OffsetDateTime,
) -> Result<(), StorageError> {
    let changed = transaction
        .execute(
            "UPDATE idempotency_records \
             SET status = 'terminal', durable_outcome = ?1, completed_at = ?2, expires_at = ?3, \
                 result_session_state_revision = ?4, result_session_updated_at = ?5 \
             WHERE principal_ref = ?6 AND operation = 'stop' AND idempotency_key = ?7 \
               AND request_digest = ?8 AND status = 'in_progress'",
            params![
                durable_outcome,
                format_time(at)?,
                format_time(at + IDEMPOTENCY_RETENTION)?,
                format_revision(session.session_state_revision()),
                format_time(session.updated_at())?,
                input.principal_ref.as_str(),
                input.key.as_str(),
                input.request_digest.as_str(),
            ],
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    if changed != 1 {
        return Err(StorageError::new(StorageErrorKind::StateConflict));
    }
    Ok(())
}

impl Storage {
    pub(super) fn mark_restart_recovery_pending(
        &mut self,
    ) -> Result<Vec<RecoverySubject>, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        // An active readiness probe can only survive opening this process if
        // its prior owner exited before finalization. Convert it to explicit
        // recovery ownership before any new admission can inspect it.
        transaction
            .execute(
                "UPDATE control_leases
                 SET lease_state = 'recovery_pending'
                 WHERE owner_kind IN ('provider_probe', 'native_probe')
                   AND lease_state = 'active'",
                [],
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let session_ids = active_session_ids(&transaction)?;
        let mut subjects = Vec::with_capacity(session_ids.len());
        for session_id in session_ids {
            let mut session = load_required_session(&transaction, &session_id)?;
            let (turn_id, turn_revision) = match session.activity() {
                SessionActivity::Starting {
                    turn_id,
                    turn_state_revision,
                }
                | SessionActivity::Running {
                    turn_id,
                    turn_state_revision,
                }
                | SessionActivity::RecoveryPending {
                    turn_id,
                    turn_state_revision,
                } => (turn_id, turn_state_revision),
                SessionActivity::Idle => {
                    return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
                }
            };
            let expected = ExpectedRevisions::new(session.session_state_revision(), turn_revision);
            let at = OffsetDateTime::now_utc().max(session.updated_at());
            let mutation = session
                .mark_active_recovery_pending(expected, at)
                .map_err(StorageError::from)?;
            if matches!(mutation, LifecycleMutation::Committed(_)) {
                persist_lifecycle_mutation(&transaction, &session, &turn_id, expected)?;
                update_turn_idempotency(&transaction, &session, &turn_id, at)?;
            }
            let changed = transaction
                .execute(
                    "UPDATE control_leases SET lease_state = 'recovery_pending' WHERE session_id = ?1 AND turn_id = ?2",
                    params![session_id.as_str(), turn_id.as_str()],
                )
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
            if changed != 1 {
                return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
            }
            insert_safe_log(
                &transaction,
                &canonical_log(
                    LogEvent::RestartRecoveryPending,
                    LogSeverity::Warning,
                    &session,
                    &turn_id,
                    at,
                )?,
            )?;
            subjects.push(load_recovery_subject(&transaction, &session, &turn_id)?);
        }
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(subjects)
    }
}

impl From<LifecycleError> for StorageError {
    fn from(source: LifecycleError) -> Self {
        Self {
            kind: StorageErrorKind::StateConflict,
            conflicting_session_id: None,
            source: Some(Box::new(source)),
        }
    }
}
