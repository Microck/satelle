use super::codec::unix_timestamp_nanos;
use super::open::sqlite_error;
use super::sql::{logs_need_pruning, prune_expired_logs};
use super::{Storage, StorageError, StorageErrorKind};
use rusqlite::{Connection, Transaction, TransactionBehavior, params};
use satelle_core::SessionId;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const DEFAULT_SESSION_RETENTION: time::Duration = time::Duration::days(7);
const DEFAULT_SETUP_LEDGER_RETENTION: time::Duration = time::Duration::days(30);

impl Storage {
    /// Removes only expired Satelle-owned Session and setup-ledger metadata.
    ///
    /// Canonical log-prefix pruning runs first because it alone owns cursor
    /// expiry. A Session remains until no retained lifecycle log references it;
    /// expired replay records, the Session cascade, and known terminal setup
    /// runs are then deleted in the same immediate transaction. Setup cleanup
    /// cannot invoke an executor or change external host state.
    pub(crate) fn prune_expired_session_metadata(
        &mut self,
        observed_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let session_cutoff = observed_at
            .checked_sub(DEFAULT_SESSION_RETENTION)
            .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidInput))?;
        let session_cutoff_nanos = unix_timestamp_nanos(session_cutoff)?;
        let setup_cutoff = observed_at
            .checked_sub(DEFAULT_SETUP_LEDGER_RETENTION)
            .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidInput))?;
        // Status and log polling call this path frequently. Keep the common
        // no-work case read-only instead of taking SQLite write ownership.
        if !retention_needs_pruning(
            &self.connection,
            session_cutoff,
            session_cutoff_nanos,
            setup_cutoff,
            observed_at,
        )? {
            return Ok(());
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        prune_expired_logs(&transaction, observed_at)?;
        let candidates =
            terminal_session_candidates(&transaction, session_cutoff, session_cutoff_nanos)?;

        for session_id in candidates {
            if !idempotency_records_allow_deletion(&transaction, &session_id, observed_at)? {
                continue;
            }
            delete_session_metadata(&transaction, &session_id)?;
        }
        for run_id in terminal_setup_run_candidates(&transaction, setup_cutoff)? {
            delete_setup_run_metadata(&transaction, &run_id)?;
        }

        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
    }
}

fn retention_needs_pruning(
    connection: &Connection,
    session_cutoff: OffsetDateTime,
    session_cutoff_nanos: i64,
    setup_cutoff: OffsetDateTime,
    observed_at: OffsetDateTime,
) -> Result<bool, StorageError> {
    if logs_need_pruning(connection, observed_at)? {
        return Ok(true);
    }
    for session_id in terminal_session_candidates(connection, session_cutoff, session_cutoff_nanos)?
    {
        if idempotency_records_allow_deletion(connection, &session_id, observed_at)? {
            return Ok(true);
        }
    }
    Ok(!terminal_setup_run_candidates(connection, setup_cutoff)?.is_empty())
}

fn terminal_session_candidates(
    connection: &Connection,
    cutoff: OffsetDateTime,
    retained_log_cutoff_nanos: i64,
) -> Result<Vec<SessionId>, StorageError> {
    // The turns table CHECK constraint makes terminal_at NULL exactly for
    // nonterminal states, so retention does not duplicate the state tokens.
    let mut statement = connection
        .prepare(
            "SELECT s.session_id, latest.terminal_at
             FROM sessions s
             JOIN turns latest ON latest.session_id = s.session_id
             WHERE latest.ordinal = (
                 SELECT max(candidate.ordinal) FROM turns candidate
                 WHERE candidate.session_id = s.session_id
             )
               AND latest.terminal_at IS NOT NULL
               AND NOT EXISTS (
                   SELECT 1 FROM turns nonterminal
                   WHERE nonterminal.session_id = s.session_id
                     AND nonterminal.terminal_at IS NULL
               )
               AND NOT EXISTS (
                   SELECT 1 FROM control_leases lease
                   WHERE lease.session_id = s.session_id
               )
               AND NOT EXISTS (
                   SELECT 1 FROM logs retained_log
                   WHERE retained_log.session_id = s.session_id
                     AND retained_log.recorded_at_unix_nanos >= ?1
               )
             ORDER BY s.session_id",
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    let rows = statement
        .query_map([retained_log_cutoff_nanos], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    let mut candidates = Vec::new();
    for row in rows {
        let (session_id, terminal_at) =
            row.map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if parse_stored_time(&terminal_at)? < cutoff {
            candidates.push(
                SessionId::parse(&session_id)
                    .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?,
            );
        }
    }
    Ok(candidates)
}

fn idempotency_records_allow_deletion(
    connection: &Connection,
    session_id: &SessionId,
    observed_at: OffsetDateTime,
) -> Result<bool, StorageError> {
    let mut statement = connection
        .prepare(
            "SELECT expires_at FROM idempotency_records
             WHERE session_id = ?1",
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    let rows = statement
        .query_map([session_id.as_str()], |row| row.get::<_, String>(0))
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    for row in rows {
        let expires_at =
            row.map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if parse_stored_time(&expires_at)? > observed_at {
            return Ok(false);
        }
    }
    Ok(true)
}

fn delete_session_metadata(
    transaction: &Transaction<'_>,
    session_id: &SessionId,
) -> Result<(), StorageError> {
    transaction
        .execute(
            "DELETE FROM idempotency_records WHERE session_id = ?1",
            [session_id.as_str()],
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    let deleted = transaction
        .execute(
            "DELETE FROM sessions
             WHERE session_id = ?1
               AND NOT EXISTS (
                   SELECT 1 FROM control_leases lease
                   WHERE lease.session_id = sessions.session_id
               )
               AND NOT EXISTS (
                   SELECT 1 FROM turns nonterminal
                   WHERE nonterminal.session_id = sessions.session_id
                     AND nonterminal.terminal_at IS NULL
               )
               AND NOT EXISTS (
                   SELECT 1 FROM logs retained_log
                   WHERE retained_log.session_id = sessions.session_id
               )",
            params![session_id.as_str()],
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    if deleted != 1 {
        return Err(StorageError::new(StorageErrorKind::StateConflict));
    }
    Ok(())
}

fn terminal_setup_run_candidates(
    connection: &Connection,
    cutoff: OffsetDateTime,
) -> Result<Vec<String>, StorageError> {
    // Running and outcome-unknown rows remain authoritative recovery input.
    // Parse timestamps instead of ordering RFC 3339 text because fractional
    // second spellings are not lexicographically chronological.
    let mut statement = connection
        .prepare(
            "SELECT run_id, finished_at
             FROM setup_runs
             WHERE status IN ('completed', 'failed', 'partial_failure')",
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    let mut candidates = Vec::new();
    for row in rows {
        let (run_id, finished_at) =
            row.map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let finished_at = parse_stored_time(&finished_at)?;
        if finished_at < cutoff {
            candidates.push((finished_at, run_id));
        }
    }
    candidates.sort_by(|(left_time, left_id), (right_time, right_id)| {
        left_time
            .cmp(right_time)
            .then_with(|| left_id.cmp(right_id))
    });
    Ok(candidates.into_iter().map(|(_, run_id)| run_id).collect())
}

fn delete_setup_run_metadata(
    transaction: &Transaction<'_>,
    run_id: &str,
) -> Result<(), StorageError> {
    // setup_actions cascade from setup_runs. No setup executor participates in
    // retention, so deleting this metadata cannot undo a completed action.
    let deleted = transaction
        .execute(
            "DELETE FROM setup_runs
             WHERE run_id = ?1
               AND status IN ('completed', 'failed', 'partial_failure')",
            [run_id],
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    if deleted != 1 {
        return Err(StorageError::new(StorageErrorKind::StateConflict));
    }
    Ok(())
}

fn parse_stored_time(value: &str) -> Result<OffsetDateTime, StorageError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
}
