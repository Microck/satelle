use super::codec::unix_timestamp_nanos;
use super::open::sqlite_error;
use super::sql::prune_expired_logs;
use super::{Storage, StorageError, StorageErrorKind};
use rusqlite::{Connection, Transaction, TransactionBehavior, params};
use satelle_core::SessionId;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const DEFAULT_SESSION_RETENTION: time::Duration = time::Duration::days(7);

impl Storage {
    /// Removes only Satelle-owned metadata for fully terminal Sessions.
    ///
    /// Canonical log-prefix pruning runs first because it alone owns cursor
    /// expiry. A Session remains until no retained lifecycle log references it;
    /// expired replay records and the Session cascade are then deleted in the
    /// same immediate transaction.
    pub(crate) fn prune_expired_session_metadata(
        &mut self,
        observed_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let cutoff = observed_at
            .checked_sub(DEFAULT_SESSION_RETENTION)
            .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidInput))?;
        let cutoff_nanos = unix_timestamp_nanos(cutoff)?;
        // Status and log polling call this path frequently. Keep the common
        // no-work case read-only instead of taking SQLite write ownership.
        if !session_retention_needs_pruning(&self.connection, cutoff, cutoff_nanos, observed_at)? {
            return Ok(());
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        prune_expired_logs(&transaction, observed_at)?;
        let candidates = terminal_session_candidates(&transaction, cutoff, cutoff_nanos)?;

        for session_id in candidates {
            if !idempotency_records_allow_deletion(&transaction, &session_id, observed_at)? {
                continue;
            }
            delete_session_metadata(&transaction, &session_id)?;
        }

        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
    }
}

fn session_retention_needs_pruning(
    connection: &Connection,
    cutoff: OffsetDateTime,
    cutoff_nanos: i64,
    observed_at: OffsetDateTime,
) -> Result<bool, StorageError> {
    for session_id in terminal_session_candidates(connection, cutoff, cutoff_nanos)? {
        if idempotency_records_allow_deletion(connection, &session_id, observed_at)? {
            return Ok(true);
        }
    }
    Ok(false)
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
            "SELECT status, expires_at FROM idempotency_records
             WHERE session_id = ?1",
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    let rows = statement
        .query_map([session_id.as_str()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    for row in rows {
        let (status, expires_at) =
            row.map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if status != "terminal" || parse_stored_time(&expires_at)? > observed_at {
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

fn parse_stored_time(value: &str) -> Result<OffsetDateTime, StorageError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
}
