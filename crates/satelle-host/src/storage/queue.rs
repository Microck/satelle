use super::codec::{format_time, parse_time};
use super::logs::queue_log;
use super::sql::insert_safe_log;
use super::{Storage, StorageError, StorageErrorKind, sqlite_error};
use crate::{LogEvent, LogSeverity};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use satelle_core::queue::{QueueFailure, QueueRequestStatus, QueueStatus};
use satelle_core::{QueueRequestId, SessionId, TurnId};
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TurnQueueOperation {
    Run,
    Steer,
}

impl TurnQueueOperation {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Steer => "steer",
        }
    }

    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "run" => Ok(Self::Run),
            "steer" => Ok(Self::Steer),
            _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
        }
    }
}

pub(crate) struct NewQueueRecord<'a> {
    pub(crate) queue_request_id: &'a QueueRequestId,
    pub(crate) lease_key: &'a str,
    pub(crate) token_id: &'a str,
    pub(crate) credential_revision: u64,
    pub(crate) principal_ref: &'a str,
    pub(crate) operation: TurnQueueOperation,
    pub(crate) idempotency_key: &'a str,
    pub(crate) request_digest: &'a str,
    pub(crate) payload_file: &'a str,
    pub(crate) payload_sha256: &'a str,
    pub(crate) enqueued_at: OffsetDateTime,
    pub(crate) expires_at: OffsetDateTime,
    pub(crate) session_id: Option<&'a SessionId>,
}

#[derive(Clone, Debug)]
pub(crate) struct StoredQueueRecord {
    pub(crate) status: QueueStatus,
    pub(crate) lease_key: String,
    pub(crate) operation: TurnQueueOperation,
    pub(crate) payload_file: String,
    pub(crate) payload_sha256: String,
}

pub(crate) enum QueueEnqueueOutcome {
    Inserted(StoredQueueRecord),
    Replayed(StoredQueueRecord),
    Full,
}

impl Storage {
    pub(crate) fn queued_payload_files(&self) -> Result<Vec<(String, String)>, StorageError> {
        self.connection
            .prepare(
                "SELECT payload_file, payload_sha256 FROM turn_admission_queue
                 WHERE status = 'queued' ORDER BY queue_request_id",
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
    }

    pub(crate) fn enqueue_queue_request(
        &mut self,
        record: &NewQueueRecord<'_>,
        max_depth: u16,
    ) -> Result<QueueEnqueueOutcome, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if let Some(existing) = load_idempotent_queue_record(
            &transaction,
            record.principal_ref,
            record.operation,
            record.idempotency_key,
        )? {
            if existing.1 != record.request_digest || existing.2 != record.payload_sha256 {
                return Err(StorageError::new(StorageErrorKind::IdempotencyConflict));
            }
            let stored = load_queue_record(&transaction, record.principal_ref, &existing.0)?
                .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
            transaction
                .commit()
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
            return Ok(QueueEnqueueOutcome::Replayed(stored));
        }
        let depth: i64 = transaction
            .query_row(
                "SELECT count(*) FROM turn_admission_queue WHERE lease_key = ?1 AND status = 'queued'",
                params![record.lease_key],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if depth >= i64::from(max_depth) {
            return Ok(QueueEnqueueOutcome::Full);
        }
        transaction
            .execute(
                "INSERT INTO turn_admission_queue (
                    queue_request_id, lease_key, token_id, credential_revision,
                    principal_ref, operation, idempotency_key, request_digest,
                    payload_file, payload_sha256, status, enqueued_at, expires_at,
                    session_id, state_revision
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'queued', ?11, ?12, ?13, 1)",
                params![
                    record.queue_request_id.as_str(),
                    record.lease_key,
                    record.token_id,
                    i64::try_from(record.credential_revision)
                        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?,
                    record.principal_ref,
                    record.operation.as_str(),
                    record.idempotency_key,
                    record.request_digest,
                    record.payload_file,
                    record.payload_sha256,
                    format_time(record.enqueued_at)?,
                    format_time(record.expires_at)?,
                    record.session_id.map(SessionId::as_str),
                ],
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let stored =
            load_queue_record(&transaction, record.principal_ref, record.queue_request_id)?
                .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
        insert_safe_log(
            &transaction,
            &queue_log(
                LogEvent::TurnQueued,
                LogSeverity::Info,
                stored.status.clone(),
                record.enqueued_at,
            )?,
        )?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(QueueEnqueueOutcome::Inserted(stored))
    }

    pub(crate) fn queue_status(
        &self,
        principal_ref: &str,
        queue_request_id: &QueueRequestId,
    ) -> Result<Option<StoredQueueRecord>, StorageError> {
        load_queue_record(&self.connection, principal_ref, queue_request_id)
    }

    pub(crate) fn first_queued_request(
        &self,
        lease_key: &str,
    ) -> Result<Option<StoredQueueRecord>, StorageError> {
        let id = self
            .connection
            .query_row(
                "SELECT queue_request_id FROM turn_admission_queue
                 WHERE lease_key = ?1 AND status = 'queued'
                 ORDER BY rtrim(enqueued_at, 'Z'), queue_request_id LIMIT 1",
                params![lease_key],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        id.map(|id| {
            let id = QueueRequestId::parse(&id)
                .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
            load_queue_record_unowned(&self.connection, &id)?
                .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))
        })
        .transpose()
    }

    pub(crate) fn expire_queue_requests(
        &mut self,
        observed_at: OffsetDateTime,
    ) -> Result<Vec<(StoredQueueRecord, u16)>, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let cutoff = format_time(observed_at)?;
        let queue_request_ids = transaction
            .prepare(
                "SELECT queue_request_id FROM turn_admission_queue
                 WHERE status = 'queued' AND expires_at <= ?1",
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?
            .query_map(params![cutoff], |row| row.get::<_, String>(0))
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let old_positions = queue_request_ids
            .iter()
            .map(|value| {
                let id = QueueRequestId::parse(value)
                    .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
                let record = load_queue_record_unowned(&transaction, &id)?
                    .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
                let position = record
                    .status
                    .position
                    .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
                Ok((id, position))
            })
            .collect::<Result<Vec<_>, StorageError>>()?;
        transaction
            .execute(
                "UPDATE turn_admission_queue
                 SET status = 'expired', state_revision = state_revision + 1
                 WHERE status = 'queued' AND expires_at <= ?1",
                params![cutoff],
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let expired = old_positions
            .into_iter()
            .map(|(id, position)| {
                load_queue_record_unowned(&transaction, &id)?
                    .map(|record| (record, position))
                    .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (record, _) in &expired {
            insert_safe_log(
                &transaction,
                &queue_log(
                    LogEvent::TurnQueueExpired,
                    LogSeverity::Info,
                    record.status.clone(),
                    observed_at,
                )?,
            )?;
        }
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(expired)
    }

    /// Records the derived FIFO position change as a queue state change and
    /// returns the exact committed statuses that callers must publish.
    pub(crate) fn advance_queue_positions(
        &mut self,
        lease_key: &str,
        first_changed_position: u16,
    ) -> Result<Vec<StoredQueueRecord>, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let offset = i64::from(first_changed_position.saturating_sub(1));
        let ids = transaction
            .prepare(
                "SELECT queue_request_id FROM turn_admission_queue
                 WHERE lease_key = ?1 AND status = 'queued'
                 ORDER BY rtrim(enqueued_at, 'Z'), queue_request_id LIMIT -1 OFFSET ?2",
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?
            .query_map(params![lease_key, offset], |row| row.get::<_, String>(0))
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let mut records = Vec::with_capacity(ids.len());
        for value in ids {
            let id = QueueRequestId::parse(&value)
                .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
            transaction
                .execute(
                    "UPDATE turn_admission_queue
                     SET state_revision = state_revision + 1
                     WHERE queue_request_id = ?1 AND status = 'queued'",
                    params![id.as_str()],
                )
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
            records.push(
                load_queue_record_unowned(&transaction, &id)?
                    .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?,
            );
        }
        for record in &records {
            insert_safe_log(
                &transaction,
                &queue_log(
                    LogEvent::QueuePositionChanged,
                    LogSeverity::Info,
                    record.status.clone(),
                    OffsetDateTime::now_utc(),
                )?,
            )?;
        }
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(records)
    }

    pub(crate) fn queue_status_unowned(
        &self,
        queue_request_id: &QueueRequestId,
    ) -> Result<Option<StoredQueueRecord>, StorageError> {
        load_queue_record_unowned(&self.connection, queue_request_id)
    }

    pub(crate) fn cancel_queue_request(
        &mut self,
        principal_ref: &str,
        queue_request_id: &QueueRequestId,
    ) -> Result<Option<StoredQueueRecord>, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let Some(before) = load_queue_record(&transaction, principal_ref, queue_request_id)? else {
            return Ok(None);
        };
        if before.status.status == QueueRequestStatus::Queued {
            transaction
                .execute(
                    "UPDATE turn_admission_queue
                     SET status = 'cancelled', state_revision = state_revision + 1
                     WHERE queue_request_id = ?1 AND status = 'queued'",
                    params![queue_request_id.as_str()],
                )
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        }
        let after = load_queue_record(&transaction, principal_ref, queue_request_id)?
            .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
        if before.status.status == QueueRequestStatus::Queued
            && after.status.status == QueueRequestStatus::Cancelled
        {
            insert_safe_log(
                &transaction,
                &queue_log(
                    LogEvent::TurnQueueCancelled,
                    LogSeverity::Info,
                    after.status.clone(),
                    OffsetDateTime::now_utc(),
                )?,
            )?;
        }
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(Some(after))
    }

    pub(crate) fn admit_queue_request(
        &mut self,
        queue_request_id: &QueueRequestId,
        session_id: &SessionId,
        turn_id: &TurnId,
    ) -> Result<bool, StorageError> {
        update_terminal(
            &mut self.connection,
            queue_request_id,
            QueueTerminalUpdate::Admitted {
                session_id,
                turn_id,
            },
        )
    }

    pub(crate) fn fail_queue_request(
        &mut self,
        queue_request_id: &QueueRequestId,
        failure: &QueueFailure,
    ) -> Result<bool, StorageError> {
        update_terminal(
            &mut self.connection,
            queue_request_id,
            QueueTerminalUpdate::ValidationFailed { failure },
        )
    }

    pub(crate) fn fail_queue_requests_for_credential(
        &mut self,
        token_id: &str,
        credential_revision: u64,
        failure: &QueueFailure,
    ) -> Result<Vec<(StoredQueueRecord, u16)>, StorageError> {
        let credential_revision = i64::try_from(credential_revision)
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let ids = transaction
            .prepare(
                "SELECT queue_request_id FROM turn_admission_queue
                 WHERE token_id = ?1 AND credential_revision = ?2 AND status = 'queued'",
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?
            .query_map(params![token_id, credential_revision], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let old_positions = ids
            .into_iter()
            .map(|value| {
                let id = QueueRequestId::parse(&value)
                    .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
                let record = load_queue_record_unowned(&transaction, &id)?
                    .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
                let position = record
                    .status
                    .position
                    .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
                Ok((id, position))
            })
            .collect::<Result<Vec<_>, StorageError>>()?;
        transaction
            .execute(
                "UPDATE turn_admission_queue
                 SET status = 'validation_failed', failure_code = ?3, failure_message = ?4,
                     state_revision = state_revision + 1
                 WHERE token_id = ?1 AND credential_revision = ?2 AND status = 'queued'",
                params![token_id, credential_revision, failure.code, failure.message],
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let records = old_positions
            .into_iter()
            .map(|(id, position)| {
                load_queue_record_unowned(&transaction, &id)?
                    .map(|record| (record, position))
                    .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (record, _) in &records {
            insert_safe_log(
                &transaction,
                &queue_log(
                    LogEvent::TurnQueueValidationFailed,
                    LogSeverity::Warning,
                    record.status.clone(),
                    OffsetDateTime::now_utc(),
                )?,
            )?;
        }
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(records)
    }
}

enum QueueTerminalUpdate<'a> {
    Admitted {
        session_id: &'a SessionId,
        turn_id: &'a TurnId,
    },
    ValidationFailed {
        failure: &'a QueueFailure,
    },
}

fn update_terminal(
    connection: &mut rusqlite::Connection,
    queue_request_id: &QueueRequestId,
    update: QueueTerminalUpdate<'_>,
) -> Result<bool, StorageError> {
    let (status, session_id, turn_id, failure, event, severity) = match update {
        QueueTerminalUpdate::Admitted {
            session_id,
            turn_id,
        } => (
            "admitted",
            Some(session_id),
            Some(turn_id),
            None,
            LogEvent::TurnDequeued,
            LogSeverity::Info,
        ),
        QueueTerminalUpdate::ValidationFailed { failure } => (
            "validation_failed",
            None,
            None,
            Some(failure),
            LogEvent::TurnQueueValidationFailed,
            LogSeverity::Warning,
        ),
    };
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    let changed = transaction
        .execute(
            "UPDATE turn_admission_queue
             SET status = ?2, session_id = coalesce(?3, session_id), turn_id = ?4,
                 failure_code = ?5, failure_message = ?6, state_revision = state_revision + 1
             WHERE queue_request_id = ?1 AND status = 'queued'",
            params![
                queue_request_id.as_str(),
                status,
                session_id.map(SessionId::as_str),
                turn_id.map(TurnId::as_str),
                failure.map(|failure| failure.code.as_str()),
                failure.map(|failure| failure.message.as_str()),
            ],
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    if changed == 1 {
        let record = load_queue_record_unowned(&transaction, queue_request_id)?
            .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
        insert_safe_log(
            &transaction,
            &queue_log(event, severity, record.status, OffsetDateTime::now_utc())?,
        )?;
    }
    transaction
        .commit()
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    Ok(changed == 1)
}

fn load_idempotent_queue_record(
    connection: &rusqlite::Connection,
    principal_ref: &str,
    operation: TurnQueueOperation,
    idempotency_key: &str,
) -> Result<Option<(QueueRequestId, String, String)>, StorageError> {
    connection
        .query_row(
            "SELECT queue_request_id, request_digest, payload_sha256
             FROM turn_admission_queue
             WHERE principal_ref = ?1 AND operation = ?2 AND idempotency_key = ?3",
            params![principal_ref, operation.as_str(), idempotency_key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?
        .map(|(id, digest, payload_sha256)| {
            QueueRequestId::parse(&id)
                .map(|id| (id, digest, payload_sha256))
                .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
        })
        .transpose()
}

fn load_queue_record(
    connection: &rusqlite::Connection,
    principal_ref: &str,
    queue_request_id: &QueueRequestId,
) -> Result<Option<StoredQueueRecord>, StorageError> {
    load_queue_record_where(
        connection,
        "queue_request_id = ?1 AND principal_ref = ?2",
        params![queue_request_id.as_str(), principal_ref],
    )
}

fn load_queue_record_unowned(
    connection: &rusqlite::Connection,
    queue_request_id: &QueueRequestId,
) -> Result<Option<StoredQueueRecord>, StorageError> {
    load_queue_record_where(
        connection,
        "queue_request_id = ?1",
        params![queue_request_id.as_str()],
    )
}

fn load_queue_record_where<P: rusqlite::Params>(
    connection: &rusqlite::Connection,
    predicate: &str,
    params: P,
) -> Result<Option<StoredQueueRecord>, StorageError> {
    let sql = format!(
        "SELECT queue_request_id, operation, payload_file, payload_sha256, status,
                enqueued_at, expires_at, session_id, turn_id, failure_code,
                failure_message, state_revision, lease_key
         FROM turn_admission_queue WHERE {predicate}"
    );
    connection
        .query_row(&sql, params, |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, Option<String>>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, String>(12)?,
            ))
        })
        .optional()
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?
        .map(|row| decode_queue_record(connection, row))
        .transpose()
}

#[allow(clippy::type_complexity)]
fn decode_queue_record(
    connection: &rusqlite::Connection,
    row: (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        i64,
        String,
    ),
) -> Result<StoredQueueRecord, StorageError> {
    let (
        queue_request_id,
        operation,
        payload_file,
        payload_sha256,
        status,
        enqueued_at,
        expires_at,
        session_id,
        turn_id,
        failure_code,
        failure_message,
        state_revision,
        lease_key,
    ) = row;
    let queue_request_id = QueueRequestId::parse(&queue_request_id)
        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
    let operation = TurnQueueOperation::parse(&operation)?;
    let status = parse_status(&status)?;
    let session_id = session_id
        .map(|value| SessionId::parse(&value))
        .transpose()
        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
    let turn_id = turn_id
        .map(|value| TurnId::parse(&value))
        .transpose()
        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
    let failure = match (failure_code, failure_message) {
        (Some(code), Some(message)) => Some(QueueFailure { code, message }),
        (None, None) => None,
        _ => return Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
    };
    let position = if status == QueueRequestStatus::Queued {
        let position: i64 = connection
            .query_row(
                "SELECT count(*) FROM turn_admission_queue
                 WHERE lease_key = ?1 AND status = 'queued'
                   AND (rtrim(enqueued_at, 'Z'), queue_request_id) <= (
                       SELECT rtrim(enqueued_at, 'Z'), queue_request_id FROM turn_admission_queue
                       WHERE queue_request_id = ?2
                   )",
                params![lease_key, queue_request_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Some(
            u16::try_from(position)
                .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?,
        )
    } else {
        None
    };
    let state_revision = u64::try_from(state_revision)
        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
    Ok(StoredQueueRecord {
        status: QueueStatus::new(
            queue_request_id,
            status,
            position,
            parse_time(&enqueued_at)?,
            parse_time(&expires_at)?,
            session_id,
            turn_id,
            failure,
            state_revision,
        ),
        lease_key,
        operation,
        payload_file,
        payload_sha256,
    })
}

fn parse_status(value: &str) -> Result<QueueRequestStatus, StorageError> {
    match value {
        "queued" => Ok(QueueRequestStatus::Queued),
        "admitted" => Ok(QueueRequestStatus::Admitted),
        "cancelled" => Ok(QueueRequestStatus::Cancelled),
        "expired" => Ok(QueueRequestStatus::Expired),
        "validation_failed" => Ok(QueueRequestStatus::ValidationFailed),
        _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queue_record<'a>(
        id: &'a QueueRequestId,
        idempotency_key: &'a str,
        payload_file: &'a str,
        enqueued_at: OffsetDateTime,
    ) -> NewQueueRecord<'a> {
        NewQueueRecord {
            queue_request_id: id,
            lease_key: "host-test:desktop-test",
            token_id: "tok_test",
            credential_revision: 1,
            principal_ref: "principal-test",
            operation: TurnQueueOperation::Run,
            idempotency_key,
            request_digest: payload_file,
            payload_file,
            payload_sha256: payload_file,
            enqueued_at,
            expires_at: enqueued_at + time::Duration::HOUR,
            session_id: None,
        }
    }

    #[test]
    fn queue_storage_preserves_fifo_capacity_cancellation_and_expiry() {
        let state = crate::TestStateDir::new().expect("temporary state directory");
        let (mut storage, _) = Storage::open(state.path()).expect("open storage");
        let at = OffsetDateTime::UNIX_EPOCH + time::Duration::days(20_000);
        let first_id = QueueRequestId::new();
        let second_id = QueueRequestId::new();
        let third_id = QueueRequestId::new();

        let QueueEnqueueOutcome::Inserted(first) = storage
            .enqueue_queue_request(&queue_record(&first_id, "first", "first.json", at), 2)
            .expect("enqueue first")
        else {
            panic!("first request must be inserted");
        };
        assert_eq!(first.status.position, Some(1));
        let QueueEnqueueOutcome::Inserted(second) = storage
            .enqueue_queue_request(
                &queue_record(
                    &second_id,
                    "second",
                    "second.json",
                    at + time::Duration::MILLISECOND,
                ),
                2,
            )
            .expect("enqueue second")
        else {
            panic!("second request must be inserted");
        };
        assert_eq!(second.status.position, Some(2));
        assert!(matches!(
            storage
                .enqueue_queue_request(&queue_record(&third_id, "third", "third.json", at), 2,)
                .expect("enforce queue limit"),
            QueueEnqueueOutcome::Full
        ));

        let cancelled = storage
            .cancel_queue_request("principal-test", &first_id)
            .expect("cancel first")
            .expect("first exists");
        assert_eq!(cancelled.status.status, QueueRequestStatus::Cancelled);
        let moved = storage
            .advance_queue_positions("host-test:desktop-test", 1)
            .expect("commit the derived FIFO position change");
        assert_eq!(moved.len(), 1);
        assert_eq!(moved[0].status.position, Some(1));
        assert_eq!(moved[0].status.state_revision, 2);
        let expired = storage
            .expire_queue_requests(at + time::Duration::HOUR + time::Duration::SECOND)
            .expect("expire remaining request");
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0.status.status, QueueRequestStatus::Expired);

        let logs = storage.logs_after(None, 10).expect("read queue logs");
        assert_eq!(
            logs.iter()
                .map(|record| record.record().event())
                .collect::<Vec<_>>(),
            [
                LogEvent::TurnQueued,
                LogEvent::TurnQueued,
                LogEvent::TurnQueueCancelled,
                LogEvent::QueuePositionChanged,
                LogEvent::TurnQueueExpired,
            ]
        );
        let encoded_logs = serde_json::to_string(&logs[3].record().subject())
            .expect("serialize the redacted queue log subject");
        assert!(encoded_logs.contains(second_id.as_str()));
        assert!(!encoded_logs.contains("second.json"));
    }

    #[test]
    fn credential_rotation_fails_only_matching_pending_requests() {
        let state = crate::TestStateDir::new().expect("temporary state directory");
        let (mut storage, _) = Storage::open(state.path()).expect("open storage");
        let at = OffsetDateTime::UNIX_EPOCH + time::Duration::days(20_000);
        let id = QueueRequestId::new();
        storage
            .enqueue_queue_request(&queue_record(&id, "credential", "credential.json", at), 2)
            .expect("enqueue request");
        let failure = QueueFailure {
            code: "queued-principal-no-longer-authorized".to_string(),
            message: "credential changed".to_string(),
        };

        assert!(
            storage
                .fail_queue_requests_for_credential("other-token", 1, &failure)
                .expect("ignore another credential")
                .is_empty()
        );
        let failed = storage
            .fail_queue_requests_for_credential("tok_test", 1, &failure)
            .expect("fail matching credential");
        assert_eq!(failed.len(), 1);
        assert_eq!(
            failed[0].0.status.status,
            QueueRequestStatus::ValidationFailed
        );
        assert_eq!(failed[0].0.status.failure.as_ref(), Some(&failure));
        assert_eq!(failed[0].1, 1);
    }
}
