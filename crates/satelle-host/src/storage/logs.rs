#[cfg(test)]
use super::codec::load_log_records;
use super::codec::{load_log_page_records, log_retention_bounds};
use super::open::sqlite_error;
#[cfg(any(test, feature = "test-support"))]
use super::sql::insert_safe_log;
use super::sql::{logs_need_pruning, prune_expired_logs};
use super::{Storage, StorageError, StorageErrorKind};
use crate::{
    DaemonLogEntry, DaemonLogPage, LogCursor, LogEvent, LogPageMode, LogPageQuery, LogSeverity,
    LogSource, LogSubject,
};
use rusqlite::TransactionBehavior;
use satelle_core::TurnId;
use satelle_core::session::Session;
use time::OffsetDateTime;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SafeLogRecord {
    pub(super) recorded_at: OffsetDateTime,
    pub(super) source: LogSource,
    pub(super) severity: LogSeverity,
    pub(super) event: LogEvent,
    pub(super) subject: LogSubject,
}

impl SafeLogRecord {
    pub(crate) fn new(
        recorded_at: OffsetDateTime,
        source: LogSource,
        severity: LogSeverity,
        event: LogEvent,
        subject: LogSubject,
    ) -> Result<Self, StorageError> {
        if event.has_turn_subject() != matches!(subject, LogSubject::Turn { .. }) {
            return Err(StorageError::new(StorageErrorKind::InvalidInput));
        }
        Ok(Self {
            recorded_at,
            source,
            severity,
            event,
            subject,
        })
    }

    #[cfg(test)]
    pub(crate) fn recorded_at(&self) -> OffsetDateTime {
        self.recorded_at
    }

    #[cfg(test)]
    pub(crate) fn source(&self) -> LogSource {
        self.source
    }

    #[cfg(test)]
    pub(crate) fn severity(&self) -> LogSeverity {
        self.severity
    }

    #[cfg(test)]
    pub(crate) fn event(&self) -> LogEvent {
        self.event
    }

    pub(crate) const fn subject(&self) -> &LogSubject {
        &self.subject
    }
}

pub(super) fn canonical_log(
    event: LogEvent,
    severity: LogSeverity,
    session: &Session,
    turn_id: &TurnId,
    recorded_at: OffsetDateTime,
) -> Result<SafeLogRecord, StorageError> {
    let turn = session
        .turn(turn_id)
        .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
    SafeLogRecord::new(
        recorded_at,
        LogSource::HostDaemon,
        severity,
        event,
        LogSubject::Turn {
            session_id: session.id().clone(),
            turn_id: turn_id.clone(),
            session_state_revision: session.session_state_revision(),
            turn_state_revision: turn.turn_state_revision(),
        },
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredLogRecord {
    pub(super) cursor: u64,
    pub(super) record: SafeLogRecord,
}

impl StoredLogRecord {
    #[cfg(test)]
    pub(crate) fn cursor(&self) -> u64 {
        self.cursor
    }

    #[cfg(test)]
    pub(crate) fn record(&self) -> &SafeLogRecord {
        &self.record
    }
}

impl Storage {
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn append_safe_log(&mut self, record: &SafeLogRecord) -> Result<u64, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let cursor = insert_safe_log(&transaction, record)?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(cursor)
    }

    #[cfg(test)]
    pub(crate) fn logs_after(
        &self,
        cursor: Option<u64>,
        limit: usize,
    ) -> Result<Vec<StoredLogRecord>, StorageError> {
        if limit == 0 || limit > 10_000 {
            return Err(StorageError::new(StorageErrorKind::InvalidInput));
        }
        let cursor = i64::try_from(cursor.unwrap_or(0))
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidInput))?;
        let limit =
            i64::try_from(limit).map_err(|_| StorageError::new(StorageErrorKind::InvalidInput))?;
        load_log_records(&self.connection, cursor, limit)
    }

    pub(crate) fn log_page(
        &mut self,
        query: &LogPageQuery,
    ) -> Result<DaemonLogPage, LogPageStorageError> {
        self.prune_logs_if_needed(OffsetDateTime::now_utc())?;
        let (expired_through, earliest_available, high_water) =
            log_retention_bounds(&self.connection)?;
        if query.mode() == LogPageMode::Forward
            && query
                .cursor()
                .is_some_and(|cursor| cursor.position() < expired_through)
        {
            return Err(LogPageStorageError::CursorExpired {
                earliest_available_cursor: earliest_available,
                resume_cursor: expired_through,
            });
        }
        if query.mode() == LogPageMode::Forward
            && query
                .cursor()
                .is_some_and(|cursor| cursor.position() > high_water)
        {
            return Err(LogPageStorageError::CursorAhead);
        }

        let mut stored = load_log_page_records(&self.connection, query, query.limit() + 1)?;
        let truncated = stored.len() > query.limit();
        if truncated {
            stored.pop();
        }
        if query.mode() == LogPageMode::Tail {
            stored.reverse();
        }
        let entries = stored
            .into_iter()
            .map(stored_page_entry)
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = if query.mode() == LogPageMode::Forward && truncated {
            entries.last().map_or_else(
                || LogCursor::from_position(high_water),
                |entry| entry.cursor(),
            )
        } else {
            LogCursor::from_position(high_water)
        };
        Ok(DaemonLogPage::new(entries, next_cursor, truncated))
    }

    fn prune_logs_if_needed(&mut self, observed_at: OffsetDateTime) -> Result<(), StorageError> {
        if !logs_need_pruning(&self.connection, observed_at)? {
            return Ok(());
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        prune_expired_logs(&transaction, observed_at)?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
    }
}

fn stored_page_entry(stored: StoredLogRecord) -> Result<DaemonLogEntry, StorageError> {
    let record = stored.record;
    DaemonLogEntry::from_parts(
        stored.cursor,
        record.recorded_at,
        record.source,
        record.severity,
        record.event,
        record.subject,
    )
    .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
}

#[derive(Debug)]
pub(crate) enum LogPageStorageError {
    Storage(StorageError),
    CursorExpired {
        earliest_available_cursor: Option<u64>,
        resume_cursor: u64,
    },
    CursorAhead,
}

impl LogPageStorageError {
    #[cfg(test)]
    pub(crate) const fn earliest_available_cursor(&self) -> Option<u64> {
        match self {
            Self::CursorExpired {
                earliest_available_cursor,
                ..
            } => *earliest_available_cursor,
            Self::Storage(_) | Self::CursorAhead => None,
        }
    }

    #[cfg(test)]
    pub(crate) const fn resume_cursor(&self) -> Option<u64> {
        match self {
            Self::CursorExpired { resume_cursor, .. } => Some(*resume_cursor),
            Self::Storage(_) | Self::CursorAhead => None,
        }
    }
}

impl From<StorageError> for LogPageStorageError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}
