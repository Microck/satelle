use super::codec::format_time;
use super::sql::matching_idempotency;
use super::{IdempotencyInput, Storage, StorageError, StorageErrorKind, StorageMigrationCleanup};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

const PENDING_OUTCOME: &str = "v1.storage_migration.pending";
const COMPLETED_OUTCOME: &str = "v1.storage_migration.completed";

#[derive(Clone, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    content = "cleanup",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum StorageMigrationReply {
    Acknowledged,
    SourceCleaned(Box<StorageMigrationCleanup>),
}

pub(crate) enum StorageMigrationRequestState {
    Pending(Option<Box<StorageMigrationCleanup>>),
    Completed(StorageMigrationReply),
}

impl Storage {
    pub(crate) fn storage_migration_request_state(
        &self,
        input: &IdempotencyInput,
    ) -> Result<Option<StorageMigrationRequestState>, StorageError> {
        let Some(record) = matching_idempotency(&self.connection, input)? else {
            return Ok(None);
        };
        let invalid = || StorageError::new(StorageErrorKind::InvalidStoredState);
        let state = match (record.status.as_str(), record.durable_outcome.as_str()) {
            ("in_progress", PENDING_OUTCOME) => StorageMigrationRequestState::Pending(
                record
                    .result_json
                    .as_deref()
                    .map(serde_json::from_str)
                    .transpose()
                    .map_err(|_| invalid())?,
            ),
            ("terminal", COMPLETED_OUTCOME) => StorageMigrationRequestState::Completed(
                serde_json::from_str(record.result_json.as_deref().ok_or_else(invalid)?)
                    .map_err(|_| invalid())?,
            ),
            _ => return Err(invalid()),
        };
        Ok(Some(state))
    }

    /// The source cleanup plan precedes every unlink. A process interruption
    /// therefore cannot turn a retry into an empty, different success report.
    pub(crate) fn start_storage_migration_request(
        &self,
        input: &IdempotencyInput,
        cleanup: Option<&StorageMigrationCleanup>,
    ) -> Result<(), StorageError> {
        let cleanup = cleanup
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidInput))?;
        self.connection
            .execute(
                "INSERT INTO idempotency_records (
                principal_ref, operation, idempotency_key, operation_id,
                request_digest, digest_schema_version, hmac_key_version,
                status, durable_outcome, result_json, created_at, expires_at
             ) VALUES (?1, 'storage_migration', ?2, ?3, ?4, ?5, ?6,
                       'in_progress', ?7, ?8, ?9, ?10)",
                params![
                    input.principal_ref,
                    input.key,
                    format!("migration-request-{}", uuid::Uuid::now_v7()),
                    input.request_digest,
                    input.digest_schema_version,
                    input.hmac_key_version,
                    PENDING_OUTCOME,
                    cleanup,
                    format_time(input.created_at)?,
                    format_time(input.expires_at)?,
                ],
            )
            .map_err(|source| {
                super::open::sqlite_error(StorageErrorKind::OperationFailed, source)
            })?;
        Ok(())
    }

    pub(crate) fn finish_storage_migration_request(
        &self,
        input: &IdempotencyInput,
        reply: &StorageMigrationReply,
        completed_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let encoded = serde_json::to_string(reply)
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidInput))?;
        let updated = self
            .connection
            .execute(
                "UPDATE idempotency_records
             SET status = 'terminal', durable_outcome = ?4,
                 result_json = ?5, completed_at = ?6, expires_at = ?7
             WHERE principal_ref = ?1 AND operation = 'storage_migration'
               AND idempotency_key = ?2 AND request_digest = ?3 AND status = 'in_progress'",
                params![
                    input.principal_ref,
                    input.key,
                    input.request_digest,
                    COMPLETED_OUTCOME,
                    encoded,
                    format_time(completed_at)?,
                    format_time(completed_at + super::IDEMPOTENCY_RETENTION)?
                ],
            )
            .map_err(|source| {
                super::open::sqlite_error(StorageErrorKind::OperationFailed, source)
            })?;
        if updated != 1 {
            return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
        }
        Ok(())
    }
}
