use super::codec::unix_timestamp_nanos;
use super::open::sqlite_error;
use super::{Storage, StorageError, StorageErrorKind};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use satelle_core::recording::{RecordingArtifactMetadata, RecordingManifest, RecordingMode};
use satelle_core::{SessionId, TurnId};
use std::path::PathBuf;
use time::OffsetDateTime;

impl Storage {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_recording(
        &mut self,
        recording_id: &str,
        principal_ref: &str,
        session_id: &SessionId,
        turn_id: &TurnId,
        host_alias: &str,
        mode: RecordingMode,
        directory: &std::path::Path,
        created_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        self.connection
            .execute(
                "INSERT INTO recording_audit (
                    recording_id, principal_ref, session_id, turn_id, host_alias,
                    mode, recording_directory, created_at_unix_nanos,
                    expires_at_unix_nanos, status
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'capturing')",
                params![
                    recording_id,
                    principal_ref,
                    session_id.as_str(),
                    turn_id.as_str(),
                    host_alias,
                    mode.as_str(),
                    directory.display().to_string(),
                    unix_timestamp_nanos(created_at)?,
                    unix_timestamp_nanos(expires_at)?,
                ],
            )
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        Ok(())
    }

    pub(crate) fn finish_recording(
        &mut self,
        manifest: &RecordingManifest,
    ) -> Result<(), StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        let changed = transaction
            .execute(
                "UPDATE recording_audit
                 SET status = 'retained', manifest_path = ?2, manifest_json = ?3
                 WHERE recording_id = ?1 AND status = 'capturing'",
                params![
                    manifest.recording_id,
                    manifest.manifest_path,
                    serde_json::to_string(manifest)
                        .map_err(|_| StorageError::new(StorageErrorKind::InvalidInput))?,
                ],
            )
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        if changed != 1 {
            return Err(StorageError::state_conflict());
        }
        for artifact in &manifest.artifacts {
            insert_artifact(&transaction, &manifest.recording_id, artifact)?;
        }
        transaction
            .commit()
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))
    }

    pub(crate) fn fail_recording(&self, recording_id: &str) -> Result<(), StorageError> {
        let changed = self
            .connection
            .execute(
                "UPDATE recording_audit SET status = 'failed'
                 WHERE recording_id = ?1 AND status = 'capturing'",
                [recording_id],
            )
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        if changed == 1 {
            Ok(())
        } else {
            Err(StorageError::state_conflict())
        }
    }

    pub(crate) fn recording_manifest(
        &self,
        principal_ref: &str,
        turn_id: &TurnId,
    ) -> Result<Option<RecordingManifest>, StorageError> {
        let manifest = self
            .connection
            .query_row(
                "SELECT manifest_json FROM recording_audit
                 WHERE principal_ref = ?1 AND turn_id = ?2 AND status = 'retained'",
                params![principal_ref, turn_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        manifest
            .map(|manifest| {
                serde_json::from_str(&manifest)
                    .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
            })
            .transpose()
    }

    pub(crate) fn recover_recordings(&self) -> Result<Vec<PathBuf>, StorageError> {
        self.recording_directories("capturing", None)
    }

    pub(crate) fn mark_abandoned_recordings_failed(&self) -> Result<(), StorageError> {
        self.connection
            .execute(
                "UPDATE recording_audit SET status = 'failed' WHERE status = 'capturing'",
                [],
            )
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        Ok(())
    }

    pub(crate) fn expired_recordings(
        &self,
        observed_at: OffsetDateTime,
    ) -> Result<Vec<PathBuf>, StorageError> {
        self.recording_directories("retained", Some(unix_timestamp_nanos(observed_at)?))
    }

    pub(crate) fn mark_recordings_expired(
        &mut self,
        observed_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        let timestamp = unix_timestamp_nanos(observed_at)?;
        transaction
            .execute(
                "UPDATE recording_artifacts SET retention_state = 'expired'
                 WHERE recording_id IN (
                    SELECT recording_id FROM recording_audit
                    WHERE status = 'retained' AND expires_at_unix_nanos <= ?1
                 )",
                [timestamp],
            )
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        transaction
            .execute(
                "UPDATE recording_audit SET status = 'expired'
                 WHERE status = 'retained' AND expires_at_unix_nanos <= ?1",
                [timestamp],
            )
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        transaction
            .commit()
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))
    }

    fn recording_directories(
        &self,
        status: &str,
        expires_before: Option<i64>,
    ) -> Result<Vec<PathBuf>, StorageError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT recording_directory FROM recording_audit
                 WHERE status = ?1
                   AND (?2 IS NULL OR expires_at_unix_nanos <= ?2)
                 ORDER BY recording_id",
            )
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        let rows = statement
            .query_map(params![status, expires_before], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        rows.map(|row| {
            row.map(PathBuf::from)
                .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))
        })
        .collect()
    }
}

fn insert_artifact(
    transaction: &rusqlite::Transaction<'_>,
    recording_id: &str,
    artifact: &RecordingArtifactMetadata,
) -> Result<(), StorageError> {
    let created_at = OffsetDateTime::parse(
        &artifact.created_at,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|_| StorageError::new(StorageErrorKind::InvalidInput))?;
    transaction
        .execute(
            "INSERT INTO recording_artifacts (
                recording_id, artifact_path, artifact_type, created_at_unix_nanos,
                sha256, byte_size, retention_state
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                recording_id,
                artifact.path,
                artifact.artifact_type,
                unix_timestamp_nanos(created_at)?,
                artifact.sha256,
                i64::try_from(artifact.byte_size)
                    .map_err(|_| StorageError::new(StorageErrorKind::InvalidInput))?,
                artifact.retention_state,
            ],
        )
        .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
    Ok(())
}
