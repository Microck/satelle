use super::codec::unix_timestamp_nanos;
use super::open::sqlite_error;
use super::{Storage, StorageError, StorageErrorKind};
use rusqlite::{OptionalExtension, params};
use satelle_core::TurnId;
use satelle_core::sensitive_diagnostics::{RawDiagnosticExportOutcome, RawDiagnosticManifest};
use time::OffsetDateTime;

impl Storage {
    /// Only bounded manifest metadata crosses this boundary. There is no field
    /// for protocol bodies, output paths, prompts, or artifact bytes in the SQL.
    pub(crate) fn begin_raw_diagnostic_export(
        &self,
        principal_ref: &str,
        manifest: &RawDiagnosticManifest,
        created_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let categories = serde_json::to_string(&manifest.included)
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidInput))?;
        self.connection
            .execute(
                "INSERT INTO raw_diagnostic_audit (turn_id, session_id, principal_ref, host_alias,
             command, data_categories, redaction_policy_version, created_at_unix_nanos, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'capturing')",
                params![
                    manifest.turn_id.as_str(),
                    manifest.session_id.as_str(),
                    principal_ref,
                    manifest.source_host,
                    manifest.command.as_str(),
                    categories,
                    manifest.redaction_policy_version,
                    unix_timestamp_nanos(created_at)?
                ],
            )
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        Ok(())
    }

    pub(crate) fn prepare_raw_diagnostic_export(
        &self,
        turn_id: &TurnId,
        artifact_byte_size: usize,
    ) -> Result<(), StorageError> {
        let changed = self
            .connection
            .execute(
                "UPDATE raw_diagnostic_audit SET status = 'prepared', artifact_byte_size = ?2
             WHERE turn_id = ?1 AND status = 'capturing'",
                params![turn_id.as_str(), artifact_byte_size as i64],
            )
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        if changed != 1 {
            return Err(StorageError::state_conflict());
        }
        Ok(())
    }

    /// A retry may confirm the same terminal outcome. It cannot turn a failed
    /// or expired export into a claim that a Controller wrote the artifact.
    pub(crate) fn finish_raw_diagnostic_export(
        &self,
        principal_ref: &str,
        turn_id: &TurnId,
        outcome: RawDiagnosticExportOutcome,
        finished_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let changed = self
            .connection
            .execute(
                "UPDATE raw_diagnostic_audit SET status = ?3, completed_at_unix_nanos = ?4
             WHERE turn_id = ?1 AND principal_ref = ?2
               AND (status = 'prepared' OR (status = 'capturing' AND ?3 = 'failed'))",
                params![
                    turn_id.as_str(),
                    principal_ref,
                    outcome.as_str(),
                    unix_timestamp_nanos(finished_at)?
                ],
            )
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        if changed == 1 {
            return Ok(());
        }
        let status: Option<String> = self
            .connection
            .query_row(
                "SELECT status FROM raw_diagnostic_audit WHERE turn_id = ?1 AND principal_ref = ?2",
                params![turn_id.as_str(), principal_ref],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        if status.as_deref() == Some(outcome.as_str()) {
            Ok(())
        } else {
            Err(StorageError::state_conflict())
        }
    }

    pub(crate) fn recover_raw_diagnostic_exports(
        &self,
        observed_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        // Capture is memory-only. A restarted Host cannot resume it or infer
        // that a Controller finished writing an artifact before disconnecting.
        self.connection
            .execute(
                "UPDATE raw_diagnostic_audit SET status = 'failed', completed_at_unix_nanos = ?1
             WHERE status IN ('capturing', 'prepared')",
                [unix_timestamp_nanos(observed_at)?],
            )
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use satelle_core::sensitive_diagnostics::RawDiagnosticCommand;

    #[test]
    fn raw_diagnostic_audit_distinguishes_preparation_acknowledgement_and_restart_loss() {
        let state = crate::TestStateDir::new().unwrap();
        let (storage, _) = Storage::open(state.path()).unwrap();
        let now = OffsetDateTime::now_utc();
        let manifest = RawDiagnosticManifest::new(
            "local-demo",
            "host-test",
            RawDiagnosticCommand::Run,
            satelle_core::SessionId::new(),
            TurnId::new(),
        );
        storage
            .begin_raw_diagnostic_export("controller", &manifest, now)
            .unwrap();
        assert!(
            storage
                .finish_raw_diagnostic_export(
                    "controller",
                    &manifest.turn_id,
                    RawDiagnosticExportOutcome::Exported,
                    now
                )
                .is_err()
        );
        storage
            .prepare_raw_diagnostic_export(&manifest.turn_id, 123)
            .unwrap();
        assert!(
            storage
                .finish_raw_diagnostic_export(
                    "another-controller",
                    &manifest.turn_id,
                    RawDiagnosticExportOutcome::Exported,
                    now
                )
                .is_err()
        );
        for _ in 0..2 {
            storage
                .finish_raw_diagnostic_export(
                    "controller",
                    &manifest.turn_id,
                    RawDiagnosticExportOutcome::Exported,
                    now,
                )
                .unwrap();
        }
        let pending = RawDiagnosticManifest {
            turn_id: TurnId::new(),
            ..manifest.clone()
        };
        storage
            .begin_raw_diagnostic_export("controller", &pending, now)
            .unwrap();
        storage
            .prepare_raw_diagnostic_export(&pending.turn_id, 456)
            .unwrap();
        drop(storage);
        let (storage, _) = Storage::open(state.path()).unwrap();
        storage.recover_raw_diagnostic_exports(now).unwrap();
        assert!(
            storage
                .finish_raw_diagnostic_export(
                    "controller",
                    &pending.turn_id,
                    RawDiagnosticExportOutcome::Exported,
                    now
                )
                .is_err()
        );
        let statuses: Vec<String> = storage
            .connection
            .prepare("SELECT status FROM raw_diagnostic_audit ORDER BY turn_id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(statuses, ["exported", "failed"]);
        storage
            .finish_raw_diagnostic_export(
                "controller",
                &manifest.turn_id,
                RawDiagnosticExportOutcome::Exported,
                now,
            )
            .unwrap();
    }
}
