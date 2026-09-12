use super::codec::unix_timestamp_nanos;
use super::open::sqlite_error;
use super::{Storage, StorageError, StorageErrorKind};
use rusqlite::{OptionalExtension, params};
use satelle_core::sensitive_diagnostics::{RawDiagnosticAuditMetadata, RawDiagnosticExportOutcome};
use time::OffsetDateTime;

impl Storage {
    /// Only bounded manifest metadata crosses this boundary. There is no field
    /// for protocol bodies, output paths, prompts, or artifact bytes in the SQL.
    pub(crate) fn begin_raw_diagnostic_export(
        &self,
        principal_ref: &str,
        metadata: &RawDiagnosticAuditMetadata,
        created_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let categories = serde_json::to_string(&metadata.included)
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidInput))?;
        self.connection
            .execute(
                "INSERT INTO raw_diagnostic_audit (export_id, principal_ref, host_alias, command,
             scope_kind, scope_ref, data_categories, redaction_policy_version,
             created_at_unix_nanos, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'capturing')",
                params![
                    metadata.export_id,
                    principal_ref,
                    metadata.source_host,
                    metadata.command.as_str(),
                    metadata.scope_kind.as_str(),
                    metadata.scope_ref,
                    categories,
                    metadata.redaction_policy_version,
                    unix_timestamp_nanos(created_at)?
                ],
            )
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        Ok(())
    }

    pub(crate) fn prepare_raw_diagnostic_export(
        &self,
        export_id: &str,
        artifact_byte_size: usize,
    ) -> Result<(), StorageError> {
        let changed = self
            .connection
            .execute(
                "UPDATE raw_diagnostic_audit SET status = 'prepared', artifact_byte_size = ?2
             WHERE export_id = ?1 AND status = 'capturing'",
                params![export_id, artifact_byte_size as i64],
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
        export_id: &str,
        outcome: RawDiagnosticExportOutcome,
        finished_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let changed = self
            .connection
            .execute(
                "UPDATE raw_diagnostic_audit SET status = ?3, completed_at_unix_nanos = ?4
             WHERE export_id = ?1 AND principal_ref = ?2
               AND (status = 'prepared' OR (status = 'capturing' AND ?3 = 'failed'))",
                params![
                    export_id,
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
                "SELECT status FROM raw_diagnostic_audit WHERE export_id = ?1 AND principal_ref = ?2",
                params![export_id, principal_ref],
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
    use satelle_core::TurnId;
    use satelle_core::sensitive_diagnostics::{
        RawDiagnosticCommand, RawDiagnosticManifest, RawSubprocessCommand, RawSubprocessManifest,
    };

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
            .begin_raw_diagnostic_export("controller", &(&manifest).into(), now)
            .unwrap();
        assert!(
            storage
                .finish_raw_diagnostic_export(
                    "controller",
                    manifest.turn_id.as_str(),
                    RawDiagnosticExportOutcome::Exported,
                    now
                )
                .is_err()
        );
        storage
            .prepare_raw_diagnostic_export(manifest.turn_id.as_str(), 123)
            .unwrap();
        assert!(
            storage
                .finish_raw_diagnostic_export(
                    "another-controller",
                    manifest.turn_id.as_str(),
                    RawDiagnosticExportOutcome::Exported,
                    now
                )
                .is_err()
        );
        for _ in 0..2 {
            storage
                .finish_raw_diagnostic_export(
                    "controller",
                    manifest.turn_id.as_str(),
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
            .begin_raw_diagnostic_export("controller", &(&pending).into(), now)
            .unwrap();
        storage
            .prepare_raw_diagnostic_export(pending.turn_id.as_str(), 456)
            .unwrap();
        drop(storage);
        let (storage, _) = Storage::open(state.path()).unwrap();
        storage.recover_raw_diagnostic_exports(now).unwrap();
        assert!(
            storage
                .finish_raw_diagnostic_export(
                    "controller",
                    pending.turn_id.as_str(),
                    RawDiagnosticExportOutcome::Exported,
                    now
                )
                .is_err()
        );
        let statuses: Vec<String> = storage
            .connection
            .prepare("SELECT status FROM raw_diagnostic_audit ORDER BY export_id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(statuses, ["exported", "failed"]);
        storage
            .finish_raw_diagnostic_export(
                "controller",
                manifest.turn_id.as_str(),
                RawDiagnosticExportOutcome::Exported,
                now,
            )
            .unwrap();

        let subprocess = RawSubprocessManifest::new(
            "local-demo",
            "host-test",
            RawSubprocessCommand::Setup,
            uuid::Uuid::now_v7().to_string(),
        );
        storage
            .begin_raw_diagnostic_export("controller", &(&subprocess).into(), now)
            .unwrap();
        storage
            .prepare_raw_diagnostic_export(&subprocess.invocation_id, 321)
            .unwrap();
        storage
            .finish_raw_diagnostic_export(
                "controller",
                &subprocess.invocation_id,
                RawDiagnosticExportOutcome::Exported,
                now,
            )
            .unwrap();
        let subprocess_scope: (String, String, String) = storage
            .connection
            .query_row(
                "SELECT command, scope_kind, scope_ref FROM raw_diagnostic_audit
                 WHERE export_id = ?1",
                [&subprocess.invocation_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            subprocess_scope,
            (
                "setup".to_string(),
                "command_invocation".to_string(),
                subprocess.invocation_id,
            )
        );
    }
}
