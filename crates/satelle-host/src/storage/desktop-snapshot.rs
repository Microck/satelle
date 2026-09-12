use super::codec::unix_timestamp_nanos;
use super::open::sqlite_error;
use super::{LeaseOwner, Storage, StorageError, StorageErrorKind};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use satelle_core::sensitive_diagnostics::{DesktopSnapshotExportOutcome, DesktopSnapshotManifest};
use satelle_core::session::{DesktopBindingRef, HostIdentityRef};
use time::OffsetDateTime;

impl Storage {
    pub(crate) fn recover_desktop_snapshots(
        &mut self,
        observed_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        transaction
            .execute(
                "UPDATE desktop_snapshot_audit
                 SET status = 'failed', completed_at_unix_nanos = ?1
                 WHERE status IN ('capturing', 'prepared')",
                [unix_timestamp_nanos(observed_at)?],
            )
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        transaction
            .execute(
                "DELETE FROM control_leases WHERE owner_kind = 'desktop_snapshot'",
                [],
            )
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        transaction
            .commit()
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))
    }

    pub(crate) fn begin_desktop_snapshot(
        &mut self,
        principal_ref: &str,
        source_host: &str,
        host_identity: &HostIdentityRef,
        desktop_binding: &DesktopBindingRef,
        desktop_session_ref: Option<&str>,
        owner: &LeaseOwner,
    ) -> Result<(), StorageError> {
        let snapshot_id = owner.operation_id();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        super::sql::ensure_control_lease_available(&transaction, host_identity, desktop_binding)?;
        transaction
            .execute(
                "INSERT INTO control_leases (
                    host_identity_ref, desktop_binding_ref, operation_id,
                    owner_process_id, owner_process_start_ref, owner_boot_identity_ref,
                    acquired_at, heartbeat_at, lease_state, owner_kind, desktop_snapshot_ref
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 'active', 'desktop_snapshot', ?8)",
                params![
                    host_identity.as_str(),
                    desktop_binding.as_str(),
                    owner.operation_id.as_str(),
                    i64::from(owner.process_id),
                    owner.process_start_ref.as_str(),
                    owner.boot_identity_ref.as_str(),
                    super::codec::format_time(owner.acquired_at)?,
                    snapshot_id,
                ],
            )
            .map_err(|error| sqlite_error(StorageErrorKind::LeaseConflict, error))?;
        transaction
            .execute(
                "INSERT INTO desktop_snapshot_audit (
                    snapshot_id, principal_ref, host_alias, host_identity_ref,
                    desktop_binding_ref, desktop_session_ref, data_categories,
                    redaction_policy_version, redaction_categories,
                    unredacted_risk_categories, created_at_unix_nanos,
                    artifact_format, status
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, '[]',
                    ?7, '[]', '[]', ?8, 'image/png', 'capturing')",
                params![
                    snapshot_id,
                    principal_ref,
                    source_host,
                    host_identity.as_str(),
                    desktop_binding.as_str(),
                    desktop_session_ref,
                    satelle_core::sensitive_diagnostics::DESKTOP_SNAPSHOT_REDACTION_POLICY_VERSION,
                    unix_timestamp_nanos(owner.acquired_at)?,
                ],
            )
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        transaction
            .commit()
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))
    }

    pub(crate) fn prepare_desktop_snapshot(
        &mut self,
        manifest: &DesktopSnapshotManifest,
    ) -> Result<(), StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        let included = serde_json::to_string(&manifest.included)
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidInput))?;
        let redaction = serde_json::to_string(&manifest.redaction_categories_applied)
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidInput))?;
        let risks = serde_json::to_string(&manifest.known_unredacted_visual_risk_categories)
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidInput))?;
        let changed = transaction
            .execute(
                "UPDATE desktop_snapshot_audit
                 SET status = 'prepared', data_categories = ?2,
                     redaction_categories = ?3, unredacted_risk_categories = ?4,
                     artifact_byte_size = ?5
                 WHERE snapshot_id = ?1 AND status = 'capturing'",
                params![
                    manifest.snapshot_id,
                    included,
                    redaction,
                    risks,
                    manifest.artifact_byte_size as i64,
                ],
            )
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        if changed != 1 {
            return Err(StorageError::state_conflict());
        }
        release_snapshot_lease(&transaction, &manifest.snapshot_id)?;
        transaction
            .commit()
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))
    }

    pub(crate) fn fail_desktop_snapshot(
        &mut self,
        snapshot_id: &str,
        failed_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        let changed = transaction
            .execute(
                "UPDATE desktop_snapshot_audit
                 SET status = 'failed', completed_at_unix_nanos = ?2
                 WHERE snapshot_id = ?1 AND status = 'capturing'",
                params![snapshot_id, unix_timestamp_nanos(failed_at)?],
            )
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        if changed != 1 {
            return Err(StorageError::state_conflict());
        }
        release_snapshot_lease(&transaction, snapshot_id)?;
        transaction
            .commit()
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))
    }

    pub(crate) fn finish_desktop_snapshot(
        &self,
        principal_ref: &str,
        snapshot_id: &str,
        outcome: DesktopSnapshotExportOutcome,
        finished_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let changed = self
            .connection
            .execute(
                "UPDATE desktop_snapshot_audit
                 SET status = ?3, completed_at_unix_nanos = ?4
                 WHERE snapshot_id = ?1 AND principal_ref = ?2 AND status = 'prepared'",
                params![
                    snapshot_id,
                    principal_ref,
                    outcome.as_str(),
                    unix_timestamp_nanos(finished_at)?,
                ],
            )
            .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
        if changed == 1 {
            return Ok(());
        }
        let status: Option<String> = self
            .connection
            .query_row(
                "SELECT status FROM desktop_snapshot_audit
                 WHERE snapshot_id = ?1 AND principal_ref = ?2",
                params![snapshot_id, principal_ref],
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
}

fn release_snapshot_lease(
    transaction: &rusqlite::Transaction<'_>,
    snapshot_id: &str,
) -> Result<(), StorageError> {
    let changed = transaction
        .execute(
            "DELETE FROM control_leases
             WHERE owner_kind = 'desktop_snapshot' AND desktop_snapshot_ref = ?1",
            [snapshot_id],
        )
        .map_err(|error| sqlite_error(StorageErrorKind::OperationFailed, error))?;
    if changed != 1 {
        return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_audit_owns_the_control_lease_and_retains_only_metadata() {
        let state = crate::TestStateDir::new().expect("create state directory");
        let (mut storage, _) = Storage::open(state.path()).expect("open storage");
        let host_identity = storage.host_identity().expect("load Host identity");
        let desktop_binding = DesktopBindingRef::new("operator").expect("desktop binding");
        let created_at = OffsetDateTime::now_utc();
        let snapshot_id = uuid::Uuid::now_v7().hyphenated().to_string();
        let owner = LeaseOwner::new(
            snapshot_id.clone(),
            std::process::id(),
            "snapshot-test-process",
            "snapshot-test-boot",
            created_at,
        )
        .expect("lease owner");

        storage
            .begin_desktop_snapshot(
                "principal-1",
                "local-demo",
                &host_identity,
                &desktop_binding,
                Some("desktop-session-1"),
                &owner,
            )
            .expect("begin snapshot");

        let second_snapshot_id = uuid::Uuid::now_v7().hyphenated().to_string();
        let second_owner = LeaseOwner::new(
            second_snapshot_id.clone(),
            std::process::id(),
            "snapshot-test-process",
            "snapshot-test-boot",
            created_at,
        )
        .expect("second lease owner");
        let conflict = storage
            .begin_desktop_snapshot(
                "principal-1",
                "local-demo",
                &host_identity,
                &desktop_binding,
                Some("desktop-session-1"),
                &second_owner,
            )
            .expect_err("one Desktop Binding has one control owner");
        assert_eq!(conflict.kind(), StorageErrorKind::LeaseConflict);

        let manifest = DesktopSnapshotManifest::new(
            &snapshot_id,
            "local-demo",
            host_identity.as_str(),
            desktop_binding.as_str(),
            Some("desktop-session-1".to_string()),
            123,
        );
        storage
            .prepare_desktop_snapshot(&manifest)
            .expect("prepare metadata");
        storage
            .finish_desktop_snapshot(
                "principal-1",
                &snapshot_id,
                DesktopSnapshotExportOutcome::Exported,
                created_at + time::Duration::seconds(1),
            )
            .expect("finish snapshot audit");

        let (status, artifact_size, data_categories): (String, i64, String) = storage
            .connection
            .query_row(
                "SELECT status, artifact_byte_size, data_categories
                 FROM desktop_snapshot_audit WHERE snapshot_id = ?1",
                [&snapshot_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("read snapshot audit metadata");
        assert_eq!(status, "exported");
        assert_eq!(artifact_size, 123);
        assert_eq!(data_categories, r#"["current_visible_desktop_pixels"]"#);
        let active_lease_count: i64 = storage
            .connection
            .query_row(
                "SELECT COUNT(*) FROM control_leases WHERE desktop_snapshot_ref = ?1",
                [&snapshot_id],
                |row| row.get(0),
            )
            .expect("count snapshot leases");
        assert_eq!(active_lease_count, 0);

        storage.set_log_retention(time::Duration::seconds(1));
        storage
            .prune_expired_session_metadata_with_retention(
                created_at + time::Duration::seconds(3),
                time::Duration::hours(1),
                time::Duration::hours(1),
            )
            .expect("prune snapshot audit metadata");
        let retained: i64 = storage
            .connection
            .query_row(
                "SELECT COUNT(*) FROM desktop_snapshot_audit WHERE snapshot_id = ?1",
                [&snapshot_id],
                |row| row.get(0),
            )
            .expect("count retained snapshot audit rows");
        assert_eq!(retained, 0);
    }
}
