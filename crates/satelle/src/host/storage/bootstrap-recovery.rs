use super::{
    SetupActionSkipReason, SetupActionStatus, SetupOperationKind, SetupRunStatus, Storage,
    StorageError, StorageErrorKind, open,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

/// Evidence for one exact abandoned or completed setup claim, never a lock reset.
#[derive(Debug, Serialize)]
pub struct BootstrapRecovery {
    pub schema_version: &'static str,
    pub host_identity: String,
    pub operation_id: String,
    pub claim_identity: String,
    pub mutation_attempt: String,
    pub outcome: &'static str,
    pub archive_path: PathBuf,
    pub changed: bool,
}

pub(crate) fn recover(
    state_root: &Path,
    bootstrap_state_root: &Path,
    expected_host_identity: &str,
    operation_id: &str,
    apply: bool,
) -> Result<BootstrapRecovery, StorageError> {
    // Never initialize a new database and mistake it for the original ledger.
    if !Storage::has_existing_state(state_root)? {
        return Err(conflict());
    }
    // This canonical open owns the existing store. A running daemon or another
    // recovery cannot mutate the ledger while absence is checked and archived.
    // Retention preserves running and outcome-unknown runs. Absence establishes
    // no remaining recovery work, not that a historical transaction never ran.
    let storage = Storage::open_without_restart_recovery(state_root)?;
    if storage.host_identity()?.as_str() != expected_host_identity {
        return Err(conflict());
    }
    let run = storage.load_setup_run(operation_id)?;
    let completed = if let Some(run) = run.as_ref() {
        if !matches!(
            run.operation_kind(),
            SetupOperationKind::Setup | SetupOperationKind::Repair
        ) || run.status() != SetupRunStatus::Completed
            || run.actions().is_empty()
            || run.actions().iter().any(|action| match action.status() {
                SetupActionStatus::Completed => false,
                SetupActionStatus::Skipped => !matches!(
                    action.skip_reason(),
                    Some(
                        SetupActionSkipReason::AlreadySatisfied
                            | SetupActionSkipReason::NotRequired
                    )
                ),
                _ => true,
            })
        {
            return Err(conflict());
        }
        // A completed ledger proves only this setup's mutations. Another lease
        // may still own external work, so never archive its fence indirectly.
        let leased: bool = storage.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM maintenance_leases) OR EXISTS(SELECT 1 FROM control_leases)",
            [],
            |row| row.get(0),
        ).map_err(|error| StorageError::with_source(StorageErrorKind::OperationFailed, error))?;
        if leased {
            return Err(conflict());
        }
        true
    } else {
        false
    };
    let bootstrap_root = open::open_state_root_read_only(bootstrap_state_root)?;
    let lock_root = bootstrap_state_root.join("bootstrap.lock");
    let lock_directory = open::open_state_root_read_only(&lock_root)?;
    let claims = fs::read_dir(&lock_root)
        .map_err(io_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(io_error)?;
    // A competing controller claim keeps the operation fenced. Recovery never
    // chooses a convenient claim from an ambiguous set.
    if claims.len() != 1 {
        return Err(conflict());
    }
    let claim_path = claims[0].path();
    let claim = open::open_state_root_read_only(&claim_path)?;
    let snapshot = read_claim(&claim_path, &claim)?;
    let value = |name: &str| snapshot.get(name).map(String::as_str).ok_or_else(conflict);
    let identity = value("claim_identity")?;
    let attempt = value("mutation_attempt")?;
    let heartbeat =
        OffsetDateTime::parse(value("heartbeat_at")?, &Rfc3339).map_err(|_| conflict())?;
    // The producer publishes an opaque directory nonce separately from the
    // private claim identity. Bind the name to this operation, not that identity.
    let claim_prefix = format!("claim.{operation_id}.");
    let claim_nonce = claim_path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix(&claim_prefix));
    if value("operation_id")? != operation_id
        || !matches!(
            value("operation_kind")?,
            "initial_setup" | "missing_daemon_repair"
        )
        || value("state")? != "recovery_pending"
        || !matches!(
            (completed, value("mutation_phase")?),
            (false, "setup_maintenance_begin")
                | (
                    true,
                    "setup_maintenance_begin"
                        | "setup_action_start"
                        | "setup_action_complete"
                        | "setup_maintenance_finish"
                )
        )
        || !hex_identity(identity)
        || !hex_identity(attempt)
        || claim_nonce.is_none_or(|nonce| {
            nonce.is_empty() || !nonce.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
        || OffsetDateTime::now_utc() - heartbeat <= time::Duration::seconds(30)
    {
        return Err(conflict());
    }
    if run.as_ref().is_some_and(|run| {
        (run.operation_kind() == SetupOperationKind::Setup
            && value("operation_kind").ok() != Some("initial_setup"))
            || (run.operation_kind() == SetupOperationKind::Repair
                && value("operation_kind").ok() != Some("missing_daemon_repair"))
    }) {
        return Err(conflict());
    }
    let markers = snapshot
        .keys()
        .filter(|name| name.starts_with("execution_"))
        .collect::<Vec<_>>();
    if markers.len() != 1 || markers[0] != &format!("execution_started.{attempt}") {
        return Err(conflict());
    }
    let report = BootstrapRecovery {
        schema_version: "satelle.bootstrap-recovery.v1",
        host_identity: expected_host_identity.to_string(),
        operation_id: operation_id.to_string(),
        claim_identity: identity.to_string(),
        mutation_attempt: attempt.to_string(),
        outcome: if completed {
            "setup_run_completed"
        } else {
            "begin_has_no_ledger_run"
        },
        archive_path: bootstrap_state_root
            .join(format!("bootstrap-recovered.{operation_id}.{identity}")),
        changed: apply,
    };
    if !apply {
        return Ok(report);
    }
    if report.archive_path.try_exists().map_err(io_error)?
        || read_claim(&claim_path, &claim)? != snapshot
    {
        return Err(conflict());
    }
    let receipt = serde_json::to_vec(&report)
        .map_err(|error| StorageError::with_source(StorageErrorKind::OperationFailed, error))?;
    // Persist the proof before freeing the fence. A crash leaves either the
    // original claim plus receipt or the complete archive, never lost evidence.
    match claim.read_private_leaf_bounded("recovery.json", 4096)? {
        Some(existing) if existing == receipt => {}
        Some(_) => return Err(conflict()),
        None => claim.create_private_leaf_durable("recovery.json", &receipt)?,
    }
    drop(claim);
    lock_directory.move_child_durable(
        claim_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(conflict)?,
        &bootstrap_root,
        report
            .archive_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(conflict)?,
    )?;
    // `storage` and both pinned parent directories remain alive through rename.
    Ok(report)
}

fn read_claim(
    path: &Path,
    directory: &open::StateDirectory,
) -> Result<BTreeMap<String, String>, StorageError> {
    let mut values = BTreeMap::new();
    for entry in fs::read_dir(path).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let name = entry.file_name().into_string().map_err(|_| conflict())?;
        if name == "mailbox" {
            let _mailbox = open::open_state_root_read_only(&entry.path())?;
            continue;
        }
        if name == "recovery.json" {
            // An earlier crash may have persisted the receipt before rename.
            // Validate its private leaf now; its exact contents are checked on apply.
            directory
                .read_private_leaf_bounded(&name, 4096)?
                .ok_or_else(conflict)?;
            continue;
        }
        // The POSIX fence uses empty directories for execution markers;
        // Windows uses private files. Respect each platform's native contract.
        #[cfg(unix)]
        if name.starts_with("execution_") {
            let _marker = open::open_state_root_read_only(&entry.path())?;
            if fs::read_dir(entry.path())
                .map_err(io_error)?
                .next()
                .is_some()
            {
                return Err(conflict());
            }
            values.insert(name, String::new());
            continue;
        }
        let bytes = directory
            .read_private_leaf_bounded(&name, 512)?
            .ok_or_else(conflict)?;
        let value = String::from_utf8(bytes).map_err(|_| conflict())?;
        values.insert(name, value.trim_end_matches(['\r', '\n']).to_string());
    }
    Ok(values)
}

fn hex_identity(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn conflict() -> StorageError {
    StorageError::new(StorageErrorKind::StateConflict)
}

fn io_error(error: std::io::Error) -> StorageError {
    StorageError::with_source(StorageErrorKind::OperationFailed, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::storage::{
        LeaseOwner, SetupActionPlan, SetupOperationKind, SetupRunPlan, TestStateDir,
    };

    const OPERATION: &str = "interrupted-setup";
    const IDENTITY: &str = "0123456789abcdef0123456789abcdef";
    const ATTEMPT: &str = "abcdef0123456789abcdef0123456789";

    struct Fixture {
        _root: TestStateDir,
        state: PathBuf,
        bootstrap: PathBuf,
        claim: PathBuf,
        host_identity: String,
    }

    impl Fixture {
        fn new() -> Self {
            let root = TestStateDir::new().unwrap();
            let state = root.path().join("store");
            let storage = Storage::open_without_restart_recovery(&state).unwrap();
            let host_identity = storage.host_identity().unwrap().as_str().to_string();
            drop(storage);
            let bootstrap = root.path().join("bootstrap");
            open::prepare_state_root(&bootstrap).unwrap();
            let lock = bootstrap.join("bootstrap.lock");
            open::prepare_state_root(&lock).unwrap();
            let claim = lock.join(format!("claim.{OPERATION}.{IDENTITY}"));
            let directory = open::prepare_state_root(&claim).unwrap();
            for (name, value) in [
                ("operation_id", OPERATION),
                ("claim_identity", IDENTITY),
                ("operation_kind", "initial_setup"),
                ("state", "recovery_pending"),
                ("mutation_phase", "setup_maintenance_begin"),
                ("mutation_attempt", ATTEMPT),
                ("heartbeat_at", "2026-01-01T00:00:00Z"),
            ] {
                directory
                    .create_private_leaf_durable(name, value.as_bytes())
                    .unwrap();
            }
            #[cfg(windows)]
            directory
                .create_private_leaf_durable(&format!("execution_started.{ATTEMPT}"), b"")
                .unwrap();
            #[cfg(unix)]
            open::prepare_state_root(&claim.join(format!("execution_started.{ATTEMPT}"))).unwrap();
            drop(directory);
            Self {
                _root: root,
                state,
                bootstrap,
                claim,
                host_identity,
            }
        }

        fn complete_setup(&self, now: OffsetDateTime) {
            self.finish_setup(now, None);
        }

        fn finish_setup(&self, now: OffsetDateTime, skip: Option<SetupActionSkipReason>) {
            let mut storage = Storage::open_without_restart_recovery(&self.state).unwrap();
            let plan = SetupRunPlan::new(
                OPERATION,
                SetupOperationKind::Setup,
                None,
                now,
                vec![SetupActionPlan::new("bootstrap-handoff", "Start Host", true).unwrap()],
            )
            .unwrap();
            let owner = LeaseOwner::new(OPERATION, 123, "process", "boot", now).unwrap();
            let capability = if skip.is_some() {
                storage.begin_setup_run(&plan, owner).unwrap()
            } else {
                storage.begin_bootstrap_maintenance(&plan, owner).unwrap()
            };
            if let Some(reason) = skip {
                storage
                    .skip_setup_action(
                        &capability,
                        "bootstrap-handoff",
                        reason,
                        now + time::Duration::seconds(1),
                    )
                    .unwrap();
            } else {
                storage
                    .complete_setup_action_after_verified_postcondition(
                        &capability,
                        "bootstrap-handoff",
                        now + time::Duration::seconds(1),
                    )
                    .unwrap();
            }
            storage
                .finish_setup_run_and_release_maintenance(
                    &capability,
                    now + time::Duration::seconds(2),
                )
                .unwrap();
        }

        fn recover(&self, apply: bool) -> Result<BootstrapRecovery, StorageError> {
            recover(
                &self.state,
                &self.bootstrap,
                &self.host_identity,
                OPERATION,
                apply,
            )
        }
    }

    #[test]
    fn absent_begin_is_planned_then_archived_with_original_evidence() {
        let fixture = Fixture::new();
        let plan = fixture.recover(false).unwrap();
        assert!(!plan.changed);
        assert!(fixture.claim.is_dir());
        assert!(!plan.archive_path.exists());
        let result = fixture.recover(true).unwrap();
        assert!(result.changed);
        assert!(!fixture.claim.exists());
        let archive = open::open_state_root_read_only(&result.archive_path).unwrap();
        assert_eq!(
            archive
                .read_private_leaf_bounded("mutation_attempt", 512)
                .unwrap()
                .unwrap(),
            ATTEMPT.as_bytes()
        );
        #[cfg(windows)]
        assert_eq!(
            archive
                .read_private_leaf_bounded(&format!("execution_started.{ATTEMPT}"), 512)
                .unwrap()
                .unwrap(),
            b""
        );
        #[cfg(unix)]
        assert!(
            result
                .archive_path
                .join(format!("execution_started.{ATTEMPT}"))
                .is_dir()
        );
        assert_eq!(
            archive
                .read_private_leaf_bounded("recovery.json", 4096)
                .unwrap()
                .unwrap(),
            serde_json::to_vec(&result).unwrap()
        );
        let storage = Storage::open_without_restart_recovery(&fixture.state).unwrap();
        assert!(storage.load_setup_run(OPERATION).unwrap().is_none());
    }

    #[test]
    fn completed_setup_archives_only_its_ledger_phase_and_preserves_the_run() {
        for phase in ["setup_action_complete", "service_start"] {
            let fixture = Fixture::new();
            fixture.complete_setup(OffsetDateTime::now_utc());
            let directory = open::open_state_root_read_only(&fixture.claim).unwrap();
            directory
                .delete_private_leaf_durable("mutation_phase")
                .unwrap();
            directory
                .create_private_leaf_durable("mutation_phase", phase.as_bytes())
                .unwrap();
            drop(directory);
            if phase == "service_start" {
                assert!(fixture.recover(true).is_err());
                assert!(fixture.claim.is_dir());
                continue;
            }
            let preview = fixture.recover(false).unwrap();
            assert_eq!(preview.outcome, "setup_run_completed");
            assert!(!preview.changed);
            let recovered = fixture.recover(true).unwrap();
            assert!(recovered.archive_path.is_dir());
            assert!(!fixture.claim.exists());
            let storage = Storage::open_without_restart_recovery(&fixture.state).unwrap();
            assert_eq!(
                storage.load_setup_run(OPERATION).unwrap().unwrap().status(),
                SetupRunStatus::Completed
            );
        }
    }

    #[test]
    fn safe_skips_recover_but_dependency_failure_stays_fenced() {
        for reason in [
            SetupActionSkipReason::AlreadySatisfied,
            SetupActionSkipReason::NotRequired,
            SetupActionSkipReason::DependencyFailed,
        ] {
            let fixture = Fixture::new();
            fixture.finish_setup(OffsetDateTime::now_utc(), Some(reason));
            if reason == SetupActionSkipReason::DependencyFailed {
                assert!(fixture.recover(true).is_err());
                assert!(fixture.claim.is_dir());
            } else {
                assert!(fixture.recover(true).unwrap().changed);
                assert!(!fixture.claim.exists());
            }
        }
    }

    #[test]
    fn foreign_empty_or_retiring_claim_names_keep_the_claim_fenced() {
        for basename in [
            "claim.another-operation.fhgc9G",
            "claim.interrupted-setup.",
            "claim.interrupted-setup.fhgc9G.closing",
        ] {
            let mut fixture = Fixture::new();
            let renamed = fixture.claim.with_file_name(basename);
            fs::rename(&fixture.claim, &renamed).unwrap();
            fixture.claim = renamed;
            assert!(fixture.recover(true).is_err(), "{basename}");
            assert!(fixture.claim.is_dir());
        }
    }

    #[test]
    fn live_store_owner_and_recorded_begin_keep_the_claim_fenced() {
        let fixture = Fixture::new();
        let mut storage = Storage::open_without_restart_recovery(&fixture.state).unwrap();
        assert!(fixture.recover(true).is_err());
        let now = OffsetDateTime::now_utc();
        let plan = SetupRunPlan::new(
            OPERATION,
            SetupOperationKind::Setup,
            None,
            now,
            vec![SetupActionPlan::new("on_demand_handoff", "Start Host", true).unwrap()],
        )
        .unwrap();
        let owner = LeaseOwner::new(OPERATION, 123, "process", "boot", now).unwrap();
        storage.begin_setup_run(&plan, owner).unwrap();
        drop(storage);
        assert!(fixture.recover(true).is_err());
        assert!(fixture.claim.is_dir());
        let storage = Storage::open_without_restart_recovery(&fixture.state).unwrap();
        assert!(storage.load_setup_run(OPERATION).unwrap().is_some());
    }

    #[test]
    fn completed_setup_does_not_retire_another_maintenance_owner() {
        let fixture = Fixture::new();
        let now = OffsetDateTime::now_utc();
        fixture.complete_setup(now);
        let mut storage = Storage::open_without_restart_recovery(&fixture.state).unwrap();
        let another = SetupRunPlan::new(
            "another-setup",
            SetupOperationKind::Setup,
            None,
            now,
            vec![SetupActionPlan::new("service-config", "Configure Host", true).unwrap()],
        )
        .unwrap();
        let owner = LeaseOwner::new("another-setup", 456, "other-process", "boot", now).unwrap();
        storage.begin_setup_run(&another, owner).unwrap();
        drop(storage);
        assert!(fixture.recover(true).is_err());
        assert!(fixture.claim.is_dir());
    }

    #[test]
    fn fresh_foreign_or_changed_execution_evidence_is_not_recovered() {
        for (name, value) in [
            ("state", "live".to_string()),
            ("mutation_phase", "managed_setup".to_string()),
            ("operation_id", "another-operation".to_string()),
            (
                "heartbeat_at",
                OffsetDateTime::now_utc().format(&Rfc3339).unwrap(),
            ),
            ("execution_committed.foreign", "".to_string()),
        ] {
            let fixture = Fixture::new();
            let directory = open::open_state_root_read_only(&fixture.claim).unwrap();
            directory.delete_private_leaf_durable(name).unwrap();
            directory
                .create_private_leaf_durable(name, value.as_bytes())
                .unwrap();
            drop(directory);
            assert!(fixture.recover(true).is_err(), "{name}");
            assert!(fixture.claim.is_dir());
        }
        let fixture = Fixture::new();
        assert!(
            recover(
                &fixture.state,
                &fixture.bootstrap,
                "another-host",
                OPERATION,
                true
            )
            .is_err()
        );
        assert!(fixture.claim.is_dir());
    }

    #[test]
    fn receipt_before_archive_can_resume_after_a_crash() {
        let fixture = Fixture::new();
        let mut report = fixture.recover(false).unwrap();
        report.changed = true;
        let directory = open::open_state_root_read_only(&fixture.claim).unwrap();
        directory
            .create_private_leaf_durable("recovery.json", &serde_json::to_vec(&report).unwrap())
            .unwrap();
        drop(directory);
        let recovered = fixture.recover(true).unwrap();
        assert!(recovered.archive_path.is_dir());
    }

    #[test]
    fn pruned_terminal_history_is_not_reported_as_nonmutation() {
        let fixture = Fixture::new();
        let mut storage = Storage::open_without_restart_recovery(&fixture.state).unwrap();
        let started = OffsetDateTime::now_utc() - time::Duration::days(2);
        let plan = SetupRunPlan::new(
            OPERATION,
            SetupOperationKind::Setup,
            None,
            started,
            vec![SetupActionPlan::new("bootstrap-handoff", "Start Host", true).unwrap()],
        )
        .unwrap();
        let owner = LeaseOwner::new(OPERATION, 123, "process", "boot", started).unwrap();
        let capability = storage.begin_bootstrap_maintenance(&plan, owner).unwrap();
        storage
            .complete_setup_action_after_verified_postcondition(
                &capability,
                "bootstrap-handoff",
                started + time::Duration::seconds(1),
            )
            .unwrap();
        storage
            .finish_setup_run_and_release_maintenance(
                &capability,
                started + time::Duration::seconds(2),
            )
            .unwrap();
        storage
            .prune_expired_session_metadata_with_retention(
                OffsetDateTime::now_utc(),
                time::Duration::days(7),
                time::Duration::hours(1),
            )
            .unwrap();
        assert!(storage.load_setup_run(OPERATION).unwrap().is_none());
        drop(storage);
        let recovered = fixture.recover(true).unwrap();
        assert_eq!(recovered.outcome, "begin_has_no_ledger_run");
    }
}
