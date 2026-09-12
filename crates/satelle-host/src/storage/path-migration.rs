use satelle_core::daemon_service::DaemonResolvedPathSet;
use satelle_core::{DaemonPathOverrides, ErrorCode, SatelleError};
use satelle_core::{
    open_existing_private_file, open_new_owner_only_file, open_or_create_owner_only_directory,
    open_owner_only_directory, sync_owner_only_directory,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageMigrationItemKind {
    SqliteStore,
    HostState,
    OperatorLog,
    Recording,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageMigrationItem {
    pub source: PathBuf,
    pub destination: PathBuf,
    pub kind: StorageMigrationItemKind,
    pub estimated_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageMigrationPlan {
    pub source: DaemonResolvedPathSet,
    pub destination: DaemonResolvedPathSet,
    pub items: Vec<StorageMigrationItem>,
    pub estimated_bytes: Option<u64>,
    pub backup_location: PathBuf,
    pub validation_checks: Vec<String>,
    pub rollback_plan: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageMigrationStage {
    pub operation_id: String,
    pub plan: StorageMigrationPlan,
    pub host_identity: String,
    pub copied_files: usize,
    pub invalidated_native_readiness: u64,
}

const STAGING_RECEIPT: &str = ".satelle-storage-migration-staged-v1.json";
const STAGING_RECEIPT_LIMIT: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageMigrationCleanup {
    pub operation_id: String,
    pub source: DaemonResolvedPathSet,
    pub files: Vec<PathBuf>,
    pub removed_files: Vec<PathBuf>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CopiedSourceFile {
    path: PathBuf,
    sha256: [u8; 32],
}

pub(crate) fn migration_requires_rollback(
    source_root: &Path,
    operation_id: &str,
) -> Result<bool, SatelleError> {
    let directory = super::open::open_state_root_read_only(source_root)
        .map_err(crate::runtime::storage_failure)?;
    let Some((journal, _)) = super::read_offline_storage_maintenance_journal(&directory)
        .map_err(crate::runtime::storage_failure)?
    else {
        return Ok(false);
    };
    if journal.operation_id != operation_id
        || journal.action_id != crate::STORAGE_MIGRATION_ACTION_ID
    {
        return Err(SatelleError::state_conflict());
    }
    Ok(true)
}

/// Published only after all copies and checks finish. The maintenance journal
/// alone proves ownership, but cannot prove a complete copy after a crash.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StagingReceipt {
    operation_id: String,
    source: DaemonResolvedPathSet,
    destination: DaemonResolvedPathSet,
    host_identity: String,
    source_files: Vec<CopiedSourceFile>,
}

impl super::Storage {
    fn storage_migration_receipt(
        &self,
        operation_id: &str,
        expected_paths: &DaemonResolvedPathSet,
    ) -> Result<StagingReceipt, SatelleError> {
        let encoded = self
            ._state_directory
            .read_private_leaf_bounded(STAGING_RECEIPT, STAGING_RECEIPT_LIMIT)
            .map_err(crate::runtime::storage_failure)?
            .ok_or_else(SatelleError::state_conflict)?;
        let receipt: StagingReceipt =
            serde_json::from_slice(&encoded).map_err(|_| SatelleError::state_conflict())?;
        if receipt.operation_id != operation_id
            || receipt.destination != *expected_paths
            || receipt.host_identity
                != self
                    .host_identity()
                    .map_err(crate::runtime::storage_failure)?
                    .as_str()
        {
            return Err(SatelleError::state_conflict());
        }
        Ok(receipt)
    }

    pub(crate) fn verify_storage_migration(
        &self,
        operation_id: &str,
        expected_paths: &DaemonResolvedPathSet,
    ) -> Result<(), SatelleError> {
        let receipt = self.storage_migration_receipt(operation_id, expected_paths)?;
        // A lost response can be replayed after normal work resumes. Its
        // completed ledger is authoritative; do not erase newer readiness.
        if self
            .load_setup_run(operation_id)
            .map_err(crate::runtime::storage_failure)?
            .is_some_and(|run| run.status() == super::SetupRunStatus::Completed)
        {
            return Ok(());
        }
        super::open::verify_integrity(&self.connection).map_err(crate::runtime::storage_failure)?;
        let cached: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM native_readiness_results WHERE host_identity_ref = ?1)",
            [receipt.host_identity.as_str()], |row| row.get(0),
        ).map_err(|source| crate::runtime::storage_failure(super::open::sqlite_error(
            super::StorageErrorKind::OperationFailed, source,
        )))?;
        if cached {
            return Err(SatelleError::state_conflict());
        }
        for root in [
            &expected_paths.operator_log_root,
            &expected_paths.recording_root,
        ] {
            verify_directory_writable(Path::new(root))?;
        }
        Ok(())
    }

    pub(crate) fn migration_source_for_cleanup(
        &self,
        operation_id: &str,
        active_paths: &DaemonResolvedPathSet,
    ) -> Result<StagingReceipt, SatelleError> {
        let receipt = self.storage_migration_receipt(operation_id, active_paths)?;
        if !self
            .load_setup_run(operation_id)
            .map_err(crate::runtime::storage_failure)?
            .is_some_and(|run| run.status() == super::SetupRunStatus::Completed)
        {
            return Err(SatelleError::state_conflict());
        }
        Ok(receipt)
    }
}

impl StagingReceipt {
    /// File hashing and deletion run outside the active destination's SQLite
    /// mutex, so cleanup cannot stall normal Host work behind a large recording.
    pub(crate) fn cleanup(
        self,
        approved: Option<&StorageMigrationCleanup>,
    ) -> Result<StorageMigrationCleanup, SatelleError> {
        let receipt = self;
        if approved.is_some_and(|plan| {
            plan.operation_id != receipt.operation_id || plan.source != receipt.source
        }) {
            return Err(SatelleError::state_conflict());
        }
        let selected =
            approved.map(|plan| plan.files.iter().collect::<std::collections::BTreeSet<_>>());
        let operation_id = receipt.operation_id.clone();
        let source =
            super::open::OfflineStoreReset::migration_source(Path::new(&receipt.source.state_root))
                .map_err(crate::runtime::storage_failure)?;
        let (journal, _) = super::read_offline_storage_maintenance_journal(&source.state_directory)
            .map_err(crate::runtime::storage_failure)?
            .ok_or_else(SatelleError::state_conflict)?;
        if journal.operation_id != operation_id
            || journal.action_id != crate::STORAGE_MIGRATION_ACTION_ID
        {
            return Err(SatelleError::state_conflict());
        }
        let mut report = StorageMigrationCleanup {
            operation_id,
            source: receipt.source,
            files: Vec::new(),
            removed_files: Vec::new(),
        };
        // Inspect the complete copy list before deleting anything. Files added
        // after staging are outside this immutable list and remain untouched.
        for file in receipt.source_files.iter().filter(|file| {
            selected
                .as_ref()
                .is_none_or(|paths| paths.contains(&file.path))
        }) {
            if super::open::verify_migrated_source_file(&file.path, &file.sha256)
                .map_err(crate::runtime::storage_failure)?
            {
                report.files.push(file.path.clone());
            }
        }
        for name in super::open::PROTECTED_FILE_NAMES
            .iter()
            .filter(|name| **name != super::open::LOCK_FILE_NAME)
        {
            let path = Path::new(&report.source.state_root).join(name);
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    if selected
                        .as_ref()
                        .is_some_and(|paths| !paths.contains(&path))
                    {
                        return Err(source_error(
                            &path,
                            "preserved SQLite files changed after cleanup was planned",
                        ));
                    }
                    open_existing_private_file(&path).map_err(|_| {
                        source_error(&path, "could not inspect the preserved SQLite file")
                    })?;
                    report.files.push(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => {
                    return Err(source_error(
                        &path,
                        "could not inspect the preserved SQLite file",
                    ));
                }
            }
        }
        if approved.is_none() {
            return Ok(report);
        }
        let deletion = (|| {
            for file in receipt.source_files.iter().filter(|file| {
                selected
                    .as_ref()
                    .is_none_or(|paths| paths.contains(&file.path))
            }) {
                if super::open::remove_verified_migrated_source_file(&file.path, &file.sha256)
                    .map_err(crate::runtime::storage_failure)?
                {
                    report.removed_files.push(file.path.clone());
                }
            }
            match source.reset_metadata() {
                Ok(names) => report.removed_files.extend(
                    names
                        .iter()
                        .map(|name| Path::new(&report.source.state_root).join(name)),
                ),
                Err((names, error)) => {
                    report.removed_files.extend(
                        names
                            .iter()
                            .map(|name| Path::new(&report.source.state_root).join(name)),
                    );
                    return Err(crate::runtime::storage_failure(error));
                }
            }
            Ok(())
        })();
        if let Err(mut error) = deletion {
            error.code = ErrorCode::SetupPartiallyApplied;
            error
                .details
                .insert("cleanup".into(), serde_json::json!(report));
            return Err(error);
        }
        Ok(report)
    }
}

/// The caller has persisted the maintenance operation and stopped the service.
/// Keep the source lock until every selected file has a verified destination.
/// Any incomplete destination remains fenced by the copied maintenance journal.
pub(crate) fn stage(mut plan: StorageMigrationPlan) -> Result<StorageMigrationStage, SatelleError> {
    let source_root = Path::new(&plan.source.state_root);
    let source = super::Storage::open_without_restart_recovery(source_root)
        .map_err(crate::runtime::storage_failure)?;
    let host_identity = source
        .host_identity()
        .map_err(crate::runtime::storage_failure)?;
    let (journal, encoded) =
        super::read_offline_storage_maintenance_journal(&source._state_directory)
            .map_err(crate::runtime::storage_failure)?
            .ok_or_else(SatelleError::state_conflict)?;
    if journal.action_id != crate::STORAGE_MIGRATION_ACTION_ID {
        return Err(SatelleError::state_conflict());
    }
    plan.items
        .retain(|item| item.kind == StorageMigrationItemKind::SqliteStore);
    plan.items
        .extend(collect_auxiliary_files(&plan.source, &plan.destination)?);
    plan.items
        .sort_by(|left, right| left.destination.cmp(&right.destination));
    plan.estimated_bytes = plan
        .items
        .iter()
        .try_fold(0_u64, |total, item| total.checked_add(item.estimated_bytes));

    let destination_root = Path::new(&plan.destination.state_root);
    drop(prepare_migration_directory(destination_root)?);
    let destination_directory = super::open::prepare_state_root(destination_root)
        .map_err(crate::runtime::storage_failure)?;
    destination_directory
        .create_private_leaf_durable(super::OFFLINE_STORAGE_MAINTENANCE_JOURNAL, &encoded)
        .map_err(crate::runtime::storage_failure)?;
    drop(
        super::open::create_verified_sqlite_copy(
            &source.connection,
            destination_root,
            &destination_directory,
            super::open::DATABASE_FILE_NAME,
        )
        .map_err(crate::runtime::storage_failure)?,
    );
    drop(destination_directory);

    let mut destination = super::Storage::open_without_restart_recovery(destination_root)
        .map_err(crate::runtime::storage_failure)?;
    if destination
        .host_identity()
        .map_err(crate::runtime::storage_failure)?
        != host_identity
    {
        return Err(SatelleError::state_conflict());
    }
    let mut source_files = Vec::new();
    for item in &plan.items {
        if item.kind != StorageMigrationItemKind::SqliteStore {
            let sha256 = copy_verified_file(&item.source, &item.destination)?;
            source_files.push(CopiedSourceFile {
                path: item.source.clone(),
                sha256,
            });
        }
    }
    for root in [
        &plan.destination.operator_log_root,
        &plan.destination.recording_root,
    ] {
        verify_directory_writable(Path::new(root))?;
    }
    let invalidated_native_readiness = destination
        .invalidate_all_native_readiness()
        .map_err(crate::runtime::storage_failure)?;
    let receipt = StagingReceipt {
        operation_id: journal.operation_id.clone(),
        source: plan.source.clone(),
        destination: plan.destination.clone(),
        host_identity: host_identity.to_string(),
        source_files,
    };
    let encoded = serde_json::to_vec(&receipt).map_err(|_| SatelleError::state_conflict())?;
    if encoded.len() > STAGING_RECEIPT_LIMIT {
        return Err(SatelleError::state_conflict());
    }
    destination
        ._state_directory
        .create_private_leaf_durable(STAGING_RECEIPT, &encoded)
        .map_err(crate::runtime::storage_failure)?;
    let copied_files = plan.items.len();
    Ok(StorageMigrationStage {
        operation_id: journal.operation_id,
        plan,
        host_identity: host_identity.to_string(),
        copied_files,
        invalidated_native_readiness,
    })
}

fn copy_verified_file(source: &Path, destination: &Path) -> Result<[u8; 32], SatelleError> {
    let destination_error = || {
        migration_error(
            ErrorCode::StorageMigrationDestinationInvalid,
            "could not create or verify the staged private file",
            destination,
        )
    };
    let parent = destination.parent().ok_or_else(destination_error)?;
    let directory = prepare_migration_directory(parent)?;
    let mut input = open_existing_private_file(source)
        .map_err(|_| source_error(source, "could not open the selected source file"))?;
    let mut output = open_new_owner_only_file(destination).map_err(|_| destination_error())?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let length = input
            .read(&mut buffer)
            .map_err(|_| source_error(source, "could not read the selected source file"))?;
        if length == 0 {
            break;
        }
        digest.update(&buffer[..length]);
        output
            .write_all(&buffer[..length])
            .map_err(|_| destination_error())?;
    }
    output.sync_all().map_err(|_| destination_error())?;
    drop(output);
    let mut verification =
        open_existing_private_file(destination).map_err(|_| destination_error())?;
    let mut verified_digest = Sha256::new();
    loop {
        let length = verification
            .read(&mut buffer)
            .map_err(|_| destination_error())?;
        if length == 0 {
            break;
        }
        verified_digest.update(&buffer[..length]);
    }
    let digest = digest.finalize();
    if digest != verified_digest.finalize() {
        return Err(destination_error());
    }
    sync_owner_only_directory(parent, &directory).map_err(|_| destination_error())?;
    Ok(digest.into())
}

fn verify_directory_writable(path: &Path) -> Result<(), SatelleError> {
    let invalid = || {
        migration_error(
            ErrorCode::StorageMigrationDestinationInvalid,
            "destination directory does not support private file writes",
            path,
        )
    };
    let directory = prepare_migration_directory(path)?;
    let probe = path.join(format!(
        ".satelle-storage-write-check-{}",
        uuid::Uuid::now_v7()
    ));
    let mut file = open_new_owner_only_file(&probe).map_err(|_| invalid())?;
    file.write_all(b"storage migration write check\n")
        .map_err(|_| invalid())?;
    file.sync_all().map_err(|_| invalid())?;
    drop(file);
    fs::remove_file(probe).map_err(|_| invalid())?;
    sync_owner_only_directory(path, &directory).map_err(|_| invalid())
}

/// Create missing parents from the existing private boundary outward. The
/// secure directory primitive creates one leaf, not a recursive tree. Sync
/// each parent so a completed copy also retains its new directory entries.
fn prepare_migration_directory(
    path: &Path,
) -> Result<satelle_core::OwnerOnlyDirectory, SatelleError> {
    let invalid = || {
        migration_error(
            ErrorCode::StorageMigrationDestinationInvalid,
            "could not create or verify the staged private directory",
            path,
        )
    };
    let mut missing = Vec::new();
    let mut existing = path;
    loop {
        match fs::symlink_metadata(existing) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(existing);
                existing = existing.parent().ok_or_else(invalid)?;
            }
            Err(_) => return Err(invalid()),
        }
    }
    let mut directory = open_owner_only_directory(existing).map_err(|_| invalid())?;
    for child in missing.into_iter().rev() {
        let created = open_or_create_owner_only_directory(child).map_err(|_| invalid())?;
        sync_owner_only_directory(existing, &directory).map_err(|_| invalid())?;
        existing = child;
        directory = created;
    }
    Ok(directory)
}

/// Inspects the selected Host's paths from the maintenance process. Preview
/// never opens a Host runtime, creates a directory, or writes a SQLite sidecar.
pub(crate) fn plan(
    source: &DaemonResolvedPathSet,
    destination_root: &Path,
) -> Result<StorageMigrationPlan, SatelleError> {
    plan_for_operation(source, destination_root, None)
}

pub(crate) fn plan_for_operation(
    source: &DaemonResolvedPathSet,
    destination_root: &Path,
    operation_id: Option<&str>,
) -> Result<StorageMigrationPlan, SatelleError> {
    let source_state = canonical_source_directory(Path::new(&source.state_root))?;
    let destination_root = destination_path(destination_root)?;
    let destination = source.with_service_overrides(&DaemonPathOverrides {
        state_dir: Some(destination_root.join("state")),
        log_dir: Some(destination_root.join("logs")),
        ..DaemonPathOverrides::default()
    });
    let source_roots = [
        source_state.as_path(),
        Path::new(&source.operator_log_root),
        Path::new(&source.recording_root),
    ];
    let destination_roots = [
        Path::new(&destination.state_root),
        Path::new(&destination.operator_log_root),
    ];
    for source_root in source_roots {
        let source_root = resolved_optional_source_path(source_root)?;
        for destination in destination_roots {
            if paths_overlap(&source_root, destination) {
                return Err(migration_error(
                    ErrorCode::StorageMigrationPathsOverlap,
                    "source and destination storage paths overlap",
                    &source_root,
                ));
            }
        }
    }
    for destination in destination_roots {
        require_empty_destination(destination)?;
    }

    // These markers describe unfinished state transitions. Copying one would
    // move recovery authority to a different path before its owner completes.
    for marker in [
        super::SSH_IDENTITY_COMMIT_JOURNAL,
        super::OFFLINE_STORAGE_MAINTENANCE_JOURNAL,
        ".satelle-restore-activation-v1",
        "codex-install-intent.json",
    ] {
        if marker == super::OFFLINE_STORAGE_MAINTENANCE_JOURNAL
            && let Some(operation_id) = operation_id
            && migration_requires_rollback(&source_state, operation_id)?
        {
            continue;
        }
        match fs::symlink_metadata(source_state.join(marker)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(source_error(
                    &source_state,
                    "could not inspect Host maintenance state",
                ));
            }
            Ok(_) => {
                return Err(source_error(
                    &source_state.join(marker),
                    "finish or recover the existing Host maintenance operation before migration",
                ));
            }
        }
    }

    let mut items = Vec::new();
    add_file(
        &mut items,
        &source_state.join(super::open::DATABASE_FILE_NAME),
        Path::new(&destination.sqlite_store),
        StorageMigrationItemKind::SqliteStore,
    )?;
    items.extend(collect_auxiliary_files(source, &destination)?);
    items.sort_by(|left, right| left.destination.cmp(&right.destination));
    let estimated_bytes = items
        .iter()
        .try_fold(0_u64, |total, item| total.checked_add(item.estimated_bytes));
    Ok(StorageMigrationPlan {
        source: source.clone(),
        destination,
        items,
        estimated_bytes,
        backup_location: source_state,
        validation_checks: vec![
            "verify every staged file against its source".to_string(),
            "verify SQLite integrity and Host identity".to_string(),
            "verify the restarted Host API reports the destination paths".to_string(),
            "verify operator log and recording path writes".to_string(),
            "invalidate native readiness results".to_string(),
        ],
        rollback_plan: vec![
            "preserve all source storage and destination staging files".to_string(),
            "restore the previous Host service path configuration".to_string(),
            "restart and verify the Host against the preserved source".to_string(),
        ],
    })
}

/// Collects files that can change while the maintenance ledger is opened.
/// SQLite stays outside this pass: closing an extra database descriptor could
/// release the process's POSIX SQLite locks during staging.
fn collect_auxiliary_files(
    source: &DaemonResolvedPathSet,
    destination: &DaemonResolvedPathSet,
) -> Result<Vec<StorageMigrationItem>, SatelleError> {
    let source_state = Path::new(&source.state_root);
    let mut items = Vec::new();
    for entry in fs::read_dir(source_state)
        .map_err(|_| source_error(source_state, "could not list Host state files"))?
    {
        let entry =
            entry.map_err(|_| source_error(source_state, "could not inspect a Host state file"))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        // Controller history and arbitrary colocated files are outside the
        // Host storage contract. Existing backup pairs retain their own names.
        if matches!(name, "codex-install-receipt.json" | "install-receipt.json")
            || (name.starts_with("satelle.sqlite3.migration-v")
                && (name.ends_with(".backup") || name.ends_with(".backup.json")))
        {
            add_file(
                &mut items,
                &entry.path(),
                &Path::new(&destination.state_root).join(name),
                StorageMigrationItemKind::HostState,
            )?;
        }
    }
    add_directory(
        &mut items,
        Path::new(&source.operator_log_root),
        Path::new(&destination.operator_log_root),
        StorageMigrationItemKind::OperatorLog,
    )?;
    add_directory(
        &mut items,
        Path::new(&source.recording_root),
        Path::new(&destination.recording_root),
        StorageMigrationItemKind::Recording,
    )?;
    Ok(items)
}

fn add_file(
    items: &mut Vec<StorageMigrationItem>,
    source: &Path,
    destination: &Path,
    kind: StorageMigrationItemKind,
) -> Result<(), SatelleError> {
    if source.to_str().is_none() || destination.to_str().is_none() {
        return Err(source_error(
            source,
            "migration paths must contain valid UTF-8",
        ));
    }
    let file = open_existing_private_file(source)
        .map_err(|_| source_error(source, "source must be a readable private regular file"))?;
    let metadata = file
        .metadata()
        .map_err(|_| source_error(source, "could not inspect the source file"))?;
    items.push(StorageMigrationItem {
        source: source.to_path_buf(),
        destination: destination.to_path_buf(),
        kind,
        estimated_bytes: metadata.len(),
    });
    Ok(())
}

fn add_directory(
    items: &mut Vec<StorageMigrationItem>,
    source: &Path,
    destination: &Path,
    kind: StorageMigrationItemKind,
) -> Result<(), SatelleError> {
    match fs::symlink_metadata(source) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => {
            return Err(source_error(
                source,
                "could not inspect the source directory",
            ));
        }
        Ok(_) => {}
    }
    let _directory = open_owner_only_directory(source)
        .map_err(|_| source_error(source, "source must be a private non-symlink directory"))?;
    for entry in fs::read_dir(source)
        .map_err(|_| source_error(source, "could not list the source directory"))?
    {
        let entry = entry
            .map_err(|_| source_error(source, "could not inspect a source directory entry"))?;
        let source = entry.path();
        let destination = destination.join(entry.file_name());
        let file_type = entry
            .file_type()
            .map_err(|_| source_error(&source, "could not inspect a source directory entry"))?;
        if file_type.is_dir() {
            add_directory(items, &source, &destination, kind)?;
        } else {
            add_file(items, &source, &destination, kind)?;
        }
    }
    Ok(())
}

fn canonical_source_directory(path: &Path) -> Result<PathBuf, SatelleError> {
    let _directory = open_owner_only_directory(path)
        .map_err(|_| source_error(path, "source must be a readable private directory"))?;
    fs::canonicalize(path).map_err(|_| source_error(path, "could not resolve the source directory"))
}

fn resolved_optional_source_path(path: &Path) -> Result<PathBuf, SatelleError> {
    match fs::symlink_metadata(path) {
        Ok(_) => canonical_source_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => resolve_missing_path(path)
            .map_err(|_| source_error(path, "could not resolve the optional source directory")),
        Err(_) => Err(source_error(path, "could not inspect the source directory")),
    }
}

fn destination_path(path: &Path) -> Result<PathBuf, SatelleError> {
    let invalid = || {
        migration_error(
            ErrorCode::StorageMigrationDestinationInvalid,
            "destination must have an absolute path inside a writable private directory",
            path,
        )
    };
    let resolved = resolve_missing_path(path).map_err(|()| invalid())?;
    let existing = resolved
        .ancestors()
        .find(|ancestor| ancestor.exists())
        .ok_or_else(invalid)?;
    let _directory = open_owner_only_directory(existing).map_err(|_| invalid())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if fs::metadata(existing)
            .map_err(|_| invalid())?
            .permissions()
            .mode()
            & 0o300
            != 0o300
        {
            return Err(invalid());
        }
    }
    Ok(resolved)
}

/// Resolves existing ancestors before comparing paths. Missing leaves stay
/// literal; parent traversal and symlink aliases are never accepted as input.
fn resolve_missing_path(path: &Path) -> Result<PathBuf, ()> {
    if !path.is_absolute()
        || path.parent().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(());
    }
    let mut ancestor = path;
    let mut missing = Vec::new();
    loop {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => break,
            Ok(_) => return Err(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(ancestor.file_name().ok_or(())?);
                ancestor = ancestor.parent().ok_or(())?;
            }
            Err(_) => return Err(()),
        }
    }
    let _directory = open_owner_only_directory(ancestor).map_err(|_| ())?;
    let mut resolved = fs::canonicalize(ancestor).map_err(|_| ())?;
    for name in missing.into_iter().rev() {
        resolved.push(name);
    }
    Ok(resolved)
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    #[cfg(windows)]
    {
        let left = PathBuf::from(left.to_string_lossy().to_uppercase());
        let right = PathBuf::from(right.to_string_lossy().to_uppercase());
        left.starts_with(&right) || right.starts_with(&left)
    }
    #[cfg(not(windows))]
    {
        left.starts_with(right) || right.starts_with(left)
    }
}

fn require_empty_destination(path: &Path) -> Result<(), SatelleError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Ok(_) | Err(_) => {}
    }
    let _directory = open_owner_only_directory(path).map_err(|_| {
        migration_error(
            ErrorCode::StorageMigrationDestinationInvalid,
            "destination must be a private non-symlink directory",
            path,
        )
    })?;
    let mut entries = fs::read_dir(path).map_err(|_| {
        migration_error(
            ErrorCode::StorageMigrationDestinationInvalid,
            "could not inspect the destination directory",
            path,
        )
    })?;
    if entries.next().is_some() {
        return Err(migration_error(
            ErrorCode::StorageMigrationDestinationNotEmpty,
            "destination storage must be absent or an empty directory",
            path,
        ));
    }
    Ok(())
}

fn source_error(path: &Path, message: &str) -> SatelleError {
    migration_error(ErrorCode::StorageMigrationSourceInvalid, message, path)
}

fn migration_error(code: ErrorCode, message: &str, path: &Path) -> SatelleError {
    SatelleError {
        code,
        message: message.to_string(),
        recovery_command: None,
        source_detail: None,
        details: BTreeMap::from([("path".to_string(), serde_json::json!(path))]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use satelle_core::open_new_owner_only_file;
    #[cfg(unix)]
    use satelle_core::open_or_create_owner_only_directory;
    use satelle_test_contract::assert_directory_tree_unchanged;

    fn source_paths(root: &Path) -> DaemonResolvedPathSet {
        let state = root.join("source");
        let (storage, _) = super::super::Storage::open(&state).unwrap();
        drop(storage);
        let state = fs::canonicalize(state).unwrap();
        let mut config = satelle_core::SatelleConfig::defaults()
            .hosts
            .remove(satelle_core::LOCAL_DEMO_HOST)
            .unwrap();
        config.daemon_state_dir = Some(state.clone());
        config.daemon_log_dir = Some(state.join("logs"));
        config.daemon_cache_dir = Some(state.join("cache"));
        config.daemon_config_file = Some(state.join("config.toml"));
        // Completion compares the full live path evidence, including source
        // attribution. Use the Host resolver, not synthesized offline evidence.
        crate::HostService::resolved_daemon_paths_for_host(&config).unwrap()
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        drop(prepare_migration_directory(path.parent().unwrap()).unwrap());
        open_new_owner_only_file(path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }

    #[test]
    fn preview_lists_owned_files_and_preserves_the_entire_directory_tree() {
        let root = crate::TestStateDir::new().unwrap();
        let source = source_paths(root.path());
        write_private(
            &Path::new(&source.state_root).join("controller-history.json"),
            b"controller",
        );
        write_private(
            &Path::new(&source.state_root).join("codex-install-receipt.json"),
            b"receipt",
        );
        write_private(
            &Path::new(&source.operator_log_root).join("satelle.log"),
            b"operator log",
        );
        write_private(
            &Path::new(&source.recording_root)
                .join("session")
                .join("recording.mp4"),
            b"recording",
        );
        let destination = fs::canonicalize(root.path()).unwrap().join("destination");
        let plan =
            assert_directory_tree_unchanged("storage migration preview", root.path(), || {
                plan(&source, &destination).unwrap()
            });
        assert_eq!(plan.source, source);
        assert_eq!(plan.destination.config_file, source.config_file);
        assert_eq!(plan.destination.cache_root, source.cache_root);
        assert_eq!(plan.items.len(), 4);
        assert!(
            plan.items
                .iter()
                .all(|item| item.destination.starts_with(&destination))
        );
        assert!(
            plan.items
                .iter()
                .any(|item| item.kind == StorageMigrationItemKind::SqliteStore)
        );
        assert!(
            plan.items
                .iter()
                .all(|item| item.source.file_name().unwrap() != "controller-history.json")
        );
        assert_eq!(
            plan.estimated_bytes,
            Some(plan.items.iter().map(|item| item.estimated_bytes).sum())
        );
        assert_eq!(plan.backup_location, Path::new(&source.state_root));
        assert!(!destination.exists());
    }

    #[test]
    fn preview_classifies_invalid_source_overlap_and_occupied_destination_without_writes() {
        let root = crate::TestStateDir::new().unwrap();
        let source = source_paths(root.path());
        let destination = fs::canonicalize(root.path()).unwrap().join("destination");
        let relative =
            assert_directory_tree_unchanged("relative destination preview", root.path(), || {
                plan(&source, Path::new("relative")).unwrap_err()
            });
        assert_eq!(relative.code, ErrorCode::StorageMigrationDestinationInvalid);
        let overlap = assert_directory_tree_unchanged("overlap preview", root.path(), || {
            plan(&source, &Path::new(&source.state_root).join("nested")).unwrap_err()
        });
        assert_eq!(overlap.code, ErrorCode::StorageMigrationPathsOverlap);
        write_private(&destination.join("state").join("unrelated"), b"keep");
        let occupied =
            assert_directory_tree_unchanged("occupied destination preview", root.path(), || {
                plan(&source, &destination).unwrap_err()
            });
        assert_eq!(
            occupied.code,
            ErrorCode::StorageMigrationDestinationNotEmpty
        );
        fs::remove_file(&source.sqlite_store).unwrap();
        let missing =
            assert_directory_tree_unchanged("missing source preview", root.path(), || {
                plan(&source, &root.path().join("unused")).unwrap_err()
            });
        assert_eq!(missing.code, ErrorCode::StorageMigrationSourceInvalid);
    }

    #[test]
    fn preview_accepts_empty_destinations_but_refuses_an_unfinished_maintenance_operation() {
        let root = crate::TestStateDir::new().unwrap();
        let source = source_paths(root.path());
        let destination = fs::canonicalize(root.path()).unwrap().join("destination");
        for child in ["state", "logs"] {
            drop(prepare_migration_directory(&destination.join(child)).unwrap());
        }
        let accepted =
            assert_directory_tree_unchanged("empty destination preview", root.path(), || {
                plan(&source, &destination).unwrap()
            });
        assert_eq!(accepted.items.len(), 1);
        write_private(
            &Path::new(&source.state_root).join(super::super::OFFLINE_STORAGE_MAINTENANCE_JOURNAL),
            b"unfinished maintenance",
        );
        let blocked =
            assert_directory_tree_unchanged("unfinished maintenance preview", root.path(), || {
                plan(&source, &destination).unwrap_err()
            });
        assert_eq!(blocked.code, ErrorCode::StorageMigrationSourceInvalid);
    }

    #[test]
    fn staging_preserves_source_identity_and_files_and_invalidates_only_destination_readiness() {
        let root = crate::TestStateDir::new().unwrap();
        let source = source_paths(root.path());
        let source_root = Path::new(&source.state_root);
        let store = super::super::Storage::open_without_restart_recovery(source_root).unwrap();
        let host_identity = store.host_identity().unwrap();
        let observed_at = time::OffsetDateTime::now_utc();
        let observed_nanos = i64::try_from(observed_at.unix_timestamp_nanos()).unwrap();
        let expires_nanos =
            i64::try_from((observed_at + time::Duration::minutes(5)).unix_timestamp_nanos())
                .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO native_readiness_results (
                result_id, host_identity_ref, desktop_binding_ref, desktop_session_ref,
                adapter_ref, status, codex_version, native_runtime_version,
                os_permission_state, os_permission_fingerprint, app_approval_state,
                app_approval_fingerprint, observed_at, expires_at
             ) VALUES ('migration-test', ?1, 'desktop', 'session', 'adapter', 'passed',
                       '1', '1', 'granted', 'permission', 'granted', 'approval', ?2, ?3)",
                rusqlite::params![host_identity.as_str(), observed_nanos, expires_nanos],
            )
            .unwrap();
        drop(store);
        let recording = Path::new(&source.recording_root)
            .join("session")
            .join("recording.mp4");
        let recording_bytes = vec![42_u8; 131_079];
        write_private(&recording, &recording_bytes);
        write_private(&source_root.join("controller-history.json"), b"controller");
        write_private(&source_root.join("codex-install-receipt.json"), b"receipt");
        let destination = fs::canonicalize(root.path()).unwrap().join("destination");
        let operation_id = "path-migration-test";
        let staged =
            crate::HostService::stage_storage_migration(&source, &destination, operation_id)
                .unwrap();
        assert_eq!(staged.host_identity, host_identity.as_str());
        assert_eq!(staged.invalidated_native_readiness, 1);
        // Starting the ledger can append an operator log before the copy.
        assert!(staged.copied_files >= 3);
        let destination_root = Path::new(&staged.plan.destination.state_root);
        assert_eq!(fs::read(&recording).unwrap(), recording_bytes);
        assert_eq!(
            fs::read(
                Path::new(&staged.plan.destination.recording_root)
                    .join("session")
                    .join("recording.mp4")
            )
            .unwrap(),
            recording_bytes,
        );
        assert_eq!(
            fs::read(source_root.join("controller-history.json")).unwrap(),
            b"controller"
        );
        assert!(!destination_root.join("controller-history.json").exists());
        for (state_root, readiness_count) in [(source_root, 1_i64), (destination_root, 0)] {
            let store = super::super::Storage::open_without_restart_recovery(state_root).unwrap();
            assert_eq!(store.host_identity().unwrap(), host_identity);
            assert_eq!(
                store
                    .connection
                    .query_row("SELECT COUNT(*) FROM native_readiness_results", [], |row| {
                        row.get::<_, i64>(0)
                    },)
                    .unwrap(),
                readiness_count
            );
            let (journal, _) =
                super::super::read_offline_storage_maintenance_journal(&store._state_directory)
                    .unwrap()
                    .unwrap();
            assert_eq!(journal.operation_id, operation_id);
            assert_eq!(journal.action_id, crate::STORAGE_MIGRATION_ACTION_ID);
            assert!(store.maintenance_lease_state().unwrap().is_some());
        }
        let destination_store =
            super::super::Storage::open_without_restart_recovery(destination_root).unwrap();
        destination_store
            .verify_storage_migration(operation_id, &staged.plan.destination)
            .unwrap();
        assert!(
            destination_store
                .verify_storage_migration("different-operation", &staged.plan.destination)
                .is_err()
        );
        fs::remove_file(destination_root.join(STAGING_RECEIPT)).unwrap();
        assert!(
            destination_store
                .verify_storage_migration(operation_id, &staged.plan.destination)
                .is_err()
        );
        assert!(
            destination_store
                .maintenance_lease_state()
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn rollback_recovers_a_committed_lease_when_the_external_journal_was_not_written() {
        let root = crate::TestStateDir::new().unwrap();
        let source = source_paths(root.path());
        let source_root = Path::new(&source.state_root);
        let service = crate::HostService::production_for_offline_storage(source_root);
        let operation_id = "migration-journal-write-failed";
        let now = time::OffsetDateTime::now_utc();
        let plan = crate::SetupRunPlan::new(
            operation_id,
            crate::SetupOperationKind::StorageMigration,
            None,
            now,
            vec![
                crate::SetupActionPlan::new(
                    crate::STORAGE_MIGRATION_ACTION_ID,
                    crate::STORAGE_MIGRATION_ACTION_LABEL,
                    true,
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let operation = service.begin_setup_run(&plan).unwrap();
        service
            .start_setup_action(&operation, crate::STORAGE_MIGRATION_ACTION_ID, now)
            .unwrap();
        drop(operation);
        drop(service);
        assert!(
            !source_root
                .join(super::super::OFFLINE_STORAGE_MAINTENANCE_JOURNAL)
                .exists()
        );
        crate::HostService::rollback_storage_migration(source_root, operation_id).unwrap();
        crate::HostService::rollback_storage_migration(source_root, operation_id).unwrap();
        let store = super::super::Storage::open_without_restart_recovery(source_root).unwrap();
        assert!(store.maintenance_lease_state().unwrap().is_none());
        assert_eq!(
            store
                .load_setup_run(operation_id)
                .unwrap()
                .unwrap()
                .status(),
            super::super::SetupRunStatus::Failed
        );
    }

    #[test]
    fn storage_migration_cleanup_resumes_after_deletion_without_losing_its_original_report() {
        let root = crate::TestStateDir::new().unwrap();
        let source = source_paths(root.path());
        let copied_log = Path::new(&source.operator_log_root).join("copied.log");
        write_private(&copied_log, b"copied operator log\n");
        let destination = fs::canonicalize(root.path()).unwrap().join("destination");
        let operation = "interrupted-source-cleanup";
        let staged =
            crate::HostService::stage_storage_migration(&source, &destination, operation).unwrap();
        let mut config = satelle_core::SatelleConfig::defaults()
            .hosts
            .remove(satelle_core::LOCAL_DEMO_HOST)
            .unwrap();
        config.daemon_state_dir = Some(staged.plan.destination.state_root.clone().into());
        config.daemon_log_dir = Some(staged.plan.destination.operator_log_root.clone().into());
        config.daemon_cache_dir = Some(staged.plan.destination.cache_root.clone().into());
        config.daemon_config_file = Some(staged.plan.destination.config_file.clone().into());
        let service = crate::HostService::production_for_host(&config);
        service.initialize_daemon().unwrap();
        assert_eq!(
            service.daemon_resolved_paths().unwrap(),
            staged.plan.destination
        );
        service
            .complete_storage_migration(operation, &staged.plan.destination)
            .unwrap();
        let token = crate::ApiBearerToken::generate().unwrap();
        service
            .register_api_token(&token, "cleanup-admin", crate::ApiScopes::ADMIN, None)
            .unwrap();
        let authority = crate::MutationAuthority::new(
            service.authenticate_api_token(&token).unwrap().unwrap(),
            "cleanup-request",
        )
        .unwrap();
        let canonical = serde_json::to_vec(&crate::StorageMigrationRequest::SourceCleanup {
            operation_id: operation,
        })
        .unwrap();
        let identity = service
            .runtime
            .authenticated_request_identity(
                authority.principal(),
                super::super::IdempotentOperation::StorageMigration,
                authority.idempotency_key(),
                &canonical,
                1,
            )
            .unwrap();
        let original = service.preview_storage_migration_source(operation).unwrap();
        assert!(original.files.contains(&copied_log));
        service
            .runtime
            .start_storage_migration_request(&identity, Some(&original))
            .unwrap();
        // Stop at the real crash boundary: source files are gone, but the
        // destination still holds an in-progress request with its original plan.
        service
            .runtime
            .cleanup_storage_migration_source(operation, &staged.plan.destination, Some(&original))
            .unwrap();
        assert!(!copied_log.exists());
        assert!(!Path::new(&source.sqlite_store).exists());
        drop(service);

        let restarted = crate::HostService::production_for_host(&config);
        restarted.initialize_daemon().unwrap();
        let completed = restarted
            .cleanup_storage_migration_source_idempotent(operation, &authority)
            .unwrap();
        assert_eq!(completed.files, original.files);
        assert_eq!(completed.removed_files, original.files);
        // Windows keeps the live destination SQLite files locked. The replay
        // must leave the preserved source tree alone; the equality check below
        // also proves that it returns the original durable cleanup report.
        let replay = assert_directory_tree_unchanged(
            "completed cleanup replay",
            Path::new(&source.state_root),
            || {
                restarted
                    .operation_capacity
                    .execute_exclusive(|| {
                        restarted.cleanup_storage_migration_source_idempotent(operation, &authority)
                    })
                    .unwrap()
            },
        );
        assert_eq!(replay, completed);
    }

    #[test]
    fn staging_never_overwrites_a_destination_created_after_preview() {
        let root = crate::TestStateDir::new().unwrap();
        let source = source_paths(root.path());
        let destination = fs::canonicalize(root.path()).unwrap().join("destination");
        let approved = plan(&source, &destination).unwrap();
        crate::HostService::start_offline_storage_maintenance(
            Path::new(&source.state_root),
            "path-migration-conflict",
            crate::STORAGE_MIGRATION_ACTION_ID,
            crate::STORAGE_MIGRATION_ACTION_LABEL,
        )
        .unwrap();
        let occupied = Path::new(&approved.destination.sqlite_store);
        write_private(occupied, b"new destination owner");
        let occupied = occupied.to_path_buf();
        assert!(stage(approved).is_err());
        assert_eq!(fs::read(occupied).unwrap(), b"new destination owner");
        let source_store =
            super::super::Storage::open_without_restart_recovery(Path::new(&source.state_root))
                .unwrap();
        assert!(source_store.maintenance_lease_state().unwrap().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn preview_rejects_source_and_destination_symlinks_and_read_only_destination_parents() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let root = crate::TestStateDir::new().unwrap();
        let source = source_paths(root.path());
        let destination = fs::canonicalize(root.path()).unwrap().join("destination");
        let external = root.path().join("external");
        open_or_create_owner_only_directory(&destination).unwrap();
        open_or_create_owner_only_directory(&external).unwrap();
        symlink(&external, destination.join("state")).unwrap();
        let error =
            assert_directory_tree_unchanged("destination symlink preview", root.path(), || {
                plan(&source, &destination).unwrap_err()
            });
        assert_eq!(error.code, ErrorCode::StorageMigrationDestinationInvalid);
        fs::remove_file(destination.join("state")).unwrap();
        open_or_create_owner_only_directory(Path::new(&source.operator_log_root)).unwrap();
        write_private(&external.join("secret"), b"private source");
        let link = Path::new(&source.operator_log_root).join("linked.log");
        symlink(external.join("secret"), &link).unwrap();
        let error = assert_directory_tree_unchanged("source symlink preview", root.path(), || {
            plan(&source, &destination).unwrap_err()
        });
        assert_eq!(error.code, ErrorCode::StorageMigrationSourceInvalid);
        fs::remove_file(link).unwrap();
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o500)).unwrap();
        let error = plan(&source, &destination).unwrap_err();
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(error.code, ErrorCode::StorageMigrationDestinationInvalid);
    }
}
