mod auth;
mod codec;
mod logs;
mod open;
mod operational;
#[path = "storage/operator-log.rs"]
mod operator_log;
#[path = "storage/provider-secret-journal.rs"]
mod provider_secret_journal;
mod retention;
mod setup_ledger;
mod sql;
pub(crate) mod stop;
#[cfg(test)]
mod tests;

// Admission needs an initial expiry, then the terminal commit resets it so the
// full replay window begins only after the operation has finished.
pub(crate) const IDEMPOTENCY_RETENTION: time::Duration = time::Duration::hours(24);
pub(crate) const DEFAULT_LEASE_STALE_AFTER: time::Duration = time::Duration::seconds(30);

pub(crate) use self::auth::{ApiTokenRegistration, SensitiveRequestDigest};
use self::codec::{
    format_time, idempotent_operation_token, load_required_session,
    load_session_at_operation_outcome, load_session_from_connection, parse_time,
    turn_idempotency_token, validated_private_reference,
};
pub(crate) use self::logs::LogPageStorageError;
use self::logs::canonical_log;
pub(crate) use self::logs::{SafeLogRecord, StoredLogRecord};
#[cfg(test)]
use self::open::DATABASE_FILE_NAME;
#[cfg(all(test, unix))]
use self::open::LOCK_FILE_NAME;
use self::open::sqlite_error;
#[cfg(test)]
pub(crate) use self::operator_log::{
    OperatorLogFailureKind, OperatorLogSink, OperatorLogWriteOutcome,
};
pub(crate) use self::operator_log::{OperatorLogMirror, OperatorLogPolicy};
pub(crate) use self::provider_secret_journal::{
    BeginProviderSecretProvisioning, PROVIDER_SECRET_CANDIDATE_HMAC_DOMAIN,
    PROVIDER_SECRET_PRIOR_HMAC_DOMAIN, ProviderSecretProvisioningJournal,
    ProviderSecretProvisioningPhase, ProviderSecretProvisioningPlan,
    ProviderSecretProvisioningPreflight, ProviderSecretProvisioningReplay,
    provider_secret_file_paths,
};
pub(crate) use self::retention::DEFAULT_SETUP_LEDGER_RETENTION;
pub(crate) use self::setup_ledger::{
    MaintenanceLeaseCapability, MaintenanceLeaseState, MaintenanceRecoverySubject,
};
pub use self::setup_ledger::{
    SetupActionPlan, SetupActionRecord, SetupActionSkipReason, SetupActionStatus,
    SetupOperationKind, SetupRepairAction, SetupRepairDecision, SetupRepairPlan,
    SetupRepairPostcondition, SetupRepairProbe, SetupRunPlan, SetupRunRecord, SetupRunStatus,
};

pub(crate) fn plan_migration_backup_cleanup(
    state_root: &std::path::Path,
) -> Result<Vec<String>, StorageError> {
    open::plan_migration_backup_cleanup(state_root)
}

pub(crate) fn validate_migration_backup_for_restore(
    state_root: &std::path::Path,
    backup_file_name: &str,
) -> Result<(), StorageError> {
    open::validate_migration_backup_for_restore(state_root, backup_file_name)
}

pub(crate) fn restore_migration_backup_offline(
    state_root: &std::path::Path,
    backup_file_name: &str,
) -> Result<(String, Vec<String>), StorageError> {
    open::restore_migration_backup_offline(state_root, backup_file_name).map(|activation| {
        (
            activation.failed_store_file_name,
            activation.failed_sidecar_file_names,
        )
    })
}

pub(crate) fn cleanup_migration_backups_offline(
    state_root: &std::path::Path,
) -> Result<Vec<String>, StorageError> {
    open::cleanup_migration_backups_offline(state_root)
}

pub(crate) fn begin_store_reset_offline(
    state_root: &std::path::Path,
) -> Result<open::OfflineStoreReset, StorageError> {
    open::begin_store_reset_offline(state_root)
}
use self::sql::{
    StoredIdempotency, ensure_control_lease_available, ensure_no_pending_stop,
    insert_control_lease, insert_idempotency, insert_initial_session, insert_safe_log,
    insert_terminal_json_idempotency, insert_turn, load_recovery_subject, matching_idempotency,
    merge_observed_reference, persist_lifecycle_mutation, require_operation,
    synchronize_control_lease, update_session_row, update_turn_idempotency,
    validate_initial_session,
};
pub(crate) use self::stop::{BeginStopOutcome, StopCommit, StopCommitOutcome};
use crate::{ApiBearerToken, ApiPrincipal, ReadinessCacheKey};
pub(crate) use crate::{LogEvent, LogSeverity, LogSource};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use satelle_core::session::{
    DesktopBindingRef, ExecutionPolicy, ExpectedRevisions, HostIdentityRef, Session,
    SessionStateRevision, TurnState, TurnTransition,
};
use satelle_core::{
    ProviderBindingAuthorization, ProviderBindingSource, PublicResolvedProviderBinding,
    ResolvedProviderBinding, SatelleError, SessionId, SshIdentityCommitRecord, TurnId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;
use std::io::Read;
use std::path::Path;
#[cfg(any(test, feature = "test-support"))]
use std::path::PathBuf;
use time::OffsetDateTime;

const SSH_IDENTITY_COMMIT_JOURNAL: &str = ".satelle-ssh-identity-commit";

fn sha256_path(path: &Path) -> Result<String, StorageError> {
    let mut file = std::fs::File::open(path).map_err(|source| {
        StorageError::with_source(StorageErrorKind::InvalidStoredState, source)
    })?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|source| {
            StorageError::with_source(StorageErrorKind::InvalidStoredState, source)
        })?;
        if count == 0 {
            return Ok(digest
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect());
        }
        digest.update(&buffer[..count]);
    }
}

fn executing_path_matches(recorded: &str, executing: &Path) -> bool {
    let Ok(recorded) = std::fs::canonicalize(recorded) else {
        return false;
    };
    let Ok(executing) = std::fs::canonicalize(executing) else {
        return false;
    };
    recorded == executing
}

const fn current_target_id() -> &'static str {
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        "linux-arm64-gnu"
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        "linux-x64-gnu"
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        "darwin-arm64"
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        "darwin-x64"
    }
    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    {
        "win32-arm64-msvc"
    }
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        "win32-x64-msvc"
    }
}

#[cfg(test)]
mod ssh_identity_commit_tests {
    use super::*;

    const OPERATION_ID: &str = "0195f6d5-18da-7a80-8000-000000000001";
    const OTHER_OPERATION_ID: &str = "0195f6d5-18da-7a80-8000-000000000002";
    const HOST_IDENTITY: &str = "host-0195f6d5-18da-7a80-8000-000000000003";
    const EXPECTED_MIGRATIONS: &[(i64, &str)] = &[
        (1, "fnv1a64:4510abfafef47a94"),
        (2, "fnv1a64:983538919ef94c60"),
        (3, "fnv1a64:3bd8f1edd993d68e"),
        (4, "fnv1a64:0acb1dd04635f1c3"),
        (5, "fnv1a64:0721b4f8eebf7e32"),
        (6, "fnv1a64:9e412e0d3a845cd5"),
        (7, "fnv1a64:e8bf3ca4c0aa3b74"),
        (8, "fnv1a64:6f25e8f86e1f6294"),
        (9, "fnv1a64:be23d907fb9ba35f"),
        (10, "fnv1a64:cd0986f490266e82"),
        (11, "fnv1a64:a861bcf791484f8b"),
        (12, "fnv1a64:a5672c42bd40d2a8"),
        (13, "fnv1a64:5db2b0aa00a5f745"),
    ];
    const EXPECTED_SCHEMA_ROW_COUNT: usize = 69;
    const EXPECTED_SCHEMA_SHA256: &str =
        "6d8e2eba05361b91d977feb785033618a1f1688094fe52adb0056b933c70f1be";

    fn identity() -> HostIdentityRef {
        HostIdentityRef::new(HOST_IDENTITY.to_string()).expect("valid Host Identity fixture")
    }

    fn prepared_state_root(state: &crate::TestStateDir) -> PathBuf {
        let state_root = state.path().join("state");
        drop(
            super::open::prepare_state_root(&state_root)
                .expect("prepare owner-only identity state directory"),
        );
        state_root
    }

    fn operation(state_root: &Path, create_artifact: bool) -> (SshIdentityCommitRecord, PathBuf) {
        let artifact_bytes = b"retained SSH Host artifact";
        let binary_sha256 = Sha256::digest(artifact_bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let artifact = state_root
            .parent()
            .expect("state root has a parent")
            .join("cache")
            .join("bootstrap")
            .join(OPERATION_ID)
            .join(&binary_sha256)
            .join(if cfg!(windows) {
                "satelle.exe"
            } else {
                "satelle"
            });
        if create_artifact {
            std::fs::create_dir_all(artifact.parent().expect("artifact has a parent"))
                .expect("create operation artifact directory");
            std::fs::write(&artifact, artifact_bytes).expect("write retained operation artifact");
        }
        let record = SshIdentityCommitRecord::new(
            OPERATION_ID,
            identity(),
            current_target_id(),
            state_root.to_string_lossy(),
            env!("CARGO_PKG_VERSION"),
            "11".repeat(32),
            binary_sha256,
            artifact.to_string_lossy(),
        )
        .expect("construct identity operation record");
        (record, artifact)
    }

    fn persist_record(state_root: &Path, record: &SshIdentityCommitRecord) {
        satelle_core::persist_new_owner_only_secret_file(
            &state_root.join(SSH_IDENTITY_COMMIT_JOURNAL),
            &record.encode(),
        )
        .expect("persist interrupted identity operation record");
    }

    fn update_length_prefixed(digest: &mut Sha256, value: &str) {
        digest.update(
            u32::try_from(value.len())
                .expect("schema field length fits u32")
                .to_be_bytes(),
        );
        digest.update(value.as_bytes());
    }

    fn assert_canonical_timestamp(field: &str, value: &str) {
        let parsed =
            parse_time(value).unwrap_or_else(|_| panic!("{field} parses as an RFC 3339 timestamp"));
        assert_eq!(
            format_time(parsed).expect("format parsed storage timestamp"),
            value,
            "{field} uses the canonical UTC storage representation"
        );
    }

    fn assert_committed_identity_contract(storage: &Storage) {
        let connection = &storage.connection;
        let (singleton, host_identity, identity_created_at): (i64, String, String) = connection
            .query_row(
                "SELECT singleton, host_identity_ref, created_at FROM daemon_identity",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("read committed Host Identity");
        assert_eq!(singleton, 1);
        assert_eq!(host_identity, HOST_IDENTITY);
        assert_canonical_timestamp("daemon_identity.created_at", &identity_created_at);

        let (key_version, key_material, key_created_at, retired_at): (
            i64,
            Vec<u8>,
            String,
            Option<String>,
        ) = connection
            .query_row(
                "SELECT key_version, key_material, created_at, retired_at \
                 FROM idempotency_hmac_keys",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("read committed idempotency HMAC key");
        assert_eq!(key_version, 1);
        assert_eq!(key_material.len(), 32);
        assert_canonical_timestamp("idempotency_hmac_keys.created_at", &key_created_at);
        assert!(retired_at.is_none());

        let (provider_singleton, provider_material, provider_created_at): (i64, Vec<u8>, String) =
            connection
                .query_row(
                    "SELECT singleton, key_material, created_at FROM provider_smoke_hmac_key",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .expect("read committed provider HMAC key");
        assert_eq!(provider_singleton, 1);
        assert_eq!(provider_material.len(), 32);
        assert_canonical_timestamp("provider_smoke_hmac_key.created_at", &provider_created_at);

        let migrations = connection
            .prepare(
                "SELECT version, checksum, applied_at \
                 FROM schema_migrations ORDER BY version",
            )
            .expect("prepare migration contract")
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .expect("read migration contract")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect migration contract");
        assert_eq!(migrations.len(), EXPECTED_MIGRATIONS.len());
        for ((version, checksum, applied_at), (expected_version, expected_checksum)) in
            migrations.iter().zip(EXPECTED_MIGRATIONS)
        {
            assert_eq!(version, expected_version);
            assert_eq!(checksum, expected_checksum);
            assert_canonical_timestamp("schema_migrations.applied_at", applied_at);
        }
        let user_version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("read schema user version");
        assert_eq!(user_version, 13);

        let schema = connection
            .prepare(
                "SELECT type, name, tbl_name, sql \
                 FROM sqlite_schema ORDER BY type, name, tbl_name",
            )
            .expect("prepare complete schema contract")
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?
                        .map(|sql| sql.split_whitespace().collect::<Vec<_>>().join(" ")),
                ))
            })
            .expect("read complete schema contract")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect complete schema contract");
        assert_eq!(schema.len(), EXPECTED_SCHEMA_ROW_COUNT);
        let mut digest = Sha256::new();
        digest.update(
            u32::try_from(schema.len())
                .expect("schema row count fits u32")
                .to_be_bytes(),
        );
        for (object_type, name, table_name, sql) in schema {
            update_length_prefixed(&mut digest, &object_type);
            update_length_prefixed(&mut digest, &name);
            update_length_prefixed(&mut digest, &table_name);
            match sql {
                None => digest.update([0]),
                Some(sql) => {
                    digest.update([1]);
                    update_length_prefixed(&mut digest, &sql);
                }
            }
        }
        assert_eq!(
            digest
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            EXPECTED_SCHEMA_SHA256,
            "the complete sqlite_schema matches the independent pinned snapshot"
        );
    }

    #[test]
    fn failed_fresh_upload_leaves_no_record_or_operation_artifact() {
        let state = crate::TestStateDir::new().expect("create state directory");
        let state_root = prepared_state_root(&state);
        let (record, artifact) = operation(&state_root, false);

        assert!(Storage::commit_fresh_ssh_host_identity(&state_root, &record, &artifact).is_err());
        assert!(!artifact.exists());
        assert!(!state_root.join(SSH_IDENTITY_COMMIT_JOURNAL).exists());
    }

    #[test]
    fn fresh_host_commit_creates_record_only_with_present_exact_artifact_and_retains_it() {
        let state = crate::TestStateDir::new().expect("create state directory");
        let state_root = prepared_state_root(&state);
        let (record, artifact) = operation(&state_root, true);
        let journal = state_root.join(SSH_IDENTITY_COMMIT_JOURNAL);
        assert!(!journal.exists());

        let committed = Storage::commit_fresh_ssh_host_identity(&state_root, &record, &artifact)
            .expect("commit fresh identity from exact artifact");

        assert_eq!(committed, identity());
        assert_eq!(
            std::fs::read_to_string(&journal).expect("read record"),
            record.encode()
        );
        assert!(artifact.exists());
        let storage =
            Storage::open_without_restart_recovery(&state_root).expect("reopen committed storage");
        assert_eq!(
            storage.host_identity().expect("read Host Identity"),
            identity()
        );
        drop(
            storage
                .provider_smoke_hmac_key()
                .expect("read committed provider HMAC key"),
        );
        assert_committed_identity_contract(&storage);
    }

    #[test]
    fn pending_identity_commit_requires_exact_record_and_artifact_and_retains_record_until_finalization()
     {
        let state = crate::TestStateDir::new().expect("create state directory");
        let state_root = prepared_state_root(&state);
        let (record, artifact) = operation(&state_root, true);
        persist_record(&state_root, &record);
        let mismatched = SshIdentityCommitRecord::new(
            OPERATION_ID,
            HostIdentityRef::new("host-0195f6d5-18da-7a80-8000-000000000004".to_string())
                .expect("valid different identity"),
            record.target_id(),
            record.canonical_state_root(),
            record.artifact_version(),
            record.archive_sha256(),
            record.binary_sha256(),
            record.exact_remote_path(),
        )
        .expect("construct mismatched record");

        assert!(
            Storage::commit_fresh_ssh_host_identity(&state_root, &mismatched, &artifact).is_err()
        );
        std::fs::remove_file(&artifact).expect("remove exact artifact");
        assert!(Storage::commit_fresh_ssh_host_identity(&state_root, &record, &artifact).is_err());
        std::fs::write(&artifact, b"retained SSH Host artifact").expect("restore exact artifact");
        Storage::commit_fresh_ssh_host_identity(&state_root, &record, &artifact)
            .expect("resume exact pending operation");
        assert!(state_root.join(SSH_IDENTITY_COMMIT_JOURNAL).exists());
        assert!(artifact.exists());
    }

    #[test]
    fn post_binding_record_delete_failure_preserves_artifact() {
        let state = crate::TestStateDir::new().expect("create state directory");
        let state_root = prepared_state_root(&state);
        let (record, artifact) = operation(&state_root, true);
        Storage::commit_fresh_ssh_host_identity(&state_root, &record, &artifact)
            .expect("commit fresh identity");
        let mut storage =
            Storage::open_without_restart_recovery(&state_root).expect("open committed storage");

        assert!(
            storage
                .finalize_fresh_ssh_identity_commit(OTHER_OPERATION_ID)
                .is_err()
        );
        assert!(state_root.join(SSH_IDENTITY_COMMIT_JOURNAL).exists());
        assert!(artifact.exists());
    }

    #[test]
    fn post_binding_artifact_delete_failure_leaves_no_pending_record() {
        let state = crate::TestStateDir::new().expect("create state directory");
        let state_root = prepared_state_root(&state);
        let (record, artifact) = operation(&state_root, true);
        Storage::commit_fresh_ssh_host_identity(&state_root, &record, &artifact)
            .expect("commit fresh identity");
        let mut storage =
            Storage::open_without_restart_recovery(&state_root).expect("open committed storage");

        assert!(
            storage
                .finalize_fresh_ssh_identity_commit(OPERATION_ID)
                .expect("delete durable record")
        );
        assert!(!state_root.join(SSH_IDENTITY_COMMIT_JOURNAL).exists());
        assert!(artifact.exists());
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "status", content = "result", rename_all = "snake_case")]
pub(crate) enum ProviderBindingAuthorizationReplay {
    Completed(PublicResolvedProviderBinding),
    Failed(SatelleError),
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "status", content = "result", rename_all = "snake_case")]
pub(crate) enum ProviderBindingDeletionReplay {
    Completed(bool),
    Failed(SatelleError),
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "status", content = "result", rename_all = "snake_case")]
pub(crate) enum NativeReadinessInvalidationReplay {
    Completed(u64),
    Failed(SatelleError),
}

/// Owns a temporary state directory whose path and permissions satisfy the
/// same platform security rules as production state.
#[cfg(any(test, feature = "test-support"))]
pub struct TestStateDir {
    _temporary_parent: tempfile::TempDir,
    path: PathBuf,
}

#[cfg(any(test, feature = "test-support"))]
impl TestStateDir {
    pub fn new() -> std::io::Result<Self> {
        #[cfg(unix)]
        let temporary_parent = {
            use std::os::unix::fs::PermissionsExt;

            let temporary_parent = tempfile::Builder::new()
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir()?;
            std::fs::set_permissions(
                temporary_parent.path(),
                std::fs::Permissions::from_mode(0o700),
            )?;
            temporary_parent
        };
        #[cfg(not(unix))]
        let temporary_parent = tempfile::tempdir()?;
        #[cfg(windows)]
        let path = temporary_parent.path().join("state");
        #[cfg(target_os = "macos")]
        let path = std::fs::canonicalize(temporary_parent.path())?;
        #[cfg(not(any(target_os = "macos", windows)))]
        let path = temporary_parent.path().to_path_buf();
        #[cfg(windows)]
        drop(open::prepare_state_root(&path).map_err(std::io::Error::other)?);
        Ok(Self {
            _temporary_parent: temporary_parent,
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StorageErrorKind {
    StateDirectoryUnavailable,
    UnsafeStatePath,
    LockUnavailable,
    StoreInUse,
    OpenFailed,
    Busy,
    MigrationFailed,
    MigrationIntegrity,
    IntegrityCheckFailed,
    InvalidInput,
    InvalidStoredState,
    SessionNotFound,
    SessionNotSteerable,
    LeaseConflict,
    StateConflict,
    IdempotencyConflict,
    AdmissionCancelled,
    PrivateReferenceConflict,
    OperationFailed,
}

impl fmt::Display for StorageErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::StateDirectoryUnavailable => "the Satelle state directory is unavailable",
            Self::UnsafeStatePath => "the Satelle state path is unsafe",
            Self::LockUnavailable => "the Satelle store ownership lock is unavailable",
            Self::StoreInUse => "the Satelle store is already in use",
            Self::OpenFailed => "the Satelle SQLite store could not be opened",
            Self::Busy => "the Satelle SQLite store is busy",
            Self::MigrationFailed => "the Satelle SQLite migration failed",
            Self::MigrationIntegrity => "the Satelle SQLite migration history is inconsistent",
            Self::IntegrityCheckFailed => "the Satelle SQLite integrity check failed",
            Self::InvalidInput => "the storage operation input is invalid",
            Self::InvalidStoredState => "the stored Satelle lifecycle state is invalid",
            Self::SessionNotFound => "the requested Satelle Session was not found",
            Self::SessionNotSteerable => {
                "the Session has no retained upstream thread available for steering"
            }
            Self::LeaseConflict => "the selected Satelle Control Lease is already owned",
            Self::StateConflict => "the stored Satelle lifecycle state changed concurrently",
            Self::IdempotencyConflict => "the idempotency key was reused for a different request",
            Self::AdmissionCancelled => "the admission was cancelled before it committed",
            Self::PrivateReferenceConflict => {
                "an observed private runtime reference conflicts with stored state"
            }
            Self::OperationFailed => "the Satelle storage operation failed",
        })
    }
}

pub(crate) struct StorageError {
    kind: StorageErrorKind,
    conflicting_session_id: Option<SessionId>,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl fmt::Debug for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StorageError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl StorageError {
    fn new(kind: StorageErrorKind) -> Self {
        Self {
            kind,
            conflicting_session_id: None,
            source: None,
        }
    }

    pub(crate) fn kind(&self) -> StorageErrorKind {
        self.kind
    }

    pub(crate) fn state_conflict() -> Self {
        Self::new(StorageErrorKind::StateConflict)
    }

    #[cfg(test)]
    pub(crate) fn for_test(kind: StorageErrorKind) -> Self {
        Self::new(kind)
    }

    pub(crate) fn conflicting_session_id(&self) -> Option<&SessionId> {
        self.conflicting_session_id.as_ref()
    }

    fn lease_conflict(session_id: SessionId) -> Self {
        Self {
            kind: StorageErrorKind::LeaseConflict,
            conflicting_session_id: Some(session_id),
            source: None,
        }
    }

    fn with_source(kind: StorageErrorKind, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            kind,
            conflicting_session_id: None,
            source: Some(Box::new(source)),
        }
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(formatter)
    }
}

impl Error for StorageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_deref().map(|source| source as _)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PrivateRequestToken(String);

impl PrivateRequestToken {
    pub(crate) fn new(value: impl Into<String>) -> Result<Self, StorageError> {
        validated_private_reference(value.into()).map(Self)
    }
}

impl fmt::Debug for PrivateRequestToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateRequestToken([redacted])")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PrivateUpstreamRef(String);

impl PrivateUpstreamRef {
    pub(crate) fn new(value: impl Into<String>) -> Result<Self, StorageError> {
        validated_private_reference(value.into()).map(Self)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PrivateUpstreamRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateUpstreamRef([redacted])")
    }
}

#[derive(Clone)]
pub(crate) struct LeaseOwner {
    operation_id: String,
    process_id: u32,
    process_start_ref: String,
    boot_identity_ref: String,
    acquired_at: OffsetDateTime,
}

impl LeaseOwner {
    pub(crate) fn new(
        operation_id: impl Into<String>,
        process_id: u32,
        process_start_ref: impl Into<String>,
        boot_identity_ref: impl Into<String>,
        acquired_at: OffsetDateTime,
    ) -> Result<Self, StorageError> {
        if process_id == 0 {
            return Err(StorageError::new(StorageErrorKind::InvalidInput));
        }
        Ok(Self {
            operation_id: validated_private_reference(operation_id.into())?,
            process_id,
            process_start_ref: validated_private_reference(process_start_ref.into())?,
            boot_identity_ref: validated_private_reference(boot_identity_ref.into())?,
            acquired_at,
        })
    }

    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LeaseFreshness {
    Fresh,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "later API packets consume these frozen mutation classes"
    )
)]
pub(crate) enum IdempotentOperation {
    Run,
    Steer,
    Stop,
    Setup,
    Repair,
    HostUpdate,
    StorageMigration,
    DestructiveMaintenance,
    ProviderSecretProvisioning,
    ProviderDescriptorValidation,
    ProviderBindingAuthorization,
    ProviderBindingDeletion,
    SetupVerification,
    NativeReadinessInvalidation,
}

#[derive(Clone)]
pub(crate) struct IdempotencyInput {
    principal_ref: String,
    operation: IdempotentOperation,
    key: String,
    operation_id: String,
    request_digest: String,
    digest_schema_version: u16,
    hmac_key_version: u16,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

impl IdempotencyInput {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        principal_ref: impl Into<String>,
        operation: IdempotentOperation,
        key: impl Into<String>,
        operation_id: impl Into<String>,
        request_digest: impl Into<String>,
        digest_schema_version: u16,
        hmac_key_version: u16,
        created_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<Self, StorageError> {
        let request_digest = request_digest.into();
        if request_digest.len() != 64
            || !request_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || digest_schema_version == 0
            || hmac_key_version == 0
            || expires_at <= created_at
        {
            return Err(StorageError::new(StorageErrorKind::InvalidInput));
        }
        Ok(Self {
            principal_ref: validated_private_reference(principal_ref.into())?,
            operation,
            key: validated_private_reference(key.into())?,
            operation_id: validated_private_reference(operation_id.into())?,
            request_digest,
            digest_schema_version,
            hmac_key_version,
            created_at,
            expires_at,
        })
    }
}

#[derive(Clone)]
pub(crate) struct AdmissionContext {
    lease_owner: LeaseOwner,
    idempotency: IdempotencyInput,
    request_token: PrivateRequestToken,
}

impl AdmissionContext {
    pub(crate) fn new(
        lease_owner: LeaseOwner,
        idempotency: IdempotencyInput,
        request_token: PrivateRequestToken,
    ) -> Self {
        Self {
            lease_owner,
            idempotency,
            request_token,
        }
    }

    pub(crate) fn lease_owner(&self) -> &LeaseOwner {
        &self.lease_owner
    }

    #[cfg(test)]
    pub(crate) fn idempotency(&self) -> &IdempotencyInput {
        &self.idempotency
    }
}

pub(crate) enum ObservedUpstreamRef {
    Thread(PrivateUpstreamRef),
    Turn(PrivateUpstreamRef),
    Goal(PrivateUpstreamRef),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadinessProbeTerminal {
    Failed,
    TimedOut,
    OutcomeUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadinessProbeKind {
    Native,
    Provider,
}

impl ReadinessProbeKind {
    pub(crate) const fn owner_kind(self) -> &'static str {
        match self {
            Self::Native => "native_probe",
            Self::Provider => "provider_probe",
        }
    }

    pub(crate) const fn reference_column(self) -> &'static str {
        match self {
            Self::Native => "native_probe_ref",
            Self::Provider => "provider_probe_ref",
        }
    }
}

impl ReadinessProbeTerminal {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Failed => "failed",
            Self::TimedOut => "timed_out",
            Self::OutcomeUnknown => "outcome_unknown",
        }
    }
}

#[derive(Clone)]
pub(crate) struct ProbeRecoverySubject {
    host_identity: HostIdentityRef,
    desktop_binding: DesktopBindingRef,
    probe_kind: ReadinessProbeKind,
    probe_ref: PrivateUpstreamRef,
    upstream_thread_ref: Option<PrivateUpstreamRef>,
    upstream_turn_ref: Option<PrivateUpstreamRef>,
    recovery_pending: bool,
}

impl ProbeRecoverySubject {
    pub(crate) const fn probe_kind(&self) -> ReadinessProbeKind {
        self.probe_kind
    }

    pub(crate) fn probe_ref(&self) -> &str {
        self.probe_ref.as_str()
    }

    pub(crate) fn upstream_thread_ref(&self) -> Option<&str> {
        self.upstream_thread_ref
            .as_ref()
            .map(PrivateUpstreamRef::as_str)
    }

    pub(crate) fn upstream_turn_ref(&self) -> Option<&str> {
        self.upstream_turn_ref
            .as_ref()
            .map(PrivateUpstreamRef::as_str)
    }

    pub(crate) const fn is_recovery_pending(&self) -> bool {
        self.recovery_pending
    }
}

impl fmt::Debug for ProbeRecoverySubject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProbeRecoverySubject")
            .field("host_identity", &self.host_identity)
            .field("desktop_binding", &self.desktop_binding)
            .finish_non_exhaustive()
    }
}

impl ObservedUpstreamRef {
    pub(crate) fn thread(value: impl Into<String>) -> Result<Self, StorageError> {
        Ok(Self::Thread(PrivateUpstreamRef::new(value)?))
    }

    pub(crate) fn turn(value: impl Into<String>) -> Result<Self, StorageError> {
        Ok(Self::Turn(PrivateUpstreamRef::new(value)?))
    }

    pub(crate) fn goal(value: impl Into<String>) -> Result<Self, StorageError> {
        Ok(Self::Goal(PrivateUpstreamRef::new(value)?))
    }
}

#[derive(Clone)]
pub(crate) struct RecoverySubject {
    session_id: SessionId,
    turn_id: TurnId,
    turn_state: TurnState,
    expected_revisions: ExpectedRevisions,
    host_identity: HostIdentityRef,
    request_token: PrivateRequestToken,
    upstream_thread_ref: Option<PrivateUpstreamRef>,
    upstream_turn_ref: Option<PrivateUpstreamRef>,
    upstream_goal_ref: Option<PrivateUpstreamRef>,
}

impl RecoverySubject {
    pub(crate) fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub(crate) fn turn_id(&self) -> &TurnId {
        &self.turn_id
    }

    pub(crate) fn turn_state(&self) -> TurnState {
        self.turn_state
    }

    pub(crate) fn expected_revisions(&self) -> ExpectedRevisions {
        self.expected_revisions
    }

    pub(crate) fn host_identity(&self) -> &HostIdentityRef {
        &self.host_identity
    }

    pub(crate) fn request_token(&self) -> &PrivateRequestToken {
        &self.request_token
    }

    pub(crate) fn upstream_thread_ref(&self) -> Option<&PrivateUpstreamRef> {
        self.upstream_thread_ref.as_ref()
    }

    pub(crate) fn upstream_turn_ref(&self) -> Option<&PrivateUpstreamRef> {
        self.upstream_turn_ref.as_ref()
    }

    pub(crate) fn upstream_goal_ref(&self) -> Option<&PrivateUpstreamRef> {
        self.upstream_goal_ref.as_ref()
    }
}

impl fmt::Debug for RecoverySubject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoverySubject")
            .field("session_id", &self.session_id)
            .field("turn_id", &self.turn_id)
            .field("turn_state", &self.turn_state)
            .field("expected_revisions", &self.expected_revisions)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub(crate) enum AdmissionOutcome {
    Execute {
        session: Session,
        recovery_subject: RecoverySubject,
    },
    InProgress(Session),
    Complete(Session),
}

pub(crate) enum DurableAdmissionState {
    Missing,
    Admitted(Box<AdmissionReplay>),
    Cancelled,
    RecoveryPending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DurableCancellationOutcome {
    Cancelled,
    RecoveryPending,
}

impl DurableCancellationOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::RecoveryPending => "recovery_pending",
        }
    }

    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "cancelled" => Ok(Self::Cancelled),
            "recovery_pending" => Ok(Self::RecoveryPending),
            _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
        }
    }
}

/// A durable idempotency replay and the exact handles stored with that record.
///
/// The handles remain explicit because a terminal Session snapshot may later
/// contain additional Turns. Callers must not recover admission identity from
/// Turn history position.
pub(crate) struct AdmissionReplay {
    outcome: AdmissionOutcome,
    session_id: SessionId,
    turn_id: TurnId,
}

impl AdmissionReplay {
    #[cfg(test)]
    pub(crate) fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[cfg(test)]
    pub(crate) fn turn_id(&self) -> &TurnId {
        &self.turn_id
    }

    pub(crate) fn into_parts(self) -> (AdmissionOutcome, SessionId, TurnId) {
        (self.outcome, self.session_id, self.turn_id)
    }

    fn into_outcome(self) -> AdmissionOutcome {
        self.outcome
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StorageSnapshot {
    session_count: usize,
    active_turn_count: usize,
    recovery_pending_turn_count: usize,
}

impl StorageSnapshot {
    pub(crate) const fn session_count(self) -> usize {
        self.session_count
    }

    pub(crate) const fn active_turn_count(self) -> usize {
        self.active_turn_count
    }

    pub(crate) const fn recovery_pending_turn_count(self) -> usize {
        self.recovery_pending_turn_count
    }
}

fn replay_admission(
    connection: &Connection,
    record: &StoredIdempotency,
    expected_session_id: Option<&SessionId>,
) -> Result<AdmissionReplay, StorageError> {
    let session_id = record
        .session_id
        .as_deref()
        .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))
        .and_then(|value| {
            SessionId::parse(value)
                .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
        })?;
    let turn_id = record
        .turn_id
        .as_deref()
        .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))
        .and_then(|value| {
            TurnId::parse(value)
                .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
        })?;
    if expected_session_id.is_some_and(|expected| expected != &session_id) {
        return Err(StorageError::new(StorageErrorKind::IdempotencyConflict));
    }

    let outcome = match record.status.as_str() {
        "in_progress" => {
            let session = load_required_session(connection, &session_id)?;
            validate_replayed_turn_outcome(record, &session, &turn_id)?;
            AdmissionOutcome::InProgress(session)
        }
        "terminal" => {
            let session_revision = record
                .result_session_state_revision
                .as_deref()
                .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
            let session_updated_at = record
                .result_session_updated_at
                .as_deref()
                .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
            let session = load_session_at_operation_outcome(
                connection,
                &session_id,
                &turn_id,
                session_revision,
                session_updated_at,
            )?;
            validate_replayed_turn_outcome(record, &session, &turn_id)?;
            AdmissionOutcome::Complete(session)
        }
        _ => return Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
    };
    Ok(AdmissionReplay {
        outcome,
        session_id,
        turn_id,
    })
}

fn validate_replayed_turn_outcome(
    record: &StoredIdempotency,
    session: &Session,
    turn_id: &TurnId,
) -> Result<(), StorageError> {
    let turn = session
        .turn(turn_id)
        .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
    if record.durable_outcome != turn_idempotency_token(turn.state()) {
        return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
    }
    Ok(())
}

fn matching_admission_cancellation(
    connection: &Connection,
    input: &IdempotencyInput,
    observed_at: OffsetDateTime,
) -> Result<Option<DurableCancellationOutcome>, StorageError> {
    let record = connection
        .query_row(
            "SELECT request_digest, digest_schema_version, hmac_key_version, outcome, expires_at
             FROM admission_cancellations
             WHERE principal_ref = ?1 AND operation = ?2 AND idempotency_key = ?3",
            rusqlite::params![
                input.principal_ref.as_str(),
                idempotent_operation_token(input.operation),
                input.key.as_str(),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    let Some((digest, digest_schema_version, hmac_key_version, outcome, expires_at)) = record
    else {
        return Ok(None);
    };
    let outcome = DurableCancellationOutcome::parse(&outcome)?;
    if outcome == DurableCancellationOutcome::Cancelled && parse_time(&expires_at)? <= observed_at {
        return Ok(None);
    }
    if digest != input.request_digest
        || digest_schema_version != i64::from(input.digest_schema_version)
        || hmac_key_version != i64::from(input.hmac_key_version)
    {
        return Err(StorageError::new(StorageErrorKind::IdempotencyConflict));
    }
    // A recovery-pending tombstone records unresolved upstream ownership, not
    // a completed cancellation guarantee. It cannot expire into Missing:
    // callers must reconcile ownership and use a new idempotency key rather
    // than treating elapsed retention time as proof that nothing dispatched.
    Ok(Some(outcome))
}

pub(crate) struct Storage {
    // Field order is a drop invariant: SQLite must close every delegated file
    // before the ownership lock and pinned state directory are released.
    connection: Connection,
    _ownership_lock: open::OwnershipLock,
    _state_directory: open::StateDirectory,
}

impl Storage {
    #[cfg(test)]
    pub(crate) fn open(state_root: &Path) -> Result<(Self, Vec<RecoverySubject>), StorageError> {
        let mut storage = Self::open_without_restart_recovery(state_root)?;
        let recovery = storage.initialize_restart_recovery()?;
        Ok((storage, recovery))
    }

    pub(crate) fn open_without_restart_recovery(state_root: &Path) -> Result<Self, StorageError> {
        let (connection, ownership_lock, state_directory) = open::open_parts(state_root)?;
        auth::validate_sensitive_state(&connection)?;
        Ok(Self {
            connection,
            _ownership_lock: ownership_lock,
            _state_directory: state_directory,
        })
    }

    pub(crate) fn has_existing_state(state_root: &Path) -> Result<bool, StorageError> {
        open::prepare_state_root(state_root)?.has_existing_store_state()
    }

    pub(crate) fn fresh_ssh_identity_commit_pending(
        state_root: &Path,
    ) -> Result<bool, StorageError> {
        match std::fs::symlink_metadata(state_root.join(SSH_IDENTITY_COMMIT_JOURNAL)) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(StorageError::with_source(
                StorageErrorKind::StateDirectoryUnavailable,
                error,
            )),
        }
    }

    pub(crate) fn commit_fresh_ssh_host_identity(
        state_root: &Path,
        record: &SshIdentityCommitRecord,
        executing_artifact: &Path,
    ) -> Result<HostIdentityRef, StorageError> {
        let encoded = record.encode();
        if record.target_id() != current_target_id()
            || Path::new(record.canonical_state_root()) != state_root
            || !executing_path_matches(record.exact_remote_path(), executing_artifact)
            || record.artifact_version() != env!("CARGO_PKG_VERSION")
            || sha256_path(executing_artifact)? != record.binary_sha256()
        {
            return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
        }

        let (connection, ownership_lock, state_directory) =
            open::open_parts_with_locked_preflight(state_root, |claimed_directory| {
                match claimed_directory
                    .read_private_leaf_bounded(SSH_IDENTITY_COMMIT_JOURNAL, 4_096)?
                {
                    Some(observed) if observed == encoded.as_bytes() => {}
                    Some(_) => {
                        return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
                    }
                    None => {
                        if claimed_directory.has_existing_store_state()? {
                            return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
                        }
                        claimed_directory.create_private_leaf_durable(
                            SSH_IDENTITY_COMMIT_JOURNAL,
                            encoded.as_bytes(),
                        )?;
                    }
                }
                Ok(())
            })?;
        let mut storage = Self {
            connection,
            _ownership_lock: ownership_lock,
            _state_directory: state_directory,
        };
        auth::validate_sensitive_state(&storage.connection)?;
        let current = storage.host_identity()?;
        if current != *record.candidate_host_identity() {
            auth::commit_fresh_host_identity(
                &mut storage.connection,
                record.candidate_host_identity(),
            )?;
        }
        let committed = storage.host_identity()?;
        if committed != *record.candidate_host_identity() {
            return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
        }
        drop(storage);
        Ok(committed)
    }

    pub(crate) fn finalize_fresh_ssh_identity_commit(
        &mut self,
        operation_id: &str,
    ) -> Result<bool, StorageError> {
        let Some(encoded) = self
            ._state_directory
            .read_private_leaf_bounded(SSH_IDENTITY_COMMIT_JOURNAL, 4_096)?
        else {
            return Ok(false);
        };
        let encoded = std::str::from_utf8(&encoded)
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
        let record = SshIdentityCommitRecord::parse(encoded)
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
        if record.operation_id() != operation_id {
            return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
        }
        self._state_directory
            .delete_private_leaf_durable(SSH_IDENTITY_COMMIT_JOURNAL)
    }

    pub(crate) fn initialize_restart_recovery(
        &mut self,
    ) -> Result<Vec<RecoverySubject>, StorageError> {
        let detected_at = OffsetDateTime::now_utc();
        self.mark_interrupted_provider_descriptor_validations_failed(detected_at)?;
        self.mark_interrupted_setup_verifications_failed(detected_at)?;
        self.mark_interrupted_setup_actions_outcome_unknown(detected_at)?;
        self.mark_restart_recovery_pending()
    }

    fn mark_interrupted_provider_descriptor_validations_failed(
        &mut self,
        detected_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let replay = serde_json::to_string(&serde_json::json!({
            "status": "failed",
            "result": satelle_core::SatelleError::state_conflict(),
        }))
        .map_err(|source| StorageError::with_source(StorageErrorKind::OperationFailed, source))?;
        self.connection
            .execute(
                "UPDATE idempotency_records
                 SET status = 'terminal',
                     durable_outcome = 'v2.provider_descriptor_validation.failed',
                     result_json = ?1,
                     completed_at = ?2
                 WHERE operation = 'provider_descriptor_validation'
                   AND status = 'in_progress'
                   AND durable_outcome = 'v2.provider_descriptor_validation.pending'",
                rusqlite::params![replay, format_time(detected_at)?],
            )
            .map(|_| ())
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
    }

    fn mark_interrupted_setup_verifications_failed(
        &mut self,
        detected_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let replay = serde_json::to_string(&serde_json::json!({
            "status": "failed",
            "result": satelle_core::SatelleError::state_conflict(),
        }))
        .map_err(|source| StorageError::with_source(StorageErrorKind::OperationFailed, source))?;
        self.connection
            .execute(
                "UPDATE idempotency_records
                 SET status = 'terminal',
                     durable_outcome = 'v1.setup_verification.failed',
                     result_json = ?1,
                     completed_at = ?2
                 WHERE operation = 'setup_verification'
                   AND status = 'in_progress'
                   AND durable_outcome = 'v1.setup_verification.pending'",
                rusqlite::params![replay, format_time(detected_at)?],
            )
            .map(|_| ())
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
    }

    pub(crate) fn host_identity(&self) -> Result<HostIdentityRef, StorageError> {
        auth::host_identity(&self.connection)
    }

    pub(crate) fn digest_idempotency_payload(
        &self,
        canonical_payload: &[u8],
    ) -> Result<SensitiveRequestDigest, StorageError> {
        auth::digest_idempotency_payload(&self.connection, canonical_payload, None)
    }

    pub(crate) fn digest_idempotency_payload_with_key(
        &self,
        canonical_payload: &[u8],
        key_version: u16,
    ) -> Result<SensitiveRequestDigest, StorageError> {
        auth::digest_idempotency_payload(&self.connection, canonical_payload, Some(key_version))
    }

    pub(crate) fn rotate_idempotency_hmac_key(
        &mut self,
        at: OffsetDateTime,
    ) -> Result<u16, StorageError> {
        auth::rotate_idempotency_hmac_key(&mut self.connection, at)
    }

    pub(crate) fn provider_smoke_hmac_key(
        &self,
    ) -> Result<crate::provider_auth::ProviderSmokeHmacKey, StorageError> {
        auth::provider_smoke_hmac_key(&self.connection)
    }

    pub(crate) fn register_api_token(
        &mut self,
        registration: ApiTokenRegistration,
    ) -> Result<(), StorageError> {
        auth::register_api_token(&mut self.connection, registration)
    }

    pub(crate) fn authenticate_api_token(
        &self,
        token: &ApiBearerToken,
        at: OffsetDateTime,
    ) -> Result<Option<ApiPrincipal>, StorageError> {
        auth::authenticate_api_token(&self.connection, token.token_id(), &token.verifier(), at)
    }

    pub(crate) fn authenticate_pending_setup_api_token(
        &self,
        token: &ApiBearerToken,
        at: OffsetDateTime,
    ) -> Result<Option<ApiPrincipal>, StorageError> {
        auth::authenticate_pending_setup_api_token(
            &self.connection,
            token.token_id(),
            &token.verifier(),
            at,
        )
    }

    pub(crate) fn api_principal_is_active(
        &self,
        principal: &ApiPrincipal,
        at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        auth::api_principal_is_active(&self.connection, principal, at)
    }

    pub(crate) fn rotate_api_token(
        &mut self,
        replacement: &ApiBearerToken,
        expected_credential_revision: u64,
        at: OffsetDateTime,
    ) -> Result<ApiPrincipal, StorageError> {
        auth::rotate_api_token(
            &mut self.connection,
            replacement,
            expected_credential_revision,
            at,
        )
    }

    pub(crate) fn activate_api_token(
        &mut self,
        token_id: &str,
        at: OffsetDateTime,
    ) -> Result<ApiPrincipal, StorageError> {
        auth::activate_api_token(&mut self.connection, token_id, at)
    }

    pub(crate) fn abort_setup_api_token(
        &mut self,
        token_id: &str,
        at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        auth::abort_setup_api_token(&mut self.connection, token_id, at)
    }

    pub(crate) fn revoke_api_token(
        &mut self,
        token_id: &str,
        at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        auth::revoke_api_token(&mut self.connection, token_id, at)
    }

    pub(crate) fn replay_admission_if_present(
        &self,
        operation: IdempotentOperation,
        idempotency: &IdempotencyInput,
        expected_session_id: Option<&SessionId>,
    ) -> Result<Option<AdmissionReplay>, StorageError> {
        require_operation(idempotency, operation)?;
        matching_idempotency(&self.connection, idempotency)?
            .map(|record| replay_admission(&self.connection, &record, expected_session_id))
            .transpose()
    }

    pub(crate) fn resolve_admission_operation(
        &self,
        operation: IdempotentOperation,
        idempotency: &IdempotencyInput,
        expected_session_id: Option<&SessionId>,
        observed_at: OffsetDateTime,
    ) -> Result<DurableAdmissionState, StorageError> {
        require_operation(idempotency, operation)?;
        if let Some(record) = matching_idempotency(&self.connection, idempotency)? {
            return replay_admission(&self.connection, &record, expected_session_id)
                .map(Box::new)
                .map(DurableAdmissionState::Admitted);
        }
        matching_admission_cancellation(&self.connection, idempotency, observed_at).map(|outcome| {
            match outcome {
                Some(DurableCancellationOutcome::Cancelled) => DurableAdmissionState::Cancelled,
                Some(DurableCancellationOutcome::RecoveryPending) => {
                    DurableAdmissionState::RecoveryPending
                }
                None => DurableAdmissionState::Missing,
            }
        })
    }

    pub(crate) fn record_admission_cancellation(
        &mut self,
        operation: IdempotentOperation,
        idempotency: &IdempotencyInput,
        expected_session_id: Option<&SessionId>,
        outcome: DurableCancellationOutcome,
        observed_at: OffsetDateTime,
    ) -> Result<DurableAdmissionState, StorageError> {
        self.record_admission_cancellation_inner(
            operation,
            idempotency,
            expected_session_id,
            outcome,
            observed_at,
            false,
        )
    }

    pub(crate) fn reconcile_admission_cancellation(
        &mut self,
        operation: IdempotentOperation,
        idempotency: &IdempotencyInput,
        expected_session_id: Option<&SessionId>,
        outcome: DurableCancellationOutcome,
        observed_at: OffsetDateTime,
    ) -> Result<DurableAdmissionState, StorageError> {
        self.record_admission_cancellation_inner(
            operation,
            idempotency,
            expected_session_id,
            outcome,
            observed_at,
            true,
        )
    }

    fn record_admission_cancellation_inner(
        &mut self,
        operation: IdempotentOperation,
        idempotency: &IdempotencyInput,
        expected_session_id: Option<&SessionId>,
        outcome: DurableCancellationOutcome,
        observed_at: OffsetDateTime,
        reconciled: bool,
    ) -> Result<DurableAdmissionState, StorageError> {
        require_operation(idempotency, operation)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if let Some(record) = matching_idempotency(&transaction, idempotency)? {
            let replay = replay_admission(&transaction, &record, expected_session_id)?;
            transaction
                .commit()
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
            return Ok(DurableAdmissionState::Admitted(Box::new(replay)));
        }
        let existing = matching_admission_cancellation(&transaction, idempotency, observed_at)?;
        let state = match existing {
            Some(DurableCancellationOutcome::RecoveryPending)
                if reconciled && outcome == DurableCancellationOutcome::Cancelled =>
            {
                transaction
                    .execute(
                        "UPDATE admission_cancellations
                         SET outcome = 'cancelled', created_at = ?4, expires_at = ?5
                         WHERE principal_ref = ?1 AND operation = ?2 AND idempotency_key = ?3",
                        rusqlite::params![
                            idempotency.principal_ref.as_str(),
                            idempotent_operation_token(idempotency.operation),
                            idempotency.key.as_str(),
                            format_time(observed_at)?,
                            format_time(observed_at + IDEMPOTENCY_RETENTION)?,
                        ],
                    )
                    .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
                DurableAdmissionState::Cancelled
            }
            Some(DurableCancellationOutcome::RecoveryPending) => {
                DurableAdmissionState::RecoveryPending
            }
            Some(DurableCancellationOutcome::Cancelled)
                if outcome == DurableCancellationOutcome::RecoveryPending =>
            {
                transaction
                    .execute(
                        "UPDATE admission_cancellations SET outcome = 'recovery_pending'
                         WHERE principal_ref = ?1 AND operation = ?2 AND idempotency_key = ?3",
                        rusqlite::params![
                            idempotency.principal_ref.as_str(),
                            idempotent_operation_token(idempotency.operation),
                            idempotency.key.as_str(),
                        ],
                    )
                    .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
                DurableAdmissionState::RecoveryPending
            }
            Some(DurableCancellationOutcome::Cancelled) => DurableAdmissionState::Cancelled,
            None => {
                transaction
                    .execute(
                        "DELETE FROM admission_cancellations
                         WHERE principal_ref = ?1 AND operation = ?2 AND idempotency_key = ?3",
                        rusqlite::params![
                            idempotency.principal_ref.as_str(),
                            idempotent_operation_token(idempotency.operation),
                            idempotency.key.as_str(),
                        ],
                    )
                    .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
                transaction
                    .execute(
                        "INSERT INTO admission_cancellations
                         (principal_ref, operation, idempotency_key, request_digest,
                          digest_schema_version, hmac_key_version, outcome, created_at, expires_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                        rusqlite::params![
                            idempotency.principal_ref.as_str(),
                            idempotent_operation_token(idempotency.operation),
                            idempotency.key.as_str(),
                            idempotency.request_digest.as_str(),
                            i64::from(idempotency.digest_schema_version),
                            i64::from(idempotency.hmac_key_version),
                            outcome.as_str(),
                            format_time(observed_at)?,
                            format_time(observed_at + IDEMPOTENCY_RETENTION)?,
                        ],
                    )
                    .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
                match outcome {
                    DurableCancellationOutcome::Cancelled => DurableAdmissionState::Cancelled,
                    DurableCancellationOutcome::RecoveryPending => {
                        DurableAdmissionState::RecoveryPending
                    }
                }
            }
        };
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(state)
    }

    pub(crate) fn idempotency_hmac_key_version(
        &self,
        principal_ref: &str,
        operation: IdempotentOperation,
        key: &str,
    ) -> Result<Option<u16>, StorageError> {
        let version: Option<i64> = self
            .connection
            .query_row(
                "SELECT hmac_key_version FROM idempotency_records WHERE principal_ref = ?1 AND operation = ?2 AND idempotency_key = ?3",
                rusqlite::params![principal_ref, idempotent_operation_token(operation), key],
                |row| row.get(0),
            )
            .optional()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let version = match version {
            Some(version) => Some(version),
            None => {
                let observed_at = format_time(OffsetDateTime::now_utc())?;
                self.connection
                    .query_row(
                        "SELECT hmac_key_version FROM admission_cancellations
                         WHERE principal_ref = ?1 AND operation = ?2 AND idempotency_key = ?3
                           AND (outcome = 'recovery_pending' OR expires_at > ?4)",
                        rusqlite::params![
                            principal_ref,
                            idempotent_operation_token(operation),
                            key,
                            observed_at,
                        ],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?
            }
        };
        version
            .map(|version| {
                u16::try_from(version)
                    .ok()
                    .filter(|version| *version > 0)
                    .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))
            })
            .transpose()
    }

    pub(crate) fn claim_provider_descriptor_validation(
        &mut self,
        idempotency: &IdempotencyInput,
    ) -> Result<Option<String>, StorageError> {
        require_operation(
            idempotency,
            IdempotentOperation::ProviderDescriptorValidation,
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if let Some(record) = matching_idempotency(&transaction, idempotency)? {
            return match (
                record.status.as_str(),
                record.durable_outcome.as_str(),
                record.result_json,
            ) {
                (
                    "terminal",
                    "v2.provider_descriptor_validation.completed"
                    | "v2.provider_descriptor_validation.failed",
                    Some(result_json),
                ) => Ok(Some(result_json)),
                ("in_progress", "v2.provider_descriptor_validation.pending", None) => {
                    Err(StorageError::new(StorageErrorKind::StateConflict))
                }
                _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
            };
        }
        insert_idempotency(
            &transaction,
            idempotency,
            "in_progress",
            "v2.provider_descriptor_validation.pending",
            None,
            None,
            None,
        )?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(None)
    }

    pub(crate) fn complete_provider_descriptor_validation(
        &mut self,
        idempotency: &IdempotencyInput,
        result_json: &str,
        failed: bool,
        completed_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        require_operation(
            idempotency,
            IdempotentOperation::ProviderDescriptorValidation,
        )?;
        if result_json.is_empty() {
            return Err(StorageError::new(StorageErrorKind::InvalidInput));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let record = matching_idempotency(&transaction, idempotency)?
            .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
        if record.status != "in_progress"
            || record.durable_outcome != "v2.provider_descriptor_validation.pending"
            || record.result_json.is_some()
        {
            return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
        }
        let updated = transaction
            .execute(
                "UPDATE idempotency_records
                 SET status = 'terminal',
                     durable_outcome = ?1,
                     result_json = ?2,
                     completed_at = ?3,
                     expires_at = ?4
                 WHERE principal_ref = ?5
                   AND operation = ?6
                   AND idempotency_key = ?7
                   AND status = 'in_progress'",
                rusqlite::params![
                    if failed {
                        "v2.provider_descriptor_validation.failed"
                    } else {
                        "v2.provider_descriptor_validation.completed"
                    },
                    result_json,
                    self::codec::format_time(completed_at)?,
                    self::codec::format_time(idempotency.expires_at)?,
                    idempotency.principal_ref.as_str(),
                    self::codec::idempotent_operation_token(idempotency.operation),
                    idempotency.key.as_str(),
                ],
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if updated != 1 {
            return Err(StorageError::new(StorageErrorKind::StateConflict));
        }
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
    }

    pub(crate) fn claim_setup_verification(
        &mut self,
        idempotency: &IdempotencyInput,
    ) -> Result<Option<String>, StorageError> {
        require_operation(idempotency, IdempotentOperation::SetupVerification)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if let Some(record) = matching_idempotency(&transaction, idempotency)? {
            return match (
                record.status.as_str(),
                record.durable_outcome.as_str(),
                record.result_json,
            ) {
                (
                    "terminal",
                    "v1.setup_verification.completed" | "v1.setup_verification.failed",
                    Some(result_json),
                ) => Ok(Some(result_json)),
                ("in_progress", "v1.setup_verification.pending", None) => {
                    Err(StorageError::new(StorageErrorKind::StateConflict))
                }
                _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
            };
        }
        insert_idempotency(
            &transaction,
            idempotency,
            "in_progress",
            "v1.setup_verification.pending",
            None,
            None,
            None,
        )?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(None)
    }

    pub(crate) fn complete_setup_verification(
        &mut self,
        idempotency: &IdempotencyInput,
        result_json: &str,
        failed: bool,
        completed_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        require_operation(idempotency, IdempotentOperation::SetupVerification)?;
        if result_json.is_empty() {
            return Err(StorageError::new(StorageErrorKind::InvalidInput));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let record = matching_idempotency(&transaction, idempotency)?
            .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
        if record.status != "in_progress"
            || record.durable_outcome != "v1.setup_verification.pending"
            || record.result_json.is_some()
        {
            return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
        }
        let updated = transaction
            .execute(
                "UPDATE idempotency_records
                 SET status = 'terminal',
                     durable_outcome = ?1,
                     result_json = ?2,
                     completed_at = ?3,
                     expires_at = ?4
                 WHERE principal_ref = ?5
                   AND operation = ?6
                   AND idempotency_key = ?7
                   AND status = 'in_progress'",
                rusqlite::params![
                    if failed {
                        "v1.setup_verification.failed"
                    } else {
                        "v1.setup_verification.completed"
                    },
                    result_json,
                    self::codec::format_time(completed_at)?,
                    self::codec::format_time(idempotency.expires_at)?,
                    idempotency.principal_ref.as_str(),
                    self::codec::idempotent_operation_token(idempotency.operation),
                    idempotency.key.as_str(),
                ],
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if updated != 1 {
            return Err(StorageError::new(StorageErrorKind::StateConflict));
        }
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
    }

    pub(crate) fn invalidate_native_readiness_idempotent<M>(
        &mut self,
        idempotency: &IdempotencyInput,
        key: Option<&ReadinessCacheKey>,
        completed_at: OffsetDateTime,
        map_failure: M,
    ) -> Result<NativeReadinessInvalidationReplay, StorageError>
    where
        M: FnOnce(&StorageError) -> SatelleError,
    {
        require_operation(
            idempotency,
            IdempotentOperation::NativeReadinessInvalidation,
        )?;
        let mut transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if let Some(record) = matching_idempotency(&transaction, idempotency)? {
            let replay = match (
                record.status.as_str(),
                record.durable_outcome.as_str(),
                record.result_json,
            ) {
                (
                    "terminal",
                    "v1.native_readiness_invalidation.completed"
                    | "v1.native_readiness_invalidation.failed",
                    Some(result_json),
                ) => serde_json::from_str(&result_json)
                    .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?,
                _ => return Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
            };
            transaction
                .commit()
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
            return Ok(replay);
        }

        let savepoint = transaction
            .savepoint()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let invalidated = auth::host_identity(&savepoint).and_then(|host_identity| {
            key.map_or(Ok(0), |key| {
                operational::invalidate_native_readiness_for_key(
                    &savepoint,
                    host_identity.as_str(),
                    key,
                )
            })
        });
        let replay = match invalidated {
            Ok(deleted) => {
                savepoint
                    .commit()
                    .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
                NativeReadinessInvalidationReplay::Completed(deleted)
            }
            Err(error) => {
                savepoint
                    .finish()
                    .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
                NativeReadinessInvalidationReplay::Failed(map_failure(&error))
            }
        };
        let failed = matches!(replay, NativeReadinessInvalidationReplay::Failed(_));
        let result_json = serde_json::to_string(&replay).map_err(|source| {
            StorageError::with_source(StorageErrorKind::OperationFailed, source)
        })?;
        insert_terminal_json_idempotency(
            &transaction,
            idempotency,
            if failed {
                "v1.native_readiness_invalidation.failed"
            } else {
                "v1.native_readiness_invalidation.completed"
            },
            &result_json,
            completed_at,
        )?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(replay)
    }

    pub(crate) fn provider_binding_authorization_replay(
        &self,
        idempotency: &IdempotencyInput,
    ) -> Result<Option<ProviderBindingAuthorizationReplay>, StorageError> {
        require_operation(
            idempotency,
            IdempotentOperation::ProviderBindingAuthorization,
        )?;
        let Some(record) = matching_idempotency(&self.connection, idempotency)? else {
            return Ok(None);
        };
        match (
            record.status.as_str(),
            record.durable_outcome.as_str(),
            record.result_json,
        ) {
            (
                "terminal",
                "v1.provider_binding_authorization.completed"
                | "v1.provider_binding_authorization.failed",
                Some(result_json),
            ) => serde_json::from_str(&result_json)
                .map(Some)
                .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState)),
            _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
        }
    }

    pub(crate) fn authorize_provider_binding_idempotent<V, M>(
        &mut self,
        idempotency: &IdempotencyInput,
        expected_previous_digest: Option<&str>,
        completed_at: OffsetDateTime,
        validate: V,
        map_failure: M,
    ) -> Result<ProviderBindingAuthorizationReplay, StorageError>
    where
        V: FnOnce() -> Result<ResolvedProviderBinding, SatelleError>,
        M: FnOnce(&StorageError) -> SatelleError,
    {
        require_operation(
            idempotency,
            IdempotentOperation::ProviderBindingAuthorization,
        )?;
        let mut transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if let Some(record) = matching_idempotency(&transaction, idempotency)? {
            let replay = match (
                record.status.as_str(),
                record.durable_outcome.as_str(),
                record.result_json,
            ) {
                (
                    "terminal",
                    "v1.provider_binding_authorization.completed"
                    | "v1.provider_binding_authorization.failed",
                    Some(result_json),
                ) => serde_json::from_str(&result_json)
                    .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?,
                _ => return Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
            };
            transaction
                .commit()
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
            return Ok(replay);
        }

        let replay = match validate() {
            Err(error) => ProviderBindingAuthorizationReplay::Failed(error),
            Ok(binding) => {
                let public_binding = PublicResolvedProviderBinding::from(&binding);
                let savepoint = transaction
                    .savepoint()
                    .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
                let current_digest = Self::provider_binding_digest_in_connection(
                    &savepoint,
                    binding.requested_model_alias(),
                    binding.requested_provider_alias(),
                )?;
                let stored = if current_digest.as_deref() != expected_previous_digest {
                    Err(StorageError::new(StorageErrorKind::StateConflict))
                } else {
                    Self::authorize_provider_binding_in_connection(
                        &savepoint,
                        &binding,
                        completed_at,
                    )
                };
                match stored {
                    Ok(()) => {
                        savepoint.commit().map_err(|source| {
                            sqlite_error(StorageErrorKind::OperationFailed, source)
                        })?;
                        ProviderBindingAuthorizationReplay::Completed(public_binding)
                    }
                    Err(error) => {
                        savepoint.finish().map_err(|source| {
                            sqlite_error(StorageErrorKind::OperationFailed, source)
                        })?;
                        ProviderBindingAuthorizationReplay::Failed(map_failure(&error))
                    }
                }
            }
        };
        let failed = matches!(replay, ProviderBindingAuthorizationReplay::Failed(_));
        let result_json = serde_json::to_string(&replay).map_err(|source| {
            StorageError::with_source(StorageErrorKind::OperationFailed, source)
        })?;
        insert_terminal_json_idempotency(
            &transaction,
            idempotency,
            if failed {
                "v1.provider_binding_authorization.failed"
            } else {
                "v1.provider_binding_authorization.completed"
            },
            &result_json,
            completed_at,
        )?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(replay)
    }

    pub(crate) fn delete_provider_binding_idempotent<V, M>(
        &mut self,
        idempotency: &IdempotencyInput,
        model_alias: &str,
        provider_alias: &str,
        completed_at: OffsetDateTime,
        validate: V,
        map_failure: M,
    ) -> Result<ProviderBindingDeletionReplay, StorageError>
    where
        V: FnOnce() -> Result<(), SatelleError>,
        M: FnOnce(&StorageError) -> SatelleError,
    {
        require_operation(idempotency, IdempotentOperation::ProviderBindingDeletion)?;
        let mut transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if let Some(record) = matching_idempotency(&transaction, idempotency)? {
            let replay = match (
                record.status.as_str(),
                record.durable_outcome.as_str(),
                record.result_json,
            ) {
                (
                    "terminal",
                    "v1.provider_binding_deletion.completed"
                    | "v1.provider_binding_deletion.failed",
                    Some(result_json),
                ) => serde_json::from_str(&result_json)
                    .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?,
                _ => return Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
            };
            transaction
                .commit()
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
            return Ok(replay);
        }

        let replay = match validate() {
            Err(error) => ProviderBindingDeletionReplay::Failed(error),
            Ok(()) => {
                let savepoint = transaction
                    .savepoint()
                    .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
                match Self::delete_provider_binding_in_connection(
                    &savepoint,
                    model_alias,
                    provider_alias,
                ) {
                    Ok(deleted) => {
                        savepoint.commit().map_err(|source| {
                            sqlite_error(StorageErrorKind::OperationFailed, source)
                        })?;
                        ProviderBindingDeletionReplay::Completed(deleted)
                    }
                    Err(error) => {
                        savepoint.finish().map_err(|source| {
                            sqlite_error(StorageErrorKind::OperationFailed, source)
                        })?;
                        ProviderBindingDeletionReplay::Failed(map_failure(&error))
                    }
                }
            }
        };
        let failed = matches!(replay, ProviderBindingDeletionReplay::Failed(_));
        let result_json = serde_json::to_string(&replay).map_err(|source| {
            StorageError::with_source(StorageErrorKind::OperationFailed, source)
        })?;
        insert_terminal_json_idempotency(
            &transaction,
            idempotency,
            if failed {
                "v1.provider_binding_deletion.failed"
            } else {
                "v1.provider_binding_deletion.completed"
            },
            &result_json,
            completed_at,
        )?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(replay)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn authorize_provider_binding(
        &mut self,
        binding: &ResolvedProviderBinding,
        updated_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Self::authorize_provider_binding_in_connection(&transaction, binding, updated_at)?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
    }

    fn authorize_provider_binding_in_connection(
        connection: &Connection,
        binding: &ResolvedProviderBinding,
        updated_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        if binding.source() != ProviderBindingSource::UserConfig
            || !binding.has_valid_binding_digest()
        {
            return Err(StorageError::new(StorageErrorKind::InvalidInput));
        }
        let auth_source_json = binding
            .auth_source()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|source| {
                StorageError::with_source(StorageErrorKind::OperationFailed, source)
            })?;
        let previous_digest = connection
            .query_row(
                "SELECT binding_digest
                 FROM authorized_provider_bindings
                 WHERE provider_alias = ?1 AND model_alias = ?2",
                rusqlite::params![
                    binding.requested_provider_alias(),
                    binding.requested_model_alias()
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        connection
            .execute(
                "INSERT INTO authorized_provider_bindings (
                    provider_alias,
                    model_alias,
                    model,
                    model_provider,
                    endpoint,
                    auth_source_json,
                    source,
                    experimental_provider_computer_use,
                    allow_project_selection,
                    binding_digest,
                    updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'user_config', ?7, ?8, ?9, ?10)
                 ON CONFLICT(provider_alias, model_alias) DO UPDATE SET
                    model = excluded.model,
                    model_provider = excluded.model_provider,
                    endpoint = excluded.endpoint,
                    auth_source_json = excluded.auth_source_json,
                    source = excluded.source,
                    experimental_provider_computer_use =
                        excluded.experimental_provider_computer_use,
                    allow_project_selection = excluded.allow_project_selection,
                    binding_digest = excluded.binding_digest,
                    updated_at = excluded.updated_at",
                rusqlite::params![
                    binding.requested_provider_alias(),
                    binding.requested_model_alias(),
                    binding.model(),
                    binding.model_provider(),
                    binding.endpoint(),
                    auth_source_json,
                    i64::from(binding.experimental_provider_computer_use()),
                    i64::from(binding.allow_project_selection()),
                    binding.binding_digest(),
                    format_time(updated_at)?,
                ],
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if let Some(previous_digest) = previous_digest
            && previous_digest != binding.binding_digest()
        {
            connection
                .execute(
                    "DELETE FROM provider_smoke_results
                     WHERE provider_config_fingerprint = ?1",
                    rusqlite::params![previous_digest],
                )
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        }
        Ok(())
    }

    pub(crate) fn authorize_provider_binding_if_unchanged(
        &mut self,
        binding: &ResolvedProviderBinding,
        expected_previous_digest: Option<&str>,
        updated_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let current_digest = Self::provider_binding_digest_in_connection(
            &transaction,
            binding.requested_model_alias(),
            binding.requested_provider_alias(),
        )?;
        if current_digest.as_deref() != expected_previous_digest {
            return Err(StorageError::new(StorageErrorKind::StateConflict));
        }
        Self::authorize_provider_binding_in_connection(&transaction, binding, updated_at)?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
    }

    fn provider_binding_digest_in_connection(
        connection: &Connection,
        model_alias: &str,
        provider_alias: &str,
    ) -> Result<Option<String>, StorageError> {
        connection
            .query_row(
                "SELECT binding_digest
                 FROM authorized_provider_bindings
                 WHERE provider_alias = ?1 AND model_alias = ?2",
                rusqlite::params![provider_alias, model_alias],
                |row| row.get(0),
            )
            .optional()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
    }

    pub(crate) fn delete_authorized_provider_binding(
        &mut self,
        model_alias: &str,
        provider_alias: &str,
    ) -> Result<bool, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let deleted =
            Self::delete_provider_binding_in_connection(&transaction, model_alias, provider_alias)?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(deleted)
    }

    fn delete_provider_binding_in_connection(
        connection: &Connection,
        model_alias: &str,
        provider_alias: &str,
    ) -> Result<bool, StorageError> {
        let previous_digest = connection
            .query_row(
                "SELECT binding_digest
                 FROM authorized_provider_bindings
                 WHERE provider_alias = ?1 AND model_alias = ?2",
                rusqlite::params![provider_alias, model_alias],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let deleted = connection
            .execute(
                "DELETE FROM authorized_provider_bindings
                 WHERE provider_alias = ?1 AND model_alias = ?2",
                rusqlite::params![provider_alias, model_alias],
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if deleted == 1
            && let Some(previous_digest) = previous_digest
        {
            connection
                .execute(
                    "DELETE FROM provider_smoke_results
                     WHERE provider_config_fingerprint = ?1",
                    rusqlite::params![previous_digest],
                )
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        }
        Ok(deleted == 1)
    }

    pub(crate) fn load_authorized_provider_binding(
        &self,
        model_alias: &str,
        provider_alias: &str,
    ) -> Result<Option<ResolvedProviderBinding>, StorageError> {
        let stored = self
            .connection
            .query_row(
                "SELECT model,
                        model_provider,
                        endpoint,
                        auth_source_json,
                        source,
                        experimental_provider_computer_use,
                        allow_project_selection,
                        binding_digest
                 FROM authorized_provider_bindings
                 WHERE provider_alias = ?1 AND model_alias = ?2",
                rusqlite::params![provider_alias, model_alias],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, String>(7)?,
                    ))
                },
            )
            .optional()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let Some((
            model,
            model_provider,
            endpoint,
            auth_source_json,
            source,
            experimental,
            allow_project_selection,
            stored_digest,
        )) = stored
        else {
            return Ok(None);
        };
        if source != ProviderBindingSource::UserConfig.as_str()
            || !matches!(experimental, 0 | 1)
            || !matches!(allow_project_selection, 0 | 1)
        {
            return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
        }
        let auth_source = auth_source_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|source| {
                StorageError::with_source(StorageErrorKind::InvalidStoredState, source)
            })?;
        let mut authorization =
            ProviderBindingAuthorization::new(model_alias, provider_alias, model, model_provider)
                .with_allow_project_selection(allow_project_selection == 1)
                .with_experimental_provider_computer_use(experimental == 1);
        if let Some(endpoint) = endpoint {
            authorization = authorization.with_endpoint(endpoint);
        }
        if let Some(auth_source) = auth_source {
            authorization = authorization.with_auth_source(auth_source);
        }
        let binding = ResolvedProviderBinding::from_authorization(
            authorization,
            ProviderBindingSource::UserConfig,
        );
        if binding.binding_digest() != stored_digest {
            return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
        }
        Ok(Some(binding))
    }

    pub(crate) fn recovery_subject(
        &self,
        session_id: &SessionId,
        turn_id: &TurnId,
    ) -> Result<RecoverySubject, StorageError> {
        let session = load_required_session(&self.connection, session_id)?;
        load_recovery_subject(&self.connection, &session, turn_id)
    }

    pub(crate) fn begin_session(
        &mut self,
        session: &Session,
        context: &AdmissionContext,
    ) -> Result<AdmissionOutcome, StorageError> {
        require_operation(&context.idempotency, IdempotentOperation::Run)?;
        if context.idempotency.operation_id != context.lease_owner.operation_id {
            return Err(StorageError::new(StorageErrorKind::InvalidInput));
        }
        validate_initial_session(session)?;
        let turn = session
            .turns()
            .next()
            .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidInput))?;
        let session_id = session.id().clone();
        let turn_id = turn.id().clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;

        if let Some(record) = matching_idempotency(&transaction, &context.idempotency)? {
            let outcome = replay_admission(&transaction, &record, None)?.into_outcome();
            transaction
                .commit()
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
            return Ok(outcome);
        }
        if matching_admission_cancellation(
            &transaction,
            &context.idempotency,
            context.idempotency.created_at,
        )?
        .is_some()
        {
            return Err(StorageError::new(StorageErrorKind::AdmissionCancelled));
        }

        ensure_control_lease_available(
            &transaction,
            session.host_identity(),
            session.desktop_binding(),
        )?;
        insert_initial_session(&transaction, session, &context.request_token)?;
        insert_control_lease(&transaction, session, &turn_id, &context.lease_owner)?;
        insert_idempotency(
            &transaction,
            &context.idempotency,
            "in_progress",
            "v1.turn.starting",
            Some(&session_id),
            Some(&turn_id),
            None,
        )?;
        insert_safe_log(
            &transaction,
            &canonical_log(
                LogEvent::SessionStarted,
                LogSeverity::Info,
                session,
                &turn_id,
                session.updated_at(),
            )?,
        )?;
        let recovery_subject = load_recovery_subject(&transaction, session, &turn_id)?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(AdmissionOutcome::Execute {
            session: session.clone(),
            recovery_subject,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_follow_up(
        &mut self,
        session_id: &SessionId,
        expected_session_revision: SessionStateRevision,
        turn_id: TurnId,
        execution_policy: ExecutionPolicy,
        at: OffsetDateTime,
        requires_upstream_thread: bool,
        context: &AdmissionContext,
    ) -> Result<AdmissionOutcome, StorageError> {
        require_operation(&context.idempotency, IdempotentOperation::Steer)?;
        if context.idempotency.operation_id != context.lease_owner.operation_id {
            return Err(StorageError::new(StorageErrorKind::InvalidInput));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;

        if let Some(record) = matching_idempotency(&transaction, &context.idempotency)? {
            let outcome = replay_admission(&transaction, &record, Some(session_id))?.into_outcome();
            transaction
                .commit()
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
            return Ok(outcome);
        }
        if matching_admission_cancellation(
            &transaction,
            &context.idempotency,
            context.idempotency.created_at,
        )?
        .is_some()
        {
            return Err(StorageError::new(StorageErrorKind::AdmissionCancelled));
        }

        let mut session = load_required_session(&transaction, session_id)?;
        if session.is_active() {
            return Err(StorageError::lease_conflict(session.id().clone()));
        }
        if requires_upstream_thread {
            let upstream_thread_ref = transaction
                .query_row(
                    "SELECT upstream_thread_ref FROM session_private_refs WHERE session_id = ?1",
                    [session_id.as_str()],
                    |row| row.get::<_, Option<String>>(0),
                )
                .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
            let upstream_thread_ref = upstream_thread_ref
                .ok_or_else(|| StorageError::new(StorageErrorKind::SessionNotSteerable))?;
            PrivateUpstreamRef::new(upstream_thread_ref)
                .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
        }
        let previous_revision = session.session_state_revision();
        session
            .start_follow_up(
                expected_session_revision,
                turn_id.clone(),
                execution_policy,
                at,
            )
            .map_err(StorageError::from)?;
        ensure_control_lease_available(
            &transaction,
            session.host_identity(),
            session.desktop_binding(),
        )?;
        update_session_row(&transaction, &session, previous_revision)?;
        let turn = session
            .turn(&turn_id)
            .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
        insert_turn(
            &transaction,
            session_id,
            session.turns().len() - 1,
            turn,
            &context.request_token,
        )?;
        insert_control_lease(&transaction, &session, &turn_id, &context.lease_owner)?;
        insert_idempotency(
            &transaction,
            &context.idempotency,
            "in_progress",
            "v1.turn.starting",
            Some(session_id),
            Some(&turn_id),
            None,
        )?;
        insert_safe_log(
            &transaction,
            &canonical_log(
                LogEvent::FollowUpStarted,
                LogSeverity::Info,
                &session,
                &turn_id,
                session.updated_at(),
            )?,
        )?;
        let recovery_subject = load_recovery_subject(&transaction, &session, &turn_id)?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(AdmissionOutcome::Execute {
            session,
            recovery_subject,
        })
    }

    pub(crate) fn commit_lifecycle(
        &mut self,
        session_id: &SessionId,
        turn_id: &TurnId,
        expected: ExpectedRevisions,
        transition: TurnTransition,
        at: OffsetDateTime,
    ) -> Result<Session, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if matches!(
            &transition,
            &TurnTransition::Running | &TurnTransition::RecoveryPending
        ) {
            // A stop observation owns the next nonterminal transition. A
            // concurrent terminal result may still win through the normal
            // lifecycle compare-and-swap.
            ensure_no_pending_stop(&transaction, session_id, turn_id)?;
        }
        let mut session = load_required_session(&transaction, session_id)?;
        session
            .transition_turn(turn_id, expected, transition, at)
            .map_err(StorageError::from)?;
        persist_lifecycle_mutation(&transaction, &session, turn_id, expected)?;
        synchronize_control_lease(&transaction, &session, turn_id)?;
        update_turn_idempotency(&transaction, &session, turn_id, at)?;
        insert_safe_log(
            &transaction,
            &canonical_log(
                LogEvent::TurnStateCommitted,
                LogSeverity::Info,
                &session,
                turn_id,
                session.updated_at(),
            )?,
        )?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(session)
    }

    /// Persists private upstream identity as soon as the adapter observes it.
    /// This transaction deliberately does not mutate lifecycle revisions,
    /// idempotency outcomes, logs, or lease ownership.
    pub(crate) fn record_upstream_ref(
        &mut self,
        session_id: &SessionId,
        turn_id: &TurnId,
        observed_ref: &ObservedUpstreamRef,
    ) -> Result<(), StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        merge_observed_reference(&transaction, session_id, turn_id, observed_ref)?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(())
    }

    pub(crate) fn load_session(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<Session>, StorageError> {
        load_session_from_connection(&self.connection, session_id)
    }

    pub(crate) fn snapshot(&self) -> Result<StorageSnapshot, StorageError> {
        let counts: (i64, i64, i64) = self
            .connection
            .query_row(
                "SELECT \
                    (SELECT count(*) FROM sessions), \
                    (SELECT count(*) FROM turns WHERE state IN ('starting', 'running')), \
                    (SELECT count(*) FROM turns WHERE state = 'recovery_pending')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let decode = |count: i64| {
            usize::try_from(count)
                .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
        };
        Ok(StorageSnapshot {
            session_count: decode(counts.0)?,
            active_turn_count: decode(counts.1)?,
            recovery_pending_turn_count: decode(counts.2)?,
        })
    }
}
