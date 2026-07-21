use super::codec::{format_time, parse_time};
use super::{StorageError, StorageErrorKind};
use rusqlite::backup::Backup;
use rusqlite::ffi::ErrorCode as SqliteErrorCode;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, TryLockError};
use std::io::{Read, Seek, Write};
use std::path::Path;
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

#[cfg(unix)]
use rustix::fs::{FileType, Mode, OFlags};
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix_vfs;
#[cfg(windows)]
mod windows;

#[cfg(test)]
#[path = "backup-tests.rs"]
mod backup_tests;

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
compile_error!("Satelle storage supports only Linux, macOS, and Windows hosts");

pub(super) const DATABASE_FILE_NAME: &str = "satelle.sqlite3";
pub(super) const LOCK_FILE_NAME: &str = "satelle.sqlite3.lock";
pub(super) const PROTECTED_FILE_NAMES: [&str; 5] = [
    DATABASE_FILE_NAME,
    LOCK_FILE_NAME,
    "satelle.sqlite3-wal",
    "satelle.sqlite3-shm",
    "satelle.sqlite3-journal",
];
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const BACKUP_FORMAT_VERSION: u32 = 1;
const MIGRATIONS: [Migration; 10] = [
    Migration {
        version: 1,
        sql: include_str!("0001_initial.sql"),
        seeds_sensitive_state: true,
        irreversible: false,
    },
    Migration {
        version: 2,
        sql: include_str!("0002_operational_evidence.sql"),
        seeds_sensitive_state: false,
        irreversible: false,
    },
    Migration {
        version: 3,
        sql: include_str!("0003_native_readiness_results.sql"),
        seeds_sensitive_state: false,
        irreversible: true,
    },
    Migration {
        version: 4,
        sql: include_str!("0004_provider_smoke_results.sql"),
        seeds_sensitive_state: false,
        irreversible: true,
    },
    Migration {
        version: 5,
        sql: include_str!("0005_provider_probe_recovery.sql"),
        seeds_sensitive_state: false,
        irreversible: true,
    },
    Migration {
        version: 6,
        sql: include_str!("0006_native_probe_recovery.sql"),
        seeds_sensitive_state: false,
        irreversible: true,
    },
    Migration {
        version: 7,
        sql: include_str!("0007_setup_action_ledger.sql"),
        seeds_sensitive_state: false,
        irreversible: false,
    },
    Migration {
        version: 8,
        sql: include_str!("0008_api_token_state.sql"),
        seeds_sensitive_state: false,
        irreversible: false,
    },
    Migration {
        version: 9,
        sql: include_str!("0009_session_metadata.sql"),
        seeds_sensitive_state: false,
        irreversible: false,
    },
    Migration {
        version: 10,
        sql: include_str!("0010_admission_cancellations.sql"),
        seeds_sensitive_state: false,
        irreversible: false,
    },
];

#[derive(Clone, Copy)]
struct Migration {
    version: i64,
    sql: &'static str,
    seeds_sensitive_state: bool,
    irreversible: bool,
}

#[derive(Clone, Copy)]
enum LeafOpenMode {
    Existing,
    ExistingPrivate,
    ExistingPrivateGuarded,
    CreateIfMissing,
    CreateNew,
}

#[derive(Clone, Deserialize, Serialize)]
struct MigrationBackupManifest {
    manifest_version: u32,
    backup_file: String,
    source_schema_version: i64,
    source_database_digest: String,
    created_at: String,
    satelle_version: String,
    restore_compatibility: RestoreCompatibility,
}

#[derive(Clone, Deserialize, Serialize)]
struct RestoreCompatibility {
    database_format: String,
    schema_version: i64,
    explicit_restore_required: bool,
}

#[derive(Clone, Copy)]
struct MigrationBackupName {
    schema_version: i64,
    backup_id: Uuid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LeafIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    volume_serial_number: u32,
    #[cfg(windows)]
    file_index: u64,
}

impl LeafIdentity {
    fn update_digest(self, digest: &mut Sha256) {
        #[cfg(unix)]
        {
            digest.update(self.device.to_le_bytes());
            digest.update(self.inode.to_le_bytes());
        }
        #[cfg(windows)]
        {
            digest.update(self.volume_serial_number.to_le_bytes());
            digest.update(self.file_index.to_le_bytes());
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct RestorePointToken {
    backup_id: Uuid,
    schema_version: i64,
    source_database_digest: String,
    manifest_digest: String,
    backup_identity: LeafIdentity,
    manifest_identity: LeafIdentity,
}

#[derive(Debug)]
pub(super) struct ValidatedMigrationBackup {
    backup_file_name: String,
    manifest_file_name: String,
    token: RestorePointToken,
}

pub(super) struct RestoreActivation {
    pub(super) failed_store_file_name: String,
    pub(super) failed_sidecar_file_names: Vec<String>,
}

impl fmt::Debug for RestoreActivation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestoreActivation")
            .field("failed_store_file_name", &self.failed_store_file_name)
            .field("failed_sidecar_file_names", &self.failed_sidecar_file_names)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActivationStep {
    CandidateValidated,
    StagedValidated,
    RecoveryStateDurable,
    SidecarsMovedDurably,
    BeforeStagedInstallMove,
    InstalledBeforeValidation,
    ReplacementDurable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ValidationStep {
    DigestVerified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupStep {
    CandidateValidated,
    BeforeBackupQuarantineMove,
    BackupQuarantined,
    BeforeManifestQuarantineMove,
    PairQuarantined,
    BeforeBackupDelete,
    BackupDeleteCommitted,
    BeforeManifestDelete,
    ManifestDeleteCommitted,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum CleanupTombstoneKind {
    Backup,
    Manifest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupDeletingKind {
    Backup,
    Manifest,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CleanupTombstoneKey {
    schema_version: i64,
    backup_id: Uuid,
    cleanup_id: Uuid,
    backup_fingerprint: String,
    manifest_fingerprint: String,
}

#[derive(Default)]
struct CleanupTombstonePair {
    backup_file_name: Option<String>,
    manifest_file_name: Option<String>,
}

struct ReadManifest {
    manifest: MigrationBackupManifest,
    file: File,
    identity: LeafIdentity,
    digest: String,
}

pub(super) fn sqlite_error(fallback: StorageErrorKind, source: rusqlite::Error) -> StorageError {
    let kind = match source.sqlite_error_code() {
        Some(SqliteErrorCode::DatabaseBusy | SqliteErrorCode::DatabaseLocked) => {
            StorageErrorKind::Busy
        }
        _ => fallback,
    };
    StorageError::with_source(kind, source)
}

pub(super) struct StateDirectory {
    // Field order is a drop invariant on macOS: release every retained SQLite
    // descriptor and pathname before closing the directory descriptor.
    #[cfg(target_os = "macos")]
    _vfs_registration: unix_vfs::DirectoryRegistration,
    #[cfg(unix)]
    handle: File,
    #[cfg(windows)]
    secure: windows::SecureStateDirectory,
}

impl StateDirectory {
    #[cfg(unix)]
    fn sync(&self) -> Result<(), StorageError> {
        self.sync_for(StorageErrorKind::MigrationFailed)
    }

    #[cfg(unix)]
    fn sync_for(&self, fallback: StorageErrorKind) -> Result<(), StorageError> {
        self.handle
            .sync_all()
            .map_err(|source| StorageError::with_source(fallback, source))
    }

    #[cfg(windows)]
    fn sync(&self) -> Result<(), StorageError> {
        self.secure.sync()
    }

    #[cfg(windows)]
    fn sync_for(&self, _fallback: StorageErrorKind) -> Result<(), StorageError> {
        self.secure.sync()
    }

    #[cfg(unix)]
    fn leaf_names(&self) -> Result<Vec<String>, StorageError> {
        let directory = rustix::fs::Dir::read_from(&self.handle).map_err(|source| {
            StorageError::with_source(StorageErrorKind::OperationFailed, source)
        })?;
        let mut names = Vec::new();
        for entry in directory {
            let entry = entry.map_err(|source| {
                StorageError::with_source(StorageErrorKind::OperationFailed, source)
            })?;
            if let Ok(name) = entry.file_name().to_str()
                && !matches!(name, "." | "..")
            {
                names.push(name.to_owned());
            }
        }
        Ok(names)
    }

    #[cfg(windows)]
    fn leaf_names(&self) -> Result<Vec<String>, StorageError> {
        self.secure.leaf_names()
    }

    #[cfg(unix)]
    fn remove_leaf(&self, file_name: &str) -> Result<bool, StorageError> {
        match rustix::fs::unlinkat(&self.handle, file_name, rustix::fs::AtFlags::empty()) {
            Ok(()) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(source) => Err(StorageError::with_source(
                StorageErrorKind::OperationFailed,
                source,
            )),
        }
    }

    #[cfg(unix)]
    fn delete_leaf(
        &self,
        file_name: &str,
        expected_identity: LeafIdentity,
    ) -> Result<bool, StorageError> {
        if open_private_leaf_identity(self, file_name)? != Some(expected_identity) {
            return Err(StorageError::new(StorageErrorKind::StateConflict));
        }
        self.remove_leaf(file_name)
    }

    #[cfg(windows)]
    fn delete_leaf(
        &self,
        file_name: &str,
        expected_identity: LeafIdentity,
    ) -> Result<bool, StorageError> {
        self.secure.delete_leaf(file_name, expected_identity)
    }

    #[cfg(unix)]
    fn move_leaf(&self, source: &str, destination: &str) -> Result<(), StorageError> {
        match rustix::fs::renameat_with(
            &self.handle,
            source,
            &self.handle,
            destination,
            rustix::fs::RenameFlags::NOREPLACE,
        ) {
            Ok(()) => Ok(()),
            Err(rustix::io::Errno::EXIST) => {
                Err(StorageError::new(StorageErrorKind::StateConflict))
            }
            Err(source) => Err(StorageError::with_source(
                StorageErrorKind::OperationFailed,
                source,
            )),
        }
    }

    #[cfg(windows)]
    fn move_leaf(&self, source: &str, destination: &str) -> Result<(), StorageError> {
        self.secure.move_leaf(source, destination)
    }
}

#[cfg(unix)]
fn leaf_identity(file: &File, fallback: StorageErrorKind) -> Result<LeafIdentity, StorageError> {
    let metadata = file
        .metadata()
        .map_err(|source| StorageError::with_source(fallback, source))?;
    Ok(LeafIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(windows)]
fn leaf_identity(file: &File, fallback: StorageErrorKind) -> Result<LeafIdentity, StorageError> {
    windows::leaf_identity(file, fallback)
}

pub(super) struct OwnershipLock(File);

impl Drop for OwnershipLock {
    fn drop(&mut self) {
        // A child between fork and exec can retain this descriptor. Explicitly
        // unlock the shared file description before closing our descriptor so
        // dropping Storage always hands ownership to the next opener.
        let _ = self.0.unlock();
    }
}

pub(super) fn open_parts(
    state_root: &Path,
) -> Result<(Connection, OwnershipLock, StateDirectory), StorageError> {
    open_parts_after_lock(state_root, || {})
}

fn open_parts_after_lock(
    state_root: &Path,
    after_lock: impl FnOnce(),
) -> Result<(Connection, OwnershipLock, StateDirectory), StorageError> {
    let state_directory = prepare_state_root(state_root)?;
    preflight_protected_files(&state_directory)?;
    let ownership_lock = acquire_ownership_lock(&state_directory)?;
    after_lock();
    // Pre-create and permission the database through the pinned state
    // directory. Existing SQLite sidecars were checked before this point, so
    // the platform VFS cannot encounter an unchecked protected leaf.
    let database_guard = open_private_leaf(
        &state_directory,
        DATABASE_FILE_NAME,
        LeafOpenMode::CreateIfMissing,
        StorageErrorKind::OpenFailed,
    )?
    .ok_or_else(|| StorageError::new(StorageErrorKind::OpenFailed))?;
    // SQLite's Unix VFS uses process-scoped POSIX locks. Closing any other
    // descriptor for the database inode after those locks are taken can drop
    // them, so every Satelle-owned preflight descriptor is closed first.
    drop(database_guard);
    let database_path = sqlite_database_path(state_root, &state_directory);
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let mut connection =
        Connection::open_with_flags_and_vfs(&database_path, flags, unix_vfs::name()?)
            .map_err(|source| sqlite_error(StorageErrorKind::OpenFailed, source))?;
    #[cfg(windows)]
    let mut connection = Connection::open_with_flags(&database_path, flags)
        .map_err(|source| sqlite_error(StorageErrorKind::OpenFailed, source))?;
    verify_database_readable(&connection)?;
    configure_connection(&connection)?;
    apply_migrations(&mut connection, state_root, &state_directory)?;
    verify_integrity(&connection)?;
    #[cfg(windows)]
    restrict_database_files(&state_directory)?;
    Ok((connection, ownership_lock, state_directory))
}

#[cfg(target_os = "macos")]
fn sqlite_database_path(state_root: &Path, state_directory: &StateDirectory) -> std::path::PathBuf {
    sqlite_leaf_path(state_root, state_directory, DATABASE_FILE_NAME)
}

#[cfg(target_os = "macos")]
fn sqlite_leaf_path(
    _state_root: &Path,
    state_directory: &StateDirectory,
    file_name: &str,
) -> std::path::PathBuf {
    use std::os::fd::AsRawFd;

    format!(
        "/.satelle-fd/{}/{}",
        state_directory.handle.as_raw_fd(),
        file_name
    )
    .into()
}

#[cfg(target_os = "linux")]
fn sqlite_database_path(state_root: &Path, state_directory: &StateDirectory) -> std::path::PathBuf {
    sqlite_leaf_path(state_root, state_directory, DATABASE_FILE_NAME)
}

#[cfg(target_os = "linux")]
fn sqlite_leaf_path(
    _state_root: &Path,
    state_directory: &StateDirectory,
    file_name: &str,
) -> std::path::PathBuf {
    use std::os::fd::AsRawFd;

    format!(
        "/proc/self/fd/{}/{}",
        state_directory.handle.as_raw_fd(),
        file_name
    )
    .into()
}

#[cfg(windows)]
fn sqlite_database_path(state_root: &Path, state_directory: &StateDirectory) -> std::path::PathBuf {
    sqlite_leaf_path(state_root, state_directory, DATABASE_FILE_NAME)
}

#[cfg(windows)]
fn sqlite_leaf_path(
    _state_root: &Path,
    state_directory: &StateDirectory,
    file_name: &str,
) -> std::path::PathBuf {
    state_directory.secure.sqlite_leaf_path(file_name)
}

#[cfg(all(test, target_os = "linux"))]
pub(super) fn anchored_vfs_name_for_test() -> Result<&'static std::ffi::CStr, StorageError> {
    unix_vfs::name()
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
pub(super) fn open_parts_with_after_lock_hook(
    state_root: &Path,
    after_lock: impl FnOnce(),
) -> Result<(Connection, OwnershipLock, StateDirectory), StorageError> {
    open_parts_after_lock(state_root, after_lock)
}

#[cfg(unix)]
pub(super) fn prepare_state_root(state_root: &Path) -> Result<StateDirectory, StorageError> {
    if !state_root.is_absolute() || state_root.parent().is_none() {
        return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
    }
    validate_state_root_ancestors(state_root)?;
    match fs::symlink_metadata(state_root) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
            }
            validate_state_root_owner(&metadata)?;
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(state_root).map_err(|source| {
                StorageError::with_source(StorageErrorKind::StateDirectoryUnavailable, source)
            })?;
            let metadata = fs::symlink_metadata(state_root).map_err(|source| {
                StorageError::with_source(StorageErrorKind::StateDirectoryUnavailable, source)
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
            }
            validate_state_root_owner(&metadata)?;
        }
        Err(source) => {
            return Err(StorageError::with_source(
                StorageErrorKind::StateDirectoryUnavailable,
                source,
            ));
        }
    }
    // Recheck the full ancestor chain after creation. A writable or symlinked
    // parent is rejected before any protected leaf is opened.
    validate_state_root_ancestors(state_root)?;
    open_and_restrict_state_directory(state_root)
}

#[cfg(unix)]
fn validate_state_root_ancestors(state_root: &Path) -> Result<(), StorageError> {
    let effective_uid = rustix::process::geteuid().as_raw();
    for ancestor in state_root.ancestors().skip(1) {
        let metadata = match fs::symlink_metadata(ancestor) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(StorageError::with_source(
                    StorageErrorKind::StateDirectoryUnavailable,
                    source,
                ));
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
        }
        let mode = metadata.mode();
        let replaceable_by_another_principal = mode & 0o022 != 0 && mode & 0o1000 == 0;
        let trusted_owner = metadata.uid() == effective_uid || metadata.uid() == 0;
        if replaceable_by_another_principal || !trusted_owner {
            return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_state_root_owner(metadata: &fs::Metadata) -> Result<(), StorageError> {
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
    }
    Ok(())
}

#[cfg(unix)]
fn open_and_restrict_state_directory(path: &Path) -> Result<StateDirectory, StorageError> {
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| secure_open_error(StorageErrorKind::StateDirectoryUnavailable, source))?;
    let metadata = rustix::fs::fstat(&descriptor).map_err(|source| {
        StorageError::with_source(StorageErrorKind::StateDirectoryUnavailable, source)
    })?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != rustix::process::geteuid().as_raw()
    {
        return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
    }
    rustix::fs::fchmod(&descriptor, Mode::RWXU).map_err(|source| {
        StorageError::with_source(StorageErrorKind::StateDirectoryUnavailable, source)
    })?;
    let path_metadata = fs::symlink_metadata(path).map_err(|source| {
        StorageError::with_source(StorageErrorKind::StateDirectoryUnavailable, source)
    })?;
    #[cfg(target_os = "macos")]
    // macOS exposes `dev_t` as a signed C integer even though it is an opaque
    // device bit pattern. Preserve those bits for `MetadataExt::dev()`.
    let descriptor_device = metadata.st_dev as u64;
    #[cfg(not(target_os = "macos"))]
    let descriptor_device = metadata.st_dev;
    if path_metadata.file_type().is_symlink()
        || path_metadata.dev() != descriptor_device
        || path_metadata.ino() != metadata.st_ino
    {
        return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
    }
    let handle = File::from(descriptor);
    #[cfg(target_os = "macos")]
    let vfs_registration = unix_vfs::register_directory(&handle)?;
    Ok(StateDirectory {
        #[cfg(target_os = "macos")]
        _vfs_registration: vfs_registration,
        handle,
    })
}

#[cfg(windows)]
pub(super) fn prepare_state_root(state_root: &Path) -> Result<StateDirectory, StorageError> {
    windows::SecureStateDirectory::prepare(state_root).map(|secure| StateDirectory { secure })
}

fn acquire_ownership_lock(state_directory: &StateDirectory) -> Result<OwnershipLock, StorageError> {
    let file = open_private_leaf(
        state_directory,
        LOCK_FILE_NAME,
        LeafOpenMode::CreateIfMissing,
        StorageErrorKind::LockUnavailable,
    )?
    .ok_or_else(|| StorageError::new(StorageErrorKind::LockUnavailable))?;
    match file.try_lock() {
        Ok(()) => Ok(OwnershipLock(file)),
        Err(TryLockError::WouldBlock) => Err(StorageError::new(StorageErrorKind::StoreInUse)),
        Err(TryLockError::Error(source)) => Err(StorageError::with_source(
            StorageErrorKind::LockUnavailable,
            source,
        )),
    }
}

#[cfg(unix)]
fn open_private_leaf(
    state_directory: &StateDirectory,
    file_name: &str,
    mode: LeafOpenMode,
    fallback: StorageErrorKind,
) -> Result<Option<File>, StorageError> {
    let strict_private = matches!(
        mode,
        LeafOpenMode::ExistingPrivate | LeafOpenMode::ExistingPrivateGuarded
    );
    let mut flags = if strict_private {
        OFlags::RDONLY
    } else {
        OFlags::RDWR
    } | OFlags::NOFOLLOW
        | OFlags::CLOEXEC;
    match mode {
        LeafOpenMode::Existing
        | LeafOpenMode::ExistingPrivate
        | LeafOpenMode::ExistingPrivateGuarded => {}
        LeafOpenMode::CreateIfMissing => flags |= OFlags::CREATE,
        LeafOpenMode::CreateNew => flags |= OFlags::CREATE | OFlags::EXCL,
    }
    let descriptor = match rustix::fs::openat(
        &state_directory.handle,
        file_name,
        flags,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT)
            if matches!(
                mode,
                LeafOpenMode::Existing
                    | LeafOpenMode::ExistingPrivate
                    | LeafOpenMode::ExistingPrivateGuarded
            ) =>
        {
            return Ok(None);
        }
        Err(source) => return Err(secure_open_error(fallback, source)),
    };
    let metadata = rustix::fs::fstat(&descriptor)
        .map_err(|source| StorageError::with_source(fallback, source))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_nlink != 1
        || (strict_private && metadata.st_mode & 0o077 != 0)
    {
        return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
    }
    if !strict_private {
        rustix::fs::fchmod(&descriptor, Mode::RUSR | Mode::WUSR)
            .map_err(|source| StorageError::with_source(fallback, source))?;
    }
    Ok(Some(File::from(descriptor)))
}

#[cfg(unix)]
fn secure_open_error(fallback: StorageErrorKind, source: rustix::io::Errno) -> StorageError {
    if matches!(source, rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) {
        return StorageError::with_source(StorageErrorKind::UnsafeStatePath, source);
    }
    StorageError::with_source(fallback, source)
}

#[cfg(windows)]
fn open_private_leaf(
    state_directory: &StateDirectory,
    file_name: &str,
    mode: LeafOpenMode,
    fallback: StorageErrorKind,
) -> Result<Option<File>, StorageError> {
    state_directory
        .secure
        .open_private_leaf(file_name, mode, fallback)
}

fn preflight_protected_files(state_directory: &StateDirectory) -> Result<(), StorageError> {
    for file_name in PROTECTED_FILE_NAMES {
        open_private_leaf(
            state_directory,
            file_name,
            LeafOpenMode::Existing,
            StorageErrorKind::OpenFailed,
        )?;
    }
    Ok(())
}

#[cfg(windows)]
fn restrict_database_files(state_directory: &StateDirectory) -> Result<(), StorageError> {
    for file_name in PROTECTED_FILE_NAMES {
        open_private_leaf(
            state_directory,
            file_name,
            LeafOpenMode::Existing,
            StorageErrorKind::OpenFailed,
        )?;
    }
    Ok(())
}

fn configure_connection(connection: &Connection) -> Result<(), StorageError> {
    connection
        .busy_timeout(BUSY_TIMEOUT)
        .map_err(|source| sqlite_error(StorageErrorKind::OpenFailed, source))?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|source| sqlite_error(StorageErrorKind::OpenFailed, source))?;
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .map_err(|source| sqlite_error(StorageErrorKind::OpenFailed, source))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(StorageError::new(StorageErrorKind::OpenFailed));
    }
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|source| sqlite_error(StorageErrorKind::OpenFailed, source))?;
    Ok(())
}

fn verify_database_readable(connection: &Connection) -> Result<(), StorageError> {
    connection
        .query_row("PRAGMA schema_version", [], |row| row.get::<_, i64>(0))
        .map(|_| ())
        .map_err(|source| sqlite_error(StorageErrorKind::IntegrityCheckFailed, source))
}

fn apply_migrations(
    connection: &mut Connection,
    state_root: &Path,
    state_directory: &StateDirectory,
) -> Result<(), StorageError> {
    let user_version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|source| sqlite_error(StorageErrorKind::MigrationIntegrity, source))?;
    let migration_table_exists: bool = connection
        .query_row(
            "SELECT EXISTS(\
                SELECT 1 FROM sqlite_schema \
                WHERE type = 'table' AND name = 'schema_migrations'\
            )",
            [],
            |row| row.get(0),
        )
        .map_err(|source| sqlite_error(StorageErrorKind::MigrationIntegrity, source))?;
    let applied = if migration_table_exists {
        load_applied_migrations(connection)?
    } else {
        Vec::new()
    };
    if applied.len() > MIGRATIONS.len()
        || applied
            .iter()
            .zip(MIGRATIONS)
            .any(|((version, checksum), migration)| {
                *version != migration.version || *checksum != migration_checksum(migration.sql)
            })
    {
        return Err(StorageError::new(StorageErrorKind::MigrationIntegrity));
    }
    let expected_user_version = applied.last().map_or(0, |(version, _)| *version);
    if user_version != expected_user_version {
        return Err(StorageError::new(StorageErrorKind::MigrationIntegrity));
    }

    // Existing stores must prove their current state is sound before a newer
    // migration can rewrite it. Fresh stores have no schema to validate, and
    // current stores are verified once after this no-op migration pass.
    if !applied.is_empty() && applied.len() < MIGRATIONS.len() {
        verify_integrity(connection)?;
        if expected_user_version < 8 {
            super::auth::validate_sensitive_state_before_token_state_migration(connection)?;
        } else {
            super::auth::validate_sensitive_state(connection)?;
        }
    }

    if !applied.is_empty()
        && MIGRATIONS
            .iter()
            .skip(applied.len())
            .any(|migration| migration.irreversible)
    {
        create_migration_backup(
            connection,
            state_root,
            state_directory,
            expected_user_version,
        )?;
    }

    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|source| sqlite_error(StorageErrorKind::MigrationFailed, source))?;
    transaction
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (\
                version INTEGER PRIMARY KEY, \
                checksum TEXT NOT NULL, \
                applied_at TEXT NOT NULL\
            ) STRICT;",
        )
        .map_err(|source| sqlite_error(StorageErrorKind::MigrationFailed, source))?;

    for migration in MIGRATIONS.iter().skip(applied.len()) {
        let applied_at = OffsetDateTime::now_utc();
        transaction
            .execute_batch(migration.sql)
            .map_err(|source| sqlite_error(StorageErrorKind::MigrationFailed, source))?;
        if migration.seeds_sensitive_state {
            super::auth::seed_sensitive_state(&transaction, applied_at)?;
        }
        transaction
            .execute(
                "INSERT INTO schema_migrations (version, checksum, applied_at) VALUES (?1, ?2, ?3)",
                params![
                    migration.version,
                    migration_checksum(migration.sql),
                    format_time(applied_at)?,
                ],
            )
            .map_err(|source| sqlite_error(StorageErrorKind::MigrationFailed, source))?;
        transaction
            .pragma_update(None, "user_version", migration.version)
            .map_err(|source| sqlite_error(StorageErrorKind::MigrationFailed, source))?;
    }

    let final_user_version: i64 = transaction
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|source| sqlite_error(StorageErrorKind::MigrationIntegrity, source))?;
    if final_user_version
        != MIGRATIONS
            .last()
            .expect("migration registry is non-empty")
            .version
    {
        return Err(StorageError::new(StorageErrorKind::MigrationIntegrity));
    }
    transaction
        .commit()
        .map_err(|source| sqlite_error(StorageErrorKind::MigrationFailed, source))
}

fn load_applied_migrations(connection: &Connection) -> Result<Vec<(i64, String)>, StorageError> {
    load_applied_migrations_with_kind(connection, StorageErrorKind::MigrationIntegrity)
}

fn load_applied_migrations_with_kind(
    connection: &Connection,
    fallback: StorageErrorKind,
) -> Result<Vec<(i64, String)>, StorageError> {
    let mut statement = connection
        .prepare("SELECT version, checksum FROM schema_migrations ORDER BY version")
        .map_err(|source| sqlite_error(fallback, source))?;
    statement
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|source| sqlite_error(fallback, source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| sqlite_error(fallback, source))
}

fn create_migration_backup(
    source: &Connection,
    state_root: &Path,
    state_directory: &StateDirectory,
    source_schema_version: i64,
) -> Result<(), StorageError> {
    let backup_id = Uuid::now_v7();
    let backup_file_name =
        format!("satelle.sqlite3.migration-v{source_schema_version}-{backup_id}.backup");
    let manifest_file_name = format!("{backup_file_name}.json");
    let backup_path = sqlite_leaf_path(state_root, state_directory, &backup_file_name);

    let backup_guard = open_private_leaf(
        state_directory,
        &backup_file_name,
        LeafOpenMode::CreateNew,
        StorageErrorKind::MigrationFailed,
    )?
    .ok_or_else(|| StorageError::new(StorageErrorKind::MigrationFailed))?;
    drop(backup_guard);

    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let mut destination =
        Connection::open_with_flags_and_vfs(&backup_path, flags, unix_vfs::name()?)
            .map_err(|source| sqlite_error(StorageErrorKind::MigrationFailed, source))?;
    #[cfg(windows)]
    let mut destination = Connection::open_with_flags(&backup_path, flags)
        .map_err(|source| sqlite_error(StorageErrorKind::MigrationFailed, source))?;
    // The destination is a new one-shot backup file. Disabling its rollback
    // journal avoids dynamic sidecar names during the copy. The completed
    // standalone file is normalized again after Backup copies the source
    // database header, including its persisted WAL mode.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    destination
        .pragma_update(None, "journal_mode", "OFF")
        .map_err(|source| sqlite_error(StorageErrorKind::MigrationFailed, source))?;
    Backup::new(source, &mut destination)
        .and_then(|backup| backup.run_to_completion(128, Duration::from_millis(5), None))
        .map_err(|source| sqlite_error(StorageErrorKind::MigrationFailed, source))?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    destination
        .pragma_update(None, "journal_mode", "OFF")
        .map_err(|source| sqlite_error(StorageErrorKind::MigrationFailed, source))?;
    drop(destination);

    let validation_flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let validation =
        Connection::open_with_flags_and_vfs(&backup_path, validation_flags, unix_vfs::name()?)
            .map_err(|source| sqlite_error(StorageErrorKind::MigrationFailed, source))?;
    #[cfg(windows)]
    let validation = Connection::open_with_flags(&backup_path, validation_flags)
        .map_err(|source| sqlite_error(StorageErrorKind::MigrationFailed, source))?;
    verify_integrity(&validation)?;
    drop(validation);
    #[cfg(windows)]
    remove_sqlite_validation_sidecars(state_directory, &backup_file_name)?;

    let backup_file = open_private_leaf(
        state_directory,
        &backup_file_name,
        LeafOpenMode::Existing,
        StorageErrorKind::MigrationFailed,
    )?
    .ok_or_else(|| StorageError::new(StorageErrorKind::MigrationFailed))?;
    backup_file
        .sync_all()
        .map_err(|source| StorageError::with_source(StorageErrorKind::MigrationFailed, source))?;
    let source_database_digest = digest_file(&backup_file, StorageErrorKind::MigrationFailed)?;

    let created_at = OffsetDateTime::now_utc();
    let manifest = MigrationBackupManifest {
        manifest_version: BACKUP_FORMAT_VERSION,
        backup_file: backup_file_name.clone(),
        source_schema_version,
        source_database_digest,
        created_at: format_time(created_at)?,
        satelle_version: env!("CARGO_PKG_VERSION").to_owned(),
        restore_compatibility: RestoreCompatibility {
            database_format: "sqlite3".to_owned(),
            schema_version: source_schema_version,
            explicit_restore_required: true,
        },
    };
    let mut manifest_file = open_private_leaf(
        state_directory,
        &manifest_file_name,
        LeafOpenMode::CreateNew,
        StorageErrorKind::MigrationFailed,
    )?
    .ok_or_else(|| StorageError::new(StorageErrorKind::MigrationFailed))?;
    serde_json::to_writer(&mut manifest_file, &manifest)
        .map_err(|source| StorageError::with_source(StorageErrorKind::MigrationFailed, source))?;
    manifest_file
        .write_all(b"\n")
        .map_err(|source| StorageError::with_source(StorageErrorKind::MigrationFailed, source))?;
    manifest_file
        .sync_all()
        .map_err(|source| StorageError::with_source(StorageErrorKind::MigrationFailed, source))?;
    state_directory.sync()?;
    Ok(())
}

fn parse_migration_backup_file_name(file_name: &str) -> Option<MigrationBackupName> {
    let remainder = file_name
        .strip_prefix("satelle.sqlite3.migration-v")?
        .strip_suffix(".backup")?;
    let (schema_version_text, backup_id_text) = remainder.split_once('-')?;
    let schema_version = schema_version_text.parse::<i64>().ok()?;
    if schema_version.to_string() != schema_version_text {
        return None;
    }
    let backup_id = Uuid::parse_str(backup_id_text).ok()?;
    if backup_id.to_string() != backup_id_text || backup_id.get_version_num() != 7 {
        return None;
    }
    Some(MigrationBackupName {
        schema_version,
        backup_id,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn parse_restore_staged_file_name(file_name: &str) -> Option<Uuid> {
    let backup_id_text = file_name
        .strip_prefix("satelle.sqlite3.restore-")?
        .strip_suffix(".staged")?;
    let backup_id = Uuid::parse_str(backup_id_text).ok()?;
    (backup_id.to_string() == backup_id_text && backup_id.get_version_num() == 7)
        .then_some(backup_id)
}

fn cleanup_tombstone_file_name(
    token: &RestorePointToken,
    cleanup_id: Uuid,
    kind: CleanupTombstoneKind,
) -> String {
    let kind = match kind {
        CleanupTombstoneKind::Backup => "backup",
        CleanupTombstoneKind::Manifest => "manifest",
    };
    format!(
        "satelle.sqlite3.cleanup~{}~{}~{}~{}~{}~{kind}.tombstone",
        token.schema_version,
        token.backup_id,
        cleanup_id,
        backup_fingerprint(token),
        manifest_fingerprint(token),
    )
}

fn parse_cleanup_tombstone_file_name(
    file_name: &str,
) -> Option<(CleanupTombstoneKey, CleanupTombstoneKind)> {
    let mut parts = file_name.split('~');
    if parts.next()? != "satelle.sqlite3.cleanup" {
        return None;
    }
    let schema_version_text = parts.next()?;
    let schema_version = schema_version_text.parse::<i64>().ok()?;
    if schema_version.to_string() != schema_version_text {
        return None;
    }
    let backup_id_text = parts.next()?;
    let backup_id = Uuid::parse_str(backup_id_text).ok()?;
    let cleanup_id_text = parts.next()?;
    let cleanup_id = Uuid::parse_str(cleanup_id_text).ok()?;
    if backup_id.to_string() != backup_id_text
        || backup_id.get_version_num() != 7
        || cleanup_id.to_string() != cleanup_id_text
        || cleanup_id.get_version_num() != 7
    {
        return None;
    }
    let backup_fingerprint = parts.next()?;
    let manifest_fingerprint = parts.next()?;
    if !is_short_fingerprint(backup_fingerprint) || !is_short_fingerprint(manifest_fingerprint) {
        return None;
    }
    let kind = match parts.next()? {
        "backup.tombstone" => CleanupTombstoneKind::Backup,
        "manifest.tombstone" => CleanupTombstoneKind::Manifest,
        _ => return None,
    };
    if parts.next().is_some() {
        return None;
    }
    Some((
        CleanupTombstoneKey {
            schema_version,
            backup_id,
            cleanup_id,
            backup_fingerprint: backup_fingerprint.to_owned(),
            manifest_fingerprint: manifest_fingerprint.to_owned(),
        },
        kind,
    ))
}

fn cleanup_deleting_file_name(key: &CleanupTombstoneKey, kind: CleanupDeletingKind) -> String {
    let kind = match kind {
        CleanupDeletingKind::Backup => "backup",
        CleanupDeletingKind::Manifest => "manifest",
    };
    format!(
        "satelle.sqlite3.cleanup~{}~{}~{}~{}~{}~{kind}.deleting",
        key.schema_version,
        key.backup_id,
        key.cleanup_id,
        key.backup_fingerprint,
        key.manifest_fingerprint,
    )
}

fn parse_cleanup_deleting_file_name(
    file_name: &str,
) -> Option<(CleanupTombstoneKey, CleanupDeletingKind)> {
    let (base, kind) = if let Some(base) = file_name.strip_suffix("~backup.deleting") {
        (base, CleanupDeletingKind::Backup)
    } else {
        (
            file_name.strip_suffix("~manifest.deleting")?,
            CleanupDeletingKind::Manifest,
        )
    };
    let synthetic = format!("{base}~backup.tombstone");
    let (key, _) = parse_cleanup_tombstone_file_name(&synthetic)?;
    Some((key, kind))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn is_restore_internal_sqlite_leaf(file_name: &str) -> bool {
    parse_restore_staged_file_name(file_name).is_some()
        || parse_cleanup_tombstone_file_name(file_name)
            .is_some_and(|(_, kind)| kind == CleanupTombstoneKind::Backup)
}

fn is_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn is_short_fingerprint(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn digest_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!(
        "sha256:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn digest_file(mut file: &File, fallback: StorageErrorKind) -> Result<String, StorageError> {
    file.rewind()
        .map_err(|source| StorageError::with_source(fallback, source))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|source| StorageError::with_source(fallback, source))?;
        if bytes_read == 0 {
            break;
        }
        digest.update(&buffer[..bytes_read]);
    }
    Ok(format!(
        "sha256:{}",
        digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

fn read_backup_manifest(
    state_directory: &StateDirectory,
    manifest_file_name: &str,
) -> Result<ReadManifest, StorageError> {
    const MAXIMUM_MANIFEST_BYTES: u64 = 64 * 1024;

    let mut manifest_file = open_private_leaf(
        state_directory,
        manifest_file_name,
        LeafOpenMode::ExistingPrivateGuarded,
        StorageErrorKind::InvalidInput,
    )?
    .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidInput))?;
    let identity = leaf_identity(&manifest_file, StorageErrorKind::InvalidInput)?;
    let mut bytes = Vec::new();
    Read::take(&mut manifest_file, MAXIMUM_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| StorageError::with_source(StorageErrorKind::InvalidInput, source))?;
    if bytes.len() as u64 > MAXIMUM_MANIFEST_BYTES {
        return Err(StorageError::new(StorageErrorKind::InvalidInput));
    }
    let manifest = serde_json::from_slice(&bytes)
        .map_err(|source| StorageError::with_source(StorageErrorKind::InvalidInput, source))?;
    Ok(ReadManifest {
        manifest,
        file: manifest_file,
        identity,
        digest: digest_bytes(&bytes),
    })
}

fn validate_manifest_contract(
    backup_file_name: &str,
    parsed_name: MigrationBackupName,
    manifest: &MigrationBackupManifest,
) -> Result<(), StorageError> {
    let schema_is_supported = MIGRATIONS
        .iter()
        .any(|migration| migration.version == manifest.source_schema_version);
    if manifest.manifest_version != BACKUP_FORMAT_VERSION
        || manifest.backup_file != backup_file_name
        || manifest.source_schema_version != parsed_name.schema_version
        || !is_sha256_digest(&manifest.source_database_digest)
        || parse_time(&manifest.created_at).is_err()
        || manifest.satelle_version.is_empty()
        || manifest.restore_compatibility.database_format != "sqlite3"
        || manifest.restore_compatibility.schema_version != manifest.source_schema_version
        || !manifest.restore_compatibility.explicit_restore_required
        || !schema_is_supported
    {
        return Err(StorageError::new(StorageErrorKind::InvalidInput));
    }
    Ok(())
}

fn validate_backup_migration_state(
    connection: &Connection,
    source_schema_version: i64,
) -> Result<(), StorageError> {
    let user_version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|source| sqlite_error(StorageErrorKind::IntegrityCheckFailed, source))?;
    let expected_count = MIGRATIONS
        .iter()
        .position(|migration| migration.version == source_schema_version)
        .map(|index| index + 1)
        .ok_or_else(|| StorageError::new(StorageErrorKind::IntegrityCheckFailed))?;
    let applied =
        load_applied_migrations_with_kind(connection, StorageErrorKind::IntegrityCheckFailed)?;
    if user_version != source_schema_version
        || applied.len() != expected_count
        || applied
            .iter()
            .zip(MIGRATIONS.iter().take(expected_count))
            .any(|((version, checksum), migration)| {
                *version != migration.version || *checksum != migration_checksum(migration.sql)
            })
    {
        return Err(StorageError::new(StorageErrorKind::IntegrityCheckFailed));
    }
    Ok(())
}

fn validate_migration_backup_at(
    state_root: &Path,
    state_directory: &StateDirectory,
    backup_file_name: &str,
    physical_backup_file_name: &str,
    physical_manifest_file_name: &str,
) -> Result<ValidatedMigrationBackup, StorageError> {
    validate_migration_backup_at_with_hook(
        state_root,
        state_directory,
        backup_file_name,
        physical_backup_file_name,
        physical_manifest_file_name,
        |_| Ok(()),
    )
}

fn validate_migration_backup_at_with_hook(
    state_root: &Path,
    state_directory: &StateDirectory,
    backup_file_name: &str,
    physical_backup_file_name: &str,
    physical_manifest_file_name: &str,
    mut hook: impl FnMut(ValidationStep) -> Result<(), StorageError>,
) -> Result<ValidatedMigrationBackup, StorageError> {
    #[cfg(unix)]
    let _ = state_root;
    let parsed_name = parse_migration_backup_file_name(backup_file_name)
        .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidInput))?;
    let manifest_read = read_backup_manifest(state_directory, physical_manifest_file_name)?;
    validate_manifest_contract(backup_file_name, parsed_name, &manifest_read.manifest)?;

    let backup_file = open_private_leaf(
        state_directory,
        physical_backup_file_name,
        LeafOpenMode::ExistingPrivateGuarded,
        StorageErrorKind::InvalidInput,
    )?
    .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidInput))?;
    let backup_identity = leaf_identity(&backup_file, StorageErrorKind::InvalidInput)?;
    let source_database_digest = digest_file(&backup_file, StorageErrorKind::IntegrityCheckFailed)?;
    if source_database_digest != manifest_read.manifest.source_database_digest {
        return Err(StorageError::new(StorageErrorKind::IntegrityCheckFailed));
    }
    hook(ValidationStep::DigestVerified)?;

    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    #[cfg(any(target_os = "linux", windows))]
    {
        let staging_file_name = format!("satelle.sqlite3.restore-{}.staged", Uuid::now_v7());
        let staging_identity = {
            let mut source = &backup_file;
            source.rewind().map_err(|source| {
                StorageError::with_source(StorageErrorKind::IntegrityCheckFailed, source)
            })?;
            let mut staging = open_private_leaf(
                state_directory,
                &staging_file_name,
                LeafOpenMode::CreateNew,
                StorageErrorKind::IntegrityCheckFailed,
            )?
            .ok_or_else(|| StorageError::new(StorageErrorKind::IntegrityCheckFailed))?;
            std::io::copy(&mut source, &mut staging).map_err(|source| {
                StorageError::with_source(StorageErrorKind::IntegrityCheckFailed, source)
            })?;
            staging.sync_all().map_err(|source| {
                StorageError::with_source(StorageErrorKind::IntegrityCheckFailed, source)
            })?;
            leaf_identity(&staging, StorageErrorKind::IntegrityCheckFailed)?
        };
        let validation_result = (|| {
            #[cfg(target_os = "linux")]
            let validation = Connection::open_with_flags_and_vfs(
                sqlite_leaf_path(state_root, state_directory, &staging_file_name),
                flags,
                unix_vfs::name()?,
            )
            .map_err(|source| sqlite_error(StorageErrorKind::IntegrityCheckFailed, source))?;
            #[cfg(windows)]
            let validation = Connection::open_with_flags(
                sqlite_leaf_path(state_root, state_directory, &staging_file_name),
                flags,
            )
            .map_err(|source| sqlite_error(StorageErrorKind::IntegrityCheckFailed, source))?;
            validate_backup_migration_state(
                &validation,
                manifest_read.manifest.source_schema_version,
            )?;
            verify_integrity(&validation)
        })();
        // SQLite can create read-only WAL coordination files on Windows. Keep
        // those artifacts in the unique validation namespace and remove them
        // only after the validation connection has closed.
        #[cfg(windows)]
        remove_sqlite_validation_sidecars(state_directory, &staging_file_name)?;
        let removed =
            remove_private_leaf_checked(state_directory, &staging_file_name, staging_identity)?;
        validation_result?;
        if !removed {
            return Err(StorageError::new(StorageErrorKind::StateConflict));
        }
    }
    #[cfg(target_os = "macos")]
    {
        let validation_registration = unix_vfs::register_validation_file(&backup_file)?;
        let validation = Connection::open_with_flags_and_vfs(
            validation_registration.path(),
            flags,
            unix_vfs::name()?,
        )
        .map_err(|source| sqlite_error(StorageErrorKind::IntegrityCheckFailed, source))?;
        validate_backup_migration_state(&validation, manifest_read.manifest.source_schema_version)?;
        verify_integrity(&validation)?;
    }
    // The digest and SQLite checks above used the same guarded object. Check
    // the object again before releasing it, then prove both authority names
    // still resolve to those held objects.
    if digest_file(&backup_file, StorageErrorKind::IntegrityCheckFailed)? != source_database_digest
        || digest_file(&manifest_read.file, StorageErrorKind::InvalidInput)? != manifest_read.digest
        || open_private_leaf_identity(state_directory, physical_backup_file_name)?
            != Some(backup_identity)
        || open_private_leaf_identity(state_directory, physical_manifest_file_name)?
            != Some(manifest_read.identity)
    {
        return Err(StorageError::new(StorageErrorKind::StateConflict));
    }

    Ok(ValidatedMigrationBackup {
        backup_file_name: backup_file_name.to_owned(),
        manifest_file_name: format!("{backup_file_name}.json"),
        token: RestorePointToken {
            backup_id: parsed_name.backup_id,
            schema_version: parsed_name.schema_version,
            source_database_digest,
            manifest_digest: manifest_read.digest,
            backup_identity,
            manifest_identity: manifest_read.identity,
        },
    })
}

/// Validates one migration backup without granting authority to activate it.
///
/// The caller supplies a state directory that was prepared through Satelle's
/// platform security boundary. This primitive does not acquire a Maintenance
/// Lease or Bootstrap Lock; the command layer must hold the applicable guard
/// before using the returned value for activation or cleanup.
pub(super) fn validate_migration_backup(
    state_root: &Path,
    state_directory: &StateDirectory,
    backup_file_name: &str,
) -> Result<ValidatedMigrationBackup, StorageError> {
    let manifest_file_name = format!("{backup_file_name}.json");
    validate_migration_backup_at(
        state_root,
        state_directory,
        backup_file_name,
        backup_file_name,
        &manifest_file_name,
    )
}

#[cfg(test)]
fn validate_migration_backup_with_hook(
    state_root: &Path,
    state_directory: &StateDirectory,
    backup_file_name: &str,
    hook: impl FnMut(ValidationStep) -> Result<(), StorageError>,
) -> Result<ValidatedMigrationBackup, StorageError> {
    let manifest_file_name = format!("{backup_file_name}.json");
    validate_migration_backup_at_with_hook(
        state_root,
        state_directory,
        backup_file_name,
        backup_file_name,
        &manifest_file_name,
        hook,
    )
}

fn copy_private_leaf(
    state_directory: &StateDirectory,
    source_file_name: &str,
    destination_file_name: &str,
    required: bool,
) -> Result<bool, StorageError> {
    let Some(mut source) = open_private_leaf(
        state_directory,
        source_file_name,
        LeafOpenMode::ExistingPrivate,
        StorageErrorKind::OperationFailed,
    )?
    else {
        if required {
            return Err(StorageError::new(StorageErrorKind::OperationFailed));
        }
        return Ok(false);
    };
    let mut destination = open_private_leaf(
        state_directory,
        destination_file_name,
        LeafOpenMode::CreateNew,
        StorageErrorKind::OperationFailed,
    )?
    .ok_or_else(|| StorageError::new(StorageErrorKind::OperationFailed))?;
    std::io::copy(&mut source, &mut destination)
        .map_err(|source| StorageError::with_source(StorageErrorKind::OperationFailed, source))?;
    destination
        .sync_all()
        .map_err(|source| StorageError::with_source(StorageErrorKind::OperationFailed, source))?;
    Ok(true)
}

#[cfg(windows)]
fn remove_sqlite_validation_sidecars(
    state_directory: &StateDirectory,
    database_file_name: &str,
) -> Result<(), StorageError> {
    for suffix in PROTECTED_FILE_NAMES[2..]
        .iter()
        .map(|file_name| &file_name[DATABASE_FILE_NAME.len()..])
    {
        let sidecar_file_name = format!("{database_file_name}{suffix}");
        // SQLite creates these files underneath the already-pinned private
        // directory. Canonicalize their inherited ACL before using the same
        // identity-checked deletion path as every other protected leaf.
        let Some(file) = open_private_leaf(
            state_directory,
            &sidecar_file_name,
            LeafOpenMode::Existing,
            StorageErrorKind::OperationFailed,
        )?
        else {
            continue;
        };
        let identity = leaf_identity(&file, StorageErrorKind::OperationFailed)?;
        drop(file);
        remove_private_leaf_checked(state_directory, &sidecar_file_name, identity)?;
    }
    Ok(())
}

fn short_digest(digest: Sha256) -> String {
    digest
        .finalize()
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn backup_fingerprint(token: &RestorePointToken) -> String {
    backup_fingerprint_from_parts(
        token.backup_id,
        token.schema_version,
        &token.source_database_digest,
        token.backup_identity,
    )
}

fn backup_fingerprint_from_parts(
    backup_id: Uuid,
    schema_version: i64,
    source_database_digest: &str,
    backup_identity: LeafIdentity,
) -> String {
    let mut digest = Sha256::new();
    digest.update(backup_id.as_bytes());
    digest.update(schema_version.to_le_bytes());
    digest.update(source_database_digest.as_bytes());
    backup_identity.update_digest(&mut digest);
    short_digest(digest)
}

fn manifest_fingerprint(token: &RestorePointToken) -> String {
    manifest_fingerprint_from_parts(
        token.backup_id,
        token.schema_version,
        &token.manifest_digest,
        token.manifest_identity,
    )
}

fn manifest_fingerprint_from_parts(
    backup_id: Uuid,
    schema_version: i64,
    manifest_digest: &str,
    manifest_identity: LeafIdentity,
) -> String {
    let mut digest = Sha256::new();
    digest.update(backup_id.as_bytes());
    digest.update(schema_version.to_le_bytes());
    digest.update(manifest_digest.as_bytes());
    manifest_identity.update_digest(&mut digest);
    short_digest(digest)
}

fn open_private_leaf_identity(
    state_directory: &StateDirectory,
    file_name: &str,
) -> Result<Option<LeafIdentity>, StorageError> {
    let Some(file) = open_private_leaf(
        state_directory,
        file_name,
        LeafOpenMode::ExistingPrivate,
        StorageErrorKind::OperationFailed,
    )?
    else {
        return Ok(None);
    };
    leaf_identity(&file, StorageErrorKind::OperationFailed).map(Some)
}

fn move_private_leaf_durable(
    state_directory: &StateDirectory,
    source_file_name: &str,
    destination_file_name: &str,
    expected_identity: LeafIdentity,
) -> Result<(), StorageError> {
    move_private_leaf_durable_with_hook(
        state_directory,
        source_file_name,
        destination_file_name,
        expected_identity,
        || Ok(()),
    )
}

fn move_private_leaf_durable_with_hook(
    state_directory: &StateDirectory,
    source_file_name: &str,
    destination_file_name: &str,
    expected_identity: LeafIdentity,
    before_move: impl FnOnce() -> Result<(), StorageError>,
) -> Result<(), StorageError> {
    before_move()?;
    state_directory.move_leaf(source_file_name, destination_file_name)?;
    state_directory.sync_for(StorageErrorKind::OperationFailed)?;
    if open_private_leaf_identity(state_directory, destination_file_name)?
        != Some(expected_identity)
    {
        // The rename isolated an identity-distinct replacement under the
        // unique quarantine name. Restore its bytes at the canonical name
        // without consuming that evidence, and never overwrite a newer
        // object that may have appeared there after the rename.
        copy_private_leaf(
            state_directory,
            destination_file_name,
            source_file_name,
            true,
        )?;
        state_directory.sync_for(StorageErrorKind::OperationFailed)?;
        return Err(StorageError::new(StorageErrorKind::StateConflict));
    }
    Ok(())
}

fn move_current_private_leaf_durable(
    state_directory: &StateDirectory,
    source_file_name: &str,
    destination_file_name: &str,
) -> Result<LeafIdentity, StorageError> {
    state_directory.move_leaf(source_file_name, destination_file_name)?;
    state_directory.sync_for(StorageErrorKind::OperationFailed)?;
    open_private_leaf_identity(state_directory, destination_file_name)?
        .ok_or_else(|| StorageError::new(StorageErrorKind::StateConflict))
}

fn remove_private_leaf_checked(
    state_directory: &StateDirectory,
    file_name: &str,
    expected_identity: LeafIdentity,
) -> Result<bool, StorageError> {
    let removed = state_directory.delete_leaf(file_name, expected_identity)?;
    if removed {
        state_directory.sync_for(StorageErrorKind::OperationFailed)?;
    }
    Ok(removed)
}

fn restore_prior_active_store(
    state_directory: &StateDirectory,
    failed_store_file_name: &str,
    failed_store_identity: LeafIdentity,
    failed_sidecar_file_names: &[String],
    activation_id: Uuid,
) -> Result<(), StorageError> {
    if open_private_leaf_identity(state_directory, DATABASE_FILE_NAME)?.is_some() {
        let rejected_id = Uuid::now_v7();
        let rejected_name =
            format!("satelle.sqlite3.rejected-{activation_id}-{rejected_id}.sqlite3");
        move_current_private_leaf_durable(state_directory, DATABASE_FILE_NAME, &rejected_name)?;
    }
    move_private_leaf_durable(
        state_directory,
        failed_store_file_name,
        DATABASE_FILE_NAME,
        failed_store_identity,
    )?;
    restore_prior_active_sidecars(state_directory, failed_sidecar_file_names)
}

fn restore_prior_active_sidecars(
    state_directory: &StateDirectory,
    failed_sidecar_file_names: &[String],
) -> Result<(), StorageError> {
    // An activation error must leave the old SQLite file set reopenable, not
    // merely recoverable under internal quarantine names.
    for failed_sidecar_file_name in failed_sidecar_file_names {
        let suffix = if failed_sidecar_file_name.ends_with("-wal") {
            "-wal"
        } else if failed_sidecar_file_name.ends_with("-shm") {
            "-shm"
        } else if failed_sidecar_file_name.ends_with("-journal") {
            "-journal"
        } else {
            return Err(StorageError::new(StorageErrorKind::StateConflict));
        };
        let active_sidecar_file_name = format!("{DATABASE_FILE_NAME}{suffix}");
        let identity = open_private_leaf_identity(state_directory, failed_sidecar_file_name)?
            .ok_or_else(|| StorageError::new(StorageErrorKind::StateConflict))?;
        move_private_leaf_durable(
            state_directory,
            failed_sidecar_file_name,
            &active_sidecar_file_name,
            identity,
        )?;
    }
    Ok(())
}

fn same_restore_content_and_manifest(
    left: &ValidatedMigrationBackup,
    right: &ValidatedMigrationBackup,
) -> bool {
    left.backup_file_name == right.backup_file_name
        && left.token.backup_id == right.token.backup_id
        && left.token.schema_version == right.token.schema_version
        && left.token.source_database_digest == right.token.source_database_digest
        && left.token.manifest_digest == right.token.manifest_digest
        && left.token.manifest_identity == right.token.manifest_identity
}

/// Atomically installs an already validated backup after preserving the
/// current store and any SQLite sidecars in durable, owner-private files.
///
/// The caller must stop API service, close every SQLite connection, and hold
/// the applicable Maintenance Lease or Bootstrap Lock. This function does not
/// create a second operation guard or restart the service.
#[allow(
    dead_code,
    reason = "the guarded restore command owner will call this storage-only seam"
)]
pub(super) fn activate_migration_backup(
    state_root: &Path,
    state_directory: &StateDirectory,
    backup: &ValidatedMigrationBackup,
) -> Result<RestoreActivation, StorageError> {
    activate_migration_backup_with_hook(state_root, state_directory, backup, |_| Ok(()))
}

fn activate_migration_backup_with_hook(
    state_root: &Path,
    state_directory: &StateDirectory,
    backup: &ValidatedMigrationBackup,
    mut hook: impl FnMut(ActivationStep) -> Result<(), StorageError>,
) -> Result<RestoreActivation, StorageError> {
    // Consent and guard acquisition may happen after initial validation. Check
    // the named restore point again at the mutation boundary so a changed file
    // cannot inherit an earlier validation result.
    let current = validate_migration_backup(state_root, state_directory, &backup.backup_file_name)?;
    if current.token != backup.token {
        return Err(StorageError::new(StorageErrorKind::StateConflict));
    }
    hook(ActivationStep::CandidateValidated)?;

    let activation_id = Uuid::now_v7();
    let staged_file_name = format!("satelle.sqlite3.restore-{activation_id}.staged");
    let failed_store_file_name = format!("satelle.sqlite3.failed-{activation_id}.sqlite3");
    copy_private_leaf(
        state_directory,
        &backup.backup_file_name,
        &staged_file_name,
        true,
    )?;
    state_directory.sync_for(StorageErrorKind::OperationFailed)?;
    let staged = validate_migration_backup_at(
        state_root,
        state_directory,
        &backup.backup_file_name,
        &staged_file_name,
        &backup.manifest_file_name,
    )?;
    if !same_restore_content_and_manifest(backup, &staged) {
        return Err(StorageError::new(StorageErrorKind::StateConflict));
    }
    hook(ActivationStep::StagedValidated)?;

    let mut failed_sidecar_file_names = Vec::new();
    for sidecar_file_name in &PROTECTED_FILE_NAMES[2..] {
        let Some(identity) = open_private_leaf_identity(state_directory, sidecar_file_name)? else {
            continue;
        };
        let failed_sidecar_file_name = format!(
            "{failed_store_file_name}{}",
            &sidecar_file_name[DATABASE_FILE_NAME.len()..]
        );
        move_private_leaf_durable(
            state_directory,
            sidecar_file_name,
            &failed_sidecar_file_name,
            identity,
        )?;
        failed_sidecar_file_names.push(failed_sidecar_file_name);
    }
    if let Err(error) = hook(ActivationStep::SidecarsMovedDurably) {
        restore_prior_active_sidecars(state_directory, &failed_sidecar_file_names)?;
        return Err(error);
    }

    let staged_before_install = match validate_migration_backup_at(
        state_root,
        state_directory,
        &backup.backup_file_name,
        &staged_file_name,
        &backup.manifest_file_name,
    ) {
        Ok(staged_before_install) => staged_before_install,
        Err(error) => {
            restore_prior_active_sidecars(state_directory, &failed_sidecar_file_names)?;
            return Err(error);
        }
    };
    if staged_before_install.token != staged.token {
        restore_prior_active_sidecars(state_directory, &failed_sidecar_file_names)?;
        return Err(StorageError::new(StorageErrorKind::StateConflict));
    }

    // Remove the prior active name without overwriting it. From this point
    // until installation succeeds, every error restores this exact object.
    let failed_store_identity = move_current_private_leaf_durable(
        state_directory,
        DATABASE_FILE_NAME,
        &failed_store_file_name,
    )?;
    if let Err(error) = hook(ActivationStep::RecoveryStateDurable) {
        restore_prior_active_store(
            state_directory,
            &failed_store_file_name,
            failed_store_identity,
            &failed_sidecar_file_names,
            activation_id,
        )?;
        return Err(error);
    }

    let install = move_private_leaf_durable_with_hook(
        state_directory,
        &staged_file_name,
        DATABASE_FILE_NAME,
        staged.token.backup_identity,
        || hook(ActivationStep::BeforeStagedInstallMove),
    );
    if let Err(error) = install {
        restore_prior_active_store(
            state_directory,
            &failed_store_file_name,
            failed_store_identity,
            &failed_sidecar_file_names,
            activation_id,
        )?;
        return Err(error);
    }
    if let Err(error) = hook(ActivationStep::InstalledBeforeValidation) {
        restore_prior_active_store(
            state_directory,
            &failed_store_file_name,
            failed_store_identity,
            &failed_sidecar_file_names,
            activation_id,
        )?;
        return Err(error);
    }

    let installed = validate_migration_backup_at(
        state_root,
        state_directory,
        &backup.backup_file_name,
        DATABASE_FILE_NAME,
        &backup.manifest_file_name,
    );
    match installed {
        Ok(installed) if installed.token == staged.token => {}
        Ok(_) | Err(_) => {
            restore_prior_active_store(
                state_directory,
                &failed_store_file_name,
                failed_store_identity,
                &failed_sidecar_file_names,
                activation_id,
            )?;
            return Err(StorageError::new(StorageErrorKind::StateConflict));
        }
    }
    hook(ActivationStep::ReplacementDurable)?;

    Ok(RestoreActivation {
        failed_store_file_name,
        failed_sidecar_file_names,
    })
}

/// Deletes only validated backups older than the newest two restore points.
/// Malformed, incompatible, unsafe, or invalid lookalikes are ignored.
#[allow(
    dead_code,
    reason = "the consented backup-cleanup command owner will call this storage-only seam"
)]
pub(super) fn cleanup_migration_backups(
    state_root: &Path,
    state_directory: &StateDirectory,
) -> Result<Vec<String>, StorageError> {
    cleanup_migration_backups_with_hook(state_root, state_directory, |_| Ok(()))
}

fn logical_backup_file_name(key: &CleanupTombstoneKey) -> String {
    format!(
        "satelle.sqlite3.migration-v{}-{}.backup",
        key.schema_version, key.backup_id
    )
}

fn list_validated_migration_backups(
    state_root: &Path,
    state_directory: &StateDirectory,
) -> Result<Vec<ValidatedMigrationBackup>, StorageError> {
    let mut validated = Vec::new();
    for file_name in state_directory.leaf_names()? {
        if parse_migration_backup_file_name(&file_name).is_none() {
            continue;
        }
        if let Ok(backup) = validate_migration_backup(state_root, state_directory, &file_name) {
            validated.push(backup);
        }
    }
    validated.sort_by_key(|backup| backup.token.backup_id);
    Ok(validated)
}

fn tombstone_matches_token(key: &CleanupTombstoneKey, token: &RestorePointToken) -> bool {
    key.schema_version == token.schema_version
        && key.backup_id == token.backup_id
        && key.backup_fingerprint == backup_fingerprint(token)
        && key.manifest_fingerprint == manifest_fingerprint(token)
}

fn delete_quarantined_pair(
    state_directory: &StateDirectory,
    key: &CleanupTombstoneKey,
    backup_tombstone_file_name: &str,
    manifest_tombstone_file_name: &str,
    token: &RestorePointToken,
    hook: &mut impl FnMut(CleanupStep) -> Result<(), StorageError>,
    removed: &mut Vec<String>,
) -> Result<(), StorageError> {
    let logical_backup_file_name = logical_backup_file_name(key);
    hook(CleanupStep::BeforeBackupDelete)?;
    let backup_deleting_file_name = cleanup_deleting_file_name(key, CleanupDeletingKind::Backup);
    move_private_leaf_durable(
        state_directory,
        backup_tombstone_file_name,
        &backup_deleting_file_name,
        token.backup_identity,
    )?;
    hook(CleanupStep::BackupDeleteCommitted)?;
    if !remove_private_leaf_checked(
        state_directory,
        &backup_deleting_file_name,
        token.backup_identity,
    )? {
        return Err(StorageError::new(StorageErrorKind::OperationFailed));
    }
    hook(CleanupStep::BeforeManifestDelete)?;
    let manifest_deleting_file_name =
        cleanup_deleting_file_name(key, CleanupDeletingKind::Manifest);
    move_private_leaf_durable(
        state_directory,
        manifest_tombstone_file_name,
        &manifest_deleting_file_name,
        token.manifest_identity,
    )?;
    hook(CleanupStep::ManifestDeleteCommitted)?;
    if !remove_private_leaf_checked(
        state_directory,
        &manifest_deleting_file_name,
        token.manifest_identity,
    )? {
        return Err(StorageError::new(StorageErrorKind::OperationFailed));
    }
    if !removed
        .iter()
        .any(|removed_name| removed_name == &logical_backup_file_name)
    {
        removed.push(logical_backup_file_name);
    }
    Ok(())
}

fn resume_cleanup_deleting(
    state_directory: &StateDirectory,
    hook: &mut impl FnMut(CleanupStep) -> Result<(), StorageError>,
) -> Result<(), StorageError> {
    for file_name in state_directory.leaf_names()? {
        let Some((key, kind)) = parse_cleanup_deleting_file_name(&file_name) else {
            continue;
        };
        match kind {
            CleanupDeletingKind::Backup => {
                let Some(file) = open_private_leaf(
                    state_directory,
                    &file_name,
                    LeafOpenMode::ExistingPrivateGuarded,
                    StorageErrorKind::OperationFailed,
                )?
                else {
                    continue;
                };
                let identity = leaf_identity(&file, StorageErrorKind::OperationFailed)?;
                let digest = digest_file(&file, StorageErrorKind::OperationFailed)?;
                if key.backup_fingerprint
                    != backup_fingerprint_from_parts(
                        key.backup_id,
                        key.schema_version,
                        &digest,
                        identity,
                    )
                {
                    continue;
                }
                drop(file);
                hook(CleanupStep::BackupDeleteCommitted)?;
                remove_private_leaf_checked(state_directory, &file_name, identity)?;
            }
            CleanupDeletingKind::Manifest => {
                let manifest_read = match read_backup_manifest(state_directory, &file_name) {
                    Ok(manifest) => manifest,
                    Err(_) => continue,
                };
                let logical_backup_file_name = logical_backup_file_name(&key);
                let Some(parsed_name) = parse_migration_backup_file_name(&logical_backup_file_name)
                else {
                    continue;
                };
                if validate_manifest_contract(
                    &logical_backup_file_name,
                    parsed_name,
                    &manifest_read.manifest,
                )
                .is_err()
                    || key.manifest_fingerprint
                        != manifest_fingerprint_from_parts(
                            key.backup_id,
                            key.schema_version,
                            &manifest_read.digest,
                            manifest_read.identity,
                        )
                {
                    continue;
                }
                let identity = manifest_read.identity;
                drop(manifest_read);
                hook(CleanupStep::ManifestDeleteCommitted)?;
                remove_private_leaf_checked(state_directory, &file_name, identity)?;
            }
        }
    }
    Ok(())
}

fn resume_cleanup_tombstones(
    state_root: &Path,
    state_directory: &StateDirectory,
    hook: &mut impl FnMut(CleanupStep) -> Result<(), StorageError>,
    removed: &mut Vec<String>,
) -> Result<(), StorageError> {
    resume_cleanup_deleting(state_directory, hook)?;
    let retained_valid_count = list_validated_migration_backups(state_root, state_directory)?.len();
    let mut tombstones = BTreeMap::<CleanupTombstoneKey, CleanupTombstonePair>::new();
    for file_name in state_directory.leaf_names()? {
        let Some((key, kind)) = parse_cleanup_tombstone_file_name(&file_name) else {
            continue;
        };
        let pair = tombstones.entry(key).or_default();
        match kind {
            CleanupTombstoneKind::Backup => pair.backup_file_name = Some(file_name),
            CleanupTombstoneKind::Manifest => pair.manifest_file_name = Some(file_name),
        }
    }

    for (key, pair) in tombstones {
        let logical_backup_file_name = logical_backup_file_name(&key);
        let logical_manifest_file_name = format!("{logical_backup_file_name}.json");
        match (pair.backup_file_name, pair.manifest_file_name) {
            (Some(backup_tombstone), Some(manifest_tombstone)) => {
                if retained_valid_count < 2 {
                    continue;
                }
                let validated = match validate_migration_backup_at(
                    state_root,
                    state_directory,
                    &logical_backup_file_name,
                    &backup_tombstone,
                    &manifest_tombstone,
                ) {
                    Ok(validated) => validated,
                    Err(_) => continue,
                };
                if !tombstone_matches_token(&key, &validated.token) {
                    continue;
                }
                delete_quarantined_pair(
                    state_directory,
                    &key,
                    &backup_tombstone,
                    &manifest_tombstone,
                    &validated.token,
                    hook,
                    removed,
                )?;
            }
            (Some(backup_tombstone), None) => {
                if retained_valid_count < 2 {
                    continue;
                }
                if open_private_leaf_identity(state_directory, &logical_backup_file_name)?.is_some()
                {
                    // A canonical backup owns the canonical manifest. It may
                    // be an independently valid replacement pair and must not
                    // be consumed to complete an older interrupted cleanup.
                    return Err(StorageError::new(StorageErrorKind::StateConflict));
                }
                let validated = match validate_migration_backup_at(
                    state_root,
                    state_directory,
                    &logical_backup_file_name,
                    &backup_tombstone,
                    &logical_manifest_file_name,
                ) {
                    Ok(validated) => validated,
                    Err(_) => continue,
                };
                if !tombstone_matches_token(&key, &validated.token) {
                    continue;
                }
                let manifest_tombstone = cleanup_tombstone_file_name(
                    &validated.token,
                    key.cleanup_id,
                    CleanupTombstoneKind::Manifest,
                );
                move_private_leaf_durable_with_hook(
                    state_directory,
                    &logical_manifest_file_name,
                    &manifest_tombstone,
                    validated.token.manifest_identity,
                    || hook(CleanupStep::BeforeManifestQuarantineMove),
                )?;
                hook(CleanupStep::PairQuarantined)?;
                let quarantined = validate_migration_backup_at(
                    state_root,
                    state_directory,
                    &logical_backup_file_name,
                    &backup_tombstone,
                    &manifest_tombstone,
                )?;
                if quarantined.token != validated.token {
                    return Err(StorageError::new(StorageErrorKind::StateConflict));
                }
                delete_quarantined_pair(
                    state_directory,
                    &key,
                    &backup_tombstone,
                    &manifest_tombstone,
                    &quarantined.token,
                    hook,
                    removed,
                )?;
            }
            (None, Some(manifest_tombstone)) => {
                let manifest_read = match read_backup_manifest(state_directory, &manifest_tombstone)
                {
                    Ok(manifest) => manifest,
                    Err(_) => continue,
                };
                let parsed_name = match parse_migration_backup_file_name(&logical_backup_file_name)
                {
                    Some(parsed) => parsed,
                    None => continue,
                };
                if validate_manifest_contract(
                    &logical_backup_file_name,
                    parsed_name,
                    &manifest_read.manifest,
                )
                .is_err()
                    || key.manifest_fingerprint
                        != manifest_fingerprint_from_parts(
                            key.backup_id,
                            key.schema_version,
                            &manifest_read.digest,
                            manifest_read.identity,
                        )
                {
                    continue;
                }
                hook(CleanupStep::BeforeManifestDelete)?;
                let manifest_deleting_file_name =
                    cleanup_deleting_file_name(&key, CleanupDeletingKind::Manifest);
                let manifest_identity = manifest_read.identity;
                drop(manifest_read);
                move_private_leaf_durable(
                    state_directory,
                    &manifest_tombstone,
                    &manifest_deleting_file_name,
                    manifest_identity,
                )?;
                hook(CleanupStep::ManifestDeleteCommitted)?;
                if remove_private_leaf_checked(
                    state_directory,
                    &manifest_deleting_file_name,
                    manifest_identity,
                )? && !removed
                    .iter()
                    .any(|removed_name| removed_name == &logical_backup_file_name)
                {
                    removed.push(logical_backup_file_name);
                }
            }
            (None, None) => {}
        }
    }
    Ok(())
}

fn cleanup_migration_backups_with_hook(
    state_root: &Path,
    state_directory: &StateDirectory,
    mut hook: impl FnMut(CleanupStep) -> Result<(), StorageError>,
) -> Result<Vec<String>, StorageError> {
    let mut removed = Vec::new();
    resume_cleanup_tombstones(state_root, state_directory, &mut hook, &mut removed)?;

    let validated = list_validated_migration_backups(state_root, state_directory)?;
    let delete_count = validated.len().saturating_sub(2);
    for backup in validated.into_iter().take(delete_count) {
        let fresh =
            validate_migration_backup(state_root, state_directory, &backup.backup_file_name)?;
        if fresh.token != backup.token {
            return Err(StorageError::new(StorageErrorKind::StateConflict));
        }
        hook(CleanupStep::CandidateValidated)?;

        let cleanup_id = Uuid::now_v7();
        let backup_tombstone =
            cleanup_tombstone_file_name(&backup.token, cleanup_id, CleanupTombstoneKind::Backup);
        let manifest_tombstone =
            cleanup_tombstone_file_name(&backup.token, cleanup_id, CleanupTombstoneKind::Manifest);
        move_private_leaf_durable_with_hook(
            state_directory,
            &backup.backup_file_name,
            &backup_tombstone,
            backup.token.backup_identity,
            || hook(CleanupStep::BeforeBackupQuarantineMove),
        )?;
        hook(CleanupStep::BackupQuarantined)?;

        if let Err(error) = move_private_leaf_durable_with_hook(
            state_directory,
            &backup.manifest_file_name,
            &manifest_tombstone,
            backup.token.manifest_identity,
            || hook(CleanupStep::BeforeManifestQuarantineMove),
        ) {
            if open_private_leaf_identity(state_directory, &backup.backup_file_name)?.is_none() {
                move_private_leaf_durable(
                    state_directory,
                    &backup_tombstone,
                    &backup.backup_file_name,
                    backup.token.backup_identity,
                )?;
            }
            return Err(error);
        }
        hook(CleanupStep::PairQuarantined)?;
        let quarantined = validate_migration_backup_at(
            state_root,
            state_directory,
            &backup.backup_file_name,
            &backup_tombstone,
            &manifest_tombstone,
        )?;
        if quarantined.token != backup.token {
            return Err(StorageError::new(StorageErrorKind::StateConflict));
        }
        delete_quarantined_pair(
            state_directory,
            &CleanupTombstoneKey {
                schema_version: backup.token.schema_version,
                backup_id: backup.token.backup_id,
                cleanup_id,
                backup_fingerprint: backup_fingerprint(&backup.token),
                manifest_fingerprint: manifest_fingerprint(&backup.token),
            },
            &backup_tombstone,
            &manifest_tombstone,
            &quarantined.token,
            &mut hook,
            &mut removed,
        )?;
    }
    Ok(removed)
}

fn migration_checksum(value: &str) -> String {
    let mut checksum = 0xcbf29ce484222325_u64;
    for byte in value.bytes() {
        checksum ^= u64::from(byte);
        checksum = checksum.wrapping_mul(0x100000001b3);
    }
    format!("fnv1a64:{checksum:016x}")
}

fn verify_integrity(connection: &Connection) -> Result<(), StorageError> {
    let mut statement = connection
        .prepare("PRAGMA integrity_check")
        .map_err(|source| sqlite_error(StorageErrorKind::IntegrityCheckFailed, source))?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|source| sqlite_error(StorageErrorKind::IntegrityCheckFailed, source))?;
    for row in rows {
        let result =
            row.map_err(|source| sqlite_error(StorageErrorKind::IntegrityCheckFailed, source))?;
        if result != "ok" {
            return Err(StorageError::new(StorageErrorKind::IntegrityCheckFailed));
        }
    }
    let foreign_key_violation: Option<i64> = connection
        .query_row(
            "SELECT 1 FROM pragma_foreign_key_check LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|source| sqlite_error(StorageErrorKind::IntegrityCheckFailed, source))?;
    if foreign_key_violation.is_some() {
        return Err(StorageError::new(StorageErrorKind::IntegrityCheckFailed));
    }
    let lease_inconsistency: i64 = connection
        .query_row(
            "SELECT EXISTS(\
                SELECT 1 FROM turns t \
                LEFT JOIN control_leases c ON c.turn_id = t.turn_id \
                WHERE (t.state IN ('starting', 'running', 'recovery_pending') AND c.turn_id IS NULL) \
                   OR (t.state IN ('completed', 'blocked', 'failed', 'stopped') AND c.turn_id IS NOT NULL)\
            )",
            [],
            |row| row.get(0),
        )
        .map_err(|source| sqlite_error(StorageErrorKind::IntegrityCheckFailed, source))?;
    if lease_inconsistency != 0 {
        return Err(StorageError::new(StorageErrorKind::IntegrityCheckFailed));
    }
    Ok(())
}
