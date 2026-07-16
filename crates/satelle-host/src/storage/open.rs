use super::codec::format_time;
use super::{StorageError, StorageErrorKind};
use rusqlite::backup::Backup;
use rusqlite::ffi::ErrorCode as SqliteErrorCode;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::Serialize;
use sha2::{Digest, Sha256};
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
const MIGRATIONS: [Migration; 4] = [
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
    CreateIfMissing,
    CreateNew,
}

#[derive(Serialize)]
struct MigrationBackupManifest<'a> {
    manifest_version: u32,
    backup_file: &'a str,
    source_schema_version: i64,
    source_database_digest: &'a str,
    created_at: String,
    satelle_version: &'static str,
    restore_compatibility: RestoreCompatibility,
}

#[derive(Serialize)]
struct RestoreCompatibility {
    database_format: &'static str,
    schema_version: i64,
    explicit_restore_required: bool,
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
        self.handle
            .sync_all()
            .map_err(|source| StorageError::with_source(StorageErrorKind::MigrationFailed, source))
    }

    #[cfg(windows)]
    fn sync(&self) -> Result<(), StorageError> {
        self.secure.sync()
    }
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
    state_root: &Path,
    _state_directory: &StateDirectory,
    file_name: &str,
) -> std::path::PathBuf {
    state_root.join(file_name)
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
    let mut flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    match mode {
        LeafOpenMode::Existing => {}
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
        Err(rustix::io::Errno::NOENT) if matches!(mode, LeafOpenMode::Existing) => return Ok(None),
        Err(source) => return Err(secure_open_error(fallback, source)),
    };
    let metadata = rustix::fs::fstat(&descriptor)
        .map_err(|source| StorageError::with_source(fallback, source))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_nlink != 1
    {
        return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
    }
    rustix::fs::fchmod(&descriptor, Mode::RUSR | Mode::WUSR)
        .map_err(|source| StorageError::with_source(fallback, source))?;
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
        super::auth::validate_sensitive_state(connection)?;
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
    let mut statement = connection
        .prepare("SELECT version, checksum FROM schema_migrations ORDER BY version")
        .map_err(|source| sqlite_error(StorageErrorKind::MigrationIntegrity, source))?;
    statement
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|source| sqlite_error(StorageErrorKind::MigrationIntegrity, source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| sqlite_error(StorageErrorKind::MigrationIntegrity, source))
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
    Backup::new(source, &mut destination)
        .and_then(|backup| backup.run_to_completion(128, Duration::from_millis(5), None))
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

    let mut backup_file = open_private_leaf(
        state_directory,
        &backup_file_name,
        LeafOpenMode::Existing,
        StorageErrorKind::MigrationFailed,
    )?
    .ok_or_else(|| StorageError::new(StorageErrorKind::MigrationFailed))?;
    backup_file
        .sync_all()
        .map_err(|source| StorageError::with_source(StorageErrorKind::MigrationFailed, source))?;
    backup_file
        .rewind()
        .map_err(|source| StorageError::with_source(StorageErrorKind::MigrationFailed, source))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let bytes_read = backup_file.read(&mut buffer).map_err(|source| {
            StorageError::with_source(StorageErrorKind::MigrationFailed, source)
        })?;
        if bytes_read == 0 {
            break;
        }
        digest.update(&buffer[..bytes_read]);
    }
    let source_database_digest = format!(
        "sha256:{}",
        digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );

    let created_at = OffsetDateTime::now_utc();
    let manifest = MigrationBackupManifest {
        manifest_version: BACKUP_FORMAT_VERSION,
        backup_file: &backup_file_name,
        source_schema_version,
        source_database_digest: &source_database_digest,
        created_at: format_time(created_at)?,
        satelle_version: env!("CARGO_PKG_VERSION"),
        restore_compatibility: RestoreCompatibility {
            database_format: "sqlite3",
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
