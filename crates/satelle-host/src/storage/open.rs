use super::codec::format_time;
use super::{StorageError, StorageErrorKind};
use rusqlite::ffi::ErrorCode as SqliteErrorCode;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use std::fs::{File, TryLockError};
use std::path::Path;
use std::time::Duration;
use time::OffsetDateTime;

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
const INITIAL_MIGRATION_VERSION: i64 = 1;
const INITIAL_MIGRATION: &str = include_str!("0001_initial.sql");

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

pub(super) fn open_parts(
    state_root: &Path,
) -> Result<(Connection, File, StateDirectory), StorageError> {
    open_parts_after_lock(state_root, || {})
}

fn open_parts_after_lock(
    state_root: &Path,
    after_lock: impl FnOnce(),
) -> Result<(Connection, File, StateDirectory), StorageError> {
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
        true,
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
    apply_migrations(&mut connection)?;
    verify_integrity(&connection)?;
    #[cfg(windows)]
    restrict_database_files(&state_directory)?;
    Ok((connection, ownership_lock, state_directory))
}

#[cfg(target_os = "macos")]
fn sqlite_database_path(
    _state_root: &Path,
    state_directory: &StateDirectory,
) -> std::path::PathBuf {
    use std::os::fd::AsRawFd;

    format!(
        "/.satelle-fd/{}/{}",
        state_directory.handle.as_raw_fd(),
        DATABASE_FILE_NAME
    )
    .into()
}

#[cfg(target_os = "linux")]
fn sqlite_database_path(
    _state_root: &Path,
    state_directory: &StateDirectory,
) -> std::path::PathBuf {
    use std::os::fd::AsRawFd;

    format!(
        "/proc/self/fd/{}/{}",
        state_directory.handle.as_raw_fd(),
        DATABASE_FILE_NAME
    )
    .into()
}

#[cfg(windows)]
fn sqlite_database_path(
    state_root: &Path,
    _state_directory: &StateDirectory,
) -> std::path::PathBuf {
    state_root.join(DATABASE_FILE_NAME)
}

#[cfg(all(test, target_os = "linux"))]
pub(super) fn anchored_vfs_name_for_test() -> Result<&'static std::ffi::CStr, StorageError> {
    unix_vfs::name()
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
pub(super) fn open_parts_with_after_lock_hook(
    state_root: &Path,
    after_lock: impl FnOnce(),
) -> Result<(Connection, File, StateDirectory), StorageError> {
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

fn acquire_ownership_lock(state_directory: &StateDirectory) -> Result<File, StorageError> {
    let file = open_private_leaf(
        state_directory,
        LOCK_FILE_NAME,
        true,
        StorageErrorKind::LockUnavailable,
    )?
    .ok_or_else(|| StorageError::new(StorageErrorKind::LockUnavailable))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
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
    create: bool,
    fallback: StorageErrorKind,
) -> Result<Option<File>, StorageError> {
    let mut flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    if create {
        flags |= OFlags::CREATE;
    }
    let descriptor = match rustix::fs::openat(
        &state_directory.handle,
        file_name,
        flags,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) if !create => return Ok(None),
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
    create: bool,
    fallback: StorageErrorKind,
) -> Result<Option<File>, StorageError> {
    state_directory
        .secure
        .open_private_leaf(file_name, create, fallback)
}

fn preflight_protected_files(state_directory: &StateDirectory) -> Result<(), StorageError> {
    for file_name in PROTECTED_FILE_NAMES {
        open_private_leaf(
            state_directory,
            file_name,
            false,
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
            false,
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

fn apply_migrations(connection: &mut Connection) -> Result<(), StorageError> {
    let checksum = migration_checksum(INITIAL_MIGRATION);
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
    let unexpected: i64 = transaction
        .query_row(
            "SELECT count(*) FROM schema_migrations WHERE version <> ?1",
            [INITIAL_MIGRATION_VERSION],
            |row| row.get(0),
        )
        .map_err(|source| sqlite_error(StorageErrorKind::MigrationIntegrity, source))?;
    if unexpected != 0 {
        return Err(StorageError::new(StorageErrorKind::MigrationIntegrity));
    }
    let stored_checksum: Option<String> = transaction
        .query_row(
            "SELECT checksum FROM schema_migrations WHERE version = ?1",
            [INITIAL_MIGRATION_VERSION],
            |row| row.get(0),
        )
        .optional()
        .map_err(|source| sqlite_error(StorageErrorKind::MigrationIntegrity, source))?;
    match stored_checksum {
        Some(stored) if stored != checksum => {
            return Err(StorageError::new(StorageErrorKind::MigrationIntegrity));
        }
        Some(_) => {}
        None => {
            let applied_at = OffsetDateTime::now_utc();
            transaction
                .execute_batch(INITIAL_MIGRATION)
                .map_err(|source| sqlite_error(StorageErrorKind::MigrationFailed, source))?;
            super::auth::seed_sensitive_state(&transaction, applied_at)?;
            transaction
                .execute(
                    "INSERT INTO schema_migrations (version, checksum, applied_at) VALUES (?1, ?2, ?3)",
                    params![
                        INITIAL_MIGRATION_VERSION,
                        checksum,
                        format_time(applied_at)?,
                    ],
                )
                .map_err(|source| sqlite_error(StorageErrorKind::MigrationFailed, source))?;
            transaction
                .pragma_update(None, "user_version", INITIAL_MIGRATION_VERSION)
                .map_err(|source| sqlite_error(StorageErrorKind::MigrationFailed, source))?;
        }
    }
    let user_version: i64 = transaction
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|source| sqlite_error(StorageErrorKind::MigrationIntegrity, source))?;
    if user_version != INITIAL_MIGRATION_VERSION {
        return Err(StorageError::new(StorageErrorKind::MigrationIntegrity));
    }
    transaction
        .commit()
        .map_err(|source| sqlite_error(StorageErrorKind::MigrationFailed, source))
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
