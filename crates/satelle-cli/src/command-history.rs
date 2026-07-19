use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use satelle_core::{
    ErrorCode, SecureFileError, SessionId, open_or_create_owner_only_directory,
    open_or_create_owner_only_file,
};
#[cfg(not(unix))]
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use time::OffsetDateTime;

const DATABASE_FILE_NAME: &str = "command-history.sqlite3";
const DATABASE_DIRECTORY_NAME: &str = "command-history";
const DATABASE_BUSY_TIMEOUT: Duration = Duration::from_secs(2);

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS command_history (
    id INTEGER PRIMARY KEY,
    command_family TEXT NOT NULL,
    selected_host TEXT,
    selected_profile TEXT,
    session_id TEXT,
    started_at TEXT NOT NULL,
    duration_ms INTEGER NOT NULL CHECK (duration_ms >= 0),
    outcome_status TEXT NOT NULL CHECK (outcome_status IN ('success', 'failure')),
    error_code TEXT,
    cli_version TEXT NOT NULL,
    CHECK (
        (outcome_status = 'success' AND error_code IS NULL) OR
        (outcome_status = 'failure' AND error_code IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS command_history_started_at
    ON command_history(started_at DESC, id DESC);

CREATE VIEW IF NOT EXISTS command_history_totals AS
SELECT
    COUNT(*) AS command_count,
    COALESCE(SUM(outcome_status = 'success'), 0) AS success_count,
    COALESCE(SUM(outcome_status = 'failure'), 0) AS failure_count
FROM command_history;

CREATE VIEW IF NOT EXISTS command_history_hosts AS
SELECT
    selected_host,
    COUNT(*) AS command_count,
    MAX(started_at) AS last_used_at
FROM command_history
WHERE selected_host IS NOT NULL
GROUP BY selected_host;

CREATE VIEW IF NOT EXISTS command_history_profiles AS
SELECT
    selected_profile,
    COUNT(*) AS command_count,
    MAX(started_at) AS last_used_at
FROM command_history
WHERE selected_profile IS NOT NULL
GROUP BY selected_profile;

CREATE VIEW IF NOT EXISTS command_history_errors AS
SELECT
    error_code,
    COUNT(*) AS command_count,
    MAX(started_at) AS last_seen_at
FROM command_history
WHERE error_code IS NOT NULL
GROUP BY error_code;
"#;

pub(super) struct Invocation {
    command_family: &'static str,
    selected_host: Option<String>,
    selected_profile: Option<String>,
    session_id: Option<String>,
}

impl Invocation {
    pub(super) fn new(
        command_family: &'static str,
        selected_host: Option<String>,
        selected_profile: Option<String>,
        session_id: Option<String>,
    ) -> Self {
        Self {
            command_family,
            selected_host,
            selected_profile,
            session_id,
        }
    }
}

pub(super) struct InvocationStart {
    started_at: String,
    started: Instant,
}

impl InvocationStart {
    pub(super) fn capture() -> Self {
        Self {
            started_at: format_started_at(OffsetDateTime::now_utc()),
            started: Instant::now(),
        }
    }
}

fn format_started_at(timestamp: OffsetDateTime) -> String {
    // SQLite compares the timestamp column as text. Nine fractional digits
    // keep every value the same width, so lexical and chronological ordering
    // remain identical even for invocations within the same second.
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
        timestamp.year(),
        u8::from(timestamp.month()),
        timestamp.day(),
        timestamp.hour(),
        timestamp.minute(),
        timestamp.second(),
        timestamp.nanosecond(),
    )
}

/// Captures only redacted command metadata. The raw argument vector is never
/// retained, so prompts, provider values, file contents, and secret sources
/// cannot accidentally cross this persistence boundary.
pub(super) struct Recorder {
    cache_root: PathBuf,
    invocation: Invocation,
    started_at: String,
    started: Instant,
}

impl Recorder {
    pub(super) fn start(
        cache_root: PathBuf,
        invocation: Invocation,
        start: InvocationStart,
    ) -> Self {
        Self {
            cache_root,
            invocation,
            started_at: start.started_at,
            started: start.started,
        }
    }

    pub(super) fn finish(
        self,
        final_session_id: Option<&SessionId>,
        error_code: Option<ErrorCode>,
    ) -> Result<(), HistoryWriteError> {
        // Capture command latency before any best-effort filesystem or SQLite
        // work. History contention must not make the command itself look slow.
        let duration_ms = i64::try_from(self.started.elapsed().as_millis()).unwrap_or(i64::MAX);
        self.persist(final_session_id, error_code, duration_ms)
    }

    fn persist(
        self,
        final_session_id: Option<&SessionId>,
        error_code: Option<ErrorCode>,
        duration_ms: i64,
    ) -> Result<(), HistoryWriteError> {
        #[cfg(unix)]
        let cache_root = prepare_cache_root(&self.cache_root)?;
        #[cfg(windows)]
        prepare_cache_root(&self.cache_root)?;
        #[cfg(unix)]
        let database_directory = cache_root.path.join(DATABASE_DIRECTORY_NAME);
        #[cfg(windows)]
        let database_directory = self.cache_root.join(DATABASE_DIRECTORY_NAME);
        // SQLite creates journals and other sidecars beside the main file.
        // Isolate that whole namespace instead of securing only one path. The
        // live handle also prevents directory replacement on Windows.
        let _database_directory_guard = open_or_create_owner_only_directory(&database_directory)?;
        let database_path = database_directory.join(DATABASE_FILE_NAME);
        // SQLite must never create this file through the process umask or an
        // inherited Windows ACL. Establish the owner-only policy first, then
        // let SQLite open the already-private file.
        drop(open_or_create_owner_only_file(&database_path)?);
        let mut connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.busy_timeout(DATABASE_BUSY_TIMEOUT)?;
        // First-run schema creation and the row insert are one writer
        // operation. Without this transaction, concurrent first invocations
        // repeatedly release and reacquire SQLite's write lock between DDL
        // statements and the insert, which can lose best-effort rows under
        // Windows scheduler contention.
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(SCHEMA)?;

        let session_id = final_session_id
            .map(ToString::to_string)
            .or(self.invocation.session_id);
        let outcome_status = if error_code.is_some() {
            "failure"
        } else {
            "success"
        };
        transaction.execute(
            "INSERT INTO command_history (\
                 command_family, selected_host, selected_profile, session_id, started_at, \
                 duration_ms, outcome_status, error_code, cli_version\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                self.invocation.command_family,
                self.invocation.selected_host,
                self.invocation.selected_profile,
                session_id,
                self.started_at,
                duration_ms,
                outcome_status,
                error_code.map(|code| code.as_str()),
                env!("CARGO_PKG_VERSION"),
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }
}

#[cfg(unix)]
struct PreparedCacheRoot {
    // Keep the validated boundary pinned for the entire SQLite operation.
    _guard: std::fs::File,
    path: PathBuf,
}

#[cfg(unix)]
fn prepare_cache_root(path: &Path) -> Result<PreparedCacheRoot, std::io::Error> {
    use rustix::fs::{FileType, Mode, OFlags};
    use std::path::Component;

    if !path.is_absolute() {
        return Err(cache_root_permission_error(
            "the command-history cache root must be absolute",
        ));
    }

    #[cfg(target_os = "macos")]
    let resolved_path = resolve_trusted_macos_aliases_for_creation(path)?;
    #[cfg(target_os = "macos")]
    let path = resolved_path.as_path();
    #[cfg(not(target_os = "macos"))]
    let resolved_path = path.to_path_buf();

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = rustix::fs::open("/", flags, Mode::empty()).map_err(rustix_error)?;
    let effective_user = rustix::process::geteuid().as_raw();

    for component in path.components() {
        let Component::Normal(name) = component else {
            if component == Component::RootDir {
                continue;
            }
            return Err(cache_root_permission_error(
                "the command-history cache root contains an unsupported path component",
            ));
        };

        validate_ancestor_directory(&directory, effective_user)?;
        let (child, created) = match rustix::fs::openat(&directory, name, flags, Mode::empty()) {
            Ok(child) => (child, false),
            Err(rustix::io::Errno::NOENT) => {
                let created = match rustix::fs::mkdirat(&directory, name, Mode::RWXU) {
                    Ok(()) => true,
                    // Another first-run process may create this component
                    // after openat reports NOENT. Reopen it and apply the same
                    // owner, type, and replacement-safety checks below.
                    Err(rustix::io::Errno::EXIST) => false,
                    Err(error) => return Err(rustix_error(error)),
                };
                let child = rustix::fs::openat(&directory, name, flags, Mode::empty())
                    .map_err(rustix_error)?;
                (child, created)
            }
            Err(error) => return Err(rustix_error(error)),
        };

        let metadata = rustix::fs::fstat(&child).map_err(rustix_error)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
            || (metadata.st_uid != 0 && metadata.st_uid != effective_user)
        {
            return Err(cache_root_permission_error(
                "the command-history cache ancestry is not owned by a trusted principal",
            ));
        }
        if created {
            rustix::fs::fchmod(&child, Mode::RWXU).map_err(rustix_error)?;
        }
        directory = child;
    }

    let metadata = rustix::fs::fstat(&directory).map_err(rustix_error)?;
    if metadata.st_uid != effective_user || metadata.st_mode & 0o022 != 0 {
        return Err(cache_root_permission_error(
            "the command-history cache root must be user-owned and not group- or world-writable",
        ));
    }
    Ok(PreparedCacheRoot {
        _guard: std::fs::File::from(directory),
        path: resolved_path,
    })
}

#[cfg(target_os = "macos")]
fn resolve_trusted_macos_aliases_for_creation(path: &Path) -> Result<PathBuf, std::io::Error> {
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;

    let mut resolved = PathBuf::from("/");
    let mut components = path.components();
    for component in components.by_ref() {
        let Component::Normal(name) = component else {
            if component == Component::RootDir {
                continue;
            }
            return Err(cache_root_permission_error(
                "the command-history cache root contains an unsupported path component",
            ));
        };
        let candidate = resolved.join(name);
        match std::fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                let parent_metadata = std::fs::symlink_metadata(&resolved)?;
                if metadata.uid() != 0
                    || parent_metadata.uid() != 0
                    || parent_metadata.mode() & 0o022 != 0
                {
                    return Err(cache_root_permission_error(
                        "the command-history cache ancestry contains an untrusted alias",
                    ));
                }
                resolved = std::fs::canonicalize(candidate)?;
            }
            Ok(_) => resolved = candidate,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                resolved = candidate;
                for remaining in components {
                    let Component::Normal(name) = remaining else {
                        return Err(cache_root_permission_error(
                            "the command-history cache root contains an unsupported path component",
                        ));
                    };
                    resolved.push(name);
                }
                break;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(resolved)
}

#[cfg(not(unix))]
fn prepare_cache_root(path: &Path) -> Result<(), std::io::Error> {
    fs::create_dir_all(path)
}

#[cfg(unix)]
fn validate_ancestor_directory(
    directory: &impl std::os::fd::AsFd,
    effective_user: u32,
) -> Result<(), std::io::Error> {
    use rustix::fs::FileType;

    let metadata = rustix::fs::fstat(directory).map_err(rustix_error)?;
    let owner_is_trusted = metadata.st_uid == 0 || metadata.st_uid == effective_user;
    let writable_by_others = metadata.st_mode & 0o022 != 0;
    let replacement_is_sticky = metadata.st_mode & 0o1000 != 0;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || !owner_is_trusted
        || (writable_by_others && !replacement_is_sticky)
    {
        return Err(cache_root_permission_error(
            "the command-history cache ancestry permits untrusted path replacement",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn rustix_error(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(unix)]
fn cache_root_permission_error(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, message)
}

#[derive(Debug, thiserror::Error)]
pub(super) enum HistoryWriteError {
    #[error("command-history filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("command-history file security policy could not be applied: {0}")]
    SecureFile(#[from] SecureFileError),
    #[error("command-history SQLite operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

#[cfg(test)]
mod tests {
    use super::{Invocation, InvocationStart, Recorder, format_started_at};
    use std::path::PathBuf;
    use std::time::Duration;
    use time::OffsetDateTime;

    #[test]
    fn fixed_width_timestamps_sort_chronologically_within_the_same_second() {
        let second = OffsetDateTime::from_unix_timestamp(1_700_000_000)
            .expect("fixture timestamp should be representable");
        let earlier = format_started_at(second + time::Duration::milliseconds(100));
        let later = format_started_at(second + time::Duration::milliseconds(120));

        assert_eq!(earlier.len(), 30);
        assert_eq!(later.len(), 30);
        assert!(earlier < later);
    }

    #[test]
    fn recorder_preserves_work_done_before_it_is_constructed() {
        let start = InvocationStart::capture();
        std::thread::sleep(Duration::from_millis(25));
        let recorder = Recorder::start(
            PathBuf::new(),
            Invocation::new("config", None, None, None),
            start,
        );

        assert!(recorder.started.elapsed() >= Duration::from_millis(20));
    }
}
