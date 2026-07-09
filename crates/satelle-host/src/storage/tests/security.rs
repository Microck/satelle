use super::*;
use crate::LogSubject;
use crate::storage::open::PROTECTED_FILE_NAMES;

#[test]
fn normal_rows_and_database_bytes_exclude_prompt_and_upstream_canaries() {
    const PROMPT_CANARY: &str = "prompt canary with spaces SECRET-9090";
    const UPSTREAM_THREAD: &str = "thread-private-canary-9090";
    const UPSTREAM_TURN: &str = "turn-private-canary-9090";

    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let session = initial_session(&storage, SESSION_1, TURN_1, at(0));
    storage
        .begin_session(
            &session,
            &admission(IdempotentOperation::Run, "run-1", "request-run-1", at(0)),
        )
        .unwrap();
    let running = storage
        .commit_lifecycle(
            session.id(),
            &turn_id(TURN_1),
            revisions(&session, TURN_1),
            TurnTransition::Running,
            Some(&observed_refs(UPSTREAM_THREAD, UPSTREAM_TURN)),
            at(1),
        )
        .unwrap();
    let cursor = storage
        .append_safe_log(
            &SafeLogRecord::new(
                at(1),
                LogSource::CodexAdapter,
                LogSeverity::Info,
                LogEvent::TurnStateCommitted,
                LogSubject::Turn {
                    session_id: running.id().clone(),
                    turn_id: turn_id(TURN_1),
                    session_state_revision: running.session_state_revision(),
                    turn_state_revision: running
                        .turn(&turn_id(TURN_1))
                        .unwrap()
                        .turn_state_revision(),
                },
            )
            .expect("valid Turn log record"),
        )
        .expect("append safe log");
    let logs = storage
        .logs_after(cursor.checked_sub(1), 10)
        .expect("read appended adapter log");
    assert_eq!(cursor, logs[0].cursor());
    let log = logs[0].record();
    assert_eq!(at(1), log.recorded_at());
    assert_eq!(LogSource::CodexAdapter, log.source());
    assert_eq!(LogSeverity::Info, log.severity());
    assert_eq!(LogEvent::TurnStateCommitted, log.event());
    assert_eq!(
        &LogSubject::Turn {
            session_id: running.id().clone(),
            turn_id: turn_id(TURN_1),
            session_state_revision: running.session_state_revision(),
            turn_state_revision: running
                .turn(&turn_id(TURN_1))
                .unwrap()
                .turn_state_revision(),
        },
        log.subject()
    );

    let public_rows: String = storage
        .connection_for_test()
        .query_row(
            "SELECT concat_ws('|', s.session_id, s.session_state_revision, t.turn_id, t.state, l.event_kind) FROM sessions s JOIN turns t ON t.session_id = s.session_id LEFT JOIN logs l ON l.session_id = s.session_id",
            [],
            |row| row.get(0),
        )
        .expect("read public-safe rows");
    assert!(!public_rows.contains(PROMPT_CANARY));
    assert!(!public_rows.contains(UPSTREAM_THREAD));
    assert!(!public_rows.contains(UPSTREAM_TURN));
    let private_refs: (String, String) = storage
        .connection_for_test()
        .query_row(
            "SELECT s.upstream_thread_ref, t.upstream_turn_ref FROM session_private_refs s JOIN turns u ON u.session_id = s.session_id JOIN turn_private_refs t ON t.turn_id = u.turn_id",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read private refs");
    assert_eq!(
        (UPSTREAM_THREAD.to_string(), UPSTREAM_TURN.to_string()),
        private_refs
    );
    storage.checkpoint_for_test();
    drop(storage);

    for suffix in [
        "satelle.sqlite3",
        "satelle.sqlite3-wal",
        "satelle.sqlite3-shm",
    ] {
        let path = state.path().join(suffix);
        if path.exists() {
            let bytes = fs::read(path).expect("read SQLite storage file");
            assert!(!contains_bytes(&bytes, PROMPT_CANARY.as_bytes()));
        }
    }
}

#[test]
fn one_process_exclusively_owns_the_store() {
    let state = TempDir::new().expect("temporary state directory");
    let (storage, _) = Storage::open(state.path()).expect("first owner");
    let error = match Storage::open(state.path()) {
        Ok(_) => panic!("second owner must be rejected"),
        Err(error) => error,
    };
    assert_eq!(StorageErrorKind::StoreInUse, error.kind());
    drop(storage);
    Storage::open(state.path()).expect("lock released with owner");
}

#[cfg(unix)]
#[test]
fn preexisting_protected_symlinks_are_rejected() {
    use std::os::unix::fs::symlink;

    for protected_name in PROTECTED_FILE_NAMES {
        let state = TempDir::new().expect("temporary state directory");
        let target = state.path().join(format!("{protected_name}.target"));
        fs::write(&target, b"not a Satelle store").unwrap();
        symlink(&target, state.path().join(protected_name)).unwrap();

        let error = match Storage::open(state.path()) {
            Ok(_) => panic!("preexisting symlink must be rejected"),
            Err(error) => error,
        };
        assert_eq!(StorageErrorKind::UnsafeStatePath, error.kind());
        assert_eq!(
            b"not a Satelle store",
            fs::read(&target).unwrap().as_slice()
        );
    }
}

#[cfg(unix)]
#[test]
fn preexisting_protected_hard_links_are_rejected() {
    for protected_name in PROTECTED_FILE_NAMES {
        let state = TempDir::new().expect("temporary state directory");
        let target = state.path().join(format!("{protected_name}.target"));
        fs::write(&target, b"not a Satelle store").unwrap();
        fs::hard_link(&target, state.path().join(protected_name)).unwrap();

        let error = match Storage::open(state.path()) {
            Ok(_) => panic!("preexisting hard link must be rejected"),
            Err(error) => error,
        };
        assert_eq!(StorageErrorKind::UnsafeStatePath, error.kind());
        assert_eq!(
            b"not a Satelle store",
            fs::read(&target).unwrap().as_slice()
        );
    }
}

#[cfg(unix)]
#[test]
fn state_root_rejects_symlinked_parent_components() {
    use std::os::unix::fs::symlink;

    let state = TempDir::new().expect("temporary state directory");
    let real_parent = state.path().join("real-parent");
    fs::create_dir(&real_parent).unwrap();
    let linked_parent = state.path().join("linked-parent");
    symlink(&real_parent, &linked_parent).unwrap();

    let error = match Storage::open(&linked_parent.join("state")) {
        Ok(_) => panic!("a symlinked state-root parent must be rejected"),
        Err(error) => error,
    };
    assert_eq!(StorageErrorKind::UnsafeStatePath, error.kind());
    assert!(!real_parent.join("state").exists());
}

#[cfg(unix)]
#[test]
fn state_root_rejects_non_sticky_group_or_world_writable_ancestors() {
    use std::os::unix::fs::PermissionsExt;

    let state = TempDir::new().expect("temporary state directory");
    let unsafe_parent = state.path().join("unsafe-parent");
    fs::create_dir(&unsafe_parent).unwrap();
    fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777)).unwrap();

    let error = match Storage::open(&unsafe_parent.join("state")) {
        Ok(_) => panic!("an replaceable state-root ancestor must be rejected"),
        Err(error) => error,
    };
    assert_eq!(StorageErrorKind::UnsafeStatePath, error.kind());
    assert!(!unsafe_parent.join("state").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn sqlite_nofollow_keeps_proc_fd_directory_anchor_after_rename() {
    use std::fs::File;
    use std::os::fd::AsRawFd;

    let fixture = TempDir::new().expect("temporary fixture directory");
    let original = fixture.path().join("original");
    let anchored = fixture.path().join("anchored");
    fs::create_dir(&original).unwrap();
    let directory = File::open(&original).unwrap();
    fs::rename(&original, &anchored).unwrap();
    fs::create_dir(&original).unwrap();

    let descriptor_path = format!(
        "/proc/self/fd/{}/sqlite-anchor-proof.sqlite3",
        directory.as_raw_fd()
    );
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
        | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
        | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let connection = Connection::open_with_flags_and_vfs(
        &descriptor_path,
        flags,
        crate::storage::open::anchored_vfs_name_for_test()
            .expect("register the anchored SQLite VFS"),
    )
    .expect("SQLite must accept the descriptor-relative anchor");
    let sqlite_filename: String = connection
        .query_row("PRAGMA database_list", [], |row| row.get(2))
        .expect("read SQLite's retained database filename");
    assert_eq!(descriptor_path, sqlite_filename);
    connection
        .execute_batch("CREATE TABLE anchor_proof (value TEXT NOT NULL) STRICT;")
        .unwrap();
    drop(connection);

    assert!(anchored.join("sqlite-anchor-proof.sqlite3").exists());
    assert!(!original.join("sqlite-anchor-proof.sqlite3").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn ownership_lock_and_sqlite_files_share_the_pinned_directory_after_replacement() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = TempDir::new().expect("temporary fixture directory");
    fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let original = fixture.path().join("state");
    let anchored = fixture.path().join("anchored-state");
    fs::create_dir(&original).unwrap();

    let (connection, ownership_lock, state_directory) =
        crate::storage::open::open_parts_with_after_lock_hook(&original, || {
            fs::rename(&original, &anchored).unwrap();
            fs::create_dir(&original).unwrap();
        })
        .expect("open storage through the pinned directory");
    connection
        .execute_batch(
            "CREATE TABLE anchor_write (value TEXT NOT NULL) STRICT; \
             INSERT INTO anchor_write VALUES ('pinned');",
        )
        .unwrap();

    let sqlite_filename: String = connection
        .query_row("PRAGMA database_list", [], |row| row.get(2))
        .unwrap();
    assert!(sqlite_filename.starts_with("/proc/self/fd/"));
    assert!(anchored.join(LOCK_FILE_NAME).exists());
    assert!(anchored.join(DATABASE_FILE_NAME).exists());
    assert!(anchored.join("satelle.sqlite3-wal").exists());
    assert!(
        !anchored.join("satelle.sqlite3-shm").exists(),
        "unix-excl must keep the WAL index in process memory"
    );
    for protected_name in PROTECTED_FILE_NAMES {
        assert!(
            !original.join(protected_name).exists(),
            "replacement directory must not receive {protected_name}"
        );
    }

    drop(connection);
    drop(ownership_lock);
    drop(state_directory);
}

#[cfg(target_os = "linux")]
#[test]
fn sqlite_process_lock_survives_satelle_descriptor_preflight() {
    let state = TempDir::new().expect("temporary state directory");
    let (storage, _) = Storage::open(state.path()).expect("open anchored storage");
    let child = std::process::Command::new(std::env::current_exe().expect("current test binary"))
        .args([
            "--exact",
            "storage::tests::security::sqlite_process_lock_probe_child",
            "--nocapture",
        ])
        .env(
            "SATELLE_SQLITE_LOCK_PROBE",
            state.path().join(DATABASE_FILE_NAME),
        )
        .output()
        .expect("run the cross-process SQLite lock probe");
    assert!(
        child.status.success(),
        "child lock probe failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    drop(storage);
}

#[cfg(target_os = "linux")]
#[test]
fn sqlite_process_lock_probe_child() {
    let Some(database_path) = std::env::var_os("SATELLE_SQLITE_LOCK_PROBE") else {
        return;
    };
    let connection = Connection::open(database_path)
        .expect("open the database without Satelle's ownership lock");
    connection
        .busy_timeout(std::time::Duration::ZERO)
        .expect("disable lock waiting in the probe");
    let error = connection
        .execute_batch("BEGIN IMMEDIATE")
        .expect_err("the parent process must retain SQLite's database lock");
    assert!(
        matches!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
        ),
        "expected a SQLite lock conflict, got {error}"
    );
}

#[cfg(unix)]
#[test]
fn state_directory_database_and_lock_are_owner_private() {
    use std::os::unix::fs::PermissionsExt;

    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let session = initial_session(&storage, SESSION_1, TURN_1, at(0));
    storage
        .begin_session(
            &session,
            &admission(IdempotentOperation::Run, "run-1", "request-run-1", at(0)),
        )
        .expect("write through the opened database");
    assert_eq!(
        0o700,
        fs::metadata(state.path()).unwrap().permissions().mode() & 0o777
    );
    for name in [DATABASE_FILE_NAME, LOCK_FILE_NAME, "satelle.sqlite3-wal"] {
        let path = state.path().join(name);
        assert!(path.exists(), "expected private SQLite file {name}");
        assert_eq!(
            0o600,
            fs::metadata(path).unwrap().permissions().mode() & 0o777
        );
    }
    assert!(
        !state.path().join("satelle.sqlite3-shm").exists(),
        "unix-excl must not create a shared-memory sidecar"
    );
}

#[test]
fn sqlite_pragmas_and_schema_constraints_are_enforced() {
    let state = TempDir::new().expect("temporary state directory");
    let (storage, _) = Storage::open(state.path()).expect("open storage");
    let connection = storage.connection_for_test();
    assert_eq!(1_i64, pragma_integer(connection, "foreign_keys"));
    assert_eq!(2_i64, pragma_integer(connection, "synchronous"));
    assert_eq!(5_000_i64, pragma_integer(connection, "busy_timeout"));
    let journal: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!("wal", journal);

    let foreign_key_error = connection
        .execute(
            "INSERT INTO session_private_refs (session_id, host_identity_ref, desktop_binding_ref) VALUES (?1, ?2, ?3)",
            params![SESSION_1, "host", "desktop"],
        )
        .expect_err("orphan private refs violate the foreign key");
    assert!(foreign_key_error.to_string().contains("FOREIGN KEY"));
    connection
        .execute(
            "INSERT INTO sessions (session_id, session_state_revision, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)",
            params![SESSION_1, "0000000000000000", "time", "time"],
        )
        .expect_err("zero revision violates the schema check");
}

#[test]
fn sqlite_busy_exhaustion_returns_a_typed_redacted_error() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    storage
        .connection_for_test()
        .busy_timeout(std::time::Duration::from_millis(1))
        .unwrap();
    let blocker = Connection::open(state.path().join(DATABASE_FILE_NAME)).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();

    let error = storage
        .append_safe_log(
            &SafeLogRecord::new(
                at(0),
                LogSource::Storage,
                LogSeverity::Warning,
                LogEvent::StoreOpened,
                LogSubject::Host,
            )
            .expect("valid Host log record"),
        )
        .expect_err("held write lock exhausts the configured wait");
    assert_eq!(StorageErrorKind::Busy, error.kind());
    assert_eq!("the Satelle SQLite store is busy", error.to_string());
    assert_eq!("StorageError { kind: Busy, .. }", format!("{error:?}"));

    blocker.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn migration_checksum_tampering_blocks_reopen_with_safe_error_text() {
    let state = TempDir::new().expect("temporary state directory");
    let (storage, _) = Storage::open(state.path()).expect("open storage");
    drop(storage);
    let connection = Connection::open(state.path().join("satelle.sqlite3")).unwrap();
    connection
        .execute(
            "UPDATE schema_migrations SET checksum = 'tampered' WHERE version = 1",
            [],
        )
        .unwrap();
    drop(connection);

    let error = match Storage::open(state.path()) {
        Ok(_) => panic!("tampered migration history must fail closed"),
        Err(error) => error,
    };
    assert_eq!(StorageErrorKind::MigrationIntegrity, error.kind());
    assert_eq!(
        "the Satelle SQLite migration history is inconsistent",
        error.to_string()
    );
    assert!(!error.to_string().contains("UPDATE"));
    assert!(!error.to_string().contains("schema_migrations"));
}

#[test]
fn corrupt_database_fails_integrity_without_echoing_or_rewriting_bytes() {
    const CORRUPT_CANARY: &[u8] = b"not-sqlite SECRET-CORRUPT-CANARY";

    let state = TempDir::new().expect("temporary state directory");
    let database = state.path().join(DATABASE_FILE_NAME);
    fs::write(&database, CORRUPT_CANARY).unwrap();

    let error = match Storage::open(state.path()) {
        Ok(_) => panic!("corrupt database must fail closed"),
        Err(error) => error,
    };
    assert_eq!(StorageErrorKind::IntegrityCheckFailed, error.kind());
    assert_eq!(
        "the Satelle SQLite integrity check failed",
        error.to_string()
    );
    assert!(!format!("{error:?}").contains("SECRET-CORRUPT-CANARY"));
    assert_eq!(CORRUPT_CANARY, fs::read(database).unwrap().as_slice());
}

#[test]
fn test_fixture_uses_closed_safe_summary_contract() {
    let state = TempDir::new().expect("temporary state directory");
    let (storage, _) = Storage::open(state.path()).expect("open storage");
    assert_eq!("task_completed", SafeSummary::TaskCompleted.as_str());
    assert_eq!(
        TurnState::Starting,
        initial_session(&storage, SESSION_1, TURN_1, at(0))
            .turns()
            .next()
            .unwrap()
            .state()
    );
}

#[cfg(windows)]
fn create_windows_junction(link: &std::path::Path, target: &std::path::Path) {
    let status = std::process::Command::new("cmd.exe")
        .args(["/D", "/Q", "/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .status()
        .expect("invoke the Windows junction command");
    assert!(status.success(), "create an NTFS junction for the test");
}

#[cfg(windows)]
#[test]
fn windows_reparse_state_root_is_rejected_without_touching_its_target() {
    let fixture = TempDir::new().expect("temporary fixture directory");
    let target = fixture.path().join("junction-target");
    fs::create_dir(&target).unwrap();
    let canary = target.join("canary.txt");
    fs::write(&canary, b"state-root-canary").unwrap();
    let junction = fixture.path().join("state-junction");
    create_windows_junction(&junction, &target);

    let error = match Storage::open(&junction) {
        Ok(_) => panic!("a reparse-point state root must be rejected"),
        Err(error) => error,
    };

    assert_eq!(StorageErrorKind::UnsafeStatePath, error.kind());
    assert_eq!(b"state-root-canary", fs::read(canary).unwrap().as_slice());
    for protected_name in PROTECTED_FILE_NAMES {
        assert!(!target.join(protected_name).exists());
    }
}

#[cfg(windows)]
#[test]
fn windows_reparse_protected_leaves_are_rejected_before_sqlite_opens() {
    for protected_name in PROTECTED_FILE_NAMES {
        let fixture = TempDir::new().expect("temporary fixture directory");
        let state = fixture.path().join("state");
        fs::create_dir(&state).unwrap();
        let target = fixture.path().join("junction-target");
        fs::create_dir(&target).unwrap();
        let canary = target.join("canary.txt");
        fs::write(&canary, b"protected-leaf-canary").unwrap();
        create_windows_junction(&state.join(protected_name), &target);

        let error = match Storage::open(&state) {
            Ok(_) => panic!("protected reparse point {protected_name} must be rejected"),
            Err(error) => error,
        };

        assert_eq!(StorageErrorKind::UnsafeStatePath, error.kind());
        assert_eq!(
            b"protected-leaf-canary",
            fs::read(canary).unwrap().as_slice()
        );
    }
}

#[cfg(windows)]
#[test]
fn windows_hard_linked_protected_leaves_are_rejected() {
    for protected_name in PROTECTED_FILE_NAMES {
        let fixture = TempDir::new().expect("temporary fixture directory");
        let state = fixture.path().join("state");
        fs::create_dir(&state).unwrap();
        let target = fixture.path().join("hard-link-target");
        fs::write(&target, b"hard-link-canary").unwrap();
        fs::hard_link(&target, state.join(protected_name)).unwrap();

        let error = match Storage::open(&state) {
            Ok(_) => panic!("protected hard link {protected_name} must be rejected"),
            Err(error) => error,
        };

        assert_eq!(StorageErrorKind::UnsafeStatePath, error.kind());
        assert_eq!(b"hard-link-canary", fs::read(target).unwrap().as_slice());
    }
}

#[cfg(windows)]
#[test]
fn windows_state_path_remains_pinned_until_storage_closes() {
    let fixture = TempDir::new().expect("temporary fixture directory");
    let state = fixture.path().join("state");
    let renamed = fixture.path().join("renamed-state");
    let (storage, _) = Storage::open(&state).expect("open storage");

    fs::rename(&state, &renamed).expect_err("an open state path must reject rename");
    assert!(state.exists());
    assert!(!renamed.exists());

    drop(storage);
    fs::rename(&state, &renamed).expect("dropping Storage releases pinned path handles");
    assert!(renamed.exists());
}
