use assert_cmd::Command;
use rusqlite::Connection;
use satelle_core::SessionId;
use satelle_host::test_support::TestStateDir;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::time::Duration;
use tempfile::TempDir;

#[path = "support/test-file.rs"]
mod test_file;

const HISTORY_DATABASE: &str = "command-history.sqlite3";
const TEST_SUPPORT_ADAPTER_ENV: &str = "SATELLE_TEST_SUPPORT_ADAPTER";

struct Fixture {
    cache: TempDir,
    state: TestStateDir,
}

impl Fixture {
    fn new() -> Self {
        let cache = tempfile::tempdir().expect("create command-history cache root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(cache.path(), fs::Permissions::from_mode(0o700))
                .expect("secure command-history cache root");
        }
        Self {
            cache,
            state: TestStateDir::new().expect("create command-history state root"),
        }
    }

    fn command(&self) -> Command {
        satelle_command(self.cache.path(), self.state.path())
    }

    fn database_path(&self) -> std::path::PathBuf {
        self.history_root().join(HISTORY_DATABASE)
    }

    fn history_root(&self) -> std::path::PathBuf {
        self.cache.path().join("command-history")
    }

    fn connection(&self) -> Connection {
        Connection::open(self.database_path()).expect("open command-history database")
    }
}

fn satelle_command(cache_root: &Path, state_root: &Path) -> Command {
    let mut command = Command::cargo_bin("satelle").expect("satelle binary should build");
    for name in [
        "SATELLE_HOME",
        "SATELLE_CONFIG_FILE",
        "SATELLE_STATE_DIR",
        "SATELLE_CACHE_DIR",
        "SATELLE_LOG_DIR",
        "SATELLE_HOST",
        "SATELLE_PROFILE",
        "SATELLE_COMMAND_HISTORY",
    ] {
        command.env_remove(name);
    }
    command
        .env(TEST_SUPPORT_ADAPTER_ENV, "fake")
        .env("SATELLE_CACHE_DIR", cache_root)
        .env("SATELLE_STATE_DIR", state_root);
    command
}

fn session_id(output: &[u8]) -> String {
    String::from_utf8_lossy(output)
        .lines()
        .find_map(|line| line.strip_prefix("Session: "))
        .expect("detached run should print its Session id")
        .to_string()
}

fn assert_history_namespace_excludes(fixture: &Fixture, canary: &str, message: &str) {
    for entry in fs::read_dir(fixture.history_root()).expect("read command-history namespace") {
        let entry = entry.expect("read command-history entry");
        if !entry
            .file_type()
            .expect("read command-history entry type")
            .is_file()
        {
            continue;
        }
        let file_bytes = fs::read(entry.path()).expect("read command-history file");
        assert!(
            !file_bytes
                .windows(canary.len())
                .any(|window| window == canary.as_bytes()),
            "{message}: {}",
            entry.path().display()
        );
    }
}

#[test]
fn records_redacted_command_metadata_and_typed_outcomes() {
    let fixture = Fixture::new();
    let prompt_canary = "COMMAND_HISTORY_PROMPT_CANARY";

    let run_output = fixture
        .command()
        .args(["run", "--host", "local-demo", "--detach", prompt_canary])
        .assert()
        .success()
        .get_output()
        .clone();
    let session_id = session_id(&run_output.stdout);
    fixture
        .command()
        .args([
            "logs",
            "--host",
            "local-demo",
            "--session",
            &session_id,
            "--json",
        ])
        .assert()
        .success();
    fixture
        .command()
        .args(["config", "check", "--host", "missing-host", "--json"])
        .assert()
        .failure();

    let connection = fixture.connection();
    let rows = connection
        .prepare(
            "SELECT command_family, selected_host, selected_profile, session_id, \
                    outcome_status, error_code, cli_version, duration_ms >= 0, \
                    started_at <> '' \
             FROM command_history ORDER BY id",
        )
        .expect("prepare command-history query")
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, bool>(7)?,
                row.get::<_, bool>(8)?,
            ))
        })
        .expect("query command history")
        .collect::<Result<Vec<_>, _>>()
        .expect("read command history");

    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].0, "run");
    assert_eq!(rows[0].1.as_deref(), Some("local-demo"));
    assert_eq!(rows[0].2, None);
    assert_eq!(rows[0].3.as_deref(), Some(session_id.as_str()));
    assert_eq!(rows[0].4, "success");
    assert_eq!(rows[0].5, None);
    assert_eq!(rows[0].6, env!("CARGO_PKG_VERSION"));
    assert!(rows[0].7 && rows[0].8);
    assert_eq!(rows[1].0, "logs");
    assert_eq!(rows[1].1.as_deref(), Some("local-demo"));
    assert_eq!(rows[1].3.as_deref(), Some(session_id.as_str()));
    assert_eq!(rows[1].4, "success");
    assert_eq!(rows[2].0, "config");
    assert_eq!(rows[2].1, None);
    assert_eq!(rows[2].4, "failure");
    assert_eq!(rows[2].5.as_deref(), Some("host-not-found"));

    assert_history_namespace_excludes(
        &fixture,
        prompt_canary,
        "command history must not retain raw prompts",
    );
}

#[test]
fn invalid_profile_selector_is_not_persisted() {
    let fixture = Fixture::new();
    let profile_canary = "COMMAND_HISTORY_PROFILE_CANARY";

    fixture
        .command()
        // Explicit opt-in permits the recorder to persist the typed failure
        // even though configuration resolution rejects this profile.
        .env("SATELLE_COMMAND_HISTORY", "true")
        .args(["config", "check", "--profile", profile_canary, "--json"])
        .assert()
        .failure();

    let selected_profile = fixture
        .connection()
        .query_row(
            "SELECT selected_profile FROM command_history WHERE command_family = 'config'",
            [],
            |row| row.get::<_, Option<String>>(0),
        )
        .expect("query invalid-profile history");
    assert_eq!(selected_profile, None);

    assert_history_namespace_excludes(
        &fixture,
        profile_canary,
        "command history must not retain rejected profile selectors",
    );
}

#[test]
fn aggregate_views_summarize_outcomes_targets_profiles_and_errors() {
    let fixture = Fixture::new();
    let config_path = fixture.cache.path().join("profile-config.toml");
    test_file::write_user_controlled(&config_path, b"[profiles.work]\n")
        .expect("write profile config");

    fixture
        .command()
        .env("SATELLE_CONFIG_FILE", &config_path)
        .env("SATELLE_PROFILE", "work")
        .args(["status", "not-a-session", "--host", "local-demo"])
        .assert()
        .failure();
    fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .success();

    let connection = fixture.connection();
    let totals = connection
        .query_row(
            "SELECT command_count, success_count, failure_count FROM command_history_totals",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .expect("query aggregate totals");
    assert_eq!(totals, (2, 1, 1));

    let host_count = connection
        .query_row(
            "SELECT command_count FROM command_history_hosts WHERE selected_host = 'local-demo'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .expect("query last-used hosts");
    assert_eq!(host_count, 2);
    let profile_count = connection
        .query_row(
            "SELECT command_count FROM command_history_profiles WHERE selected_profile = 'work'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .expect("query last-used profiles");
    assert_eq!(profile_count, 1);
    let error_count = connection
        .query_row(
            "SELECT command_count FROM command_history_errors WHERE error_code = 'invalid-usage'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .expect("query common typed errors");
    assert_eq!(error_count, 1);
}

#[test]
fn invalid_session_text_is_never_persisted() {
    let fixture = Fixture::new();
    let session_canary = "SESSION_ARGUMENT_SECRET_CANARY";

    fixture
        .command()
        .args(["status", session_canary, "--host", "local-demo", "--json"])
        .assert()
        .failure();

    let connection = fixture.connection();
    let session_id = connection
        .query_row(
            "SELECT session_id FROM command_history WHERE command_family = 'status'",
            [],
            |row| row.get::<_, Option<String>>(0),
        )
        .expect("query invalid-session history");
    assert_eq!(session_id, None);
    drop(connection);

    assert_history_namespace_excludes(
        &fixture,
        session_canary,
        "invalid session text must not cross the redacted-history boundary",
    );
}

#[test]
fn multi_host_updates_are_not_attributed_to_the_default_host() {
    let fixture = Fixture::new();

    fixture
        .command()
        .env("SATELLE_HOST", "environment-host")
        .args([
            "host", "update", "--host", "alpha", "--host", "beta", "--json",
        ])
        .assert()
        .failure();
    fixture
        .command()
        .env("SATELLE_HOST", "environment-host")
        .args(["host", "update", "--all-remotes", "--json"])
        .assert()
        .failure();

    let connection = fixture.connection();
    let selected_hosts = connection
        .prepare(
            "SELECT selected_host FROM command_history WHERE command_family = 'host' ORDER BY id",
        )
        .expect("prepare multi-host update history query")
        .query_map([], |row| row.get::<_, Option<String>>(0))
        .expect("query multi-host update history")
        .collect::<Result<Vec<_>, _>>()
        .expect("read multi-host update history");
    assert_eq!(selected_hosts, vec![None, None]);
}

#[test]
fn config_independent_lifecycle_commands_record_their_local_default() {
    let fixture = Fixture::new();
    let config_path = fixture.cache.path().join("remote-default-config.toml");
    test_file::write_user_controlled(
        &config_path,
        br#"
default_host = "remote"

[hosts.remote]
transport = "local"
adapter = "fake"

[hosts.local-demo]
transport = "local"
adapter = "fake"
"#,
    )
    .expect("write remote-default config");

    for arguments in [
        vec!["repair", "--yes", "--json"],
        vec!["host", "stop", "--json"],
        vec!["host", "restart", "--json"],
        vec!["host", "storage", "migrate", "--json"],
    ] {
        fixture
            .command()
            .env("SATELLE_CONFIG_FILE", &config_path)
            .args(arguments)
            .assert()
            .failure();
    }

    let connection = fixture.connection();
    let selected_hosts = connection
        .prepare("SELECT selected_host FROM command_history ORDER BY id")
        .expect("prepare local lifecycle history query")
        .query_map([], |row| row.get::<_, Option<String>>(0))
        .expect("query local lifecycle history")
        .collect::<Result<Vec<_>, _>>()
        .expect("read local lifecycle history");
    assert_eq!(
        selected_hosts,
        vec![
            Some("local-demo".to_string()),
            Some("local-demo".to_string()),
            Some("local-demo".to_string()),
            Some("local-demo".to_string()),
        ]
    );
}

#[test]
fn history_failures_do_not_corrupt_json_error_output() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.history_root()).expect("create command-history directory");
    fs::create_dir(fixture.database_path()).expect("block SQLite database creation");

    let human_output = fixture
        .command()
        .args(["config", "check"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert!(
        String::from_utf8_lossy(&human_output.stderr)
            .contains("warning: command history was not recorded"),
        "human diagnostics should report the best-effort history failure"
    );

    let output = fixture
        .command()
        .args(["config", "check", "--host", "missing-host", "--json"])
        .assert()
        .failure()
        .get_output()
        .clone();
    let error: serde_json::Value =
        serde_json::from_slice(&output.stderr).expect("stderr should remain one JSON error value");
    assert_eq!(error["code"], "host-not-found");
}

#[test]
fn admitted_run_failures_retain_their_session_id() {
    let fixture = Fixture::new();
    fixture
        .command()
        .env(TEST_SUPPORT_ADAPTER_ENV, "failing")
        .args([
            "run",
            "--host",
            "local-demo",
            "--json",
            "fail after admission",
        ])
        .assert()
        .failure();

    let (session_id, outcome_status) = fixture
        .connection()
        .query_row(
            "SELECT session_id, outcome_status FROM command_history WHERE command_family = 'run'",
            [],
            |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, String>(1)?)),
        )
        .expect("query admitted run failure history");
    assert!(
        session_id
            .as_deref()
            .is_some_and(|value| value.parse::<SessionId>().is_ok()),
        "an admitted failure must retain its durable Session id"
    );
    assert_eq!(outcome_status, "failure");
}

#[test]
fn user_config_and_environment_can_disable_history_before_dispatch() {
    let configured = Fixture::new();
    let config_path = configured.cache.path().join("config.toml");
    test_file::write_user_controlled(&config_path, b"command_history = false\n")
        .expect("write user config");
    configured
        .command()
        .env("SATELLE_CONFIG_FILE", &config_path)
        .args(["config", "check", "--json"])
        .assert()
        .success();
    assert!(!configured.database_path().exists());

    let environment = Fixture::new();
    environment
        .command()
        .env("SATELLE_COMMAND_HISTORY", "false")
        .args(["config", "check", "--json"])
        .assert()
        .success();
    assert!(!environment.database_path().exists());

    for malformed in ["", "false ", "disabled-typo"] {
        let environment = Fixture::new();
        environment
            .command()
            .env("SATELLE_COMMAND_HISTORY", malformed)
            .args(["config", "check", "--json"])
            .assert()
            .success();
        assert!(
            !environment.database_path().exists(),
            "malformed history preference {malformed:?} must fail closed"
        );
    }

    let invalid = Fixture::new();
    let invalid_config_path = invalid.cache.path().join("invalid-config.toml");
    test_file::write_user_controlled(
        &invalid_config_path,
        b"command_history = false\nunknown_key = true\n",
    )
    .expect("write invalid user config");
    invalid
        .command()
        .env("SATELLE_CONFIG_FILE", &invalid_config_path)
        .args(["config", "check", "--json"])
        .assert()
        .failure();
    assert!(
        !invalid.database_path().exists(),
        "configuration failures must fail closed for command history"
    );
}

#[cfg(unix)]
#[test]
fn non_unicode_environment_preference_disables_history() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let fixture = Fixture::new();
    fixture
        .command()
        .env(
            "SATELLE_COMMAND_HISTORY",
            OsString::from_vec(vec![b'f', b'a', b'l', b's', b'e', 0xff]),
        )
        .args(["config", "check", "--json"])
        .assert()
        .success();
    assert!(!fixture.database_path().exists());
}

#[test]
fn config_check_all_is_not_attributed_to_one_context() {
    let fixture = Fixture::new();
    let config_path = fixture.cache.path().join("config.toml");
    test_file::write_user_controlled(
        &config_path,
        br#"
[profiles.work]
host = "local-demo"
"#,
    )
    .expect("write profile config");

    fixture
        .command()
        .env("SATELLE_CONFIG_FILE", &config_path)
        .args(["config", "check", "--all", "--profile", "work", "--json"])
        .assert()
        .success();

    let (selected_host, selected_profile) = fixture
        .connection()
        .query_row(
            "SELECT selected_host, selected_profile FROM command_history WHERE command_family = 'config'",
            [],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            },
        )
        .expect("query all-context history");
    assert_eq!((selected_host, selected_profile), (None, None));
}

#[cfg(unix)]
#[test]
fn recording_preserves_permissions_on_an_existing_cache_root() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    let original_mode = 0o2750;
    fs::set_permissions(
        fixture.cache.path(),
        fs::Permissions::from_mode(original_mode),
    )
    .expect("set shared cache permissions");

    fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .success();

    let actual_mode = fs::metadata(fixture.cache.path())
        .expect("read cache permissions")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(actual_mode, original_mode);
    let history_root_mode = fs::metadata(fixture.history_root())
        .expect("read command-history directory permissions")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(history_root_mode, 0o700);
    let database_mode = fs::metadata(fixture.database_path())
        .expect("read command-history database permissions")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(database_mode, 0o600);
}

#[cfg(unix)]
#[test]
fn writable_shared_cache_roots_fail_closed() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    fs::set_permissions(fixture.cache.path(), fs::Permissions::from_mode(0o2770))
        .expect("make cache root group-writable");

    fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .success();
    assert!(
        !fixture.database_path().exists(),
        "history must fail closed when another user can replace its secured directory"
    );
}

#[cfg(unix)]
#[test]
fn replaceable_cache_ancestry_fails_closed_before_creating_children() {
    use std::os::unix::fs::PermissionsExt;

    let replaceable_parent = tempfile::tempdir().expect("create replaceable cache parent");
    fs::set_permissions(replaceable_parent.path(), fs::Permissions::from_mode(0o777))
        .expect("make cache parent world-writable without sticky protection");
    let cache_root = replaceable_parent.path().join("nested").join("cache");
    let state = TestStateDir::new().expect("create command-history state root");

    satelle_command(&cache_root, state.path())
        .args(["config", "check", "--json"])
        .assert()
        .success();

    assert!(
        !replaceable_parent.path().join("nested").exists(),
        "history must not create children beneath replaceable cache ancestry"
    );
}

#[test]
fn concurrent_commands_retain_every_history_row() {
    const WRITERS: usize = 8;

    let fixture = Fixture::new();
    let cache_root = fixture.cache.path().to_path_buf();
    let state_root = fixture.state.path().to_path_buf();
    let start = Arc::new(Barrier::new(WRITERS));
    let writers = (0..WRITERS)
        .map(|_| {
            let cache_root = cache_root.clone();
            let state_root = state_root.clone();
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                let mut command = satelle_command(&cache_root, &state_root);
                start.wait();
                command
                    .args(["config", "check", "--json"])
                    .output()
                    .expect("run concurrent config check")
            })
        })
        .collect::<Vec<_>>();

    for writer in writers {
        let output = writer.join().expect("concurrent writer should not panic");
        assert!(
            output.status.success(),
            "concurrent command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let row_count = fixture
        .connection()
        .query_row("SELECT COUNT(*) FROM command_history", [], |row| {
            row.get::<_, i64>(0)
        })
        .expect("count concurrent command-history rows");
    assert_eq!(row_count, WRITERS as i64);
}

#[test]
fn history_database_wait_does_not_inflate_command_duration() {
    let fixture = Fixture::new();
    fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .success();

    let connection = fixture.connection();
    connection
        .execute_batch("BEGIN EXCLUSIVE")
        .expect("lock command-history database");

    let cache_root = fixture.cache.path().to_path_buf();
    let state_root = fixture.state.path().to_path_buf();
    let writer = std::thread::spawn(move || {
        let mut command = satelle_command(&cache_root, &state_root);
        command
            .args(["config", "check", "--json"])
            .output()
            .expect("run config check while history is locked")
    });

    // Hold the lock long enough to distinguish command execution from SQLite
    // persistence while remaining below the recorder's busy timeout.
    std::thread::sleep(Duration::from_millis(1_200));
    connection
        .execute_batch("COMMIT")
        .expect("release command-history database");

    let output = writer.join().expect("history writer should not panic");
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let duration_ms = connection
        .query_row(
            "SELECT duration_ms FROM command_history ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .expect("query command duration");
    assert!(
        duration_ms < 600,
        "history persistence latency inflated duration to {duration_ms} ms"
    );
}

#[cfg(unix)]
#[test]
fn concurrent_first_run_creates_one_secure_cache_root_without_losing_rows() {
    use std::os::unix::fs::PermissionsExt;

    const WRITERS: usize = 8;

    let parent = tempfile::tempdir().expect("create first-run cache parent");
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700))
        .expect("secure first-run cache parent");
    let cache_root = parent.path().join("new").join("cache");
    let state = TestStateDir::new().expect("create command-history state root");
    let state_root = state.path().to_path_buf();
    let start = Arc::new(Barrier::new(WRITERS));
    let writers = (0..WRITERS)
        .map(|_| {
            let cache_root = cache_root.clone();
            let state_root = state_root.clone();
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                let mut command = satelle_command(&cache_root, &state_root);
                start.wait();
                command
                    .args(["config", "check", "--json"])
                    .output()
                    .expect("run concurrent first-use config check")
            })
        })
        .collect::<Vec<_>>();

    for writer in writers {
        let output = writer.join().expect("first-run writer should not panic");
        assert!(
            output.status.success(),
            "first-run command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let database = cache_root.join("command-history").join(HISTORY_DATABASE);
    let row_count = Connection::open(database)
        .expect("open first-run command-history database")
        .query_row("SELECT COUNT(*) FROM command_history", [], |row| {
            row.get::<_, i64>(0)
        })
        .expect("count first-run command-history rows");
    assert_eq!(row_count, WRITERS as i64);
}
