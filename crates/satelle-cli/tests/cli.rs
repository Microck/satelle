use assert_cmd::Command;
use predicates::prelude::*;
use satelle_core::SessionId;
use satelle_host::{ApiBearerToken, test_support::TestStateDir};
use satelle_test_contract::{assert_directory_tree_unchanged, assert_privacy_canaries_absent};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::net::TcpListener;

#[path = "support/test-file.rs"]
mod test_file;

const TEST_SUPPORT_ADAPTER_ENV: &str = "SATELLE_TEST_SUPPORT_ADAPTER";

fn satelle() -> Command {
    let mut command = Command::cargo_bin("satelle").expect("satelle binary should build");
    for name in [
        "SATELLE_HOME",
        "SATELLE_CONFIG_FILE",
        "SATELLE_STATE_DIR",
        "SATELLE_CACHE_DIR",
        "SATELLE_LOG_DIR",
        "SATELLE_HOST",
        "SATELLE_PROFILE",
        "SATELLE_ERROR_FORMAT",
        TEST_SUPPORT_ADAPTER_ENV,
    ] {
        command.env_remove(name);
    }
    command.env(TEST_SUPPORT_ADAPTER_ENV, "fake");
    command
}

fn production_satelle() -> Command {
    let mut command = satelle();
    command.env_remove(TEST_SUPPORT_ADAPTER_ENV);
    command
}

#[test]
fn bearer_tokens_are_rejected_in_process_arguments_and_environment() {
    let token = ApiBearerToken::generate().expect("generate bearer token");
    let exposed = token.expose();

    for mut command in [
        {
            let mut command = satelle();
            command.env_remove("SATELLE_API_TOKEN");
            command.args(["run", "--host", "local-demo", exposed.as_str()]);
            command
        },
        {
            let mut command = satelle();
            command
                .env("SATELLE_API_TOKEN", exposed.as_str())
                .args(["paths", "--json"]);
            command
        },
        {
            let mut command = satelle();
            command
                .env(exposed.as_str(), "set")
                .args(["paths", "--json"]);
            command
        },
    ] {
        let output = command.output().expect("run token-carrier rejection");
        assert!(!output.status.success());
        assert_privacy_canaries_absent(
            "CLI token-carrier rejection",
            &[output.stdout.as_slice(), output.stderr.as_slice()].concat(),
            &[exposed.as_str()],
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains(
            "bearer tokens are not accepted through command-line arguments or environment variables"
        ));
    }
}

#[test]
fn host_start_requires_complete_tls_material() {
    production_satelle()
        .args([
            "host",
            "start",
            "--foreground",
            "--tls-cert",
            "certificate.pem",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--tls-key"));
}

#[cfg(unix)]
#[test]
fn host_start_rejects_a_private_key_readable_by_other_users() {
    use std::os::unix::fs::PermissionsExt;

    let state = state_dir();
    fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700))
        .expect("make TLS fixture boundary owner-only");
    let certificate = state.path().join("certificate.pem");
    let private_key = state.path().join("private-key.pem");
    fs::write(&certificate, "not parsed before key security succeeds")
        .expect("write certificate fixture");
    fs::write(&private_key, "sensitive private key fixture").expect("write key fixture");
    fs::set_permissions(&certificate, fs::Permissions::from_mode(0o644))
        .expect("make certificate owner-controlled");
    fs::set_permissions(&private_key, fs::Permissions::from_mode(0o644))
        .expect("make private key unsafe");

    production_satelle()
        .args([
            "host",
            "start",
            "--foreground",
            "--tls-cert",
            certificate.to_str().expect("UTF-8 certificate path"),
            "--tls-key",
            private_key.to_str().expect("UTF-8 key path"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("TLS private key"));
}

#[cfg(unix)]
#[test]
fn host_start_rejects_a_certificate_writable_by_other_users() {
    use std::os::unix::fs::PermissionsExt;

    let state = state_dir();
    fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700))
        .expect("make TLS fixture boundary owner-only");
    let certificate = state.path().join("certificate.pem");
    let private_key = state.path().join("private-key.pem");
    let certified = rcgen::generate_simple_self_signed(["localhost".to_string()])
        .expect("generate valid matching TLS fixture");
    fs::write(&certificate, certified.cert.pem()).expect("write certificate fixture");
    fs::write(&private_key, certified.signing_key.serialize_pem())
        .expect("write private key fixture");
    fs::set_permissions(&certificate, fs::Permissions::from_mode(0o666))
        .expect("make certificate unsafe");
    fs::set_permissions(&private_key, fs::Permissions::from_mode(0o600))
        .expect("restrict private key");

    production_satelle()
        .args([
            "host",
            "start",
            "--foreground",
            "--tls-cert",
            certificate.to_str().expect("UTF-8 certificate path"),
            "--tls-key",
            private_key.to_str().expect("UTF-8 key path"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "violates the required file security policy",
        ));
}

#[cfg(unix)]
#[test]
fn host_start_rejects_tls_files_outside_an_owner_only_boundary() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().expect("create TLS fixture directory");
    let certificate = directory.path().join("certificate.pem");
    let private_key = directory.path().join("private-key.pem");
    fs::write(&certificate, "certificate fixture").expect("write certificate fixture");
    fs::write(&private_key, "private key fixture").expect("write key fixture");
    fs::set_permissions(&certificate, fs::Permissions::from_mode(0o600))
        .expect("restrict certificate file");
    fs::set_permissions(&private_key, fs::Permissions::from_mode(0o600))
        .expect("restrict private key file");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o777))
        .expect("make TLS boundary unsafe");

    production_satelle()
        .args([
            "host",
            "start",
            "--foreground",
            "--tls-cert",
            certificate.to_str().expect("UTF-8 certificate path"),
            "--tls-key",
            private_key.to_str().expect("UTF-8 key path"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("TLS file boundary"));
}

#[cfg(unix)]
#[test]
fn host_start_resolves_bare_tls_filenames_against_the_current_directory() {
    use std::os::unix::fs::PermissionsExt;

    let state = state_dir();
    fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700))
        .expect("make TLS fixture boundary owner-only");
    for filename in ["certificate.pem", "private-key.pem"] {
        let path = state.path().join(filename);
        fs::write(&path, "invalid TLS material").expect("write TLS fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("restrict TLS fixture");
    }

    production_satelle()
        .current_dir(state.path())
        .args([
            "host",
            "start",
            "--foreground",
            "--tls-cert",
            "certificate.pem",
            "--tls-key",
            "private-key.pem",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("TLS configuration is invalid"));
}

fn state_dir() -> TestStateDir {
    TestStateDir::new().expect("secure temp state directory should be created")
}

fn write_user_config(
    path: impl AsRef<std::path::Path>,
    contents: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    test_file::write_user_controlled(path.as_ref(), contents)
}

fn absolute_test_path(components: &[&str]) -> std::path::PathBuf {
    #[cfg(windows)]
    let mut path = std::path::PathBuf::from(r"C:\");
    #[cfg(not(windows))]
    let mut path = std::path::PathBuf::from("/");
    for component in components {
        path.push(component);
    }
    path
}

fn legacy_env(name: &str) -> String {
    format!("REMOTE{}_{name}", "USE")
}

fn session_id(stdout: &[u8]) -> String {
    let text = String::from_utf8_lossy(stdout);
    text.lines()
        .find_map(|line| line.strip_prefix("Session: "))
        .expect("command should print a Session line")
        .to_string()
}

fn completed_log_session(state: &TestStateDir) -> String {
    let run_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["run", "--host", "local-demo", "Open the browser"])
        .assert()
        .success()
        .get_output()
        .clone();
    let session = session_id(&run_output.stdout);
    satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["steer", &session, "Continue"])
        .assert()
        .success();
    satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["stop", &session])
        .assert()
        .success();
    session
}

fn combined_output(output: &assert_cmd::assert::Assert) -> String {
    let output = output.get_output();
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn parse_json_output(output: &[u8]) -> Value {
    serde_json::from_slice(output).expect("stdout should be one JSON value")
}

fn parse_json_lines(output: &[u8]) -> Vec<Value> {
    String::from_utf8_lossy(output)
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("line should be JSON"))
        .collect()
}

fn assert_exact_object_keys(value: &Value, expected: &[&str]) {
    let actual = value
        .as_object()
        .expect("value should be a JSON object")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
}

fn assert_runtime_bytes_are_private(surface: &str, output: &[u8], canaries: &[&str]) {
    assert_privacy_canaries_absent(surface, output, canaries);
    let output = String::from_utf8_lossy(output);
    for forbidden in [r#""prompt""#, r#""codex_thread_id""#, "codex_thread_"] {
        assert!(
            !output.contains(forbidden),
            "runtime output exposed forbidden upstream field {forbidden:?}: {output}"
        );
    }
}

fn command_output_text(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_command_output_is_private(output: &std::process::Output, canaries: &[&str]) {
    assert_runtime_bytes_are_private("CLI command stdout", &output.stdout, canaries);
    assert_runtime_bytes_are_private("CLI command stderr", &output.stderr, canaries);
}

fn assert_command_canaries_are_absent(output: &std::process::Output, canaries: &[&str]) {
    assert_privacy_canaries_absent("CLI command stdout", &output.stdout, canaries);
    assert_privacy_canaries_absent("CLI command stderr", &output.stderr, canaries);
}

fn assert_sqlite_files_are_private(state_root: &std::path::Path, canaries: &[&str]) {
    for file_name in [
        "satelle.sqlite3",
        "satelle.sqlite3-wal",
        "satelle.sqlite3-shm",
    ] {
        let path = state_root.join(file_name);
        if file_name != "satelle.sqlite3" && !path.exists() {
            continue;
        }

        let bytes = fs::read(&path)
            .unwrap_or_else(|error| panic!("could not read SQLite state file {path:?}: {error}"));
        let surface = format!("CLI SQLite state file {file_name}");
        assert_runtime_bytes_are_private(&surface, &bytes, canaries);
    }
}

fn collect_regular_file_bytes(path: &std::path::Path, bytes: &mut Vec<u8>) {
    if !path.exists() {
        return;
    }
    if path.is_dir() {
        for entry in fs::read_dir(path).expect("read privacy scan directory") {
            collect_regular_file_bytes(&entry.expect("read privacy scan entry").path(), bytes);
        }
    } else if path.is_file() {
        bytes.extend(fs::read(path).expect("read privacy scan file"));
    }
}

#[test]
fn ordinary_production_run_is_blocked_without_fake_completion_or_state_mutation() {
    let state = state_dir();
    let empty_path = state.path().join("empty-path");
    fs::create_dir(&empty_path).expect("create a deterministic empty executable search path");
    let output = production_satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .env("PATH", empty_path)
        .args([
            "run",
            "--host",
            "local-demo",
            "--json",
            "PRODUCTION_ADMISSION_PROMPT_CANARY",
        ])
        .assert()
        .code(75)
        .get_output()
        .clone();
    let combined = command_output_text(&output);

    // Linux closes at native platform admission. On the supported desktop
    // platforms, the more specific missing-runtime control-plane diagnosis
    // precedes the native readiness blocker.
    #[cfg(target_os = "linux")]
    assert!(combined.contains("computer-use-not-ready"));
    #[cfg(any(target_os = "macos", windows))]
    assert!(combined.contains("incompatible-control-plane"));
    #[cfg(any(target_os = "macos", windows))]
    assert!(combined.contains("runtime_missing"));
    assert!(!combined.contains("fake"));
    assert!(!combined.contains("completed"));
    assert!(!combined.contains("PRODUCTION_ADMISSION_PROMPT_CANARY"));
    assert!(!state.path().join("local-demo-state.json").exists());
}

#[test]
fn ordinary_production_doctor_reports_blocked_probes_without_fake_readiness() {
    let state = state_dir();
    let output = production_satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["doctor", "--host", "local-demo", "--json"])
        .assert()
        .code(75)
        .get_output()
        .clone();
    let combined = command_output_text(&output);
    let report = parse_json_output(&output.stdout);

    assert_eq!(report["status"], "blocked");
    assert_eq!(report["summary"]["ready"], false);
    let probes = report["probe_results"]
        .as_array()
        .expect("production doctor probes should be an array");
    for blocked_scope in ["codex", "computer-use", "provider", "transport"] {
        assert!(
            probes
                .iter()
                .any(|probe| { probe["scope"] == blocked_scope && probe["status"] == "blocked" })
        );
    }
    assert!(
        probes
            .iter()
            .any(|probe| probe["scope"] == "config" && probe["status"] == "passed")
    );
    assert!(
        report["findings"]
            .as_array()
            .is_some_and(|findings| findings.iter().all(|finding| finding["scope"] != "all"))
    );
    assert!(combined.contains("doctor-readiness-blockers-found"));
    assert!(!combined.contains("fake"));
    assert!(!state.path().join("local-demo-state.json").exists());
}

#[test]
fn production_status_and_stop_do_not_read_or_mutate_demo_state() {
    let state = state_dir();
    let state_path = state.path().join("local-demo-state.json");
    let canary = b"PRODUCTION_DEMO_STATE_MUST_REMAIN_UNTOUCHED";
    fs::write(&state_path, canary).expect("state canary should be written");
    let session_id = SessionId::new().to_string();

    for command in ["status", "stop"] {
        let output = production_satelle()
            .env("SATELLE_STATE_DIR", state.path())
            .args([command, &session_id, "--json"])
            .assert()
            .code(66)
            .get_output()
            .clone();

        assert!(command_output_text(&output).contains("session-not-found"));
        assert_eq!(
            fs::read(&state_path).expect("state canary should remain readable"),
            canary
        );
    }
}

#[test]
fn canonical_default_config_advertises_codex_instead_of_the_test_adapter() {
    let home = state_dir();
    let output = satelle()
        .env("SATELLE_HOME", home.path())
        .args(["config", "explain", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);

    assert_eq!(report["selected_host"], "local-demo");
    assert_eq!(
        report["effective"]["hosts"]["local-demo"]["adapter"],
        "codex"
    );
}

#[test]
fn help_prints_satelle_and_not_old_name() {
    let output = satelle()
        .arg("--help")
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("satelle"));
    assert!(!stdout.contains("RemoteUse"));
    assert!(!stdout.contains("remoteuse"));
}

#[test]
fn version_is_exact_and_does_not_initialize_host_state() {
    let home = state_dir();
    let untouched_home = home.path().join("untouched-satelle-home");

    production_satelle()
        .env("SATELLE_HOME", &untouched_home)
        .arg("--version")
        .assert()
        .success()
        .stdout(format!("satelle {}\n", env!("CARGO_PKG_VERSION")))
        .stderr(predicate::str::is_empty());

    assert!(!untouched_home.exists());
}

#[test]
fn legacy_environment_namespace_is_ignored() {
    let state = state_dir();
    let satelle_home = state.path().join("satelle-home");
    let config_file = satelle_home.join("config").join("config.toml");
    fs::create_dir_all(config_file.parent().unwrap()).expect("config dir should be created");
    write_user_config(
        &config_file,
        r#"
default_host = "project-host"

[hosts.project-host]
transport = "direct"
adapter = "fake"
address = "127.0.0.1:3001"
"#,
    )
    .expect("config should be written");

    let output = satelle()
        .env("SATELLE_HOME", &satelle_home)
        .env(legacy_env("HOME"), state.path().join("legacy-home"))
        .env(
            legacy_env("CONFIG_FILE"),
            state.path().join("legacy-config.toml"),
        )
        .env(legacy_env("STATE_DIR"), state.path().join("legacy-state"))
        .env(legacy_env("CACHE_DIR"), state.path().join("legacy-cache"))
        .env(legacy_env("LOG_DIR"), state.path().join("legacy-logs"))
        .env(legacy_env("HOST"), "local-demo")
        .env(legacy_env("PROFILE"), "legacy-profile")
        .args(["config", "explain", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);

    assert_eq!(report["selected_host"], "project-host");
    assert_eq!(report["selected_profile"], serde_json::Value::Null);
    assert_eq!(report["checked_files"][0], serde_json::json!(config_file));
    assert_eq!(report["sources"]["environment"]["host"]["set"], false);
    assert_eq!(report["sources"]["environment"]["profile"]["set"], false);

    let output = satelle()
        .env("SATELLE_HOME", &satelle_home)
        .env(legacy_env("HOME"), state.path().join("legacy-home"))
        .env(
            legacy_env("CONFIG_FILE"),
            state.path().join("legacy-config.toml"),
        )
        .env(legacy_env("STATE_DIR"), state.path().join("legacy-state"))
        .env(legacy_env("CACHE_DIR"), state.path().join("legacy-cache"))
        .env(legacy_env("LOG_DIR"), state.path().join("legacy-logs"))
        .args(["paths", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let paths = parse_json_output(&output.stdout);

    assert_eq!(paths["config_file"], serde_json::json!(config_file));
    assert_eq!(
        paths["state_root"],
        serde_json::json!(satelle_home.join("state"))
    );
    assert_eq!(
        paths["cache_root"],
        serde_json::json!(satelle_home.join("cache"))
    );
    assert_eq!(
        paths["operator_log_root"],
        serde_json::json!(satelle_home.join("logs"))
    );
}

#[test]
fn run_steer_and_status_share_a_local_demo_session() {
    let state = state_dir();
    let run_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local-demo",
            "Open the browser and report the page title",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Session: "))
        .stdout(predicate::str::contains("Status: completed"))
        .get_output()
        .clone();
    let session_id = session_id(&run_output.stdout);

    satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["steer", &session_id, "Continue from the same session"])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!("Session: {session_id}")))
        .stdout(predicate::str::contains("Turns: 2"));

    satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["status", &session_id])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!("Session: {session_id}")))
        .stdout(predicate::str::contains("Turns: 2"))
        .stdout(predicate::str::contains("Summary: task_completed"))
        .stdout(predicate::str::contains("Continue from the same session").not());
}

#[test]
fn local_conformance_fixture_uses_one_sqlite_state_authority() {
    let state = state_dir();
    satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local-demo",
            "--json",
            "Verify the local persistence authority",
        ])
        .assert()
        .success();

    let database_path = state.path().join("satelle.sqlite3");
    let database = fs::read(&database_path).expect("SQLite authority should be created");
    assert!(database.starts_with(b"SQLite format 3\0"));
    assert!(
        !state.path().join("local-demo-state.json").exists(),
        "the hard cut must not retain a JSON compatibility store"
    );
}

#[test]
fn read_only_fixture_diagnostics_do_not_initialize_runtime_storage() {
    let state = state_dir();
    satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["doctor", "--scope", "config", "--json"])
        .assert()
        .success();

    assert!(
        !state.path().join("satelle.sqlite3").exists(),
        "read-only diagnostics must not create the runtime database"
    );
    assert!(
        !state.path().join("satelle.sqlite3.lock").exists(),
        "read-only diagnostics must not create the runtime ownership lock"
    );
}

#[test]
fn runtime_surfaces_and_persisted_state_do_not_retain_prompts_or_upstream_ids() {
    let state = state_dir();
    let run_secret = "sk-satelle-run-private-canary";
    let run_upstream_id = "thread_codex_run_private_canary";
    let run_prompt_canary = "RUN_PRIVATE_PROMPT_CANARY";
    let run_prompt = format!("{run_prompt_canary} secret={run_secret} upstream={run_upstream_id}");
    let run_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["run", "--host", "local-demo", "--json", &run_prompt])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_command_output_is_private(
        &run_output,
        &[run_prompt_canary, run_secret, run_upstream_id],
    );
    let run_report = parse_json_output(&run_output.stdout);
    assert_eq!(run_report["schema_version"], "satelle.run.v2");
    assert_eq!(run_report["provider_smoke"]["status"], "passed");
    assert_eq!(run_report["provider_smoke"]["source"], "live");
    assert!(run_report["provider_smoke"]["observed_at"].is_string());
    assert!(run_report["provider_smoke"]["expires_at"].is_string());
    assert!(run_report["provider_smoke"]["age_ms"].is_u64());
    assert!(
        run_report["provider_smoke"]
            .get("provider_config_fingerprint")
            .is_none()
    );
    let session = run_report["session_id"].as_str().unwrap().to_string();

    let steer_secret = "sk-satelle-steer-private-canary";
    let steer_upstream_id = "turn_codex_steer_private_canary";
    let steer_prompt_canary = "STEER_PRIVATE_PROMPT_CANARY";
    let steer_prompt =
        format!("{steer_prompt_canary} secret={steer_secret} upstream={steer_upstream_id}");
    let steer_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "steer",
            &session,
            "--refresh-provider-smoke-test",
            "--json",
            &steer_prompt,
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_command_output_is_private(
        &steer_output,
        &[steer_prompt_canary, steer_secret, steer_upstream_id],
    );
    let steer_report = parse_json_output(&steer_output.stdout);
    assert_eq!(steer_report["provider_smoke"]["status"], "passed");
    assert_eq!(steer_report["provider_smoke"]["source"], "refresh");

    let status_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["status", &session, "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_command_output_is_private(
        &status_output,
        &[
            run_prompt_canary,
            run_secret,
            run_upstream_id,
            steer_prompt_canary,
            steer_secret,
            steer_upstream_id,
        ],
    );

    let logs_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["logs", "--session", &session, "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_command_output_is_private(
        &logs_output,
        &[
            run_prompt_canary,
            run_secret,
            run_upstream_id,
            steer_prompt_canary,
            steer_secret,
            steer_upstream_id,
        ],
    );

    let event_secret = "sk-satelle-event-private-canary";
    let event_upstream_id = "response_codex_event_private_canary";
    let event_prompt_canary = "EVENT_PRIVATE_PROMPT_CANARY";
    let event_prompt =
        format!("{event_prompt_canary} secret={event_secret} upstream={event_upstream_id}");
    let events_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local-demo",
            "--events",
            "json",
            &event_prompt,
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_command_output_is_private(
        &events_output,
        &[event_prompt_canary, event_secret, event_upstream_id],
    );

    let verbose_secret = "sk-satelle-verbose-event-private-canary";
    let verbose_upstream_id = "response_codex_verbose_event_private_canary";
    let verbose_prompt_canary = "VERBOSE_EVENT_PRIVATE_PROMPT_CANARY";
    let verbose_prompt =
        format!("{verbose_prompt_canary} secret={verbose_secret} upstream={verbose_upstream_id}");
    let verbose_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local-demo",
            "--events",
            "human",
            "--verbose",
            "--json",
            &verbose_prompt,
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_command_output_is_private(
        &verbose_output,
        &[verbose_prompt_canary, verbose_secret, verbose_upstream_id],
    );

    let detached_run_secret = "sk-satelle-detached-run-private-canary";
    let detached_run_upstream_id = "thread_codex_detached_run_private_canary";
    let detached_run_prompt_canary = "DETACHED_RUN_PRIVATE_PROMPT_CANARY";
    let detached_run_prompt = format!(
        "{detached_run_prompt_canary} secret={detached_run_secret} upstream={detached_run_upstream_id}"
    );
    let detached_run_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local-demo",
            "--detach",
            "--json",
            &detached_run_prompt,
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_command_output_is_private(
        &detached_run_output,
        &[
            detached_run_prompt_canary,
            detached_run_secret,
            detached_run_upstream_id,
        ],
    );
    let detached_run_report = parse_json_output(&detached_run_output.stdout);
    let detached_session = detached_run_report["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    let stop_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["stop", &detached_session, "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_command_output_is_private(
        &stop_output,
        &[
            detached_run_prompt_canary,
            detached_run_secret,
            detached_run_upstream_id,
        ],
    );

    let detached_steer_secret = "sk-satelle-detached-steer-private-canary";
    let detached_steer_upstream_id = "turn_codex_detached_steer_private_canary";
    let detached_steer_prompt_canary = "DETACHED_STEER_PRIVATE_PROMPT_CANARY";
    let detached_steer_prompt = format!(
        "{detached_steer_prompt_canary} secret={detached_steer_secret} upstream={detached_steer_upstream_id}"
    );
    let detached_steer_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "steer",
            &detached_session,
            "--detach",
            "--json",
            &detached_steer_prompt,
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_command_output_is_private(
        &detached_steer_output,
        &[
            detached_steer_prompt_canary,
            detached_steer_secret,
            detached_steer_upstream_id,
        ],
    );

    let detached_status_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["status", &detached_session, "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_command_output_is_private(
        &detached_status_output,
        &[
            detached_run_prompt_canary,
            detached_run_secret,
            detached_run_upstream_id,
            detached_steer_prompt_canary,
            detached_steer_secret,
            detached_steer_upstream_id,
        ],
    );

    let detached_logs_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["logs", "--session", &detached_session, "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_command_output_is_private(
        &detached_logs_output,
        &[
            detached_run_prompt_canary,
            detached_run_secret,
            detached_run_upstream_id,
            detached_steer_prompt_canary,
            detached_steer_secret,
            detached_steer_upstream_id,
        ],
    );

    assert_sqlite_files_are_private(
        state.path(),
        &[
            run_prompt_canary,
            run_secret,
            run_upstream_id,
            steer_prompt_canary,
            steer_secret,
            steer_upstream_id,
            event_prompt_canary,
            event_secret,
            event_upstream_id,
            verbose_prompt_canary,
            verbose_secret,
            verbose_upstream_id,
            detached_run_prompt_canary,
            detached_run_secret,
            detached_run_upstream_id,
            detached_steer_prompt_canary,
            detached_steer_secret,
            detached_steer_upstream_id,
        ],
    );
}

#[test]
fn post_ingestion_errors_do_not_echo_prompt_or_secret() {
    let state = state_dir();
    let secret = "sk-satelle-error-private-canary";
    let upstream_id = "thread_codex_error_private_canary";
    let prompt_canary = "ERROR_PRIVATE_PROMPT_CANARY";
    let prompt = format!("{prompt_canary} secret={secret} upstream={upstream_id}");
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["steer", "not-a-valid-session-id", "--json", &prompt])
        .assert()
        .failure()
        .get_output()
        .clone();

    assert_command_output_is_private(&output, &[prompt_canary, secret, upstream_id]);
    let error = parse_json_output(&output.stderr);
    assert_eq!(error["code"], "invalid-usage");
    assert_eq!(
        error["suggested_commands"],
        serde_json::json!(["use the exact Session or Turn identifier returned by Satelle"])
    );
}

#[test]
fn corrupt_sqlite_fails_closed_without_mutating_or_leaking_state() {
    let state = state_dir();
    let base_secret = "sk-satelle-hard-cut-base-canary";
    let base_prompt_canary = "HARD_CUT_BASE_PROMPT_CANARY";
    let base_prompt = format!("{base_prompt_canary} secret={base_secret}");
    let run_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["run", "--host", "local-demo", "--json", &base_prompt])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_command_output_is_private(&run_output, &[base_prompt_canary, base_secret]);
    let session_id = parse_json_output(&run_output.stdout)["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    let database_path = state.path().join("satelle.sqlite3");
    let corruption_canary = "SQLITE_CORRUPTION_PRIVATE_CANARY";
    let mut corrupted = fs::read(&database_path).expect("canonical SQLite state should exist");
    assert!(corrupted.starts_with(b"SQLite format 3\0"));
    corrupted[..16].copy_from_slice(b"CORRUPT-CANARY!\0");
    corrupted.extend_from_slice(corruption_canary.as_bytes());
    fs::write(&database_path, &corrupted).expect("SQLite corruption should be written");

    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["status", &session_id, "--json"])
        .assert()
        .failure()
        .get_output()
        .clone();
    assert_command_canaries_are_absent(&output, &[corruption_canary]);

    let error = parse_json_output(&output.stderr);
    assert_eq!(error["code"], "storage-integrity-failed");
    assert_eq!(
        fs::read(&database_path).expect("rejected SQLite state should be preserved"),
        corrupted,
        "corrupt SQLite state was silently rewritten"
    );
}

#[test]
fn stopping_terminal_turn_preserves_history_and_allows_later_steer() {
    let state = state_dir();
    let run_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local-demo",
            "--json",
            "Complete a session before requesting stop",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let run_report = parse_json_output(&run_output.stdout);
    let session_id = run_report["session_id"].as_str().unwrap().to_string();
    let turn_id = run_report["latest_turn"]["turn_id"]
        .as_str()
        .unwrap()
        .to_string();

    let stop_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["stop", &session_id, "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let stopped = parse_json_output(&stop_output.stdout);
    assert_exact_object_keys(
        &stopped,
        &[
            "changed",
            "current_state",
            "outcome",
            "previous_state",
            "schema_version",
            "session_id",
            "stopped_at",
            "turn_id",
        ],
    );
    assert_eq!(stopped["schema_version"], "satelle.stop.v1");
    assert_eq!(stopped["outcome"], "already_terminal");
    assert_eq!(stopped["session_id"], session_id);
    assert_eq!(stopped["turn_id"], turn_id);
    assert_eq!(stopped["previous_state"], "completed");
    assert_eq!(stopped["current_state"], "completed");
    assert_eq!(stopped["changed"], false);
    assert!(stopped["stopped_at"].is_null());

    satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["stop", &session_id])
        .assert()
        .success()
        .stdout(predicate::str::contains("Outcome: already_terminal"))
        .stdout(predicate::str::contains("Previous state: completed"))
        .stdout(predicate::str::contains("Current state: completed"))
        .stdout(predicate::str::contains("Changed: false"))
        .stdout(predicate::str::contains("Stopped at: not applicable"))
        .stdout(predicate::str::contains("Current state: stopped").not());

    let host_status = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["host", "status", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let host_status = parse_json_output(&host_status.stdout);
    assert_eq!(host_status["running"], true);
    assert_eq!(host_status["sessions"], 1);

    let steer_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "steer",
            &session_id,
            "--json",
            "Continue after the completed turn",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let steered = parse_json_output(&steer_output.stdout);
    assert_eq!(steered["schema_version"], "satelle.steer.v2");
    assert_eq!(steered["session_id"], session_id);
    assert_eq!(steered["status"], "completed");
    assert_eq!(steered["latest_turn"]["state"], "completed");

    let status_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["status", &session_id, "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let status = parse_json_output(&status_output.stdout);
    assert_eq!(status["schema_version"], "satelle.status.v2");
    assert_eq!(status["turns"].as_array().unwrap().len(), 2);
    assert_eq!(status["turns"][0]["state"], "completed");
    assert_eq!(status["turns"][1]["state"], "completed");
}

#[test]
fn stopping_detached_turn_returns_exact_stop_contract() {
    let state = state_dir();
    let run_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .env(TEST_SUPPORT_ADAPTER_ENV, "pending")
        .args([
            "run",
            "--host",
            "local-demo",
            "--detach",
            "--json",
            "Stop this detached turn",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let run_report = parse_json_output(&run_output.stdout);
    let session_id = run_report["session_id"].as_str().unwrap().to_string();
    let turn_id = run_report["turns"][0]["turn_id"]
        .as_str()
        .unwrap()
        .to_string();

    let stop_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .env(TEST_SUPPORT_ADAPTER_ENV, "pending")
        .args(["stop", &session_id, "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let stopped = parse_json_output(&stop_output.stdout);

    assert_exact_object_keys(
        &stopped,
        &[
            "changed",
            "current_state",
            "outcome",
            "previous_state",
            "schema_version",
            "session_id",
            "stopped_at",
            "turn_id",
        ],
    );
    assert_eq!(stopped["schema_version"], "satelle.stop.v1");
    assert_eq!(stopped["outcome"], "stopped");
    assert_eq!(stopped["session_id"], session_id);
    assert_eq!(stopped["turn_id"], turn_id);
    assert_eq!(stopped["previous_state"], "recovery_pending");
    assert_eq!(stopped["current_state"], "stopped");
    assert_eq!(stopped["changed"], true);
    assert!(stopped["stopped_at"].as_str().is_some());

    let status_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .env(TEST_SUPPORT_ADAPTER_ENV, "pending")
        .args(["status", &session_id, "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let status = parse_json_output(&status_output.stdout);
    assert_eq!(status["turns"].as_array().unwrap().len(), 1);
    assert_eq!(status["turns"][0]["turn_id"], turn_id);
    assert_eq!(status["turns"][0]["state"], "stopped");
}

#[test]
fn run_and_steer_accept_prompt_file_and_stdin_sources() {
    let state = state_dir();
    let prompt_file = state.path().join("prompt.txt");
    fs::write(&prompt_file, "Read this from a file").expect("prompt file should be written");

    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local-demo",
            "--prompt-file",
            prompt_file.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let run_report = parse_json_output(&output.stdout);
    let session = run_report["session_id"].as_str().unwrap().to_string();
    assert_eq!(run_report["latest_turn"]["safe_summary"], "task_completed");
    assert_command_output_is_private(&output, &["Read this from a file"]);

    let steer_prompt_file = state.path().join("steer-prompt.txt");
    fs::write(&steer_prompt_file, "Continue from a file")
        .expect("steer prompt file should be written");
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "steer",
            &session,
            "--prompt-file",
            steer_prompt_file.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let steer_report = parse_json_output(&output.stdout);
    assert_eq!(
        steer_report["latest_turn"]["safe_summary"],
        "task_completed"
    );
    assert_command_output_is_private(&output, &["Continue from a file"]);

    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["run", "--host", "local-demo", "--json", "-"])
        .write_stdin("Read this from stdin")
        .assert()
        .success()
        .get_output()
        .clone();
    let stdin_report = parse_json_output(&output.stdout);
    assert_eq!(
        stdin_report["latest_turn"]["safe_summary"],
        "task_completed"
    );
    assert_command_output_is_private(&output, &["Read this from stdin"]);

    satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local-demo",
            "--prompt-file",
            prompt_file.to_str().unwrap(),
            "--json",
            "also positional",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("prompt-source-conflict"));
}

#[test]
fn events_json_emits_newline_delimited_satelle_events() {
    let state = state_dir();
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local-demo",
            "--events",
            "json",
            "Open the browser and report the page title",
        ])
        .assert()
        .success()
        .get_output()
        .clone();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let events = stdout
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event line should be JSON"))
        .collect::<Vec<_>>();

    assert_eq!(events.len(), 7);
    assert_eq!(events[0]["type"], "preflight");
    assert_eq!(events[0]["source"], "cli");
    assert!(events[0]["session_id"].is_null());
    assert!(events[0]["turn_id"].is_null());
    assert!(events.iter().any(|event| event["type"] == "provider_smoke"));
    assert_eq!(events[6]["type"], "turn_completed");
    let session_id = events[1]["session_id"].as_str().unwrap().to_string();
    for (index, event) in events.iter().enumerate() {
        assert_eq!(event["schema_version"], "satelle.events.v2");
        assert!(event.get("source").is_some());
        assert!(event.get("timestamp").is_some());
        assert_eq!(event["seq"], u64::try_from(index + 1).unwrap());
        assert!(event.get("session_id").is_some());
        assert!(event.get("turn_id").is_some());
        assert_eq!(event["host"], "local-demo");
        assert!(event.get("message").is_some());
        assert!(event.get("data").is_some());
    }
    assert!(
        events[1..].iter().all(|event| {
            event["session_id"] == session_id && event["turn_id"].as_str().is_some()
        })
    );

    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "steer",
            &session_id,
            "--events",
            "json",
            "Continue from the same event stream",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let steer_events = parse_json_lines(&output.stdout);
    assert_eq!(steer_events.len(), 7);
    assert_eq!(steer_events[0]["type"], "preflight");
    assert_eq!(steer_events[0]["source"], "cli");
    assert!(
        steer_events
            .iter()
            .any(|event| event["type"] == "provider_smoke")
    );
    assert_eq!(steer_events[6]["type"], "turn_completed");
    assert_eq!(steer_events[6]["session_id"], session_id);
    assert_eq!(
        steer_events
            .iter()
            .map(|event| event["seq"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [1, 2, 3, 4, 5, 6, 7]
    );
}

#[test]
fn events_json_scopes_direct_daemon_unreachable_to_run_when_wss_cannot_connect() {
    let state = state_dir();
    let user_config = state.path().join("user-config.toml");
    let token_file = state.path().join("satelle.token");
    let token = ApiBearerToken::generate().expect("generate API token");
    test_file::write_user_controlled(&token_file, token.expose().as_str())
        .expect("write owner-only API token");

    let closed_listener = TcpListener::bind("127.0.0.1:0").expect("bind temporary port");
    let closed_address = closed_listener
        .local_addr()
        .expect("read temporary address");
    drop(closed_listener);
    let token_path = toml::Value::String(token_file.to_string_lossy().into_owned()).to_string();
    write_user_config(
        &user_config,
        format!(
            r#"
default_host = "remote"

[hosts.remote]
transport = "direct"
adapter = "codex"
address = "https://{closed_address}"
expected_host_id = "host-windows-11"
api_token = {{ kind = "file", path = {token_path} }}
"#,
        ),
    )
    .expect("write direct Host config");

    for (arguments, expected_code) in [
        (
            vec![
                "run".to_string(),
                "--events".to_string(),
                "json".to_string(),
                "Open the browser".to_string(),
            ],
            "direct-daemon-unreachable",
        ),
        (
            vec![
                "steer".to_string(),
                SessionId::new().to_string(),
                "--events".to_string(),
                "json".to_string(),
                "Continue".to_string(),
            ],
            "host-unreachable",
        ),
    ] {
        let output = production_satelle()
            .env("SATELLE_CONFIG_FILE", &user_config)
            .env("SATELLE_STATE_DIR", state.path())
            .args(arguments)
            .assert()
            .code(69)
            .get_output()
            .clone();
        let events = parse_json_lines(&output.stdout);

        assert_eq!(events.len(), 2, "stdout must contain no result JSON");
        assert_eq!(events[0]["type"], "preflight");
        let terminal = &events[1];
        assert_eq!(terminal["schema_version"], "satelle.events.v2");
        assert_eq!(terminal["type"], "command_failed");
        assert_eq!(terminal["source"], "cli");
        assert_eq!(terminal["host"], "remote");
        assert!(terminal["session_id"].is_null());
        assert!(terminal["turn_id"].is_null());
        assert!(terminal["state_subject"].is_null());
        assert_eq!(terminal["data"]["code"], expected_code);
        assert_eq!(terminal["data"]["admission_phase"], "not_admitted");
        assert!(terminal["data"]["session_id"].is_null());
        assert!(terminal["data"]["turn_id"].is_null());
        assert_eq!(terminal["message"], terminal["data"]["message"]);
        assert!(terminal["data"]["details"].is_object());
        assert_exact_object_keys(
            &terminal["data"],
            &[
                "admission_phase",
                "code",
                "details",
                "message",
                "recovery_command",
                "session_id",
                "source_detail",
                "turn_id",
            ],
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event["type"] == "command_failed")
                .count(),
            1
        );
    }

    let detached = production_satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["run", "--detach", "--json", "Open the browser"])
        .assert()
        .code(69)
        .get_output()
        .clone();
    assert!(detached.stdout.is_empty());
    assert_eq!(
        parse_json_output(&detached.stderr)["code"],
        "direct-daemon-unreachable"
    );
}

#[test]
fn events_json_reports_an_explicit_unknown_host_as_not_admitted() {
    let state = state_dir();

    for arguments in [
        vec![
            "run".to_string(),
            "--host".to_string(),
            "unknown-host".to_string(),
            "--events".to_string(),
            "json".to_string(),
            "Open the browser".to_string(),
        ],
        vec![
            "steer".to_string(),
            SessionId::new().to_string(),
            "--host".to_string(),
            "unknown-host".to_string(),
            "--events".to_string(),
            "json".to_string(),
            "Continue".to_string(),
        ],
    ] {
        let output = satelle()
            .env("SATELLE_STATE_DIR", state.path())
            .args(arguments)
            .assert()
            .failure()
            .get_output()
            .clone();
        let events = parse_json_lines(&output.stdout);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["type"], "command_failed");
        assert_eq!(events[0]["schema_version"], "satelle.events.v2");
        assert_eq!(events[0]["source"], "cli");
        assert_eq!(events[0]["host"], "unknown-host");
        assert_eq!(events[0]["data"]["code"], "host-not-found");
        assert_eq!(events[0]["data"]["admission_phase"], "not_admitted");
        assert!(events[0]["session_id"].is_null());
        assert!(events[0]["turn_id"].is_null());
        assert!(events[0]["state_subject"].is_null());
        assert!(events[0]["data"]["session_id"].is_null());
        assert!(events[0]["data"]["turn_id"].is_null());

        let error = parse_json_output(&output.stderr);
        assert_eq!(error["schema_version"], "satelle.error.v1");
        assert_eq!(error["code"], "host-not-found");
    }
}

#[test]
fn events_json_reports_prompt_failure_when_explicit_host_is_already_known() {
    let state = state_dir();
    let missing_prompt = state.path().join("missing-prompt.txt");
    let output = production_satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "selected-host",
            "--events",
            "json",
            "--prompt-file",
            missing_prompt.to_str().expect("test path should be UTF-8"),
        ])
        .assert()
        .failure()
        .get_output()
        .clone();
    let events = parse_json_lines(&output.stdout);

    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["type"], "command_failed");
    assert_eq!(events[0]["schema_version"], "satelle.events.v2");
    assert_eq!(events[0]["host"], "selected-host");
    assert_eq!(events[0]["data"]["code"], "input-required");
    assert_eq!(events[0]["data"]["admission_phase"], "not_admitted");
    assert!(events[0]["data"]["session_id"].is_null());
    assert!(events[0]["data"]["turn_id"].is_null());
}

#[test]
fn events_json_reports_output_conflict_when_explicit_host_is_already_known() {
    for arguments in [
        vec![
            "run".to_string(),
            "--host".to_string(),
            "selected-host".to_string(),
            "--events".to_string(),
            "json".to_string(),
            "--format".to_string(),
            "human".to_string(),
            "Open the browser".to_string(),
        ],
        vec![
            "steer".to_string(),
            SessionId::new().to_string(),
            "--host".to_string(),
            "selected-host".to_string(),
            "--events".to_string(),
            "json".to_string(),
            "--format".to_string(),
            "human".to_string(),
            "Continue".to_string(),
        ],
    ] {
        let output = satelle()
            .args(arguments)
            .assert()
            .failure()
            .get_output()
            .clone();
        let events = parse_json_lines(&output.stdout);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["type"], "command_failed");
        assert_eq!(events[0]["schema_version"], "satelle.events.v2");
        assert_eq!(events[0]["host"], "selected-host");
        assert_eq!(events[0]["data"]["code"], "output-mode-conflict");
        assert_eq!(events[0]["data"]["admission_phase"], "not_admitted");
        assert!(events[0]["session_id"].is_null());
        assert!(events[0]["turn_id"].is_null());
        assert!(events[0]["state_subject"].is_null());

        let error = parse_json_output(&output.stderr);
        assert_eq!(error["schema_version"], "satelle.error.v1");
        assert_eq!(error["code"], "output-mode-conflict");
    }
}

#[test]
fn run_help_has_events_modes_without_a_watch_option() {
    for command in ["run", "steer"] {
        let output = satelle()
            .args([command, "--help"])
            .assert()
            .success()
            .get_output()
            .clone();
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(stdout.contains("--events <EVENTS>"));
        assert!(stdout.contains("--quiet"));
        assert!(stdout.contains("--verbose"));
        assert!(stdout.contains("--image <LOCAL_PATH>"));
        assert!(stdout.contains("local PNG or JPEG image"));
        assert!(stdout.contains("maximum 2, 5 MiB each, 10 MiB total"));
        assert!(stdout.contains("Host capabilities"));
        assert!(stdout.contains("--timeout <DURATION>"));
        assert!(stdout.contains("shell history"));
        assert!(stdout.contains("local process metadata"));
        assert!(stdout.contains("stdin or --prompt-file"));
        assert!(stdout.contains("auto"));
        assert!(stdout.contains("human"));
        assert!(stdout.contains("json"));
        assert!(stdout.contains("none"));
    }

    let output = satelle()
        .args(["run", "--help"])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(!stdout.contains("--watch"));
}

#[test]
fn run_timeout_is_bounded_and_reported_in_milliseconds() {
    let state = state_dir();
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local-demo",
            "--timeout",
            "10s",
            "--json",
            "Use a short timeout",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    assert_eq!(
        report["effective_timeouts"]["turn_execution_timeout_ms"],
        10_000
    );

    for invalid in ["30", "500ms", "25h"] {
        satelle()
            .env("SATELLE_STATE_DIR", state.path())
            .args([
                "run",
                "--host",
                "local-demo",
                "--timeout",
                invalid,
                "--json",
                "Reject the invalid timeout",
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains("invalid-usage"));
    }
}

#[test]
fn verbose_human_events_include_structured_diagnostics() {
    let state = state_dir();
    satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local-demo",
            "--verbose",
            "--events",
            "human",
            "--json",
            "Open the browser",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            r#"preflight: resolved local demo host data={"adapter":"fake","transport":"local"}"#,
        ))
        .stderr(predicate::str::contains(
            r#"readiness: fake computer-use adapter is ready data={"ready":true}"#,
        ));
}

#[test]
fn provider_computer_use_flags_are_explicit_long_options() {
    for command in ["run", "steer"] {
        let output = satelle()
            .args([command, "--help"])
            .assert()
            .success()
            .get_output()
            .clone();
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(stdout.contains("--experimental-provider-computer-use"));
        assert!(stdout.contains("Experimental: attempt non-OpenAI provider Computer Use"));
        assert!(stdout.contains("behavior may not work correctly"));
        assert!(stdout.contains("requires a live provider Computer Use smoke test"));
        assert!(stdout.contains("--refresh-provider-smoke-test"));
        assert!(stdout.contains("Refresh the cached provider Computer Use smoke-test result"));
        assert!(stdout.contains("does not enable experimental provider Computer Use"));
        assert!(!stdout.contains("-e, --experimental-provider-computer-use"));
        assert!(!stdout.contains("-r, --refresh-provider-smoke-test"));
    }

    let state = state_dir();
    satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local-demo",
            "--refresh-provider-smoke-test",
            "--json",
            "Refresh without experimental opt-in",
        ])
        .assert()
        .success();
}

#[test]
fn explicit_events_override_quiet_mode_for_run_and_steer() {
    let state = state_dir();
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local-demo",
            "--quiet",
            "--events",
            "human",
            "--refresh-provider-smoke-test",
            "--json",
            "Open the browser",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("preflight:"))
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    assert_eq!(report["provider_smoke"]["status"], "passed");
    assert_eq!(report["provider_smoke"]["source"], "refresh");
    let session = report["session_id"].as_str().unwrap();

    satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "steer", session, "--quiet", "--events", "human", "--json", "Continue",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("preflight:"));
}

#[test]
fn quiet_mode_suppresses_progress_without_skipping_provider_smoke() {
    let state = state_dir();
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local-demo",
            "--quiet",
            "--refresh-provider-smoke-test",
            "--json",
            "Verify quiet provider readiness",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("preflight:").not())
        .get_output()
        .clone();

    let report = parse_json_output(&output.stdout);
    assert_eq!(report["provider_smoke_test_status"], "passed");
    assert_eq!(report["provider_smoke"]["status"], "passed");
    assert_eq!(report["provider_smoke"]["source"], "refresh");
    assert_eq!(report["latest_turn"]["safe_summary"], "task_completed");
}

#[test]
fn events_json_with_detach_fails_with_typed_usage_error() {
    let state = state_dir();
    satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local-demo",
            "--events",
            "json",
            "--detach",
            "Open the browser",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("events-with-detach"));
}

#[test]
fn run_and_steer_reject_conflicting_interrupt_modes_before_admission() {
    let state = state_dir();
    let session_id = SessionId::new();
    for arguments in [
        vec![
            "run".to_string(),
            "--host".to_string(),
            "local-demo".to_string(),
            "--detach".to_string(),
            "--detach-on-interrupt".to_string(),
            "--json".to_string(),
            "Do not admit this run".to_string(),
        ],
        vec![
            "steer".to_string(),
            session_id.to_string(),
            "--detach".to_string(),
            "--detach-on-interrupt".to_string(),
            "--json".to_string(),
            "Do not admit this steer".to_string(),
        ],
    ] {
        let output = satelle()
            .env("SATELLE_STATE_DIR", state.path())
            .args(arguments)
            .assert()
            .code(64)
            .stdout(predicate::str::is_empty())
            .get_output()
            .clone();
        let error = parse_json_output(&output.stderr);
        assert_eq!(error["schema_version"], "satelle.error.v1");
        assert_eq!(error["code"], "interrupt-mode-conflict");
    }
    assert!(!state.path().join("satelle.sqlite3").exists());
}

#[test]
fn detach_returns_starting_session_without_event_streaming() {
    let state = state_dir();
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .env(TEST_SUPPORT_ADAPTER_ENV, "pending")
        .args([
            "run",
            "--host",
            "local-demo",
            "--detach",
            "--json",
            "Start this turn detached",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let session = parse_json_output(&output.stdout);
    let session_id = session["session_id"].as_str().unwrap().to_string();

    assert_eq!(session["status"], "starting");
    assert_eq!(session["turns"].as_array().unwrap().len(), 1);
    assert_eq!(session["turns"][0]["state"], "starting");
    assert!(session["turns"][0]["terminal_at"].is_null());

    let status_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["status", &session_id, "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let status = parse_json_output(&status_output.stdout);
    assert_eq!(status["status"], "recovery_pending");

    let logs_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["logs", "--session", &session_id, "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let entries = parse_json_lines(&logs_output.stdout);
    let recovery_cursor = entries
        .iter()
        .find(|entry| entry["event"] == "restart_recovery_pending")
        .and_then(|entry| entry["cursor"].as_str())
        .expect("restart recovery should be recorded with an opaque cursor");
    assert!(
        entries
            .iter()
            .filter(|entry| entry["event"] == "turn_state_committed")
            .all(|entry| {
                entry["cursor"]
                    .as_str()
                    .is_some_and(|cursor| cursor < recovery_cursor)
            }),
        "read-only commands must not commit liveness after recovery begins"
    );

    let busy_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local-demo",
            "--json",
            "This should not queue behind the detached turn",
        ])
        .assert()
        .failure()
        .get_output()
        .clone();
    let busy_error = parse_json_output(&busy_output.stderr);
    assert_eq!(busy_error["code"], "host-busy");
    assert_eq!(busy_error["details"]["host"], "local-demo");
    assert_eq!(busy_error["details"]["active_session_id"], session_id);

    let busy_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "steer",
            &session_id,
            "--json",
            "This should not start while the detached turn is active",
        ])
        .assert()
        .failure()
        .get_output()
        .clone();
    let busy_error = parse_json_output(&busy_output.stderr);
    assert_eq!(busy_error["code"], "host-busy");
    assert_eq!(busy_error["details"]["active_session_id"], session_id);

    satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["stop", &session_id, "--json"])
        .assert()
        .success();

    let steer_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "steer",
            &session_id,
            "--detach",
            "--json",
            "Start a detached follow-up",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let steered = parse_json_output(&steer_output.stdout);
    assert_eq!(steered["session_id"], session_id);
    assert_eq!(steered["status"], "starting");
    assert_eq!(steered["turns"].as_array().unwrap().len(), 2);
    assert_eq!(steered["turns"][1]["state"], "starting");
    assert!(steered["turns"][1]["terminal_at"].is_null());
}

#[test]
fn logs_json_applies_tail_session_source_level_and_since_on_the_host() {
    let state = state_dir();
    let session = completed_log_session(&state);

    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "logs",
            "--session",
            &session,
            "--source",
            "host_daemon",
            "--tail",
            "2",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    assert!(output.stderr.is_empty());
    let entries = parse_json_lines(&output.stdout);
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|entry| {
        entry["source"] == "host_daemon" && entry["subject"]["session_id"] == session
    }));
    assert_eq!(entries[0]["event"], "turn_state_committed");
    assert_eq!(entries[0]["severity"], "info");
    assert_eq!(entries[1]["event"], "stop_confirmed");
    assert_eq!(entries[1]["severity"], "warn");

    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "logs",
            "--source",
            "host_daemon",
            "--source",
            "storage",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let repeated_source_entries = parse_json_lines(&output.stdout);
    assert!(!repeated_source_entries.is_empty());
    assert!(
        repeated_source_entries
            .iter()
            .all(|entry| { matches!(entry["source"].as_str(), Some("host_daemon" | "storage")) })
    );

    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["logs", "--session", &session, "--level", "warn", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let entries = parse_json_lines(&output.stdout);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["severity"], "warn");

    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["logs", "--session", &session, "--since", "30m", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert!(!parse_json_lines(&output.stdout).is_empty());

    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "logs",
            "--session",
            &session,
            "--since",
            "2999-01-01T00:00:00Z",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());

    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["logs", "--tail", "10001", "--json"])
        .assert()
        .failure()
        .get_output()
        .clone();
    let error = parse_json_output(&output.stderr);
    assert_eq!(error["code"], "log-tail-limit-exceeded");
}

#[test]
fn logs_after_resumes_strictly_after_the_opaque_cursor() {
    let state = state_dir();
    let session = completed_log_session(&state);

    let initial = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["logs", "--session", &session, "--tail", "2", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let initial_entries = parse_json_lines(&initial.stdout);
    assert_eq!(initial_entries.len(), 2);
    let cursor = initial_entries[0]["cursor"]
        .as_str()
        .expect("a Log Entry should expose an opaque cursor");

    let resumed = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["logs", "--session", &session, "--after", cursor, "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert!(resumed.stderr.is_empty());
    let resumed_entries = parse_json_lines(&resumed.stdout);
    assert_eq!(resumed_entries.len(), 1);
    assert_eq!(resumed_entries[0]["cursor"], initial_entries[1]["cursor"]);
    assert!(resumed_entries.iter().all(|entry| {
        entry["cursor"]
            .as_str()
            .is_some_and(|resumed_cursor| resumed_cursor > cursor)
    }));
}

#[test]
fn logs_after_rejects_since_and_explicit_tail_with_a_typed_conflict() {
    let state = state_dir();
    let cursor = "slc1_0000000000000000";

    for conflicting_args in [
        vec!["--since", "2024-01-01T00:00:00Z"],
        vec!["--tail", "20"],
    ] {
        let mut args = vec!["logs", "--after", cursor, "--json"];
        args.extend(conflicting_args);
        let output = satelle()
            .env("SATELLE_STATE_DIR", state.path())
            .args(args)
            .assert()
            .code(64)
            .get_output()
            .clone();

        assert!(output.stdout.is_empty());
        let error = parse_json_output(&output.stderr);
        assert_eq!(error["schema_version"], "satelle.error.v1");
        assert_eq!(error["code"], "log-position-conflict");
    }
}

#[test]
fn logs_accepts_only_canonical_sources_and_severities() {
    let state = state_dir();

    for source in ["host_daemon", "storage", "codex_adapter"] {
        satelle()
            .env("SATELLE_STATE_DIR", state.path())
            .args(["logs", "--source", source, "--json"])
            .assert()
            .success()
            .stderr(predicate::str::is_empty());
    }
    for severity in ["info", "warn", "error"] {
        satelle()
            .env("SATELLE_STATE_DIR", state.path())
            .args(["logs", "--level", severity, "--json"])
            .assert()
            .success()
            .stderr(predicate::str::is_empty());
    }

    for (flag, value) in [("--source", "transport"), ("--level", "debug")] {
        let output = satelle()
            .env("SATELLE_STATE_DIR", state.path())
            .args(["logs", flag, value, "--json"])
            .assert()
            .code(64)
            .get_output()
            .clone();
        assert!(output.stdout.is_empty());
        let error = parse_json_output(&output.stderr);
        assert_eq!(error["code"], "invalid-usage");
    }
}

#[test]
fn production_setup_dry_run_reports_plan_without_mutating_declared_paths() {
    let sandbox = state_dir();
    let operator_home = sandbox.path().join("operator/home");
    let operator_config_file = sandbox.path().join("operator/config/config.toml");
    let operator_state_dir = sandbox.path().join("operator/state");
    let operator_cache_dir = sandbox.path().join("operator/cache");
    let operator_log_dir = sandbox.path().join("operator/logs");
    let daemon_home = sandbox.path().join("daemon/home");
    let daemon_config_file = sandbox.path().join("daemon/config/config.toml");
    let daemon_state_dir = sandbox.path().join("daemon/state");
    let daemon_cache_dir = sandbox.path().join("daemon/cache");
    let daemon_log_dir = sandbox.path().join("daemon/logs");

    for config_parent in [
        operator_config_file
            .parent()
            .expect("operator config path should have a parent"),
        daemon_config_file
            .parent()
            .expect("daemon config path should have a parent"),
    ] {
        fs::create_dir_all(config_parent).expect("config parent directory should be created");
    }

    write_user_config(
        &operator_config_file,
        r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"
adapter = "codex"
"#,
    )
    .expect("production local Host config should be written");
    write_user_config(&daemon_config_file, b"daemon config canary\n")
        .expect("daemon config canary should be written");

    for (directory, canary) in [
        (&operator_home, "operator home canary"),
        (&operator_state_dir, "operator state canary"),
        (&operator_cache_dir, "operator cache canary"),
        (&operator_log_dir, "operator log canary"),
        (&daemon_home, "daemon home canary"),
        (&daemon_state_dir, "daemon state canary"),
        (&daemon_cache_dir, "daemon cache canary"),
        (&daemon_log_dir, "daemon log canary"),
    ] {
        let canary_path = directory.join("nested/canary.bin");
        fs::create_dir_all(
            canary_path
                .parent()
                .expect("canary path should have a parent"),
        )
        .expect("nested canary directory should be created");
        fs::write(canary_path, canary.as_bytes()).expect("nested canary should be written");
    }

    let output = assert_directory_tree_unchanged("satelle setup --dry-run", sandbox.path(), || {
        production_satelle()
            .env("SATELLE_HOME", &operator_home)
            .env("SATELLE_CONFIG_FILE", &operator_config_file)
            .env("SATELLE_STATE_DIR", &operator_state_dir)
            .env("SATELLE_CACHE_DIR", &operator_cache_dir)
            .env("SATELLE_LOG_DIR", &operator_log_dir)
            .args(["setup", "--dry-run", "--host", "local-demo", "--json"])
            .arg("--daemon-home")
            .arg(&daemon_home)
            .arg("--daemon-config-file")
            .arg(&daemon_config_file)
            .arg("--daemon-state-dir")
            .arg(&daemon_state_dir)
            .arg("--daemon-cache-dir")
            .arg(&daemon_cache_dir)
            .arg("--daemon-log-dir")
            .arg(&daemon_log_dir)
            .assert()
            .success()
            .stderr(predicate::str::is_empty())
            .get_output()
            .clone()
    });
    let report = parse_json_output(&output.stdout);

    assert_eq!(report["schema_version"], "satelle.setup.v1");
    assert_eq!(report["dry_run"], true);
    assert_eq!(report["status"], "planned");
    assert_eq!(
        report["daemon_path_overrides"],
        serde_json::json!([
            {
                "environment_variable": "SATELLE_HOME",
                "value": daemon_home,
                "source": "setup_flag",
                "service_configuration_surface": "satelle_service_configuration",
            },
            {
                "environment_variable": "SATELLE_CONFIG_FILE",
                "value": daemon_config_file,
                "source": "setup_flag",
                "service_configuration_surface": "satelle_service_configuration",
            },
            {
                "environment_variable": "SATELLE_STATE_DIR",
                "value": daemon_state_dir,
                "source": "setup_flag",
                "service_configuration_surface": "satelle_service_configuration",
            },
            {
                "environment_variable": "SATELLE_CACHE_DIR",
                "value": daemon_cache_dir,
                "source": "setup_flag",
                "service_configuration_surface": "satelle_service_configuration",
            },
            {
                "environment_variable": "SATELLE_LOG_DIR",
                "value": daemon_log_dir,
                "source": "setup_flag",
                "service_configuration_surface": "satelle_service_configuration",
            },
        ])
    );
    assert!(
        report["planned_actions"]
            .as_array()
            .is_some_and(|actions| !actions.is_empty())
    );
    assert_eq!(report["applied_actions"], serde_json::json!([]));
    assert_eq!(report["mutated"], false);
}

#[test]
fn production_setup_with_default_host_fails_closed_before_operator_state_is_touched() {
    let sandbox = state_dir();
    let operator_home = sandbox.path().join("operator/home");
    let operator_config_file = operator_home.join("config/config.toml");
    let operator_state_dir = sandbox.path().join("operator/state");
    let operator_cache_dir = sandbox.path().join("operator/cache");
    let operator_log_dir = sandbox.path().join("operator/logs");
    fs::create_dir_all(
        operator_config_file
            .parent()
            .expect("config file has a parent"),
    )
    .expect("operator config directory should be created before the mutation check");
    write_user_config(
        &operator_config_file,
        r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"
adapter = "codex"
"#,
    )
    .expect("production config should be written");

    let output = assert_directory_tree_unchanged(
        "satelle setup --yes with the unsupported default local host",
        sandbox.path(),
        || {
            production_satelle()
                .env("SATELLE_HOME", &operator_home)
                .env("SATELLE_CONFIG_FILE", &operator_config_file)
                .env("SATELLE_STATE_DIR", &operator_state_dir)
                .env("SATELLE_CACHE_DIR", &operator_cache_dir)
                .env("SATELLE_LOG_DIR", &operator_log_dir)
                .args(["setup", "--yes", "--json"])
                .assert()
                .code(70)
                .get_output()
                .clone()
        },
    );
    let error = parse_json_output(&output.stderr);

    assert_eq!(error["code"], "not-implemented");
    assert!(
        error["message"]
            .as_str()
            .is_some_and(|message| message.contains("setup mutations are not supported"))
    );

    let output = assert_directory_tree_unchanged(
        "satelle setup with a local expected Host identity",
        sandbox.path(),
        || {
            production_satelle()
                .env("SATELLE_HOME", &operator_home)
                .env("SATELLE_CONFIG_FILE", &operator_config_file)
                .env("SATELLE_STATE_DIR", &operator_state_dir)
                .env("SATELLE_CACHE_DIR", &operator_cache_dir)
                .env("SATELLE_LOG_DIR", &operator_log_dir)
                .args([
                    "setup",
                    "--yes",
                    "--json",
                    "--expected-host-id",
                    "host-test",
                ])
                .assert()
                .code(64)
                .get_output()
                .clone()
        },
    );

    assert_eq!(parse_json_output(&output.stderr)["code"], "invalid-usage");
}

#[test]
fn production_setup_with_aliased_local_host_fails_before_operator_state_is_touched() {
    let sandbox = state_dir();
    let operator_home = sandbox.path().join("operator/home");
    let operator_config_file = operator_home.join("config/config.toml");
    let operator_state_dir = sandbox.path().join("operator/state");
    let operator_cache_dir = sandbox.path().join("operator/cache");
    let operator_log_dir = sandbox.path().join("operator/logs");
    fs::create_dir_all(
        operator_config_file
            .parent()
            .expect("config file has a parent"),
    )
    .expect("operator config directory should be created");
    write_user_config(
        &operator_config_file,
        r#"
default_host = "workstation"

[hosts.workstation]
transport = "local"
adapter = "codex"
"#,
    )
    .expect("production config should be written");

    let output = assert_directory_tree_unchanged(
        "satelle setup with an aliased local Host",
        sandbox.path(),
        || {
            production_satelle()
                .env("SATELLE_HOME", &operator_home)
                .env("SATELLE_CONFIG_FILE", &operator_config_file)
                .env("SATELLE_STATE_DIR", &operator_state_dir)
                .env("SATELLE_CACHE_DIR", &operator_cache_dir)
                .env("SATELLE_LOG_DIR", &operator_log_dir)
                .args(["setup", "--yes", "--json"])
                .assert()
                .code(70)
                .get_output()
                .clone()
        },
    );

    assert_eq!(parse_json_output(&output.stderr)["code"], "not-implemented");
}

#[test]
fn production_setup_validation_fails_before_operator_state_is_touched() {
    let sandbox = state_dir();
    let operator_home = sandbox.path().join("operator/home");
    let operator_config_file = operator_home.join("config/config.toml");
    let operator_state_dir = sandbox.path().join("operator/state");
    let operator_cache_dir = sandbox.path().join("operator/cache");
    let operator_log_dir = sandbox.path().join("operator/logs");

    for (description, arguments, expected_code) in [
        (
            "satelle setup with conflicting components",
            vec![
                "setup",
                "--component",
                "all",
                "--component",
                "codex",
                "--yes",
                "--json",
            ],
            "component-selection-conflict",
        ),
        (
            "satelle setup with conflicting modes",
            vec!["setup", "--on-demand", "--persistent", "--yes", "--json"],
            "invalid-usage",
        ),
    ] {
        let output = assert_directory_tree_unchanged(description, sandbox.path(), || {
            production_satelle()
                .env("SATELLE_HOME", &operator_home)
                .env("SATELLE_CONFIG_FILE", &operator_config_file)
                .env("SATELLE_STATE_DIR", &operator_state_dir)
                .env("SATELLE_CACHE_DIR", &operator_cache_dir)
                .env("SATELLE_LOG_DIR", &operator_log_dir)
                .args(arguments)
                .assert()
                .code(64)
                .get_output()
                .clone()
        });

        assert_eq!(parse_json_output(&output.stderr)["code"], expected_code);
    }
}

#[test]
fn production_setup_honors_environment_host_before_local_preflight() {
    let sandbox = state_dir();
    let operator_config_file = sandbox.path().join("operator/config.toml");
    fs::create_dir_all(
        operator_config_file
            .parent()
            .expect("config file has a parent"),
    )
    .expect("operator config directory should be created");
    write_user_config(
        &operator_config_file,
        r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"
adapter = "codex"
"#,
    )
    .expect("production config should be written");

    let output = assert_directory_tree_unchanged(
        "satelle setup with an environment-selected host",
        sandbox.path(),
        || {
            production_satelle()
                .env("SATELLE_CONFIG_FILE", &operator_config_file)
                .env("SATELLE_STATE_DIR", sandbox.path().join("operator/state"))
                .env("SATELLE_CACHE_DIR", sandbox.path().join("operator/cache"))
                .env("SATELLE_HOST", "remote")
                .args(["setup", "--yes", "--json"])
                .assert()
                .code(66)
                .get_output()
                .clone()
        },
    );

    assert_eq!(parse_json_output(&output.stderr)["code"], "host-not-found");
}

#[test]
fn production_setup_honors_configured_default_host_before_local_preflight() {
    let sandbox = state_dir();
    let operator_config_file = sandbox.path().join("operator/config.toml");
    fs::create_dir_all(
        operator_config_file
            .parent()
            .expect("config file has a parent"),
    )
    .expect("operator config directory should be created");
    write_user_config(
        &operator_config_file,
        r#"
default_host = "remote"
"#,
    )
    .expect("production config should be written");

    let output = assert_directory_tree_unchanged(
        "satelle setup with a configured default host",
        sandbox.path(),
        || {
            production_satelle()
                .env("SATELLE_CONFIG_FILE", &operator_config_file)
                .env("SATELLE_STATE_DIR", sandbox.path().join("operator/state"))
                .env("SATELLE_CACHE_DIR", sandbox.path().join("operator/cache"))
                .args(["setup", "--yes", "--json"])
                .assert()
                .code(66)
                .get_output()
                .clone()
        },
    );

    assert_eq!(parse_json_output(&output.stderr)["code"], "host-not-found");
}

#[test]
fn setup_component_filters_default_repeat_and_reject_all_conflict() {
    let state = state_dir();
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["setup", "--dry-run", "--host", "local-demo", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    assert_eq!(report["setup_components"], serde_json::json!(["all"]));

    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "setup",
            "--dry-run",
            "--host",
            "local-demo",
            "--component",
            "transport",
            "--component",
            "computer-use",
            "--component",
            "provider-auth",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    assert_eq!(
        report["setup_components"],
        serde_json::json!(["transport", "computer-use", "provider-auth"])
    );

    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "setup",
            "--dry-run",
            "--host",
            "local-demo",
            "--component",
            "all",
            "--component",
            "codex",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .clone();
    let error = parse_json_output(&output.stderr);
    assert_eq!(error["code"], "component-selection-conflict");

    let output = satelle()
        .args(["setup", "--help"])
        .assert()
        .success()
        .get_output()
        .clone();
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("--component <COMPONENT>"));
    assert!(help.contains("transport"));
    assert!(help.contains("provider-auth"));
    assert!(help.contains("Agent-safe noninteractive provider auth flow"));
    assert!(help.contains("host-resolved Secret Source descriptors"));
    assert!(help.contains("satelle setup --no-input --json"));
    assert!(help.contains("required human input"));
    assert!(help.contains("Accept ordinary setup mutations"));
    assert!(help.contains("--expected-host-id <HOST_ID>"));
    assert!(!help.contains("YOLO"));
    assert!(!help.contains("prompt-execution auto-approval"));
    assert!(!help.contains("-c, --component"));
}

#[test]
fn repair_yes_help_describes_ordinary_repair_mutations() {
    let output = satelle()
        .args(["repair", "--help"])
        .assert()
        .success()
        .get_output()
        .clone();
    let help = String::from_utf8_lossy(&output.stdout);

    assert!(help.contains("Accept ordinary repair mutations"));
    assert!(!help.contains("YOLO"));
    assert!(!help.contains("prompt-execution auto-approval"));
}

#[test]
fn setup_no_input_json_requires_consent_without_mutating() {
    let state = state_dir();
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["setup", "--no-input", "--json", "--host", "local-demo"])
        .assert()
        .code(64)
        .get_output()
        .clone();
    let error = parse_json_output(&output.stderr);

    assert_eq!(error["code"], "setup-consent-required");
    assert_eq!(error["details"]["applied_actions"], serde_json::json!([]));
    assert_eq!(error["details"]["mutated"], false);
    assert!(
        error["details"]["planned_actions"]
            .as_array()
            .is_some_and(|actions| actions.len() >= 3)
    );
    assert_eq!(
        error["suggested_commands"][0],
        "satelle setup --host local-demo --on-demand --no-input --json --yes"
    );
    assert!(!state.path().join("local-demo-state.json").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn setup_interactive_decline_exits_successfully_without_mutating_state() {
    let state = state_dir();
    let executable = assert_cmd::cargo::cargo_bin!("satelle");
    let command_line = format!("{} setup --host local-demo", executable.display());

    let output =
        assert_directory_tree_unchanged("declined interactive satelle setup", state.path(), || {
            let mut command = Command::new("script");
            for name in [
                "SATELLE_HOME",
                "SATELLE_CONFIG_FILE",
                "SATELLE_STATE_DIR",
                "SATELLE_CACHE_DIR",
                "SATELLE_LOG_DIR",
                "SATELLE_HOST",
                "SATELLE_PROFILE",
                "SATELLE_ERROR_FORMAT",
                TEST_SUPPORT_ADAPTER_ENV,
            ] {
                command.env_remove(name);
            }
            command
                .env("SATELLE_STATE_DIR", state.path())
                .env("SATELLE_COMMAND_HISTORY", "false")
                .env(TEST_SUPPORT_ADAPTER_ENV, "fake")
                .args(["-qec", command_line.as_str(), "/dev/null"])
                .write_stdin("n\n")
                .assert()
                .success()
                .get_output()
                .clone()
        });

    let output = String::from_utf8_lossy(&[output.stdout, output.stderr].concat()).to_string();
    assert!(
        output.contains("No changes applied."),
        "decline output should report no mutation: {output}"
    );
    assert!(!state.path().join("local-demo-state.json").exists());
}

#[test]
fn setup_provider_auth_without_a_user_binding_defers_to_host_ownership() {
    let state = state_dir();
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "setup",
            "--component",
            "provider-auth",
            "--dry-run",
            "--no-input",
            "--json",
            "--host",
            "local-demo",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    let required_input = report["required_input"].as_array().unwrap();

    assert_eq!(report["status"], "planned");
    assert_eq!(
        report["setup_components"],
        serde_json::json!(["provider-auth"])
    );
    assert_eq!(report["readiness_summary"]["provider_auth"], "host_owned");
    assert!(required_input.is_empty());
    assert_eq!(report["applied_actions"], serde_json::json!([]));
    assert_eq!(report["mutated"], false);
    assert!(!state.path().join("local-demo-state.json").exists());
}

#[test]
fn host_update_valid_selections_fail_truthfully_without_mutating_state() {
    let state = state_dir();
    for args in [
        vec!["host", "update", "--host", "local-demo", "--json"],
        vec![
            "host",
            "update",
            "--host",
            "local-demo",
            "--component",
            "host",
            "--json",
        ],
        vec![
            "host",
            "update",
            "--host",
            "local-demo",
            "--component",
            "codex",
            "--json",
        ],
        vec![
            "host",
            "update",
            "--host",
            "local-demo",
            "--component",
            "host",
            "--component",
            "codex",
            "--json",
        ],
        vec![
            "host",
            "update",
            "--host",
            "local-demo",
            "--component",
            "all",
            "--dry-run",
            "--json",
        ],
    ] {
        let output = satelle()
            .env("SATELLE_STATE_DIR", state.path())
            .args(args)
            .assert()
            .code(70)
            .get_output()
            .clone();
        assert!(output.stdout.is_empty());
        let report = parse_json_output(&output.stderr);
        assert_exact_object_keys(
            &report,
            &[
                "category",
                "code",
                "details",
                "docs_url",
                "message",
                "retryable",
                "schema_version",
                "suggested_commands",
            ],
        );
        assert_eq!(report["schema_version"], "satelle.error.v1");
        assert_eq!(report["code"], "not-implemented");
        let message = report["message"].as_str().unwrap();
        assert!(message.contains("Host update was not run"));
        assert!(message.contains("No Host state or Satelle sessions were changed"));
        assert!(!state.path().join("satelle.sqlite3").exists());
        assert!(!state.path().join("satelle.sqlite3.lock").exists());
    }
}

#[test]
fn host_update_rejects_conflicting_or_unsupported_components() {
    satelle()
        .args([
            "host",
            "update",
            "--component",
            "all",
            "--component",
            "host",
            "--json",
        ])
        .assert()
        .code(64)
        .stderr(predicate::str::contains(
            r#""code": "component-selection-conflict""#,
        ));

    let output = satelle()
        .args(["host", "update", "--component", "browser", "--json"])
        .assert()
        .code(64)
        .get_output()
        .clone();
    let error = parse_json_output(&output.stderr);

    assert_eq!(error["code"], "unsupported-update-component");
    assert_eq!(error["details"]["component"], "browser");
    assert_eq!(
        error["details"]["supported_components"],
        serde_json::json!(["host", "codex", "all"])
    );
}

#[test]
fn host_update_help_documents_json_and_component_filter_without_short_alias() {
    let output = satelle()
        .args(["host", "update", "--help"])
        .assert()
        .success()
        .get_output()
        .clone();
    let help = String::from_utf8_lossy(&output.stdout);

    assert!(help.contains("--component <COMPONENT>"));
    assert!(help.contains("--json"));
    assert!(!help.contains("-c, --component"));
    assert!(!help.contains("--plain"));
}

#[test]
fn setup_mode_flags_are_reported_in_json() {
    let state = state_dir();
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["setup", "--dry-run", "--host", "local-demo", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    assert_eq!(report["setup_mode"], "on_demand");
    assert_eq!(report["service_persistent"], false);
    assert_eq!(report["service_scope"], "on_demand");
    assert!(report["fallback_reason"].is_null());

    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "setup",
            "--dry-run",
            "--host",
            "local-demo",
            "--on-demand",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    assert_eq!(report["setup_mode"], "on_demand");
    assert_eq!(report["service_persistent"], false);
    assert_eq!(report["service_scope"], "on_demand");
    assert!(report["fallback_reason"].is_null());

    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "setup",
            "--dry-run",
            "--host",
            "local-demo",
            "--persistent",
            "--json",
        ])
        .assert()
        .get_output()
        .clone();
    #[cfg(target_os = "linux")]
    {
        assert_eq!(output.status.code(), Some(64));
        let error = parse_json_output(&output.stderr);
        assert_eq!(error["code"], "persistent-service-unsupported");
        assert_eq!(error["details"]["platform"], "linux");
        assert_eq!(error["details"]["mutated"], false);
    }
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        assert!(output.status.success());
        let report = parse_json_output(&output.stdout);
        assert_eq!(report["setup_mode"], "persistent");
        assert_eq!(report["service_persistent"], true);
    }

    let user_config = state.path().join("setup-mode-config.toml");
    write_user_config(
        &user_config,
        r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"
adapter = "fake"
setup_mode = "persistent"
"#,
    )
    .expect("setup mode config should be written");
    let output = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["setup", "--dry-run", "--host", "local-demo", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    #[cfg(target_os = "linux")]
    {
        assert_eq!(report["setup_mode"], "on_demand");
        assert_eq!(report["service_persistent"], false);
        assert!(
            report["fallback_reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("unsupported on Linux"))
        );
    }
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    assert_eq!(report["setup_mode"], "persistent");

    let output = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "setup",
            "--dry-run",
            "--host",
            "local-demo",
            "--on-demand",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    assert_eq!(report["setup_mode"], "on_demand");

    satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "setup",
            "--dry-run",
            "--host",
            "local-demo",
            "--on-demand",
            "--persistent",
            "--json",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid-usage"));
}

#[test]
fn setup_daemon_path_overrides_are_reported_and_validated() {
    let state = state_dir();
    let daemon_home = absolute_test_path(&["srv", "satelle"]);
    let daemon_config_file = daemon_home.join("config").join("config.toml");
    let daemon_state_dir = daemon_home.join("state");
    let daemon_cache_dir = daemon_home.join("cache");
    let daemon_log_dir = daemon_home.join("logs");
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "setup",
            "--dry-run",
            "--host",
            "local-demo",
            "--daemon-home",
        ])
        .arg(&daemon_home)
        .arg("--daemon-config-file")
        .arg(&daemon_config_file)
        .arg("--daemon-state-dir")
        .arg(&daemon_state_dir)
        .arg("--daemon-cache-dir")
        .arg(&daemon_cache_dir)
        .arg("--daemon-log-dir")
        .arg(&daemon_log_dir)
        .arg("--json")
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    let overrides = report["daemon_path_overrides"].as_array().unwrap();

    assert_eq!(overrides.len(), 5);
    assert_eq!(overrides[0]["environment_variable"], "SATELLE_HOME");
    assert_eq!(overrides[0]["value"], serde_json::json!(daemon_home));
    assert_eq!(overrides[0]["source"], "setup_flag");
    assert_eq!(
        overrides[0]["service_configuration_surface"],
        "satelle_service_configuration"
    );
    assert_eq!(overrides[1]["environment_variable"], "SATELLE_CONFIG_FILE");
    assert_eq!(overrides[2]["environment_variable"], "SATELLE_STATE_DIR");
    assert_eq!(overrides[3]["environment_variable"], "SATELLE_CACHE_DIR");
    assert_eq!(overrides[4]["environment_variable"], "SATELLE_LOG_DIR");
    assert_eq!(report["dry_run"], true);
    assert_eq!(report["mutated"], false);

    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "setup",
            "--dry-run",
            "--host",
            "local-demo",
            "--daemon-state-dir",
            "relative-state",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .clone();
    let error = parse_json_output(&output.stderr);
    assert_eq!(error["code"], "daemon-path-override-not-absolute");
    assert_eq!(error["details"]["flag"], "--daemon-state-dir");
    assert_eq!(error["details"]["value"], "relative-state");

    satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "setup",
            "--dry-run",
            "--host",
            "local-demo",
            "--daemon-home",
            "~/satelle",
            "--json",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            r#""code": "daemon-path-override-not-absolute""#,
        ));
}

#[test]
fn setup_uses_user_config_daemon_path_defaults_with_flags_taking_precedence() {
    let state = state_dir();
    let user_config = state.path().join("user-config.toml");
    let daemon_state_dir = absolute_test_path(&["srv", "satelle", "state-from-config"]);
    let daemon_log_dir = absolute_test_path(&["srv", "satelle", "logs-from-config"]);
    let flag_log_dir = absolute_test_path(&["srv", "satelle", "logs-from-flag"]);
    write_user_config(
        &user_config,
        format!(
            r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"
adapter = "fake"
daemon_state_dir = '{}'
daemon_log_dir = '{}'
"#,
            daemon_state_dir.display(),
            daemon_log_dir.display()
        ),
    )
    .expect("user config should be written");

    let output = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "setup",
            "--dry-run",
            "--host",
            "local-demo",
            "--daemon-log-dir",
        ])
        .arg(&flag_log_dir)
        .arg("--json")
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    let overrides = report["daemon_path_overrides"].as_array().unwrap();

    assert_eq!(overrides.len(), 2);
    assert_eq!(overrides[0]["environment_variable"], "SATELLE_STATE_DIR");
    assert_eq!(overrides[0]["value"], serde_json::json!(daemon_state_dir));
    assert_eq!(overrides[0]["source"], "user_config");
    assert_eq!(overrides[1]["environment_variable"], "SATELLE_LOG_DIR");
    assert_eq!(overrides[1]["value"], serde_json::json!(flag_log_dir));
    assert_eq!(overrides[1]["source"], "setup_flag");
}

#[test]
fn setup_does_not_inherit_local_path_environment_as_daemon_overrides() {
    let state = state_dir();
    let local_home = state.path().join("local-home");
    let local_config = state.path().join("local-config.toml");
    let local_state = state.path().join("local-state");
    let local_cache = state.path().join("local-cache");
    let local_logs = state.path().join("local-logs");

    let paths_output = satelle()
        .env("SATELLE_HOME", &local_home)
        .env("SATELLE_CONFIG_FILE", &local_config)
        .env("SATELLE_STATE_DIR", &local_state)
        .env("SATELLE_CACHE_DIR", &local_cache)
        .env("SATELLE_LOG_DIR", &local_logs)
        .args(["paths", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let paths = parse_json_output(&paths_output.stdout);
    assert_eq!(paths["state_root"], serde_json::json!(local_state));
    assert_eq!(paths["sources"]["state_root"], "explicit_environment");

    let setup_output = satelle()
        .env("SATELLE_HOME", &local_home)
        .env("SATELLE_CONFIG_FILE", &local_config)
        .env("SATELLE_STATE_DIR", &local_state)
        .env("SATELLE_CACHE_DIR", &local_cache)
        .env("SATELLE_LOG_DIR", &local_logs)
        .args(["setup", "--dry-run", "--host", "local-demo", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let setup = parse_json_output(&setup_output.stdout);
    assert_eq!(setup["daemon_path_overrides"], serde_json::json!([]));
}

#[test]
fn config_precedence_is_flags_over_project_over_user_over_defaults() {
    let state = state_dir();
    let user_config = state.path().join("xdg").join("satelle");
    let user_config_file = user_config.join("config.toml");
    fs::create_dir_all(&user_config).expect("user config dir should be created");
    write_user_config(
        &user_config_file,
        r#"
default_host = "user-host"

[hosts.user-host]
transport = "local"
adapter = "fake"

[hosts.project-host]
transport = "local"
adapter = "fake"
allow_project_selection = true

[profiles.environment-profile]

[profiles.flag-profile]
"#,
    )
    .expect("user config should be written");

    let project = state.path().join("project");
    let project_config = project.join(".satelle");
    fs::create_dir_all(&project_config).expect("project config dir should be created");
    fs::write(
        project_config.join("config.toml"),
        r#"
default_host = "project-host"
"#,
    )
    .expect("project config should be written");

    satelle()
        .current_dir(&project)
        .env("SATELLE_CONFIG_FILE", &user_config_file)
        .env("SATELLE_STATE_DIR", state.path())
        .env_remove("SATELLE_HOST")
        .args(["doctor", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""host": "project-host""#));

    satelle()
        .current_dir(&project)
        .env("SATELLE_CONFIG_FILE", &user_config_file)
        .env("SATELLE_STATE_DIR", state.path())
        .env("SATELLE_HOST", "local-demo")
        .args(["doctor", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""host": "local-demo""#));

    satelle()
        .current_dir(&project)
        .env("SATELLE_CONFIG_FILE", &user_config_file)
        .env("SATELLE_STATE_DIR", state.path())
        .env("SATELLE_HOST", "project-host")
        .args(["doctor", "--host", "local-demo", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""host": "local-demo""#));

    let output = satelle()
        .current_dir(&project)
        .env("SATELLE_CONFIG_FILE", &user_config_file)
        .env("SATELLE_STATE_DIR", state.path())
        .env("SATELLE_HOST", "local-demo")
        .env("SATELLE_PROFILE", "environment-profile")
        .args(["config", "explain", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    assert_eq!(
        report["sources"]["environment"]["host"]["name"],
        "SATELLE_HOST"
    );
    assert_eq!(report["sources"]["environment"]["host"]["set"], true);
    assert_eq!(
        report["sources"]["environment"]["host"]["value"],
        "local-demo"
    );
    assert_eq!(report["selected_profile"], "environment-profile");
    assert_eq!(
        report["sources"]["environment"]["profile"]["name"],
        "SATELLE_PROFILE"
    );
    assert_eq!(
        report["sources"]["environment"]["profile"]["value"],
        "environment-profile"
    );

    let output = satelle()
        .current_dir(&project)
        .env("SATELLE_CONFIG_FILE", &user_config_file)
        .env("SATELLE_STATE_DIR", state.path())
        .env("SATELLE_HOST", "local-demo")
        .env("SATELLE_PROFILE", "environment-profile")
        .args(["config", "explain", "--profile", "flag-profile", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    assert_eq!(report["selected_profile"], "flag-profile");
}

#[test]
fn config_explain_reports_model_and_provider_alias_intent() {
    let state = state_dir();
    let user_config = state.path().join("xdg").join("satelle");
    fs::create_dir_all(&user_config).expect("user config dir should be created");
    write_user_config(
        user_config.join("config.toml"),
        r#"
default_host = "local-demo"
model_alias = "user-model"
provider_alias = "user-provider"

[hosts.local-demo]
transport = "local"
adapter = "fake"
"#,
    )
    .expect("user config should be written");

    let project = state.path().join("project");
    let project_config = project.join(".satelle");
    fs::create_dir_all(&project_config).expect("project config dir should be created");
    fs::write(
        project_config.join("config.toml"),
        r#"
model_alias = "project-computer-use"
provider_alias = "anthropic"
"#,
    )
    .expect("project config should be written");

    let output = satelle()
        .current_dir(&project)
        .env("SATELLE_CONFIG_FILE", user_config.join("config.toml"))
        .env("SATELLE_STATE_DIR", state.path())
        .args(["config", "explain", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    let model_provider = &report["values"]["model_provider"];

    assert_eq!(report["effective"]["model_alias"], "project-computer-use");
    assert_eq!(report["effective"]["provider_alias"], "anthropic");
    assert_eq!(
        model_provider["requested_model_alias"],
        "project-computer-use"
    );
    assert_eq!(model_provider["requested_provider_alias"], "anthropic");
    assert_eq!(model_provider["model_alias_source"], "project_config");
    assert_eq!(model_provider["provider_alias_source"], "project_config");
    assert_eq!(model_provider["winning_source"], "project_config");
    assert_eq!(model_provider["binding_status"], "binding_required");
    assert_eq!(
        model_provider["resolved_codex_model"],
        serde_json::Value::Null
    );
    assert_eq!(
        model_provider["resolved_model_provider"],
        serde_json::Value::Null
    );
    assert_eq!(
        model_provider["contributing_config_files"][0],
        serde_json::json!(user_config.join("config.toml"))
    );
    assert_eq!(
        model_provider["contributing_config_files"][1],
        serde_json::json!(project_config.join("config.toml"))
    );
}

#[test]
fn config_explain_reports_user_level_experimental_provider_opt_in() {
    let state = state_dir();
    let user_config = state.path().join("user-config.toml");
    write_user_config(
        &user_config,
        r#"
default_host = "local-demo"
experimental_provider_computer_use = true

[hosts.local-demo]
transport = "local"
adapter = "fake"
"#,
    )
    .expect("user config should be written");

    let output = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["config", "explain", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    let experimental = &report["values"]["experimental_provider_computer_use"];

    assert_eq!(
        report["effective"]["experimental_provider_computer_use"],
        true
    );
    assert_eq!(experimental["active"], true);
    assert_eq!(experimental["source"], "user_config_global");
    assert_eq!(experimental["selected_by_cli_flag"], false);

    write_user_config(
        &user_config,
        r#"
default_host = "local-demo"
experimental_provider_computer_use = true

[hosts.local-demo]
transport = "local"
adapter = "fake"
experimental_provider_computer_use = false
"#,
    )
    .expect("user config should be written");

    let output = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["config", "explain", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    let experimental = &report["values"]["experimental_provider_computer_use"];

    assert_eq!(
        report["effective"]["hosts"]["local-demo"]["experimental_provider_computer_use"],
        false
    );
    assert_eq!(experimental["active"], false);
    assert_eq!(experimental["source"], "user_config_host");
    assert_eq!(experimental["host"], "local-demo");
}

#[test]
fn yolo_policy_resolves_from_user_config_and_config_explain_reports_source() {
    let state = state_dir();
    let user_config = state.path().join("user-config.toml");
    write_user_config(
        &user_config,
        r#"
default_host = "local-demo"
yolo = true

[hosts.local-demo]
transport = "local"
adapter = "fake"
yolo = false
"#,
    )
    .expect("user config should be written");

    let output = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["config", "explain", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    let yolo = &report["values"]["yolo"];

    assert_eq!(report["effective"]["yolo"], true);
    assert_eq!(report["effective"]["hosts"]["local-demo"]["yolo"], false);
    assert_eq!(yolo["active"], false);
    assert_eq!(yolo["source"], "user_config_host");
    assert_eq!(yolo["target_host"], "local-demo");
    assert_eq!(yolo["winning_source"], "user_config_host");
    assert_eq!(
        yolo["contributing_config_files"][0],
        serde_json::json!(user_config)
    );
}

#[test]
fn run_and_steer_report_yolo_state_and_flags_override_config() {
    let state = state_dir();
    let user_config = state.path().join("user-config.toml");
    write_user_config(
        &user_config,
        r#"
default_host = "local-demo"
yolo = true

[hosts.local-demo]
transport = "local"
adapter = "fake"
"#,
    )
    .expect("user config should be written");

    let output = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local-demo",
            "--json",
            "--no-yolo",
            "Check",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let run_report = parse_json_output(&output.stdout);
    let session = run_report["session_id"].as_str().unwrap().to_string();

    assert_eq!(run_report["yolo"]["active"], false);
    assert_eq!(run_report["yolo"]["source"], "cli_flag");

    let output = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["steer", &session, "--json", "--yolo", "Continue"])
        .assert()
        .success()
        .get_output()
        .clone();
    let steer_report = parse_json_output(&output.stdout);

    assert_eq!(steer_report["yolo"]["active"], true);
    assert_eq!(steer_report["yolo"]["source"], "cli_flag");
}

#[test]
fn run_human_output_identifies_active_yolo_mode_when_not_quiet() {
    let state = state_dir();
    satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["run", "--host", "local-demo", "--yolo", "Check"])
        .assert()
        .success()
        .stdout(predicate::str::contains("YOLO mode: active (cli_flag)"));
}

#[test]
fn doctor_missing_host_returns_typed_host_not_found() {
    let state = state_dir();
    satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["doctor", "--host", "missing", "--json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(r#""code": "host-not-found""#))
        .stderr(predicate::str::contains(
            "satelle setup --host local-demo --dry-run",
        ));
}

#[test]
fn doctor_json_emits_single_final_object_with_probe_contract() {
    let state = state_dir();
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["doctor", "--host", "local-demo", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let values = serde_json::Deserializer::from_str(&stdout)
        .into_iter::<Value>()
        .collect::<Result<Vec<_>, _>>()
        .expect("stdout should be parseable JSON");
    assert_eq!(values.len(), 1);

    let report = &values[0];
    for field in [
        "schema_version",
        "status",
        "target",
        "scopes",
        "started_at",
        "finished_at",
        "duration_ms",
        "summary",
        "probe_results",
        "findings",
        "recovery_commands",
        "changed",
        "cache_updates",
    ] {
        assert!(report.get(field).is_some(), "missing doctor field {field}");
    }

    assert_eq!(report["status"], "ready");
    assert_eq!(report["target"], "local-demo");
    assert_eq!(
        report["scopes"],
        serde_json::json!(["codex", "computer-use", "config", "provider", "transport"])
    );
    assert_eq!(report["summary"]["ready"], true);

    let probe = report["probe_results"][0]
        .as_object()
        .expect("probe result should be an object");
    for field in [
        "probe_id",
        "scope",
        "status",
        "started_at",
        "finished_at",
        "duration_ms",
        "cache_status",
        "dependency_status",
        "finding_ids",
    ] {
        assert!(probe.contains_key(field), "missing probe field {field}");
    }

    assert_eq!(report["findings"][0]["fixability"], "informational");
}

#[test]
fn doctor_events_emit_ndjson_with_terminal_result() {
    let state = state_dir();
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "doctor",
            "--host",
            "local-demo",
            "--scope",
            "provider",
            "--refresh",
            "--events",
        ])
        .assert()
        .success()
        .stderr(predicate::str::is_empty())
        .get_output()
        .clone();
    let events = parse_json_lines(&output.stdout);
    assert_eq!(events[0]["event_type"], "doctor_started");
    assert_eq!(events.last().unwrap()["event_type"], "doctor_finished");
    assert!(
        events
            .iter()
            .any(|event| event["event_type"] == "cache_updated")
    );

    for event in &events {
        for field in [
            "schema_version",
            "event_id",
            "event_type",
            "target",
            "scope",
            "probe_id",
            "timestamp",
            "status",
            "data",
        ] {
            assert!(event.get(field).is_some(), "missing event field {field}");
        }
        assert_eq!(event["schema_version"], "satelle.doctor.events.v1");
        assert_eq!(event["target"], "local-demo");
    }

    let terminal = events.last().expect("events should include terminal event");
    assert_eq!(terminal["data"]["status"], "ready");
    assert_eq!(terminal["data"]["scopes"], serde_json::json!(["provider"]));
}

#[test]
fn doctor_events_and_json_are_mutually_exclusive() {
    let state = state_dir();
    satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["doctor", "--host", "local-demo", "--events", "--json"])
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(
            r#""code": "output-mode-conflict""#,
        ));
}

#[test]
fn doctor_refresh_timeout_updates_cache_metadata() {
    let state = state_dir();
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "doctor",
            "--host",
            "local-demo",
            "--scope",
            "computer-use",
            "--refresh",
            "--timeout",
            "30s",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);

    assert_eq!(report["changed"], true);
    assert_eq!(
        report["cache_updates"],
        serde_json::json!(["local-demo-readiness"])
    );
    assert_eq!(report["probe_results"][0]["cache_status"], "refreshed");
    assert_eq!(report["scopes"], serde_json::json!(["computer-use"]));
}

#[test]
fn doctor_provider_refresh_reports_provider_cache_provenance() {
    let state = state_dir();
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "doctor",
            "--host",
            "local-demo",
            "--scope",
            "provider",
            "--refresh",
            "--timeout",
            "30s",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);

    assert_eq!(report["changed"], true);
    assert_eq!(
        report["cache_updates"],
        serde_json::json!(["provider_smoke"])
    );
    assert_eq!(
        report["probe_results"][0]["probe_id"],
        "provider.smoke.refresh"
    );
    assert_eq!(report["probe_results"][0]["cache_status"], "refreshed");
    assert_eq!(report["probe_results"][0]["status"], "passed");
    assert!(
        report["findings"][0]["evidence"]
            .as_array()
            .expect("provider evidence should be an array")
            .iter()
            .any(|entry| entry == "source=refresh")
    );
    assert_eq!(report["scopes"], serde_json::json!(["provider"]));
}

#[test]
fn doctor_timeout_requires_refresh_and_live_probe_scope() {
    let state = state_dir();
    satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["doctor", "--timeout", "30s", "--json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            r#""code": "refresh-timeout-without-refresh""#,
        ));

    satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "doctor",
            "--scope",
            "codex",
            "--refresh",
            "--timeout",
            "30s",
            "--json",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            r#""code": "refresh-timeout-without-refresh""#,
        ));
}

#[test]
fn doctor_refresh_requires_a_live_probe_scope() {
    let state = state_dir();
    satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["doctor", "--scope", "config", "--refresh", "--json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            r#""code": "refresh-scope-required""#,
        ));
}

#[test]
fn doctor_timeout_must_be_positive() {
    let state = state_dir();
    satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "doctor",
            "--scope",
            "computer-use",
            "--refresh",
            "--timeout",
            "0s",
            "--json",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "duration must use a positive number",
        ));
}

#[test]
fn doctor_serial_no_input_run_remains_noninteractive() {
    let state = state_dir();
    satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["doctor", "--serial-probes", "--no-input", "--json"])
        .assert()
        .success();
}

#[test]
fn doctor_events_invalid_scope_emits_failed_terminal_event() {
    let state = state_dir();
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["doctor", "--scope", "invalid", "--events"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid-usage"))
        .get_output()
        .clone();
    let events = parse_json_lines(&output.stdout);

    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event_type"], "doctor_failed");
    assert_eq!(events[0]["data"]["error"]["code"], "invalid-usage");
    assert_eq!(events[0]["data"]["error"]["exit_code"], 64);
}

#[test]
fn local_demo_outputs_do_not_include_old_product_name() {
    let state = state_dir();
    let run = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local-demo",
            "Open the browser and report the page title",
        ])
        .assert()
        .success();
    let run_text = combined_output(&run);
    assert!(!run_text.contains("RemoteUse"));
    assert!(!run_text.contains("remoteuse"));

    let session = session_id(&run.get_output().stdout);
    for args in [
        vec!["doctor", "--host", "local-demo"],
        vec!["steer", &session, "Continue from the same session"],
        vec!["status", &session],
        vec!["logs", "--host", "local-demo"],
    ] {
        let assertion = satelle()
            .env("SATELLE_STATE_DIR", state.path())
            .args(args)
            .assert()
            .success();
        let text = combined_output(&assertion);
        assert!(!text.contains("RemoteUse"));
        assert!(!text.contains("remoteuse"));
    }
}

#[test]
fn config_check_explain_and_paths_use_versioned_read_only_json_contracts() {
    let state = state_dir();
    let project = state.path().join("project");
    fs::create_dir_all(project.join(".satelle")).expect("project config dir should be created");
    fs::write(
        project.join(".satelle").join("config.toml"),
        r#"
model_alias = "project-model"
"#,
    )
    .expect("project config should be written");

    let check_output = satelle()
        .current_dir(&project)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["config", "check", "--host", "local-demo", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert!(check_output.stderr.is_empty());
    let check_report = parse_json_output(&check_output.stdout);
    assert_eq!(check_report["schema_version"], "satelle.config.check.v1");
    assert_eq!(check_report["status"], "ok");
    assert!(
        check_report["not_checked"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "native_computer_use")
    );

    let explain_output = satelle()
        .current_dir(&project)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["config", "explain", "--host", "local-demo", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert!(explain_output.stderr.is_empty());
    let explain_report = parse_json_output(&explain_output.stdout);
    assert_eq!(
        explain_report["schema_version"],
        "satelle.config.explain.v1"
    );
    assert_eq!(explain_report["selected_host"], "local-demo");
    assert!(explain_report["effective"].is_object());

    let paths_output = satelle()
        .current_dir(&project)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["paths", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert!(paths_output.stderr.is_empty());
    let paths_report = parse_json_output(&paths_output.stdout);
    assert_eq!(paths_report["schema_version"], "satelle.paths.v1");
    for field in [
        "config_file",
        "cache_root",
        "state_root",
        "sqlite_store",
        "operator_log_root",
        "recording_root",
        "project_config_file",
        "install_receipt",
    ] {
        assert!(
            !paths_report[field].is_null(),
            "paths JSON should include {field}"
        );
    }

    assert!(!state.path().join("local-demo-state.json").exists());
}

#[test]
fn paths_json_uses_satelle_home_and_explicit_overrides() {
    let state = state_dir();
    let satelle_home = state.path().join("portable-home");
    let explicit_config = state.path().join("explicit-config.toml");
    let explicit_cache = state.path().join("explicit-cache");
    let explicit_state = state.path().join("explicit-state");
    let explicit_logs = state.path().join("explicit-logs");
    let output = satelle()
        .env("SATELLE_HOME", &satelle_home)
        .env("SATELLE_CONFIG_FILE", &explicit_config)
        .env("SATELLE_CACHE_DIR", &explicit_cache)
        .env("SATELLE_STATE_DIR", &explicit_state)
        .env("SATELLE_LOG_DIR", &explicit_logs)
        .args(["paths", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let paths = parse_json_output(&output.stdout);

    assert_eq!(paths["config_file"], serde_json::json!(explicit_config));
    assert_eq!(paths["state_root"], serde_json::json!(explicit_state));
    assert_eq!(paths["cache_root"], serde_json::json!(explicit_cache));
    assert_eq!(paths["operator_log_root"], serde_json::json!(explicit_logs));
    assert_eq!(
        paths["recording_root"],
        serde_json::json!(satelle_home.join("state").join("recordings"))
    );
    assert_eq!(paths["sources"]["config_file"], "explicit_environment");
    assert_eq!(paths["sources"]["state_root"], "explicit_environment");
    assert_eq!(paths["sources"]["cache_root"], "explicit_environment");
    assert_eq!(
        paths["sources"]["operator_log_root"],
        "explicit_environment"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn paths_json_uses_the_native_macos_operator_log_root() {
    let state = state_dir();
    let home = state.path().join("home");
    let output = satelle()
        .env("HOME", &home)
        .args(["paths", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let paths = parse_json_output(&output.stdout);

    assert_eq!(
        paths["operator_log_root"],
        serde_json::json!(home.join("Library/Logs/dev.Microck.Satelle"))
    );
    assert_eq!(paths["sources"]["operator_log_root"], "os_default");
}

#[test]
fn empty_path_overrides_are_treated_as_unset() {
    let state = state_dir();
    let satelle_home = state.path().join("portable-home");
    let output = satelle()
        .env("SATELLE_HOME", &satelle_home)
        .env("SATELLE_CACHE_DIR", "")
        .args(["paths", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let paths = parse_json_output(&output.stdout);

    assert_eq!(
        paths["cache_root"],
        serde_json::json!(satelle_home.join("cache"))
    );
    assert_eq!(paths["sources"]["cache_root"], "satelle_home");
}

#[test]
fn relative_path_overrides_fail_with_typed_config_error() {
    satelle()
        .env("SATELLE_STATE_DIR", "relative-state")
        .args(["paths", "--json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            r#""code": "path-override-not-absolute""#,
        ));
}

#[test]
fn project_config_discovery_walks_up_to_nearest_satelle_config() {
    let state = state_dir();
    let project = state.path().join("project");
    let nested = project.join("nested").join("child");
    fs::create_dir_all(project.join(".satelle")).expect("project config dir should be created");
    fs::create_dir_all(&nested).expect("nested dir should be created");
    fs::write(
        project.join(".satelle").join("config.toml"),
        r#"
model_alias = "project-model"
"#,
    )
    .expect("project config should be written");

    let output = satelle()
        .current_dir(&nested)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["config", "check", "--host", "local-demo", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);

    assert_eq!(report["selected_host"], "local-demo");
    assert_eq!(
        report["checked_files"][1],
        serde_json::json!(project.join(".satelle").join("config.toml"))
    );
}

#[test]
fn config_composition_and_unknown_keys_are_rejected() {
    let state = state_dir();
    let project = state.path().join("project");
    fs::create_dir_all(project.join(".satelle")).expect("project config dir should be created");
    fs::write(
        project.join(".satelle").join("config.toml"),
        r#"
include = ["other.toml"]
"#,
    )
    .expect("project config should be written");

    satelle()
        .current_dir(&project)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["config", "check", "--json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            r#""code": "unsupported-config-composition""#,
        ));

    fs::write(
        project.join(".satelle").join("config.toml"),
        r#"
default_host = "local-demo"
defalt_host = "local-demo"

[hosts.local-demo]
transport = "local"
transpor = "direct"
"#,
    )
    .expect("project config should be written");

    let output = satelle()
        .current_dir(&project)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["config", "check", "--json"])
        .assert()
        .failure()
        .get_output()
        .clone();
    let error = parse_json_output(&output.stderr);

    assert_eq!(error["code"], "unknown-config-key");
    assert_eq!(
        error["details"]["file"],
        serde_json::json!(project.join(".satelle").join("config.toml"))
    );
    assert_eq!(error["details"]["path"], "defalt_host");
    assert_eq!(error["details"]["key"], "defalt_host");
    assert_eq!(error["details"]["suggestion"], "default_host");
    assert_eq!(
        error["details"]["accepted_keys"],
        serde_json::json!([
            "default_host",
            "model_alias",
            "provider_alias",
            "profile",
            "hosts"
        ])
    );
    assert_eq!(
        error["details"]["unknown_keys"].as_array().unwrap().len(),
        2
    );
    assert_eq!(
        error["details"]["unknown_keys"][1]["path"],
        "hosts.local-demo.transpor"
    );
    assert_eq!(
        error["details"]["unknown_keys"][1]["suggestion"],
        "transport"
    );
}

#[test]
fn project_config_forbidden_keys_report_typed_errors() {
    let state = state_dir();
    let project = state.path().join("project");
    fs::create_dir_all(project.join(".satelle")).expect("project config dir should be created");
    let config_file = project.join(".satelle").join("config.toml");

    let cases = [
        (
            r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"
adapter = "fake"
daemon_state_dir = "/srv/satelle/state"
"#,
            "project-daemon-path-override-not-allowed",
            "hosts.local-demo.daemon_state_dir",
            "daemon_state_dir",
        ),
        (
            r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"
adapter = "fake"
desktop_user = "alice"
"#,
            "project-desktop-binding-not-allowed",
            "hosts.local-demo.desktop_user",
            "desktop_user",
        ),
        (
            r#"
default_host = "local-demo"
yolo_mode = true

[hosts.local-demo]
transport = "local"
adapter = "fake"
"#,
            "project-yolo-enable-not-allowed",
            "yolo_mode",
            "yolo_mode",
        ),
        (
            r#"
default_host = "local-demo"
experimental_provider_computer_use = true

[hosts.local-demo]
transport = "local"
adapter = "fake"
"#,
            "project-experimental-provider-opt-in-not-allowed",
            "experimental_provider_computer_use",
            "experimental_provider_computer_use",
        ),
        (
            r#"
default_host = "local-demo"
assume_yes = true

[hosts.local-demo]
transport = "local"
adapter = "fake"
"#,
            "project-mutation-consent-not-allowed",
            "assume_yes",
            "assume_yes",
        ),
        (
            r#"
default_host = "local-demo"
provider_secret_source = { kind = "file", path = "~/openai-key" }

[hosts.local-demo]
transport = "local"
adapter = "fake"
"#,
            "project-secret-source-not-allowed",
            "provider_secret_source",
            "provider_secret_source",
        ),
        (
            r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"
adapter = "fake"
credential_helper = { argv = ["/usr/bin/op", "read", "secret"] }
"#,
            "project-credential-helper-not-allowed",
            "hosts.local-demo.credential_helper",
            "credential_helper",
        ),
    ];

    for (config, expected_code, expected_path, expected_key) in cases {
        fs::write(&config_file, config).expect("project config should be written");

        let output = satelle()
            .current_dir(&project)
            .env("SATELLE_STATE_DIR", state.path())
            .args(["config", "check", "--json"])
            .assert()
            .code(66)
            .get_output()
            .clone();
        let error = parse_json_output(&output.stderr);

        assert_eq!(error["code"], expected_code);
        assert_eq!(error["details"]["file"], serde_json::json!(config_file));
        assert_eq!(error["details"]["path"], expected_path);
        assert_eq!(error["details"]["key"], expected_key);
        assert_eq!(error["details"]["scope"], "project");
    }
}

#[test]
fn user_host_config_accepts_desktop_binding_and_daemon_path_fields() {
    let state = state_dir();
    let user_config = state.path().join("user-config.toml");
    write_user_config(
        &user_config,
        r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"
adapter = "fake"
desktop_user = "alice"
desktop_session_preference = "console"
daemon_home = "/srv/satelle"
daemon_config_file = "/srv/satelle/config/config.toml"
daemon_state_dir = "/srv/satelle/state"
daemon_cache_dir = "/srv/satelle/cache"
daemon_log_dir = "/srv/satelle/logs"
"#,
    )
    .expect("user config should be written");

    let output = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["config", "explain", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    let host = &report["effective"]["hosts"]["local-demo"];

    assert_eq!(host["desktop_user"], "alice");
    assert_eq!(host["desktop_session_preference"], "console");
    assert_eq!(host["daemon_home"], "/srv/satelle");
    assert_eq!(
        host["daemon_config_file"],
        "/srv/satelle/config/config.toml"
    );
    assert_eq!(host["daemon_state_dir"], "/srv/satelle/state");
    assert_eq!(host["daemon_cache_dir"], "/srv/satelle/cache");
    assert_eq!(host["daemon_log_dir"], "/srv/satelle/logs");
    let daemon_overrides = report["values"]["daemon_path_overrides"]
        .as_array()
        .expect("daemon path overrides should be an array");
    assert_eq!(daemon_overrides.len(), 5);
    assert_eq!(daemon_overrides[0]["environment_variable"], "SATELLE_HOME");
    assert_eq!(daemon_overrides[0]["value"], "/srv/satelle");
    assert_eq!(daemon_overrides[0]["source"], "user_config");
    assert_eq!(daemon_overrides[0]["setup_must_persist"], true);
    assert_eq!(
        daemon_overrides[0]["service_configuration_surface"],
        "satelle_service_configuration"
    );

    write_user_config(
        &user_config,
        r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"
adapter = "fake"
desktop_user = "alice"

[hosts.local-demo.desktop_session_native_selector]
platform = "darwin"
kind = "window-server-session-id"
value = "42"
"#,
    )
    .expect("user config should be written");

    let output = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["config", "explain", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    let selector = &report["effective"]["hosts"]["local-demo"]["desktop_session_native_selector"];

    assert_eq!(selector["platform"], "darwin");
    assert_eq!(selector["kind"], "window-server-session-id");
    assert_eq!(selector["value"], "42");
}

#[test]
fn config_rejects_portable_and_native_desktop_selectors_together() {
    let state = state_dir();
    let user_config = state.path().join("user-config.toml");
    write_user_config(
        &user_config,
        r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"
adapter = "fake"
desktop_session_preference = "only"

[hosts.local-demo.desktop_session_native_selector]
platform = "darwin"
kind = "window-server-session-id"
value = "42"
"#,
    )
    .expect("user config should be written");

    let output = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["config", "check", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let error = parse_json_output(&output.stderr);

    assert_eq!(error["code"], "desktop-session-selector-conflict");
    assert_eq!(error["details"]["file"], serde_json::json!(user_config));
    assert_eq!(error["details"]["path"], "hosts.local-demo");
    assert_eq!(
        error["details"]["conflicting_keys"],
        serde_json::json!([
            "desktop_session_preference",
            "desktop_session_native_selector"
        ])
    );
}

#[test]
fn provider_auth_secret_sources_are_host_resolved_and_redacted_in_config_explain() {
    let state = state_dir();
    let user_config = state.path().join("user-config.toml");
    let secret_file = absolute_test_path(&["run", "secrets", "openai-api-key"]);
    write_user_config(
        &user_config,
        format!(
            r#"
default_host = "local"
model_alias = "default"
provider_alias = "openai"

[hosts.local]
transport = "local"
adapter = "fake"

[hosts.local.provider_bindings.openai.default]
model = "gpt-5.2"
model_provider = "openai"
auth_source = "openai"

[hosts.local.provider_auth.openai]
kind = "file"
path = '{}'

[hosts.local.provider_auth.anthropic]
kind = "environment"
variable = "ANTHROPIC_API_KEY"

[hosts.local.provider_auth.apple]
kind = "credential-store"
service = "satelle"
account = "apple"

[hosts.local.provider_auth.local]
kind = "host-store"
name = "local-provider-token"
"#,
            secret_file.display()
        ),
    )
    .expect("user config should be written");

    satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["config", "check", "--json"])
        .assert()
        .success();

    let output = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["config", "explain", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains(secret_file.to_string_lossy().as_ref()));
    assert!(!stdout.contains("ANTHROPIC_API_KEY"));
    let report = parse_json_output(&output.stdout);
    let openai = &report["effective"]["hosts"]["local"]["provider_auth"]["openai"];
    let anthropic = &report["effective"]["hosts"]["local"]["provider_auth"]["anthropic"];

    assert_eq!(openai["kind"], "file");
    assert_eq!(openai["redacted"], true);
    assert_eq!(openai["value"], serde_json::Value::Null);
    assert_eq!(openai["redaction_reason"], "secret_source_reference");
    assert_eq!(openai["source"], "user_config");
    assert_eq!(anthropic["kind"], "environment");
    assert_eq!(anthropic["redacted"], true);

    let output = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["config", "explain", "--show-secret-references", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    let provider_auth = &report["effective"]["hosts"]["local"]["provider_auth"];

    assert_eq!(
        provider_auth["openai"]["path"],
        serde_json::json!(secret_file)
    );
    assert_eq!(provider_auth["openai"]["redacted"], false);
    assert_eq!(provider_auth["anthropic"]["variable"], "ANTHROPIC_API_KEY");
    assert_eq!(provider_auth["apple"]["service"], "satelle");
    assert_eq!(provider_auth["apple"]["account"], "apple");
    assert_eq!(provider_auth["local"]["name"], "local-provider-token");
}

#[test]
fn provider_auth_secret_source_validation_is_local_and_typed() {
    let state = state_dir();
    let user_config = state.path().join("user-config.toml");

    let cases = [
        (
            r#"
default_host = "local"
model_alias = "default"
provider_alias = "openai"

[hosts.local]
transport = "local"
adapter = "fake"

[hosts.local.provider_bindings.openai.default]
model = "gpt-5.2"
model_provider = "openai"
auth_source = "openai"

[hosts.local.provider_auth.openai]
kind = "command"
argv = ["/usr/bin/op", "read", "secret"]
"#,
            "unsupported-secret-source-kind",
        ),
        (
            r#"
default_host = "local"
model_alias = "default"
provider_alias = "openai"

[hosts.local]
transport = "local"
adapter = "fake"

[hosts.local.provider_bindings.openai.default]
model = "gpt-5.2"
model_provider = "openai"
auth_source = "openai"

[hosts.local.provider_auth.openai]
kind = "file"
path = "relative-secret"
"#,
            "secret-file-path-not-absolute",
        ),
        (
            r#"
default_host = "local"
model_alias = "default"
provider_alias = "openai"

[hosts.local]
transport = "local"
adapter = "fake"

[hosts.local.provider_bindings.openai.default]
model = "gpt-5.2"
model_provider = "openai"
auth_source = "openai"

[hosts.local.provider_auth.openai]
kind = "file"
path = "~/openai-key"
"#,
            "secret-file-path-not-absolute",
        ),
    ];

    for (config, code) in cases {
        write_user_config(&user_config, config).expect("user config should be written");

        let output = satelle()
            .env("SATELLE_CONFIG_FILE", &user_config)
            .env("SATELLE_STATE_DIR", state.path())
            .args([
                "setup",
                "--host",
                "local",
                "--component",
                "provider-auth",
                "--no-input",
                "--yes",
                "--json",
            ])
            .assert()
            .code(66)
            .get_output()
            .clone();
        let error = parse_json_output(&output.stderr);

        assert_eq!(error["code"], code);
    }

    let foreign_absolute_path = if cfg!(windows) {
        "/var/lib/satelle/openai-key"
    } else {
        r"C:\Satelle\openai-key"
    };
    write_user_config(
        &user_config,
        format!(
            r#"
default_host = "local"
model_alias = "default"
provider_alias = "openai"

[hosts.local]
transport = "local"
adapter = "fake"

[hosts.local.provider_bindings.openai.default]
model = "gpt-5.2"
model_provider = "openai"
auth_source = "openai"

[hosts.local.provider_auth.openai]
kind = "file"
path = '{foreign_absolute_path}'
"#
        ),
    )
    .expect("foreign-platform provider path config should be written");
    let output = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "setup",
            "--host",
            "local",
            "--component",
            "provider-auth",
            "--no-input",
            "--yes",
            "--json",
        ])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let error = parse_json_output(&output.stderr);
    assert_eq!(error["code"], "secret-file-path-not-absolute");
}

#[test]
fn run_and_steer_reject_a_dangling_controller_auth_source_before_admission() {
    let state = state_dir();
    let user_config = state.path().join("user-config.toml");
    write_user_config(
        &user_config,
        r#"
default_host = "local"
model_alias = "review"
provider_alias = "openai"

[hosts.local]
transport = "local"
adapter = "fake"

[hosts.local.provider_bindings.openai.review]
model = "gpt-5.2"
model_provider = "openai"
auth_source = "operator-auth"
"#,
    )
    .expect("dangling provider auth config should be written");

    for arguments in [
        vec![
            "run".to_string(),
            "--host".to_string(),
            "local".to_string(),
            "--json".to_string(),
            "Do not admit dangling provider auth".to_string(),
        ],
        vec![
            "steer".to_string(),
            SessionId::new().to_string(),
            "--host".to_string(),
            "local".to_string(),
            "--json".to_string(),
            "Do not admit dangling provider auth".to_string(),
        ],
    ] {
        let output = satelle()
            .env("SATELLE_CONFIG_FILE", &user_config)
            .env("SATELLE_STATE_DIR", state.path())
            .args(arguments)
            .assert()
            .failure()
            .get_output()
            .clone();
        let error = parse_json_output(&output.stderr);
        assert_eq!(error["code"], "model-provider-binding-missing");
        assert_eq!(error["details"]["requested_model_alias"], "review");
        assert_eq!(error["details"]["requested_provider_alias"], "openai");
    }
}

#[test]
fn config_check_failures_exit_with_configuration_error_class() {
    let state = state_dir();
    let project = state.path().join("project");
    fs::create_dir_all(project.join(".satelle")).expect("project config dir should be created");
    fs::write(
        project.join(".satelle").join("config.toml"),
        r#"
default_host = "local-demo"
defalt_host = "local-demo"
"#,
    )
    .expect("project config should be written");

    let output = satelle()
        .current_dir(&project)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["config", "check", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    assert!(output.stdout.is_empty());
    let report = parse_json_output(&output.stderr);
    assert_exact_object_keys(
        &report,
        &[
            "category",
            "code",
            "details",
            "docs_url",
            "message",
            "retryable",
            "schema_version",
            "suggested_commands",
        ],
    );
    assert_eq!(report["schema_version"], "satelle.error.v1");
    assert_eq!(report["code"], "unknown-config-key");
    assert_eq!(report["details"]["path"], "defalt_host");
}

#[test]
fn config_interpolation_syntax_is_rejected_without_expansion() {
    let state = state_dir();
    let project = state.path().join("project");
    fs::create_dir_all(project.join(".satelle")).expect("project config dir should be created");
    fs::write(
        project.join(".satelle").join("config.toml"),
        r#"
default_host = "${EXAMPLE_HOST}"

[hosts.local-demo]
transport = "local"
adapter = "fake"
address = "$EXAMPLE_ADDRESS"
ca_bundle = "${EXAMPLE_CA_BUNDLE}"

[hosts.local-demo.network]
provider = "tailscale"
hostname = "%EXAMPLE_HOSTNAME%"
"#,
    )
    .expect("project config should be written");

    let output = satelle()
        .current_dir(&project)
        .env("SATELLE_STATE_DIR", state.path())
        .env("EXAMPLE_HOST", "local-demo")
        .env("EXAMPLE_ADDRESS", "127.0.0.1")
        .args(["config", "check", "--json"])
        .assert()
        .failure()
        .get_output()
        .clone();
    let error = parse_json_output(&output.stderr);

    assert_eq!(error["code"], "config-interpolation-not-supported");
    assert_eq!(
        error["details"]["file"],
        serde_json::json!(project.join(".satelle").join("config.toml"))
    );
    assert_eq!(error["details"]["path"], "default_host");
    assert_eq!(error["details"]["syntax"], "${EXAMPLE_HOST}");
    assert_eq!(
        error["details"]["unsupported_syntax"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    assert_eq!(
        error["details"]["unsupported_syntax"][1]["path"],
        "hosts.local-demo.address"
    );
    assert_eq!(
        error["details"]["unsupported_syntax"][1]["syntax"],
        "$EXAMPLE_ADDRESS"
    );
    assert_eq!(
        error["details"]["unsupported_syntax"][2]["path"],
        "hosts.local-demo.ca_bundle"
    );
    assert_eq!(
        error["details"]["unsupported_syntax"][2]["syntax"],
        "${EXAMPLE_CA_BUNDLE}"
    );
    assert_eq!(
        error["details"]["unsupported_syntax"][3]["path"],
        "hosts.local-demo.network.hostname"
    );
    assert_eq!(
        error["details"]["unsupported_syntax"][3]["syntax"],
        "%EXAMPLE_HOSTNAME%"
    );
}

#[test]
fn config_tilde_values_are_not_shell_expanded() {
    let state = state_dir();
    let project = state.path().join("project");
    let user_config = state.path().join("user-config.toml");
    fs::create_dir_all(&project).expect("project directory should be created");
    write_user_config(
        &user_config,
        r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "direct"
adapter = "fake"
address = "~/satelle-host.sock"
"#,
    )
    .expect("user config should be written");

    let output = satelle()
        .current_dir(&project)
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["config", "explain", "--host", "local-demo", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);

    assert_eq!(
        report["effective"]["hosts"]["local-demo"]["address"],
        "~/satelle-host.sock"
    );
}

#[test]
fn config_explain_supports_secret_references_but_not_show_secrets() {
    let help_output = satelle()
        .args(["config", "explain", "--help"])
        .assert()
        .success()
        .get_output()
        .clone();
    let help = String::from_utf8_lossy(&help_output.stdout);

    assert!(help.contains("--show-secret-references"));
    assert!(!help.contains("--show-secrets"));

    satelle()
        .args(["config", "explain", "--show-secrets", "--json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument"));
}

#[test]
fn timeout_configuration_uses_nested_explicit_unit_keys() {
    let state = state_dir();
    let project = state.path().join("project");
    let user_config = state.path().join("user-config.toml");
    fs::create_dir_all(project.join(".satelle")).expect("project config dir should be created");
    write_user_config(
        &user_config,
        r#"
[hosts.local-demo]
transport = "local"
adapter = "fake"
allow_project_selection = true
"#,
    )
    .expect("user config should be written");
    fs::write(
        project.join(".satelle").join("config.toml"),
        r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"

[hosts.local-demo.timeouts]
native_readiness = "120s"
provider_smoke_test = "2m"
"#,
    )
    .expect("project config should be written");

    let output = satelle()
        .current_dir(&project)
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["config", "explain", "--host", "local-demo", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    assert_eq!(
        report["effective"]["hosts"]["local-demo"]["timeouts"]["native_readiness"],
        "120s"
    );
    assert_eq!(
        report["effective"]["hosts"]["local-demo"]["timeouts"]["provider_smoke_test"],
        "2m"
    );
    assert_eq!(
        report["values"]["effective_timeouts"]["native_readiness_timeout_ms"],
        120_000
    );
    assert_eq!(
        report["values"]["effective_timeouts"]["provider_smoke_test_timeout_ms"],
        120_000
    );

    let output = satelle()
        .current_dir(&project)
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local-demo",
            "--json",
            "Check timeout output",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    assert_eq!(
        report["effective_timeouts"]["native_readiness_timeout_ms"],
        120_000
    );
    assert_eq!(
        report["effective_timeouts"]["provider_smoke_test_timeout_ms"],
        120_000
    );

    let output = satelle()
        .current_dir(&project)
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local-demo",
            "--detach",
            "--json",
            "Check detached timeout output",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    assert_eq!(
        report["effective_timeouts"]["native_readiness_timeout_ms"],
        120_000
    );
    assert_eq!(
        report["effective_timeouts"]["provider_smoke_test_timeout_ms"],
        120_000
    );

    fs::write(
        project.join(".satelle").join("config.toml"),
        r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"
native_readiness_timeout = "120s"
"#,
    )
    .expect("project config should be written");

    satelle()
        .current_dir(&project)
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["config", "check", "--json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(r#""code": "unknown-config-key""#))
        .stderr(predicate::str::contains("native_readiness_timeout"));

    fs::write(
        project.join(".satelle").join("config.toml"),
        r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"

[hosts.local-demo.timeouts]
native_readiness = 120
"#,
    )
    .expect("project config should be written");

    let output = satelle()
        .current_dir(&project)
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["config", "check", "--json"])
        .assert()
        .failure()
        .get_output()
        .clone();
    let error = parse_json_output(&output.stderr);
    assert_eq!(error["code"], "duration-unit-required");
    assert_eq!(
        error["details"]["path"],
        "hosts.local-demo.timeouts.native_readiness"
    );
    assert_eq!(
        error["details"]["supported_units"],
        serde_json::json!(["ms", "s", "m"])
    );

    fs::write(
        project.join(".satelle").join("config.toml"),
        r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"

[hosts.local-demo.timeouts]
provider_timeout = "120s"
"#,
    )
    .expect("project config should be written");

    let output = satelle()
        .current_dir(&project)
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["config", "check", "--json"])
        .assert()
        .failure()
        .get_output()
        .clone();
    let error = parse_json_output(&output.stderr);
    assert_eq!(error["code"], "unknown-timeout-key");
    assert_eq!(error["details"]["key"], "provider_timeout");
    assert_eq!(
        error["details"]["accepted_keys"],
        serde_json::json!(["native_readiness", "provider_smoke_test", "turn_execution"])
    );
}

#[test]
fn host_sessions_lists_local_demo_metadata_only() {
    let state = state_dir();
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "host",
            "sessions",
            "--host",
            "local-demo",
            "--no-bootstrap",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);

    assert_eq!(report["schema_version"], "satelle.host.sessions.v1");
    assert_eq!(report["host"], "local-demo");
    assert_eq!(report["connection_mode"], "direct");
    assert_eq!(report["bootstrapped"], false);
    assert_eq!(report["bootstrap_actions"], serde_json::json!([]));
    assert_eq!(report["host_daemon_version"], env!("CARGO_PKG_VERSION"));

    let session = &report["sessions"][0];
    for field in [
        "session_id",
        "desktop_user",
        "state",
        "session_kind",
        "is_console",
        "is_remote",
        "display_summary",
        "portable_selectors",
        "native_selectors",
        "selected_by_current_config",
    ] {
        assert!(
            session.get(field).is_some(),
            "missing session field {field}"
        );
    }
    assert_eq!(session["session_id"], "local-demo-console");
    assert_eq!(session["desktop_user"], "local-demo-user");
    assert_eq!(session["state"], "active");
    assert_eq!(
        session["display_summary"],
        "active local demo visible desktop"
    );
    assert!(session.get("screenshot").is_none());
    assert!(session.get("thumbnail").is_none());
    assert!(session.get("window_title").is_none());

    satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["host", "sessions", "--host", "local-demo"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Connection: direct"))
        .stdout(predicate::str::contains("Selected: true"))
        .stdout(predicate::str::contains(
            "Portable selectors: console, active",
        ))
        .stdout(predicate::str::contains(
            "Native selectors: local-demo:console:active",
        ));
}

#[test]
fn setup_persists_the_deterministic_desktop_binding_atomically() {
    let state = state_dir();
    let user_config = state.path().join("desktop-setup-config.toml");
    write_user_config(
        &user_config,
        r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"
adapter = "fake"
"#,
    )
    .expect("write desktop setup user config");

    let output = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "setup",
            "--host",
            "local-demo",
            "--component",
            "desktop",
            "--no-input",
            "--yes",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    assert!(
        report["planned_actions"]
            .as_array()
            .expect("planned actions")
            .iter()
            .any(|action| action
                .as_str()
                .is_some_and(|action| action.contains("desktop_user")))
    );
    assert!(
        report["applied_actions"]
            .as_array()
            .expect("applied actions")
            .iter()
            .any(|action| action
                .as_str()
                .is_some_and(|action| action.contains("desktop_user")))
    );

    let persisted = fs::read_to_string(&user_config).expect("read persisted user config");
    let persisted =
        toml::from_str::<toml::Value>(&persisted).expect("persisted user config should parse");
    assert_eq!(
        persisted["hosts"]["local-demo"]["desktop_user"].as_str(),
        Some("local-demo-user")
    );
    assert_eq!(
        persisted["hosts"]["local-demo"]["desktop_session_preference"].as_str(),
        Some("only")
    );
}

#[test]
fn setup_unavailable_desktop_binding_preserves_user_config() {
    let state = state_dir();
    let user_config = state.path().join("desktop-unavailable-config.toml");
    write_user_config(
        &user_config,
        r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"
adapter = "fake"
desktop_user = "missing-user"
"#,
    )
    .expect("write unavailable desktop user config");
    let before = fs::read(&user_config).expect("read original user config");

    let output = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "setup",
            "--host",
            "local-demo",
            "--component",
            "desktop",
            "--no-input",
            "--yes",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .clone();
    let error = parse_json_output(&output.stderr);
    assert_eq!(error["code"], "desktop-session-unavailable");
    assert_eq!(error["details"]["desktop_user"], "missing-user");
    assert_eq!(
        fs::read(&user_config).expect("read unchanged user config"),
        before
    );
}

#[test]
fn host_sessions_marks_only_the_session_selected_by_effective_host_config() {
    let state = state_dir();
    let user_config = state.path().join("user-config.toml");
    let cases = [
        (
            "console match",
            r#"
desktop_user = "local-demo-user"
desktop_session_preference = "console"
"#,
            true,
        ),
        (
            "desktop user mismatch",
            r#"
desktop_user = "another-user"
desktop_session_preference = "only"
"#,
            false,
        ),
        (
            "native selector match",
            r#"
desktop_user = "local-demo-user"

[hosts.local-demo.desktop_session_native_selector]
platform = "local-demo"
kind = "console"
value = "active"
"#,
            true,
        ),
        (
            "native selector mismatch",
            r#"
desktop_user = "local-demo-user"

[hosts.local-demo.desktop_session_native_selector]
platform = "local-demo"
kind = "console"
value = "inactive"
"#,
            false,
        ),
    ];

    for (case, selection, expected) in cases {
        write_user_config(
            &user_config,
            format!(
                r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"
adapter = "fake"
{selection}
"#
            ),
        )
        .expect("user config should be written");

        let output = satelle()
            .env("SATELLE_CONFIG_FILE", &user_config)
            .env("SATELLE_STATE_DIR", state.path())
            .args(["host", "sessions", "--no-bootstrap", "--json"])
            .assert()
            .success()
            .get_output()
            .clone();
        let report = parse_json_output(&output.stdout);
        assert_eq!(
            report["sessions"][0]["selected_by_current_config"], expected,
            "{case}"
        );
    }
}

#[test]
fn run_and_steer_fail_before_admission_when_desktop_selection_is_invalid() {
    let state = state_dir();
    let user_config = state.path().join("user-config.toml");
    let cases = [
        (
            "unavailable binding",
            r#"desktop_user = "another-user""#,
            "desktop-session-unavailable",
        ),
        (
            "unmatched only preference",
            r#"
desktop_user = "another-user"
desktop_session_preference = "only"
"#,
            "desktop-session-preference-unmatched",
        ),
        (
            "unavailable console preference",
            r#"
desktop_user = "another-user"
desktop_session_preference = "console"
"#,
            "desktop-session-console-unavailable",
        ),
        (
            "wrong native selector platform",
            r#"
desktop_user = "local-demo-user"

[hosts.local-demo.desktop_session_native_selector]
platform = "windows"
kind = "wts-session"
value = "7"
"#,
            "desktop-session-native-selector-wrong-platform",
        ),
        (
            "unmatched native selector",
            r#"
desktop_user = "local-demo-user"

[hosts.local-demo.desktop_session_native_selector]
platform = "local-demo"
kind = "console"
value = "inactive"
"#,
            "desktop-session-native-selector-unmatched",
        ),
    ];

    for (case, desktop_config, expected_code) in cases {
        write_user_config(
            &user_config,
            format!(
                r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"
adapter = "fake"
{desktop_config}
"#
            ),
        )
        .expect("user config should be written");

        let output = satelle()
            .env("SATELLE_CONFIG_FILE", &user_config)
            .env("SATELLE_STATE_DIR", state.path())
            .args(["run", "--detach", "--json", "Open the browser"])
            .assert()
            .code(75)
            .get_output()
            .clone();
        let error = parse_json_output(&output.stderr);
        assert_eq!(error["code"], expected_code, "{case}");
    }

    write_user_config(
        &user_config,
        r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"
adapter = "fake"
desktop_user = "local-demo-user"
desktop_session_preference = "only"
"#,
    )
    .expect("user config should be written");
    let output = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["run", "--detach", "--json", "Open the browser"])
        .assert()
        .success()
        .get_output()
        .clone();
    let session_id = parse_json_output(&output.stdout)["session_id"]
        .as_str()
        .expect("detached run returns a Session identifier")
        .to_string();

    write_user_config(
        &user_config,
        r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"
adapter = "fake"
desktop_user = "another-user"
"#,
    )
    .expect("user config should be written");
    let output = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["steer", &session_id, "--detach", "--json", "Open settings"])
        .assert()
        .code(75)
        .get_output()
        .clone();
    let error = parse_json_output(&output.stderr);
    assert_eq!(error["code"], "desktop-session-unavailable");
}

#[test]
fn future_cli_surfaces_parse_and_return_typed_not_implemented() {
    let state = state_dir();
    for args in [
        vec!["repair", "--host", "local-demo", "--dry-run", "--json"],
        vec![
            "host",
            "storage",
            "migrate",
            "--host",
            "local-demo",
            "--to",
            "/tmp/satelle-state",
            "--dry-run",
            "--json",
        ],
        vec!["self", "update", "--dry-run", "--json"],
        vec![
            "support",
            "bundle",
            "--output",
            "/tmp/satelle-bundle.zip",
            "--json",
        ],
    ] {
        satelle()
            .env("SATELLE_STATE_DIR", state.path())
            .args(args)
            .assert()
            .failure()
            .stderr(predicate::str::contains(r#""code": "not-implemented""#));
    }
}

#[test]
fn host_service_lifecycle_requires_explicit_consent_before_mutation() {
    let state = state_dir();
    for action in ["stop", "restart"] {
        let output = satelle()
            .env("SATELLE_STATE_DIR", state.path())
            .args(["host", action, "--host", "local-demo", "--json"])
            .assert()
            .failure()
            .get_output()
            .clone();
        let error = parse_json_output(&output.stderr);
        assert_eq!(error["code"], "setup-consent-required");
        assert_eq!(error["details"]["mutated"], false);
        assert_eq!(
            error["suggested_commands"],
            serde_json::json!([format!("satelle host {action} --host local-demo --yes")])
        );
    }
}

#[test]
fn self_update_remote_options_require_update_remotes() {
    let state = state_dir();
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["self", "update", "--concurrency", "2", "--json"])
        .assert()
        .failure()
        .get_output()
        .clone();
    let error = parse_json_output(&output.stderr);
    assert_eq!(error["code"], "concurrency-without-remote-update");
    assert_eq!(
        error["suggested_commands"],
        serde_json::json!(["add --update-remotes or remove --concurrency"])
    );

    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "self",
            "update",
            "--update-remotes",
            "--concurrency",
            "17",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .clone();
    let error = parse_json_output(&output.stderr);
    assert_eq!(error["code"], "concurrency-limit-exceeded");
    assert_eq!(error["details"]["concurrency"], 17);
    assert_eq!(error["details"]["minimum"], 1);
    assert_eq!(error["details"]["maximum"], 16);
}

#[test]
fn self_update_is_not_triggered_by_ordinary_commands() {
    let state = state_dir();
    let ordinary_commands = [
        vec!["run", "--host", "local-demo", "--json", "Open the browser"],
        vec!["steer", "missing-session", "--json", "Continue"],
        vec!["setup", "--dry-run", "--host", "local-demo", "--json"],
        vec!["repair", "--host", "local-demo", "--dry-run", "--json"],
        vec![
            "host",
            "update",
            "--host",
            "local-demo",
            "--dry-run",
            "--json",
        ],
        vec!["doctor", "--host", "local-demo", "--json"],
    ];

    for args in ordinary_commands {
        let output = satelle()
            .env("SATELLE_STATE_DIR", state.path())
            .args(args)
            .output()
            .expect("ordinary command should run");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        assert!(
            !combined.contains("self update"),
            "ordinary command unexpectedly mentioned self update: {combined}"
        );
        assert!(
            !combined.contains("self-update"),
            "ordinary command unexpectedly mentioned self-update: {combined}"
        );
    }
}

#[test]
fn config_explain_resolves_project_aliases_through_the_selected_host_binding() {
    let state = state_dir();
    let project = state.path().join("project");
    let user_config = state.path().join("user-config.toml");
    let project_config = project.join(".satelle").join("config.toml");
    fs::create_dir_all(
        project_config
            .parent()
            .expect("project config should have a parent"),
    )
    .expect("project config directory should be created");
    write_user_config(
        &user_config,
        r#"
default_host = "local"

[hosts.local]
transport = "local"
adapter = "fake"
allow_project_selection = true

[hosts.local.provider_bindings.openai.review]
model = "gpt-5.2"
model_provider = "openai"
endpoint = "https://api.openai.example/v1"
"#,
    )
    .expect("user config should be written");
    fs::write(
        &project_config,
        r#"
default_host = "local"
model_alias = "review"
provider_alias = "openai"
"#,
    )
    .expect("project config should be written");

    let output = satelle()
        .current_dir(&project)
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["config", "explain", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    let binding = &report["values"]["model_provider"];

    assert_eq!(binding["requested_model_alias"], "review");
    assert_eq!(binding["requested_provider_alias"], "openai");
    assert_eq!(binding["resolved_codex_model"], "gpt-5.2");
    assert_eq!(binding["resolved_model_provider"], "openai");
    assert_eq!(binding["provider_binding_source"], "user_config");
    assert_eq!(binding["winning_source"], "user_config");
    assert_eq!(
        binding["contributing_config_files"],
        serde_json::json!([user_config, project_config])
    );
}

#[test]
fn per_run_model_and_provider_overrides_merge_with_the_other_effective_alias() {
    let state = state_dir();
    let user_config = state.path().join("user-config.toml");
    let config = |model_alias: &str, provider_alias: &str| {
        format!(
            r#"
default_host = "local"
model_alias = "{model_alias}"
provider_alias = "{provider_alias}"

[hosts.local]
transport = "local"
adapter = "fake"

[hosts.local.experimental_provider_computer_use_by_provider]
anthropic = true

[hosts.local.provider_bindings.openai.default]
model = "gpt-5.2"
model_provider = "openai"
auth_source = "openai"

[hosts.local.provider_bindings.openai.fast]
model = "gpt-5.2-mini"
model_provider = "openai"
auth_source = "openai"

[hosts.local.provider_bindings.anthropic.default]
model = "claude-computer-use"
model_provider = "anthropic"
auth_source = "anthropic"

[hosts.local.provider_auth.openai]
kind = "environment"
variable = "SATELLE_TEST_OPENAI_TOKEN"

[hosts.local.provider_auth.anthropic]
kind = "environment"
variable = "SATELLE_TEST_ANTHROPIC_TOKEN"
"#
        )
    };
    for (model_alias, provider_alias) in [("fast", "openai"), ("default", "anthropic")] {
        write_user_config(&user_config, config(model_alias, provider_alias))
            .expect("authorization config should be written");
        satelle()
            .env("SATELLE_CONFIG_FILE", &user_config)
            .env("SATELLE_STATE_DIR", state.path())
            .args([
                "setup",
                "--host",
                "local",
                "--component",
                "provider-auth",
                "--no-input",
                "--yes",
                "--json",
            ])
            .assert()
            .success();
        satelle()
            .env("SATELLE_CONFIG_FILE", &user_config)
            .env("SATELLE_STATE_DIR", state.path())
            .args(["host", "release-state"])
            .assert()
            .success();
    }
    write_user_config(&user_config, config("default", "openai"))
        .expect("effective default config should be restored");

    let model_override = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local",
            "--model",
            "fast",
            "--json",
            "Use the model override",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let model_override = parse_json_output(&model_override.stdout);
    assert_eq!(model_override["requested_model_alias"], "fast");
    assert_eq!(model_override["requested_provider_alias"], "openai");
    assert_eq!(model_override["resolved_codex_model"], "gpt-5.2-mini");
    assert_eq!(model_override["resolved_model_provider"], "openai");

    let provider_override = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local",
            "--provider",
            "anthropic",
            "--json",
            "Use the provider override",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let provider_override = parse_json_output(&provider_override.stdout);
    assert_eq!(provider_override["requested_model_alias"], "default");
    assert_eq!(provider_override["requested_provider_alias"], "anthropic");
    assert_eq!(
        provider_override["resolved_codex_model"],
        "claude-computer-use"
    );
    assert_eq!(provider_override["resolved_model_provider"], "anthropic");
}

#[test]
fn non_openai_run_requires_explicit_experimental_provider_opt_in() {
    let state = state_dir();
    let user_config = state.path().join("user-config.toml");
    write_user_config(
        &user_config,
        r#"
default_host = "local"
model_alias = "vision"
provider_alias = "anthropic"

[hosts.local]
transport = "local"
adapter = "fake"

[hosts.local.provider_bindings.anthropic.vision]
model = "claude-computer-use"
model_provider = "anthropic"
"#,
    )
    .expect("user config should be written");

    let output = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["run", "--host", "local", "--json", "Open the browser"])
        .assert()
        .code(64)
        .get_output()
        .clone();
    let error = parse_json_output(&output.stderr);

    assert_eq!(error["code"], "experimental-provider-opt-in-required");
    assert_eq!(error["details"]["host"], "local");
    assert_eq!(error["details"]["requested_model_alias"], "vision");
    assert_eq!(error["details"]["requested_provider_alias"], "anthropic");

    write_user_config(
        &user_config,
        r#"
default_host = "local"
model_alias = "vision"
provider_alias = "anthropic"

[hosts.local]
transport = "local"
adapter = "fake"

[hosts.local.experimental_provider_computer_use_by_provider]
anthropic = true

[hosts.local.provider_bindings.anthropic.vision]
model = "claude-computer-use"
model_provider = "anthropic"
"#,
    )
    .expect("user config should be rewritten with provider-scoped opt-in");

    satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "setup",
            "--host",
            "local",
            "--component",
            "provider-auth",
            "--no-input",
            "--yes",
            "--json",
        ])
        .assert()
        .success();
    satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["host", "release-state"])
        .assert()
        .success();

    satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["run", "--host", "local", "--json", "Open the browser"])
        .assert()
        .success()
        .stderr(predicate::str::contains("non-OpenAI provider Computer Use is experimental").not());

    satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["run", "--host", "local", "Open the browser"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Warning: non-OpenAI provider Computer Use is experimental and requires a live provider smoke test when no matching cached pass exists.",
        ));
}

#[test]
fn run_json_and_preflight_events_report_the_resolved_provider_contract() {
    let state = state_dir();
    let host_owned_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local-demo",
            "--json",
            "Report Host-owned provider preflight",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let host_owned = parse_json_output(&host_owned_output.stdout);
    assert_eq!(host_owned["resolved_codex_model"], "fake-model-v1");
    assert_eq!(host_owned["resolved_model_provider"], "fake-provider-v1");
    assert_eq!(host_owned["provider_binding_source"], "host_owned");
    assert_eq!(host_owned["experimental_provider_computer_use"], false);
    assert_eq!(host_owned["provider_smoke_test_status"], "passed");
    assert_eq!(host_owned["provider_smoke"]["status"], "passed");

    let event_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local-demo",
            "--events",
            "json",
            "Report Host-owned provider event",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let host_owned_events = parse_json_lines(&event_output.stdout);
    let host_owned_preflight = host_owned_events
        .iter()
        .find(|event| event["type"] == "preflight")
        .expect("Host-owned run should emit preflight");
    assert_eq!(
        host_owned_preflight["data"]["experimental_provider_computer_use"],
        false
    );

    let detached_output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local-demo",
            "--detach",
            "--json",
            "Report detached Host-owned provider state",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let detached = parse_json_output(&detached_output.stdout);
    assert_eq!(detached["experimental_provider_computer_use"], false);

    let user_state = state_dir();
    let user_config = user_state.path().join("user-config.toml");
    write_user_config(
        &user_config,
        r#"
default_host = "local"
model_alias = "review"
provider_alias = "openai"

[hosts.local]
transport = "local"
adapter = "fake"

[hosts.local.provider_bindings.openai.review]
model = "gpt-5.2"
model_provider = "openai"
auth_source = "openai"

[hosts.local.provider_auth.openai]
kind = "environment"
variable = "SATELLE_TEST_OPENAI_TOKEN"
"#,
    )
    .expect("user config should be written");

    satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", user_state.path())
        .args([
            "setup",
            "--host",
            "local",
            "--component",
            "provider-auth",
            "--no-input",
            "--yes",
            "--json",
        ])
        .assert()
        .success();
    satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", user_state.path())
        .args(["host", "release-state"])
        .assert()
        .success();

    let output = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", user_state.path())
        .args([
            "run",
            "--host",
            "local",
            "--events",
            "json",
            "Report provider preflight",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let events = parse_json_lines(&output.stdout);
    let preflight = events
        .iter()
        .find(|event| event["type"] == "preflight")
        .expect("run events should include preflight");
    let provider_smoke = events
        .iter()
        .find(|event| event["type"] == "provider_smoke")
        .expect("run events should include provider smoke evidence");

    assert_eq!(preflight["data"]["requested_model_alias"], "review");
    assert_eq!(preflight["data"]["requested_provider_alias"], "openai");
    assert_eq!(preflight["data"]["resolved_codex_model"], "gpt-5.2");
    assert_eq!(preflight["data"]["resolved_model_provider"], "openai");
    assert_eq!(preflight["data"]["provider_binding_source"], "user_config");
    assert_eq!(
        preflight["data"]["experimental_provider_computer_use"],
        false
    );
    assert_eq!(
        preflight["data"]["provider_smoke_test_status"],
        "configured_deferred"
    );
    assert_eq!(provider_smoke["data"]["status"], "passed");
}

#[test]
fn default_setup_derives_provider_auth_input_from_the_effective_binding() {
    let state = state_dir();
    let user_config = state.path().join("user-config.toml");
    write_user_config(
        &user_config,
        r#"
default_host = "local"
model_alias = "review"
provider_alias = "openai"

[hosts.local]
transport = "local"
adapter = "fake"

[hosts.local.provider_bindings.openai.review]
model = "gpt-5.2"
model_provider = "openai"
auth_source = "openai"
"#,
    )
    .expect("user config should be written");

    let output = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "setup",
            "--host",
            "local",
            "--dry-run",
            "--no-input",
            "--yes",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json_output(&output.stdout);
    let required_input = report["required_input"]
        .as_array()
        .expect("required_input should be an array");

    assert_eq!(report["setup_components"], serde_json::json!(["all"]));
    assert_eq!(
        report["readiness_summary"]["provider_auth"],
        "missing_descriptor"
    );
    assert!(required_input.iter().any(|input| {
        input["component"] == "provider-auth"
            && input["input_kind"] == "provider_secret_source_descriptor"
    }));
    assert_eq!(report["applied_actions"], serde_json::json!([]));
}

#[test]
fn config_check_reports_a_referenced_missing_provider_auth_descriptor() {
    let state = state_dir();
    let user_config = state.path().join("user-config.toml");
    write_user_config(
        &user_config,
        r#"
default_host = "local"
model_alias = "review"
provider_alias = "openai"

[hosts.local]
transport = "local"
adapter = "fake"

[hosts.local.provider_bindings.openai.review]
model = "gpt-5.2"
model_provider = "openai"
auth_source = "operator-auth"
"#,
    )
    .expect("user config should be written");

    let output = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["config", "check", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let error = parse_json_output(&output.stderr);

    assert_eq!(error["code"], "configuration-error");
    assert!(
        error["message"]
            .as_str()
            .is_some_and(|message| message.contains("missing_descriptor"))
    );
    assert!(
        error["message"]
            .as_str()
            .is_some_and(|message| message.contains("operator-auth"))
    );
}

#[cfg(target_os = "linux")]
#[test]
fn setup_interactive_provider_auth_persists_the_selected_source_under_the_exact_host() {
    for source_kind in ["environment", "file"] {
        let state = state_dir();
        let user_config = state.path().join("user-config.toml");
        let secret_file = state.path().join("provider-secret");
        let secret_canary = format!("raw-provider-secret-{source_kind}-canary");
        test_file::write_user_controlled(&secret_file, &secret_canary)
            .expect("provider secret fixture should be written securely");
        write_user_config(
            &user_config,
            r#"
default_host = "selected"
model_alias = "review"
provider_alias = "openai"

[hosts.selected]
transport = "local"
adapter = "fake"

[hosts.selected.provider_bindings.openai.review]
model = "gpt-5.2"
model_provider = "openai"
auth_source = "operator-auth"

[hosts.decoy]
transport = "local"
adapter = "fake"

[hosts.decoy.provider_auth.operator-auth]
kind = "environment"
variable = "DECOY_PROVIDER_TOKEN"
"#,
        )
        .expect("user config should be written");

        let (prompt_input, expected_field, expected_value) = match source_kind {
            "environment" => (
                "\nSELECTED_PROVIDER_TOKEN\n".to_string(),
                "variable",
                "SELECTED_PROVIDER_TOKEN".to_string(),
            ),
            "file" => (
                format!("\u{1b}[B\n{}\n", secret_file.display()),
                "path",
                secret_file.display().to_string(),
            ),
            _ => unreachable!("the test covers every selectable provider auth source kind"),
        };
        let executable = assert_cmd::cargo::cargo_bin!("satelle");
        let command_line = format!(
            "{} setup --host selected --component provider-auth --yes",
            executable.display()
        );
        let mut command = Command::new("script");
        for name in [
            "SATELLE_HOME",
            "SATELLE_CONFIG_FILE",
            "SATELLE_STATE_DIR",
            "SATELLE_CACHE_DIR",
            "SATELLE_LOG_DIR",
            "SATELLE_HOST",
            "SATELLE_PROFILE",
            "SATELLE_ERROR_FORMAT",
            TEST_SUPPORT_ADAPTER_ENV,
        ] {
            command.env_remove(name);
        }
        let output = command
            .env("SATELLE_CONFIG_FILE", &user_config)
            .env("SATELLE_STATE_DIR", state.path())
            .env("SATELLE_COMMAND_HISTORY", "false")
            .env("SELECTED_PROVIDER_TOKEN", &secret_canary)
            .env(TEST_SUPPORT_ADAPTER_ENV, "fake")
            .args(["-qec", command_line.as_str(), "/dev/null"])
            .write_stdin(prompt_input)
            .assert()
            .success()
            .get_output()
            .clone();
        assert_command_canaries_are_absent(&output, &[&secret_canary]);

        let persisted_text =
            fs::read_to_string(&user_config).expect("persisted user config should be readable");
        assert!(!persisted_text.contains(&secret_canary));
        let persisted = toml::from_str::<toml::Value>(&persisted_text)
            .expect("persisted config should be TOML");
        let selected_descriptor = &persisted["hosts"]["selected"]["provider_auth"]["operator-auth"];
        assert_eq!(selected_descriptor["kind"].as_str(), Some(source_kind));
        assert_eq!(
            selected_descriptor[expected_field].as_str(),
            Some(expected_value.as_str())
        );
        assert_eq!(
            persisted["hosts"]["decoy"]["provider_auth"]["operator-auth"]["kind"].as_str(),
            Some("environment")
        );
        assert_eq!(
            persisted["hosts"]["decoy"]["provider_auth"]["operator-auth"]["variable"].as_str(),
            Some("DECOY_PROVIDER_TOKEN")
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn resolved_provider_secret_is_absent_from_every_implemented_retention_surface() {
    const CANARY: &str = "PRIVATE_RESOLVED_PROVIDER_SECRET_CANARY";

    let state = state_dir();
    let user_config = state.path().join("user-config.toml");
    let secret_directory = tempfile::tempdir().expect("create external provider secret directory");
    let secret_file = secret_directory.path().join("provider-secret");
    test_file::write_user_controlled(&secret_file, CANARY).expect("write provider secret canary");
    write_user_config(
        &user_config,
        format!(
            r#"
default_host = "selected"
model_alias = "review"
provider_alias = "openai"

[hosts.selected]
transport = "local"
adapter = "fake"

[hosts.selected.experimental_provider_computer_use_by_provider]
openai = true

[hosts.selected.provider_auth.operator-auth]
kind = "file"
path = '{}'

[hosts.selected.provider_bindings.openai.review]
model = "gpt-5.2"
model_provider = "openai"
endpoint = "http://127.0.0.1:9"
auth_source = "operator-auth"
"#,
            secret_file.display()
        ),
    )
    .expect("write provider secret canary config");

    let setup = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .env(TEST_SUPPORT_ADAPTER_ENV, "resolved-secret-canary")
        .args([
            "setup",
            "--host",
            "selected",
            "--component",
            "provider-auth",
            "--no-input",
            "--yes",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_command_canaries_are_absent(&setup, &[CANARY]);

    let events = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .env(TEST_SUPPORT_ADAPTER_ENV, "resolved-secret-canary")
        .args([
            "run",
            "--host",
            "selected",
            "--events",
            "json",
            "exercise provider secret retention",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_command_canaries_are_absent(&events, &[CANARY]);
    assert_sqlite_files_are_private(state.path(), &[CANARY]);

    let connection =
        rusqlite::Connection::open(state.path().join("satelle.sqlite3")).expect("open Host state");
    let provider_cache_rows: i64 = connection
        .query_row("SELECT count(*) FROM provider_smoke_results", [], |row| {
            row.get(0)
        })
        .expect("count provider cache rows");
    assert!(
        provider_cache_rows > 0,
        "the retention proof must exercise a durable provider cache row"
    );
    let setup_ledger_text: String = connection
        .query_row(
            "SELECT COALESCE(group_concat(
                 run_id || action_id || action_label || status ||
                 COALESCE(error_code, '') || COALESCE(recovery_hint, '')
             ), '')
             FROM setup_actions",
            [],
            |row| row.get(0),
        )
        .expect("read setup action ledger");
    assert_privacy_canaries_absent(
        "setup action ledger",
        setup_ledger_text.as_bytes(),
        &[CANARY],
    );
    drop(connection);

    let mut operator_log_bytes = Vec::new();
    collect_regular_file_bytes(&state.path().join("logs"), &mut operator_log_bytes);
    assert_privacy_canaries_absent("operator log files", &operator_log_bytes, &[CANARY]);

    for show_references in [false, true] {
        let mut args = vec!["config", "explain", "--host", "selected", "--json"];
        if show_references {
            args.push("--show-secret-references");
        }
        let explain = satelle()
            .env("SATELLE_CONFIG_FILE", &user_config)
            .env("SATELLE_STATE_DIR", state.path())
            .args(args)
            .assert()
            .success()
            .get_output()
            .clone();
        assert_command_canaries_are_absent(&explain, &[CANARY]);
    }

    // `support bundle` is not implemented in PR10. The diagnostics packet
    // must replace this structural no-artifact proof with archive-content proof.
    let bundle_path = state.path().join("support-bundle.tar");
    let unavailable = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "support",
            "bundle",
            "--output",
            bundle_path.to_str().expect("UTF-8 bundle path"),
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .clone();
    assert_command_canaries_are_absent(&unavailable, &[CANARY]);
    assert_eq!(
        parse_json_output(&unavailable.stderr)["code"],
        "not-implemented"
    );
    assert!(!bundle_path.exists());
    let mut state_bytes = Vec::new();
    collect_regular_file_bytes(state.path(), &mut state_bytes);
    assert_privacy_canaries_absent("Host state tree", &state_bytes, &[CANARY]);
}

#[test]
fn provider_auth_dry_run_defers_host_resolution_without_returning_the_secret() {
    let state = state_dir();
    let user_config = state.path().join("user-config.toml");
    let secret_file = state.path().join("provider-secret");
    let secret_canary = "sk-provider-host-resolution-canary";
    test_file::write_user_controlled(&secret_file, secret_canary)
        .expect("provider secret fixture should be written securely");
    write_user_config(
        &user_config,
        format!(
            r#"
default_host = "local"
model_alias = "review"
provider_alias = "openai"

[hosts.local]
transport = "local"
adapter = "fake"

[hosts.local.provider_auth.openai]
kind = "file"
path = '{}'

[hosts.local.provider_bindings.openai.review]
model = "gpt-5.2"
model_provider = "openai"
auth_source = "openai"
"#,
            secret_file.display()
        ),
    )
    .expect("user config should be written");

    let output = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "setup",
            "--host",
            "local",
            "--component",
            "provider-auth",
            "--dry-run",
            "--no-input",
            "--yes",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_command_canaries_are_absent(&output, &[secret_canary]);
    let report = parse_json_output(&output.stdout);

    assert_eq!(
        report["readiness_summary"]["provider_auth"],
        "configured_deferred"
    );
    assert_eq!(
        report["provider_auth_validation"]["outcome"],
        "configured_deferred"
    );
    assert_eq!(report["provider_auth_validation"]["source"], "deferred");
    assert_eq!(report["required_input"], serde_json::json!([]));
    assert_eq!(report["applied_actions"], serde_json::json!([]));
}
