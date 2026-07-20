use assert_cmd::Command;
#[cfg(unix)]
use assert_cmd::cargo::CommandCargoExt;
use satelle_core::{DoctorSchemaVersion, HostSessionsSchemaVersion, SetupSchemaVersion};
use satelle_host::test_support::TestStateDir;
use serde_json::{Value, json};
use std::collections::BTreeSet;
#[cfg(unix)]
use std::process::{Command as StdCommand, Stdio};
#[cfg(unix)]
use std::{thread, time::Duration};

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

#[cfg(unix)]
fn following_satelle(state: &TestStateDir, extra_args: &[&str]) -> StdCommand {
    let mut command = StdCommand::cargo_bin("satelle").expect("satelle binary should build");
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
        .env(TEST_SUPPORT_ADAPTER_ENV, "fake")
        .args(["logs", "--host", "local-demo", "--json", "--follow"])
        .args(extra_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn json_report(state: &TestStateDir, args: Vec<&str>) -> Value {
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(args)
        .assert()
        .success()
        .get_output()
        .clone();

    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).expect("stdout should be one JSON report")
}

fn assert_report_contract(report: &Value, schema_version: &str, expected_fields: &[&str]) {
    assert_eq!(report["schema_version"], schema_version);
    let actual_fields = report
        .as_object()
        .expect("a command report should be a JSON object")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_fields = expected_fields.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(actual_fields, expected_fields);
}

#[test]
fn readiness_reports_use_their_canonical_v1_schema_tokens() {
    let state = TestStateDir::new().expect("secure temp state directory should be created");

    for (args, expected_schema, expected_fields) in [
        (
            vec!["setup", "--host", "local-demo", "--dry-run", "--json"],
            "satelle.setup.v1",
            &[
                "applied_actions",
                "daemon_path_overrides",
                "dry_run",
                "fallback_reason",
                "host",
                "mutated",
                "native_computer_use_readiness",
                "next_command",
                "planned_actions",
                "readiness_summary",
                "recovery_commands",
                "required_input",
                "schema_version",
                "service_persistent",
                "service_scope",
                "setup_components",
                "setup_mode",
                "status",
            ][..],
        ),
        (
            vec!["doctor", "--host", "local-demo", "--json"],
            "satelle.doctor.v1",
            &[
                "cache_updates",
                "changed",
                "duration_ms",
                "findings",
                "finished_at",
                "host",
                "probe_results",
                "ready",
                "recovery_commands",
                "schema_version",
                "scopes",
                "started_at",
                "status",
                "summary",
                "target",
            ][..],
        ),
        (
            vec![
                "host",
                "sessions",
                "--host",
                "local-demo",
                "--no-bootstrap",
                "--json",
            ],
            "satelle.host.sessions.v1",
            &[
                "bootstrap_actions",
                "bootstrapped",
                "connection_mode",
                "host",
                "host_daemon_version",
                "schema_version",
                "sessions",
            ][..],
        ),
    ] {
        let report = json_report(&state, args);
        assert_report_contract(&report, expected_schema, expected_fields);
    }
}

#[test]
fn local_inspection_reports_keep_their_closed_v1_shapes() {
    let state = TestStateDir::new().expect("secure temp state directory should be created");

    for (args, schema_version, expected_fields) in [
        (
            vec!["paths", "--json"],
            "satelle.paths.v1",
            &[
                "cache_root",
                "config_file",
                "host",
                "install_receipt",
                "operator_log_root",
                "project_config_file",
                "recording_root",
                "schema_version",
                "sources",
                "sqlite_store",
                "state_root",
            ][..],
        ),
        (
            vec!["config", "check", "--json"],
            "satelle.config.check.v1",
            &[
                "checked_contexts",
                "checked_files",
                "checks",
                "errors",
                "mode",
                "not_checked",
                "recovery_commands",
                "schema_version",
                "selected_host",
                "selected_profile",
                "status",
            ][..],
        ),
        (
            vec!["config", "explain", "--json"],
            "satelle.config.explain.v1",
            &[
                "checked_files",
                "effective",
                "not_checked",
                "schema_version",
                "selected_host",
                "selected_profile",
                "sources",
                "status",
                "values",
            ][..],
        ),
    ] {
        let report = json_report(&state, args);
        assert_report_contract(&report, schema_version, expected_fields);
    }
}

#[test]
fn session_commands_use_command_specific_v2_schema_tokens() {
    let state = TestStateDir::new().expect("secure temp state directory should be created");

    let run = json_report(
        &state,
        vec!["run", "--host", "local-demo", "--json", "Inspect"],
    );
    assert_report_contract(
        &run,
        "satelle.run.v2",
        &[
            "effective_timeouts",
            "latest_turn",
            "provider_smoke",
            "schema_version",
            "session_id",
            "status",
            "yolo",
        ],
    );
    let session = run["session_id"]
        .as_str()
        .expect("run should return a session id");

    let steer = json_report(
        &state,
        vec!["steer", session, "--json", "Continue inspection"],
    );
    assert_report_contract(
        &steer,
        "satelle.steer.v2",
        &[
            "effective_timeouts",
            "latest_turn",
            "provider_smoke",
            "schema_version",
            "session_id",
            "status",
            "yolo",
        ],
    );

    let status = json_report(&state, vec!["status", session, "--json"]);
    assert_report_contract(
        &status,
        "satelle.status.v2",
        &[
            "created_at",
            "host",
            "schema_version",
            "session_id",
            "status",
            "turns",
            "updated_at",
        ],
    );

    let detached_steer = json_report(
        &state,
        vec![
            "steer",
            session,
            "--detach",
            "--json",
            "Continue asynchronously",
        ],
    );
    assert_report_contract(
        &detached_steer,
        "satelle.steer.v2",
        &[
            "created_at",
            "effective_timeouts",
            "host",
            "schema_version",
            "session_id",
            "status",
            "turns",
            "updated_at",
            "yolo",
        ],
    );

    let detached_run_state =
        TestStateDir::new().expect("second secure temp state directory should be created");
    let detached_run = json_report(
        &detached_run_state,
        vec![
            "run",
            "--host",
            "local-demo",
            "--detach",
            "--json",
            "Inspect asynchronously",
        ],
    );
    assert_report_contract(
        &detached_run,
        "satelle.run.v2",
        &[
            "created_at",
            "effective_timeouts",
            "host",
            "schema_version",
            "session_id",
            "status",
            "turns",
            "updated_at",
            "yolo",
        ],
    );
}

#[test]
fn logs_json_lines_use_the_exact_entry_v1_contract() {
    let state = TestStateDir::new().expect("secure temp state directory should be created");
    let run = json_report(
        &state,
        vec!["run", "--host", "local-demo", "--json", "Inspect"],
    );
    let session = run["session_id"]
        .as_str()
        .expect("run should return a Session id");

    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["logs", "--session", session, "--json"])
        .assert()
        .success()
        .get_output()
        .clone();

    assert!(output.stderr.is_empty());
    assert!(output.stdout.ends_with(b"\n"));
    assert!(!output.stdout.contains(&b'\r'));
    let expected_fields = [
        "cursor",
        "event",
        "message",
        "redacted",
        "schema_version",
        "severity",
        "source",
        "subject",
        "timestamp",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let body = output
        .stdout
        .strip_suffix(b"\n")
        .expect("NDJSON output should have one final line feed");
    let lines = body.split(|byte| *byte == b'\n').collect::<Vec<_>>();
    assert!(!lines.is_empty());

    for line in lines {
        assert_eq!(line.first(), Some(&b'{'));
        assert_eq!(line.last(), Some(&b'}'));
        let entry =
            serde_json::from_slice::<Value>(line).expect("each line should be one JSON value");
        let actual_fields = entry
            .as_object()
            .expect("each Log Entry should be an object")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(actual_fields, expected_fields);
        assert_eq!(entry["schema_version"], "satelle.logs.entry.v1");
        assert!(
            entry["cursor"]
                .as_str()
                .is_some_and(|cursor| cursor.starts_with("slc1_"))
        );
        assert!(matches!(
            entry["source"].as_str(),
            Some("host_daemon" | "storage" | "codex_adapter")
        ));
        assert!(matches!(
            entry["severity"].as_str(),
            Some("info" | "warn" | "error")
        ));
        assert!(entry["timestamp"].is_string());
        assert!(entry["event"].is_string());
        assert!(entry["message"].is_string());
        assert_eq!(entry["redacted"], true);
        assert!(matches!(
            entry["subject"]["kind"].as_str(),
            Some("host" | "turn")
        ));
    }
}

#[cfg(unix)]
#[test]
fn logs_json_follow_streams_entry_contract_and_interrupts_cleanly() {
    let state = TestStateDir::new().expect("secure temp state directory should be created");
    json_report(
        &state,
        vec!["run", "--host", "local-demo", "--json", "Inspect"],
    );
    let mut child = following_satelle(&state, &[])
        .spawn()
        .expect("spawn logs follow process");

    thread::sleep(Duration::from_millis(500));
    assert!(
        child
            .try_wait()
            .expect("poll logs follow process")
            .is_none(),
        "an empty initial log set must remain attached"
    );

    rustix::process::kill_process(
        rustix::process::Pid::from_child(&child),
        rustix::process::Signal::INT,
    )
    .expect("interrupt logs follow process");
    let output = child
        .wait_with_output()
        .expect("collect interrupted logs follow output");

    assert_eq!(output.status.code(), Some(130));
    assert!(output.stderr.is_empty());
    let records = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).expect("parse follow NDJSON record"))
        .collect::<Vec<_>>();
    assert!(
        !records.is_empty(),
        "follow must emit matching entries before remaining attached"
    );
    assert!(
        records
            .iter()
            .all(|record| record["schema_version"] == "satelle.logs.entry.v1")
    );
}

#[cfg(unix)]
#[test]
fn empty_json_logs_are_finite_without_follow_and_attached_with_follow() {
    let state = TestStateDir::new().expect("secure temp state directory should be created");
    let missing_session = "rs_01890a5d-ac96-7b7c-8f89-37c3d0a66e11";
    let finite = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["logs", "--session", missing_session, "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert!(finite.stdout.is_empty());
    assert!(finite.stderr.is_empty());

    let mut child = following_satelle(&state, &["--session", missing_session])
        .spawn()
        .expect("spawn empty logs follow process");
    thread::sleep(Duration::from_millis(500));
    assert!(
        child
            .try_wait()
            .expect("poll empty logs follow process")
            .is_none(),
        "empty follow must remain attached"
    );
    rustix::process::kill_process(
        rustix::process::Pid::from_child(&child),
        rustix::process::Signal::INT,
    )
    .expect("interrupt empty logs follow process");
    let output = child
        .wait_with_output()
        .expect("collect empty logs follow output");
    assert_eq!(output.status.code(), Some(130));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn logs_help_exposes_follow_alias_and_reconnect_control() {
    let output = satelle()
        .args(["logs", "--help"])
        .assert()
        .success()
        .get_output()
        .clone();
    let help = String::from_utf8_lossy(&output.stdout);

    assert!(help.contains("-f, --follow"));
    assert!(help.contains("--no-reconnect"));

    let without_follow = satelle()
        .args(["logs", "--no-reconnect"])
        .assert()
        .failure()
        .get_output()
        .clone();
    assert!(without_follow.stdout.is_empty());
    assert!(String::from_utf8_lossy(&without_follow.stderr).contains("--follow"));
}

#[test]
fn readiness_report_schema_types_reject_unknown_tokens() {
    assert_eq!(
        serde_json::to_value(SetupSchemaVersion::V1).expect("setup schema token should serialize"),
        json!("satelle.setup.v1")
    );
    assert_eq!(
        serde_json::to_value(DoctorSchemaVersion::V1)
            .expect("doctor schema token should serialize"),
        json!("satelle.doctor.v1")
    );
    assert_eq!(
        serde_json::to_value(HostSessionsSchemaVersion::V1)
            .expect("Host sessions schema token should serialize"),
        json!("satelle.host.sessions.v1")
    );

    assert!(serde_json::from_value::<SetupSchemaVersion>(json!("satelle.setup.v2")).is_err());
    assert!(serde_json::from_value::<DoctorSchemaVersion>(json!("satelle.doctor.v2")).is_err());
    assert!(
        serde_json::from_value::<HostSessionsSchemaVersion>(json!("satelle.host.sessions.v2"))
            .is_err()
    );
}
