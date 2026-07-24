use assert_cmd::Command;
use satelle_core::{DoctorSchemaVersion, HostSessionsSchemaVersion, SetupSchemaVersion};
use satelle_host::test_support::TestStateDir;
use serde_json::{Value, json};
use std::collections::BTreeSet;

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
        "SATELLE_LOG",
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

fn authorize_default_provider_binding(state: &TestStateDir) -> std::path::PathBuf {
    let config_file = state.path().join("provider-binding-config.toml");
    test_file::write_user_controlled(
        &config_file,
        r#"
default_host = "local-demo"
model_alias = "schema-model"
provider_alias = "schema-provider"

[hosts.local-demo]
transport = "local"
adapter = "fake"

[hosts.local-demo.provider_bindings.schema-provider.schema-model]
model = "fake-model-v1"
model_provider = "openai"
"#,
    )
    .expect("write exact provider binding config");
    satelle()
        .env("SATELLE_CONFIG_FILE", &config_file)
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "setup",
            "--host",
            "local-demo",
            "--component",
            "provider-auth",
            "--no-input",
            "--yes",
            "--json",
        ])
        .assert()
        .success();
    satelle()
        .env("SATELLE_CONFIG_FILE", &config_file)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["host", "release-state"])
        .assert()
        .success();
    config_file
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

fn json_report_with_config(
    state: &TestStateDir,
    config_file: &std::path::Path,
    args: Vec<&str>,
) -> Value {
    let output = satelle()
        .env("SATELLE_CONFIG_FILE", config_file)
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

fn json_command_result(state: &TestStateDir, args: Vec<&str>) -> Value {
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(args)
        .assert()
        .get_output()
        .clone();
    let result = match (output.stdout.is_empty(), output.stderr.is_empty()) {
        (false, true) => &output.stdout,
        (true, false) => &output.stderr,
        _ => panic!("a JSON command must emit exactly one result stream"),
    };
    serde_json::from_slice(result).expect("command result should be one JSON object")
}

#[test]
fn every_named_json_command_result_has_a_top_level_schema_version() {
    let state = TestStateDir::new().expect("secure temp state directory should be created");
    let run = json_command_result(
        &state,
        vec!["run", "--host", "local-demo", "--json", "Inspect"],
    );
    let session_id = run["session_id"]
        .as_str()
        .expect("run should return a Session identifier")
        .to_string();

    let command_results = [
        run,
        json_command_result(
            &state,
            vec!["steer", &session_id, "--json", "Continue inspection"],
        ),
        json_command_result(&state, vec!["stop", &session_id, "--json"]),
        json_command_result(&state, vec!["status", &session_id, "--json"]),
        json_command_result(
            &state,
            vec!["setup", "--host", "local-demo", "--dry-run", "--json"],
        ),
        json_command_result(
            &state,
            vec!["repair", "--host", "local-demo", "--dry-run", "--json"],
        ),
        json_command_result(&state, vec!["doctor", "--host", "local-demo", "--json"]),
        json_command_result(&state, vec!["config", "check", "--json"]),
        json_command_result(&state, vec!["config", "explain", "--json"]),
        json_command_result(&state, vec!["self", "update", "--dry-run", "--json"]),
        json_command_result(
            &state,
            vec!["host", "update", "--host", "local-demo", "--json"],
        ),
        json_command_result(&state, vec!["paths", "--json"]),
        json_command_result(
            &state,
            vec![
                "host",
                "sessions",
                "--host",
                "local-demo",
                "--no-bootstrap",
                "--json",
            ],
        ),
    ];

    for result in command_results {
        assert!(
            result
                .get("schema_version")
                .is_some_and(serde_json::Value::is_string),
            "JSON result lacks a top-level schema_version: {result}"
        );
    }
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
                "current_daemon_paths",
                "daemon_path_overrides",
                "dry_run",
                "fallback_reason",
                "host",
                "host_artifact",
                "mutated",
                "native_computer_use_readiness",
                "next_command",
                "planned_daemon_paths",
                "planned_actions",
                "readiness_summary",
                "recovery_commands",
                "required_input",
                "schema_version",
                "service_persistent",
                "service_plan",
                "service_scope",
                "setup_components",
                "setup_mode",
                "status",
                "target_platform",
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
    let provider_config = authorize_default_provider_binding(&state);

    let run = json_report_with_config(
        &state,
        &provider_config,
        vec!["run", "--host", "local-demo", "--json", "Inspect"],
    );
    assert_report_contract(
        &run,
        "satelle.run.v2",
        &[
            "effective_timeouts",
            "experimental_provider_computer_use",
            "latest_turn",
            "provider_binding_source",
            "provider_smoke",
            "provider_smoke_test_status",
            "requested_model_alias",
            "requested_provider_alias",
            "resolved_codex_model",
            "resolved_model_provider",
            "schema_version",
            "session_id",
            "status",
            "yolo",
        ],
    );
    let session = run["session_id"]
        .as_str()
        .expect("run should return a session id");

    let steer = json_report_with_config(
        &state,
        &provider_config,
        vec!["steer", session, "--json", "Continue inspection"],
    );
    assert_report_contract(
        &steer,
        "satelle.steer.v2",
        &[
            "effective_timeouts",
            "experimental_provider_computer_use",
            "latest_turn",
            "provider_binding_source",
            "provider_smoke",
            "provider_smoke_test_status",
            "requested_model_alias",
            "requested_provider_alias",
            "resolved_codex_model",
            "resolved_model_provider",
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

    let detached_steer = json_report_with_config(
        &state,
        &provider_config,
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
            "experimental_provider_computer_use",
            "host",
            "provider_binding_source",
            "provider_smoke_test_status",
            "requested_model_alias",
            "requested_provider_alias",
            "resolved_codex_model",
            "resolved_model_provider",
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
    let detached_provider_config = authorize_default_provider_binding(&detached_run_state);
    let detached_run = json_report_with_config(
        &detached_run_state,
        &detached_provider_config,
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
            "experimental_provider_computer_use",
            "host",
            "provider_binding_source",
            "provider_smoke_test_status",
            "requested_model_alias",
            "requested_provider_alias",
            "resolved_codex_model",
            "resolved_model_provider",
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
