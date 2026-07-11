use assert_cmd::Command;
use satelle_core::{DoctorSchemaVersion, HostSessionsSchemaVersion, SetupSchemaVersion};
use satelle_host::test_support::TestStateDir;
use serde_json::{Value, json};

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
        TEST_SUPPORT_ADAPTER_ENV,
    ] {
        command.env_remove(name);
    }
    command.env(TEST_SUPPORT_ADAPTER_ENV, "fake");
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

#[test]
fn readiness_reports_use_their_canonical_v1_schema_tokens() {
    let state = TestStateDir::new().expect("secure temp state directory should be created");

    for (args, expected_schema) in [
        (
            vec!["setup", "--host", "local-demo", "--dry-run", "--json"],
            "satelle.setup.v1",
        ),
        (
            vec!["doctor", "--host", "local-demo", "--json"],
            "satelle.doctor.v1",
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
        ),
    ] {
        let report = json_report(&state, args);
        assert_eq!(report["schema_version"], expected_schema);
    }
}

#[test]
fn session_commands_use_command_specific_v1_schema_tokens() {
    let state = TestStateDir::new().expect("secure temp state directory should be created");

    let run = json_report(
        &state,
        vec!["run", "--host", "local-demo", "--json", "Inspect"],
    );
    assert_eq!(run["schema_version"], "satelle.run.v1");
    let session = run["session_id"]
        .as_str()
        .expect("run should return a session id");

    let steer = json_report(
        &state,
        vec!["steer", session, "--json", "Continue inspection"],
    );
    assert_eq!(steer["schema_version"], "satelle.steer.v1");

    let status = json_report(&state, vec!["status", session, "--json"]);
    assert_eq!(status["schema_version"], "satelle.status.v1");
    let status_fields = status.as_object().expect("status should be a JSON object");
    assert_eq!(status_fields.len(), 7);
    for field in [
        "schema_version",
        "session_id",
        "host",
        "status",
        "created_at",
        "updated_at",
        "turns",
    ] {
        assert!(status_fields.contains_key(field), "missing field {field}");
    }

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
    assert_eq!(detached_steer["schema_version"], "satelle.steer.v1");

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
    assert_eq!(detached_run["schema_version"], "satelle.run.v1");
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
