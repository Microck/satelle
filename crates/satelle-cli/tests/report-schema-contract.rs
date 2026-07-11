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
        let output = satelle()
            .env("SATELLE_STATE_DIR", state.path())
            .args(args)
            .assert()
            .success()
            .get_output()
            .clone();

        assert!(output.stderr.is_empty());
        let report: Value =
            serde_json::from_slice(&output.stdout).expect("stdout should be one JSON report");
        assert_eq!(report["schema_version"], expected_schema);
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
