use assert_cmd::Command;
use satelle_test_contract::assert_error_process;
use serde_json::Value;

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
        "SATELLE_TEST_SUPPORT_ADAPTER",
        "SATELLE_ERROR_FORMAT",
    ] {
        command.env_remove(name);
    }
    command
}

#[test]
fn internal_failures_keep_their_typed_cause_and_exit_with_the_internal_class() {
    let sandbox = tempfile::tempdir().expect("temporary Satelle home should be created");
    let bundle_path = sandbox.path().join("support-bundle.zip");

    let output = satelle()
        .env("SATELLE_STATE_DIR", sandbox.path())
        .env("SATELLE_LOG", "satelle=debug")
        .args(["support", "bundle", "--output"])
        .arg(bundle_path)
        .arg("--json")
        .assert()
        .code(70)
        .get_output()
        .clone();

    assert_error_process(&output);
    let error: Value =
        serde_json::from_slice(&output.stderr).expect("stderr should be one JSON error envelope");
    assert_eq!(error["schema_version"], "satelle.error.v1");
    assert_eq!(error["code"], "not-implemented");
    assert_eq!(error["category"], "internal");
    assert_eq!(error["retryable"], false);
}
