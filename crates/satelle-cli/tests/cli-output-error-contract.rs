use assert_cmd::Command;
use satelle_test_contract::assert_error_process;
use serde_json::Value;

#[path = "support/test-file.rs"]
mod test_file;

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
    let config_file = sandbox.path().join("config.toml");
    test_file::write_user_controlled(
        &config_file,
        r#"default_host = "local-demo"

[hosts.local-demo]
transport = "local"
adapter = "codex"
"#,
    )
    .expect("production config should be written securely");

    let output = satelle()
        .env("SATELLE_CONFIG_FILE", config_file)
        .env("SATELLE_STATE_DIR", sandbox.path())
        .args(["setup", "--yes", "--host", "local-demo", "--json"])
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
