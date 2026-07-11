use assert_cmd::Command;
use satelle_host::test_support::TestStateDir;
use serde_json::Value;

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

fn state_dir() -> TestStateDir {
    TestStateDir::new().expect("secure temp state directory should be created")
}

fn parse_json(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("output should be one JSON value")
}

fn assert_output_conflict(args: &[&str], json_error: bool) {
    let state = state_dir();
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(args)
        .assert()
        .code(64)
        .get_output()
        .clone();

    assert!(output.stdout.is_empty());
    if json_error {
        let report = parse_json(&output.stderr);
        assert_eq!(report["schema_version"], "satelle.error.v1");
        assert_eq!(report["error"]["code"], "output-mode-conflict");
    } else {
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("output-mode-conflict"),
            "human errors should retain the typed code"
        );
    }
    assert!(!state.path().join("satelle.sqlite3").exists());
    assert!(!state.path().join("satelle.sqlite3.lock").exists());
}

#[test]
fn format_json_is_an_exact_json_alias_and_explicit_human_is_unchanged() {
    let state = state_dir();
    let alias = satelle()
        .env("SATELLE_HOME", state.path())
        .args(["paths", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let canonical_json = satelle()
        .env("SATELLE_HOME", state.path())
        .args(["paths", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_eq!(alias, canonical_json);

    let implicit_human = satelle()
        .env("SATELLE_HOME", state.path())
        .args(["paths"])
        .assert()
        .success()
        .get_output()
        .clone();
    let explicit_human = satelle()
        .env("SATELLE_HOME", state.path())
        .args(["paths", "--format", "human"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_eq!(implicit_human, explicit_human);
}

#[test]
fn final_result_selectors_and_json_event_streams_report_typed_conflicts() {
    for format in ["human", "json"] {
        assert_output_conflict(&["paths", "--json", "--format", format], true);
    }

    for (args, json_error) in [
        (vec!["run", "--events", "json", "--json", "Inspect"], true),
        (
            vec!["run", "--events", "json", "--format", "json", "Inspect"],
            true,
        ),
        (
            vec!["run", "--events", "json", "--format", "human", "Inspect"],
            false,
        ),
        (
            vec![
                "steer",
                "invalid-session",
                "--events",
                "json",
                "--json",
                "Inspect",
            ],
            true,
        ),
        (
            vec![
                "steer",
                "invalid-session",
                "--events",
                "json",
                "--format",
                "json",
                "Inspect",
            ],
            true,
        ),
        (
            vec![
                "steer",
                "invalid-session",
                "--events",
                "json",
                "--format",
                "human",
                "Inspect",
            ],
            false,
        ),
        (vec!["doctor", "--events", "--json"], true),
        (vec!["doctor", "--events", "--format", "json"], true),
        (vec!["doctor", "--events", "--format", "human"], false),
    ] {
        assert_output_conflict(&args, json_error);
    }
}

#[test]
fn every_machine_readable_leaf_help_lists_only_mvp_formats() {
    for args in [
        vec!["setup", "--help"],
        vec!["repair", "--help"],
        vec!["doctor", "--help"],
        vec!["config", "check", "--help"],
        vec!["config", "explain", "--help"],
        vec!["paths", "--help"],
        vec!["host", "start", "--help"],
        vec!["host", "status", "--help"],
        vec!["host", "stop", "--help"],
        vec!["host", "restart", "--help"],
        vec!["host", "update", "--help"],
        vec!["host", "sessions", "--help"],
        vec!["host", "storage", "migrate", "--help"],
        vec!["self", "update", "--help"],
        vec!["run", "--help"],
        vec!["steer", "--help"],
        vec!["status", "--help"],
        vec!["stop", "--help"],
        vec!["logs", "--help"],
        vec!["support", "bundle", "--help"],
    ] {
        let output = satelle().args(args).assert().success().get_output().clone();
        let help = String::from_utf8_lossy(&output.stdout);
        assert!(help.contains("--format <FORMAT>"));
        assert!(help.contains("--json"));
        assert!(help.contains("[possible values: human, json]"));
    }

    for args in [
        vec!["--help"],
        vec!["config", "--help"],
        vec!["host", "--help"],
        vec!["host", "storage", "--help"],
        vec!["self", "--help"],
        vec!["support", "--help"],
    ] {
        let output = satelle().args(args).assert().success().get_output().clone();
        let help = String::from_utf8_lossy(&output.stdout);
        assert!(!help.contains("--format"));
        assert!(!help.contains("--json"));
    }
}
