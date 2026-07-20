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
        "SATELLE_ERROR_FORMAT",
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

fn assert_error_keys(report: &Value) {
    let mut keys = report
        .as_object()
        .expect("error envelope should be an object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "category",
            "code",
            "details",
            "docs_url",
            "message",
            "retryable",
            "schema_version",
            "suggested_commands",
        ]
    );
}

fn assert_exact_keys(report: &Value, expected: &[&str]) {
    let mut actual = report
        .as_object()
        .expect("JSON report should be an object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    actual.sort_unstable();

    let mut expected = expected.to_vec();
    expected.sort_unstable();
    assert_eq!(actual, expected);
}

fn assert_output_conflict(args: &[&str], json_error: bool) {
    let state = state_dir();
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(args)
        .assert()
        .failure()
        .get_output()
        .clone();

    assert!(output.stdout.is_empty());
    if json_error {
        let report = parse_json(&output.stderr);
        assert_error_keys(&report);
        assert_eq!(report["schema_version"], "satelle.error.v1");
        assert_eq!(report["code"], "output-mode-conflict");
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.starts_with("error: output-mode-conflict\n"));
        assert!(!stderr.trim_start().starts_with('{'));
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
fn json_command_output_is_stable_when_diagnostic_verbosity_changes() {
    let state = state_dir();
    let baseline = satelle()
        .env("SATELLE_HOME", state.path())
        .env_remove("SATELLE_LOG")
        .args(["paths", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();

    let verbose = satelle()
        .env("SATELLE_HOME", state.path())
        .env("SATELLE_LOG", "satelle=debug")
        .args(["paths", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();

    assert!(baseline.stderr.is_empty());
    assert!(verbose.stderr.is_empty());
    assert_eq!(parse_json(&baseline.stdout), parse_json(&verbose.stdout));

    let human_verbose = satelle()
        .env("SATELLE_HOME", state.path())
        .env("SATELLE_LOG", "satelle=debug")
        .args(["paths"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert!(
        String::from_utf8_lossy(&human_verbose.stderr).contains("Satelle diagnostics initialized"),
        "SATELLE_LOG should enable debug diagnostics on stderr"
    );
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
            true,
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
            true,
        ),
        (vec!["doctor", "--events", "--json"], true),
        (vec!["doctor", "--events", "--format", "json"], true),
        (vec!["doctor", "--events", "--format", "human"], true),
    ] {
        assert_output_conflict(&args, json_error);
    }
}

#[test]
fn stop_json_v1_has_one_closed_contract_for_stopped_and_already_terminal_turns() {
    let fields = [
        "changed",
        "current_state",
        "outcome",
        "previous_state",
        "schema_version",
        "session_id",
        "stopped_at",
        "turn_id",
    ];

    for (adapter, expected) in [
        (
            "fake",
            ("already_terminal", "completed", "completed", false),
        ),
        ("pending", ("stopped", "recovery_pending", "stopped", true)),
    ] {
        let state = state_dir();
        let mut run_command = satelle();
        run_command
            .env("SATELLE_STATE_DIR", state.path())
            .env(TEST_SUPPORT_ADAPTER_ENV, adapter)
            .args(["run", "--host", "local-demo"]);
        if adapter == "pending" {
            run_command.arg("--detach");
        }
        let run = run_command
            .args(["--json", "Inspect"])
            .assert()
            .success()
            .get_output()
            .clone();
        let run = parse_json(&run.stdout);
        let session_id = run["session_id"]
            .as_str()
            .expect("run result should include a Session id");
        let turn_id = run["latest_turn"]["turn_id"]
            .as_str()
            .or_else(|| run["turns"][0]["turn_id"].as_str())
            .expect("run result should include a Turn id");

        let stop = satelle()
            .env("SATELLE_STATE_DIR", state.path())
            .env(TEST_SUPPORT_ADAPTER_ENV, adapter)
            .args(["stop", session_id, "--json"])
            .assert()
            .success()
            .get_output()
            .clone();
        assert!(stop.stderr.is_empty());
        let stop = parse_json(&stop.stdout);

        assert_exact_keys(&stop, &fields);
        assert_eq!(stop["schema_version"], "satelle.stop.v1");
        assert_eq!(stop["session_id"], session_id);
        assert_eq!(stop["turn_id"], turn_id);
        assert_eq!(stop["outcome"], expected.0);
        assert_eq!(stop["previous_state"], expected.1);
        assert_eq!(stop["current_state"], expected.2);
        assert_eq!(stop["changed"], expected.3);
        if expected.3 {
            assert!(stop["stopped_at"].is_string());
        } else {
            assert!(stop["stopped_at"].is_null());
        }
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
