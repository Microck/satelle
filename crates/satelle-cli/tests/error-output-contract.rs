use assert_cmd::Command;
use serde_json::{Value, json};

const ERROR_FORMAT_ENV: &str = "SATELLE_ERROR_FORMAT";
const ERROR_KEYS: [&str; 8] = [
    "category",
    "code",
    "details",
    "docs_url",
    "message",
    "retryable",
    "schema_version",
    "suggested_commands",
];

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
        ERROR_FORMAT_ENV,
    ] {
        command.env_remove(name);
    }
    command
}

fn assert_json_error(stderr: &[u8], expected_code: &str, expected_suggestions: &[&str]) -> Value {
    let report: Value = serde_json::from_slice(stderr).expect("stderr should be one JSON value");
    let object = report
        .as_object()
        .expect("the JSON error envelope should be an object");
    let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(keys, ERROR_KEYS);
    assert_eq!(report["schema_version"], "satelle.error.v1");
    assert_eq!(report["code"], expected_code);
    assert_eq!(report["category"], "invalid_request");
    assert_eq!(report["retryable"], false);
    assert!(
        report["message"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    assert_eq!(report["details"], Value::Null);
    assert_eq!(report["docs_url"], Value::Null);
    assert_eq!(report["suggested_commands"], json!(expected_suggestions));

    let raw = String::from_utf8_lossy(stderr);
    assert!(
        !raw.contains('\u{1b}'),
        "JSON errors must not contain ANSI escapes"
    );
    assert!(
        !raw.starts_with("error:"),
        "JSON errors must not use human framing"
    );
    report
}

fn assert_human_error(stderr: &[u8]) {
    let raw = String::from_utf8_lossy(stderr);
    assert!(raw.starts_with("error: invalid-usage\n"));
    assert!(!raw.trim_start().starts_with('{'));
}

#[test]
fn unknown_commands_default_to_typed_human_errors() {
    let output = satelle()
        .arg("unknown-command")
        .assert()
        .failure()
        .get_output()
        .clone();

    assert!(output.stdout.is_empty());
    assert_human_error(&output.stderr);
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown-command"));
}

#[test]
fn explicit_and_environment_error_formats_select_json_for_parser_failures() {
    for (environment, args) in [
        (None, vec!["--error-format", "json", "unknown-command"]),
        (Some("json"), vec!["unknown-command"]),
    ] {
        let mut command = satelle();
        if let Some(value) = environment {
            command.env(ERROR_FORMAT_ENV, value);
        }
        let output = command.args(args).assert().failure().get_output().clone();

        assert!(output.stdout.is_empty());
        assert_json_error(&output.stderr, "invalid-usage", &["satelle --help"]);
    }
}

#[test]
fn explicit_error_format_has_precedence_over_environment_and_result_selectors() {
    let human = satelle()
        .env(ERROR_FORMAT_ENV, "json")
        .args([
            "--error-format",
            "human",
            "paths",
            "--json",
            "--unknown-option",
        ])
        .assert()
        .failure()
        .get_output()
        .clone();
    assert!(human.stdout.is_empty());
    assert_human_error(&human.stderr);

    let json = satelle()
        .env(ERROR_FORMAT_ENV, "human")
        .args(["--error-format", "json", "paths", "--unknown-option"])
        .assert()
        .failure()
        .get_output()
        .clone();
    assert!(json.stdout.is_empty());
    assert_json_error(&json.stderr, "invalid-usage", &["satelle --help"]);
}

#[test]
fn parsed_machine_selectors_choose_json_for_later_parser_failures() {
    for args in [
        vec!["paths", "--json", "--unknown-option"],
        vec!["paths", "--format", "json", "--unknown-option"],
        vec!["run", "--events", "json", "--unknown-option"],
        vec!["doctor", "--events", "--unknown-option"],
    ] {
        let output = satelle().args(args).assert().failure().get_output().clone();

        assert!(output.stdout.is_empty());
        assert_json_error(&output.stderr, "invalid-usage", &["satelle --help"]);
    }
}

#[test]
fn unparsed_and_positional_machine_selectors_do_not_choose_json() {
    for args in [
        vec!["paths", "--unknown-option", "--json"],
        vec!["paths", "--", "--json"],
    ] {
        let output = satelle().args(args).assert().failure().get_output().clone();

        assert!(output.stdout.is_empty());
        assert_human_error(&output.stderr);
    }
}

#[test]
fn parser_and_semantic_usage_failures_share_the_json_contract_and_status() {
    let parser = satelle()
        .args(["--error-format", "json", "completions", "nushell"])
        .assert()
        .failure()
        .get_output()
        .clone();
    let semantic = satelle()
        .args([
            "--error-format",
            "json",
            "paths",
            "--json",
            "--format",
            "human",
        ])
        .assert()
        .failure()
        .get_output()
        .clone();

    assert!(parser.stdout.is_empty());
    assert!(semantic.stdout.is_empty());
    assert_eq!(parser.status, semantic.status);
    assert_json_error(&parser.stderr, "invalid-usage", &["satelle --help"]);
    assert_json_error(
        &semantic.stderr,
        "output-mode-conflict",
        &["remove all but one conflicting output selector"],
    );
}

#[test]
fn help_and_version_remain_success_output_when_json_errors_are_the_default() {
    for arg in ["--help", "--version"] {
        let output = satelle()
            .env(ERROR_FORMAT_ENV, "json")
            .arg(arg)
            .assert()
            .success()
            .get_output()
            .clone();

        assert!(!output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}
