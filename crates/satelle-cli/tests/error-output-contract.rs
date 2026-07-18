use assert_cmd::Command;
use satelle_test_contract::{assert_error_process, assert_human_error, assert_json_error};

const ERROR_FORMAT_ENV: &str = "SATELLE_ERROR_FORMAT";

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

#[test]
fn unknown_commands_default_to_typed_human_errors() {
    let output = satelle()
        .arg("unknown-command")
        .assert()
        .failure()
        .get_output()
        .clone();

    assert!(output.stdout.is_empty());
    assert_human_error(&output.stderr, "invalid-usage");
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
    assert_human_error(&human.stderr, "invalid-usage");

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
fn environment_error_format_has_precedence_over_result_selectors() {
    for args in [
        vec!["paths", "--json", "--unknown-option"],
        vec!["run", "--events", "json", "--unknown-option"],
        vec!["doctor", "--events", "--unknown-option"],
    ] {
        let output = satelle()
            .env(ERROR_FORMAT_ENV, "human")
            .args(args)
            .assert()
            .failure()
            .get_output()
            .clone();

        assert_error_process(&output);
        assert_human_error(&output.stderr, "invalid-usage");
    }
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
        assert_human_error(&output.stderr, "invalid-usage");
    }
}

#[test]
fn explicit_and_environment_formats_survive_unrecognized_result_selectors() {
    let explicit = satelle()
        .args([
            "--error-format",
            "json",
            "paths",
            "--unknown-option",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .clone();
    assert_error_process(&explicit);
    assert_json_error(&explicit.stderr, "invalid-usage", &["satelle --help"]);

    let environment = satelle()
        .env(ERROR_FORMAT_ENV, "json")
        .args(["paths", "--unknown-option", "--json"])
        .assert()
        .failure()
        .get_output()
        .clone();
    assert_error_process(&environment);
    assert_json_error(&environment.stderr, "invalid-usage", &["satelle --help"]);
}

fn usage_failure(args: &[&str]) -> std::process::Output {
    satelle().args(args).assert().failure().get_output().clone()
}

#[test]
fn parser_and_semantic_usage_failures_share_the_human_and_json_contract_and_status() {
    let parser = usage_failure(&["completions", "nushell"]);
    let semantic = usage_failure(&["self", "update", "--host", "remote"]);

    assert_error_process(&parser);
    assert_error_process(&semantic);
    assert_eq!(parser.status.code(), Some(64));
    assert_eq!(semantic.status.code(), Some(64));
    assert_eq!(
        parser.status, semantic.status,
        "parser and semantic human errors must share an exit status"
    );
    assert_human_error(&parser.stderr, "invalid-usage");
    assert_human_error(&semantic.stderr, "invalid-usage");

    let parser = usage_failure(&["--error-format", "json", "completions", "nushell"]);
    let semantic = usage_failure(&[
        "--error-format",
        "json",
        "self",
        "update",
        "--host",
        "remote",
    ]);

    assert_error_process(&parser);
    assert_error_process(&semantic);
    assert_eq!(parser.status.code(), Some(64));
    assert_eq!(semantic.status.code(), Some(64));
    assert_eq!(
        parser.status, semantic.status,
        "parser and semantic JSON errors must share an exit status"
    );
    assert_json_error(&parser.stderr, "invalid-usage", &["satelle --help"]);
    assert_json_error(&semantic.stderr, "invalid-usage", &["satelle --help"]);
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
