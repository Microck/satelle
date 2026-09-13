use assert_cmd::Command;
use satelle_host::test_support::TestStateDir;
use serde_json::{Value, json};
use std::fs;

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

fn parse_records(bytes: &[u8]) -> Vec<Value> {
    String::from_utf8_lossy(bytes)
        .lines()
        .map(|line| serde_json::from_str(line).expect("batch output must be NDJSON"))
        .collect()
}

#[test]
fn batch_emits_ordered_results_and_one_summary() {
    let state = TestStateDir::new().expect("secure state directory");
    let input = state.path().join("batch.ndjson");
    fs::write(
        &input,
        [
            json!({
                "schema_version": "satelle.batch.request.v1",
                "request_id": "first",
                "arguments": ["paths"],
            })
            .to_string(),
            json!({
                "schema_version": "satelle.batch.request.v1",
                "request_id": "second",
                "arguments": ["batch", "--input", "recursive.ndjson"],
            })
            .to_string(),
        ]
        .join("\n"),
    )
    .expect("write batch input");

    let output = satelle()
        .env("SATELLE_HOME", state.path().join("home"))
        .env("SATELLE_STATE_DIR", state.path().join("state"))
        .args(["batch", "--input"])
        .arg(&input)
        .args(["--concurrency", "2"])
        .assert()
        .code(1)
        .get_output()
        .clone();
    assert!(output.stderr.is_empty());
    let records = parse_records(&output.stdout);
    assert_eq!(records.len(), 3);
    assert_eq!(records[0]["schema_version"], "satelle.batch.result.v1");
    assert_eq!(records[0]["index"], 0);
    assert_eq!(records[0]["request_id"], "first");
    assert_eq!(records[0]["status"], "success");
    assert_eq!(
        records[0]["output"][0]["schema_version"],
        "satelle.paths.v2"
    );
    assert_eq!(records[1]["index"], 1);
    assert_eq!(records[1]["request_id"], "second");
    assert_eq!(records[1]["status"], "failure");
    assert_eq!(records[1]["errors"][0]["code"], "invalid-usage");
    assert_eq!(records[2]["schema_version"], "satelle.batch.summary.v1");
    assert_eq!(records[2]["status"], "completed_with_failures");
    assert_eq!(records[2]["total"], 2);
    assert_eq!(records[2]["succeeded"], 1);
    assert_eq!(records[2]["failed"], 1);
    assert_eq!(records[2]["concurrency"], 2);
}

#[test]
fn batch_reads_standard_input_and_uses_default_concurrency() {
    let state = TestStateDir::new().expect("secure state directory");
    let request = json!({
        "schema_version": "satelle.batch.request.v1",
        "request_id": "stdin-item",
        "arguments": ["paths"],
    })
    .to_string();
    let output = satelle()
        .env("SATELLE_HOME", state.path().join("home"))
        .env("SATELLE_STATE_DIR", state.path().join("state"))
        .args(["batch", "--input", "-"])
        .write_stdin(format!("{request}\n"))
        .assert()
        .success()
        .get_output()
        .clone();
    let records = parse_records(&output.stdout);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["request_id"], "stdin-item");
    assert_eq!(records[1]["status"], "completed");
    assert_eq!(records[1]["concurrency"], 4);
}

#[test]
fn batch_rejects_concurrency_outside_the_closed_range() {
    for concurrency in ["0", "17"] {
        satelle()
            .args([
                "batch",
                "--input",
                "ignored.ndjson",
                "--concurrency",
                concurrency,
            ])
            .assert()
            .code(64);
    }
}

#[test]
fn batch_results_do_not_repeat_prompt_arguments() {
    let state = TestStateDir::new().expect("secure state directory");
    let input = state.path().join("private-batch.ndjson");
    let prompt = "BATCH_PROMPT_PRIVACY_CANARY";
    fs::write(
        &input,
        format!(
            "{}\n",
            json!({
                "schema_version": "satelle.batch.request.v1",
                "request_id": "private",
                "arguments": ["run", "--host", "missing", prompt],
            })
        ),
    )
    .expect("write batch input");
    let output = satelle()
        .env("SATELLE_HOME", state.path().join("home"))
        .args(["batch", "--input"])
        .arg(input)
        .assert()
        .code(1)
        .get_output()
        .clone();
    assert!(!String::from_utf8_lossy(&output.stdout).contains(prompt));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(prompt));
}

#[test]
fn watch_rejects_session_filters_for_targets_other_than_logs() {
    let state = TestStateDir::new().expect("secure state directory");
    let output = satelle()
        .env("SATELLE_HOME", state.path().join("home"))
        .args(["watch", "host", "--session", "rs_example"])
        .assert()
        .code(64)
        .get_output()
        .clone();

    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("--session can be used only when watching logs")
    );
}

#[test]
fn notify_requires_a_user_owned_webhook_alias_before_watching() {
    let state = TestStateDir::new().expect("secure state directory");
    let output = satelle()
        .env("SATELLE_HOME", state.path().join("home"))
        .args([
            "--error-format",
            "json",
            "notify",
            "--watch",
            "sessions",
            "--webhook",
            "missing",
            "--dry-run",
        ])
        .assert()
        .code(66)
        .get_output()
        .clone();

    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).expect("typed config error");
    assert_eq!(error["code"], "configuration-error");
    assert!(!error.to_string().contains("authorization"));
}
