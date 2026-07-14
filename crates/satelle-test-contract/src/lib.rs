use std::process::Output;

use serde_json::{Value, json};

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

pub fn assert_error_process(output: &Output) {
    assert!(!output.status.success(), "errors must exit nonzero");
    assert!(output.stdout.is_empty(), "errors must not use stdout");
}

pub fn assert_json_error(
    stderr: &[u8],
    expected_code: &str,
    expected_suggestions: &[&str],
) -> Value {
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

pub fn assert_human_error(stderr: &[u8], expected_code: &str) {
    let raw = String::from_utf8_lossy(stderr);
    let prefix = format!("error: {expected_code}\n");
    assert!(raw.starts_with(&prefix), "unexpected human error: {raw}");
    assert!(
        !raw[prefix.len()..].trim().is_empty(),
        "human errors must include a message"
    );
    assert!(
        !raw.trim_start().starts_with('{'),
        "human errors must not use JSON framing"
    );
}
