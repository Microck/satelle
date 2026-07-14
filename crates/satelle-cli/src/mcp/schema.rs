use super::output_schema;
use rmcp::model::{JsonObject, Tool, ToolAnnotations};
use satelle_core::SESSION_ID_PATTERN;
use serde_json::{Value, json};
use std::sync::Arc;

// JSON Schema 2020-12 treats `format` as an annotation unless a validator opts
// into format assertion. Keep the runtime parser authoritative for calendar
// semantics, while this portable pattern rejects strings without RFC 3339's
// lexical shape even when a client ignores `format`.
const RFC3339_LEXICAL_PATTERN: &str = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:[Zz]|[+-][0-9]{2}:[0-9]{2})$";

pub(super) fn tools() -> Vec<Tool> {
    vec![
        tool(
            "config_check",
            "Validate the selected Satelle configuration without contacting a Host.",
            object_schema(
                json!({
                    "host": non_empty_string(),
                    "all": {"type": "boolean", "default": false}
                }),
                &[],
            ),
            Some(output_schema::config_check()),
        ),
        tool(
            "config_explain",
            "Explain the effective redacted Satelle configuration.",
            object_schema(
                json!({
                    "host": non_empty_string(),
                    "show_secret_references": {"type": "boolean", "default": false}
                }),
                &[],
            ),
            Some(output_schema::config_explain()),
        ),
        tool(
            "paths",
            "Resolve Satelle configuration, state, cache, log, and recording paths.",
            object_schema(json!({"host": non_empty_string()}), &[]),
            Some(output_schema::paths()),
        ),
        tool(
            "status",
            "Read the authoritative state of one Satelle Session.",
            object_schema(
                json!({
                    "session_id": session_id_schema(),
                    "host": non_empty_string()
                }),
                &["session_id"],
            ),
            Some(output_schema::status()),
        ),
        tool(
            "logs",
            "Read a finite snapshot of normalized Satelle logs as NDJSON.",
            object_schema(
                json!({
                    "host": non_empty_string(),
                    "session": session_id_schema(),
                    "tail": {"type": "integer", "minimum": 1, "maximum": 10000},
                    "since": {
                        "type": "string",
                        "anyOf": [
                            {
                                "format": "date-time",
                                "pattern": RFC3339_LEXICAL_PATTERN
                            },
                            {"pattern": relative_duration_pattern()}
                        ]
                    },
                    "after": {"type": "string"},
                    "source": {
                        "type": "array",
                        "items": {"enum": ["host_daemon", "storage", "codex_adapter"]}
                    },
                    "level": {"enum": ["info", "warn", "error"], "default": "info"}
                }),
                &[],
            ),
            None,
        ),
        tool(
            "doctor",
            "Run read-only Satelle readiness probes and return the complete report.",
            object_schema(
                json!({
                    "host": non_empty_string(),
                    "scope": {
                        "enum": ["transport", "codex", "computer-use", "provider", "config", "all"]
                    }
                }),
                &[],
            ),
            Some(output_schema::doctor()),
        ),
        tool(
            "host_status",
            "Read the compact Host runtime status.",
            object_schema(json!({"host": non_empty_string()}), &[]),
            None,
        ),
        tool(
            "host_sessions",
            "List Host desktop sessions without attempting SSH bootstrap.",
            object_schema(json!({"host": non_empty_string()}), &[]),
            Some(output_schema::host_sessions()),
        ),
    ]
}

fn tool(
    name: &'static str,
    description: &'static str,
    input_schema: Value,
    output_schema: Option<Value>,
) -> Tool {
    let annotations = ToolAnnotations::new()
        .read_only(true)
        .destructive(false)
        .idempotent(true)
        .open_world(false);
    let mut tool = Tool::new(name, description, object(input_schema)).with_annotations(annotations);
    if let Some(output_schema) = output_schema {
        tool = tool.with_raw_output_schema(Arc::new(object(output_schema)));
    }
    tool
}

fn object_schema(properties: Value, required: &[&str]) -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false
    })
}

fn non_empty_string() -> Value {
    json!({"type": "string", "minLength": 1})
}

fn session_id_schema() -> Value {
    json!({"type": "string", "pattern": SESSION_ID_PATTERN})
}

fn relative_duration_pattern() -> String {
    format!(
        "^(?:{})(?:ms|s|m)$",
        bounded_ascii_decimal_pattern(u64::MAX)
    )
}

/// Returns a portable regular expression for ASCII decimal integers from zero
/// through `maximum`. Leading zeros remain valid because the runtime's `u64`
/// parser accepts them.
fn bounded_ascii_decimal_pattern(maximum: u64) -> String {
    if maximum == 0 {
        return "0+".to_string();
    }
    let maximum = maximum.to_string();
    let digits = maximum.as_bytes();
    let mut alternatives = Vec::new();
    if digits.len() > 1 {
        alternatives.push(format!("[1-9][0-9]{{0,{}}}", digits.len() - 2));
    }
    let mut equal_prefix = String::new();

    for (index, digit) in digits.iter().copied().enumerate() {
        let digit = digit - b'0';
        let lowest_digit = u8::from(index == 0);
        if digit > lowest_digit {
            let highest_lower_digit = digit - 1;
            let lower_digit = if highest_lower_digit == lowest_digit {
                lowest_digit.to_string()
            } else {
                format!("[{lowest_digit}-{highest_lower_digit}]")
            };
            let remaining = digits.len() - index - 1;
            let suffix = if remaining == 0 {
                String::new()
            } else {
                format!("[0-9]{{{remaining}}}")
            };
            alternatives.push(format!("{equal_prefix}{lower_digit}{suffix}"));
        }
        equal_prefix.push(char::from(b'0' + digit));
    }
    alternatives.push(equal_prefix);

    // Keep the all-zero and non-zero branches disjoint. Besides making the
    // accepted language explicit, this avoids pathological backtracking on a
    // long sequence of leading zeros.
    format!("(?:0+|0*(?:{}))", alternatives.join("|"))
}

fn object(value: Value) -> JsonObject {
    value
        .as_object()
        .expect("MCP schemas are constructed as JSON objects")
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logs_since_schema_rejects_obvious_timestamp_junk_and_duration_overflow() {
        let validator = logs_input_validator();

        for since in [
            "yesterday",
            "18446744073709551616ms",
            "018446744073709551616s",
            "19000000000000000000m",
            "99999999999999999999ms",
        ] {
            assert!(
                !validator.is_valid(&json!({"since": since})),
                "logs schema unexpectedly accepted {since}"
            );
        }
    }

    #[test]
    fn logs_since_schema_accepts_runtime_boundary_values() {
        let validator = logs_input_validator();

        for since in [
            "0ms",
            "0s",
            "000000m",
            "18446744073709551615ms",
            "18446744073709551615s",
            "18446744073709551615m",
            "00018446744073709551615ms",
            "2026-07-14T12:34:56Z",
            "1985-04-12t23:20:50.52z",
            "1996-12-19T16:39:57-08:00",
        ] {
            assert!(
                validator.is_valid(&json!({"since": since})),
                "logs schema unexpectedly rejected {since}"
            );
        }
    }

    #[test]
    fn bounded_decimal_pattern_is_exact_for_representative_maxima() {
        for maximum in [
            0_u64, 1, 8, 9, 10, 18, 19, 98, 99, 100, 105, 999, 1000, 4096,
        ] {
            let schema = json!({
                "type": "string",
                "pattern": format!("^(?:{})$", bounded_ascii_decimal_pattern(maximum))
            });
            let validator = jsonschema::validator_for(&schema)
                .expect("bounded decimal pattern is valid JSON Schema");

            for candidate in 0..=maximum + 2 {
                let expected = candidate <= maximum;
                for rendered in [candidate.to_string(), format!("000{candidate}")] {
                    assert_eq!(
                        validator.is_valid(&json!(rendered)),
                        expected,
                        "maximum={maximum}, candidate={rendered}"
                    );
                }
            }
        }
    }

    fn logs_input_validator() -> jsonschema::Validator {
        let logs = tools()
            .into_iter()
            .find(|tool| tool.name == "logs")
            .expect("logs tool is advertised");
        jsonschema::validator_for(&Value::Object(logs.input_schema.as_ref().clone()))
            .expect("logs input schema is valid JSON Schema 2020-12")
    }
}
