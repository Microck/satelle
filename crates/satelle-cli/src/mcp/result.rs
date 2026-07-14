use super::super::error_output::{ERROR_SCHEMA_VERSION, error_categories, error_envelope};
use rmcp::model::CallToolResult;
use satelle_core::SatelleError;
use serde_json::{Value, json};

pub(super) fn structured(value: Value, is_error: bool) -> CallToolResult {
    if is_error {
        CallToolResult::structured_error(value)
    } else {
        CallToolResult::structured(value)
    }
}

pub(super) fn operational_error(error: SatelleError) -> CallToolResult {
    structured(error_envelope(&error), true)
}

pub(super) fn error_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "schema_version": {"const": ERROR_SCHEMA_VERSION},
            "code": {"type": "string", "minLength": 1},
            "category": {"enum": error_categories()},
            "retryable": {"type": "boolean"},
            "message": {"type": "string", "minLength": 1},
            "details": {"type": ["object", "null"]},
            "docs_url": {"type": ["string", "null"]},
            "suggested_commands": {"type": "array", "items": {"type": "string"}}
        },
        "required": [
            "schema_version", "code", "category", "retryable", "message", "details",
            "docs_url", "suggested_commands"
        ],
        "additionalProperties": false
    })
}
