use satelle_core::SESSION_ID_PATTERN;
use serde_json::{Value, json};

pub(super) fn config_check() -> Value {
    versioned(
        "satelle.config.check.v1",
        json!({
            "status": {"type": "string"},
            "mode": {"enum": ["all", "selected"]},
            "selected_host": {"type": "string"},
            "selected_profile": {"type": ["string", "null"]},
            "checked_files": string_array(),
            "checks": string_array(),
            "checked_contexts": {"type": "array", "items": {"type": "object"}},
            "errors": {"type": "array"},
            "not_checked": string_array(),
            "recovery_commands": string_array()
        }),
        &[
            "status",
            "mode",
            "selected_host",
            "selected_profile",
            "checked_files",
            "checks",
            "checked_contexts",
            "errors",
            "not_checked",
            "recovery_commands",
        ],
    )
}

pub(super) fn config_explain() -> Value {
    versioned(
        "satelle.config.explain.v1",
        json!({
            "status": {"type": "string"},
            "selected_host": {"type": "string"},
            "selected_profile": {"type": ["string", "null"]},
            "checked_files": string_array(),
            "sources": {"type": "object"},
            "effective": {"type": "object"},
            "values": {"type": "object"},
            "not_checked": string_array()
        }),
        &[
            "status",
            "selected_host",
            "selected_profile",
            "checked_files",
            "sources",
            "effective",
            "values",
            "not_checked",
        ],
    )
}

pub(super) fn paths() -> Value {
    versioned(
        "satelle.paths.v1",
        json!({
            "host": {"type": "string"},
            "config_file": {"type": "string"},
            "cache_root": {"type": "string"},
            "state_root": {"type": "string"},
            "sqlite_store": {"type": "string"},
            "operator_log_root": {"type": "string"},
            "recording_root": {"type": "string"},
            "project_config_file": {"type": "string"},
            "install_receipt": {"type": "string"},
            "sources": {"type": "object"}
        }),
        &[
            "host",
            "config_file",
            "cache_root",
            "state_root",
            "sqlite_store",
            "operator_log_root",
            "recording_root",
            "project_config_file",
            "install_receipt",
            "sources",
        ],
    )
}

pub(super) fn status() -> Value {
    versioned(
        "satelle.status.v2",
        json!({
            "session_id": session_id(),
            "host": {"type": "string"},
            "status": {"enum": ["starting", "running", "recovery_pending", "completed", "blocked", "failed", "stopped"]},
            "created_at": {"type": "string", "format": "date-time"},
            "updated_at": {"type": "string", "format": "date-time"},
            "turns": {"type": "array", "items": {"type": "object"}}
        }),
        &[
            "session_id",
            "host",
            "status",
            "created_at",
            "updated_at",
            "turns",
        ],
    )
}

pub(super) fn doctor() -> Value {
    versioned(
        "satelle.doctor.v1",
        json!({
            "status": {"type": "string"},
            "target": {"type": "string"},
            "host": {"type": "string"},
            "scopes": string_array(),
            "started_at": {"type": "string"},
            "finished_at": {"type": "string"},
            "duration_ms": {"type": "integer", "minimum": 0},
            "summary": {"type": "object"},
            "probe_results": {"type": "array", "items": {"type": "object"}},
            "ready": {"type": "boolean"},
            "findings": {"type": "array", "items": {"type": "object"}},
            "recovery_commands": string_array(),
            "changed": {"type": "boolean"},
            "cache_updates": string_array()
        }),
        &[
            "status",
            "target",
            "host",
            "scopes",
            "started_at",
            "finished_at",
            "duration_ms",
            "summary",
            "probe_results",
            "ready",
            "findings",
            "recovery_commands",
            "changed",
            "cache_updates",
        ],
    )
}

pub(super) fn host_sessions() -> Value {
    versioned(
        "satelle.host.sessions.v1",
        json!({
            "host": {"type": "string"},
            "connection_mode": {"type": "string"},
            "bootstrapped": {"type": "boolean"},
            "bootstrap_actions": string_array(),
            "host_daemon_version": {"type": "string"},
            "sessions": {"type": "array", "items": {"type": "object"}}
        }),
        &[
            "host",
            "connection_mode",
            "bootstrapped",
            "bootstrap_actions",
            "host_daemon_version",
            "sessions",
        ],
    )
}

fn versioned(schema_version: &str, properties: Value, required: &[&str]) -> Value {
    let mut properties = properties
        .as_object()
        .expect("output schema properties are a JSON object")
        .clone();
    properties.insert(
        "schema_version".to_string(),
        json!({"const": schema_version}),
    );
    let mut required = required
        .iter()
        .map(|field| json!(field))
        .collect::<Vec<_>>();
    required.insert(0, json!("schema_version"));
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "oneOf": [
            {
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": false
            },
            super::result::error_schema()
        ]
    })
}

fn string_array() -> Value {
    json!({"type": "array", "items": {"type": "string"}})
}

fn session_id() -> Value {
    json!({
        "type": "string",
        "pattern": SESSION_ID_PATTERN
    })
}
