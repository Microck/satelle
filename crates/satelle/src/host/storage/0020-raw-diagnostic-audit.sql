CREATE TABLE raw_diagnostic_audit (
    export_id TEXT PRIMARY KEY,
    principal_ref TEXT NOT NULL,
    host_alias TEXT NOT NULL,
    command TEXT NOT NULL CHECK (command IN ('run', 'steer', 'setup', 'repair')),
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('turn', 'command_invocation')),
    scope_ref TEXT NOT NULL,
    data_categories TEXT NOT NULL,
    redaction_policy_version TEXT NOT NULL,
    created_at_unix_nanos INTEGER NOT NULL,
    completed_at_unix_nanos INTEGER,
    artifact_byte_size INTEGER CHECK (artifact_byte_size BETWEEN 0 AND 8388608),
    status TEXT NOT NULL CHECK (status IN ('capturing', 'prepared', 'exported', 'failed'))
) STRICT;

CREATE INDEX raw_diagnostic_audit_retention ON raw_diagnostic_audit(created_at_unix_nanos);
