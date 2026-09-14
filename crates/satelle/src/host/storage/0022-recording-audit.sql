CREATE TABLE recording_audit (
    recording_id TEXT PRIMARY KEY NOT NULL,
    principal_ref TEXT NOT NULL,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    turn_id TEXT NOT NULL REFERENCES turns(turn_id) ON DELETE CASCADE,
    host_alias TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('events', 'transcript', 'screenshots', 'video')),
    recording_directory TEXT NOT NULL,
    manifest_path TEXT,
    manifest_json TEXT,
    created_at_unix_nanos INTEGER NOT NULL,
    expires_at_unix_nanos INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('capturing', 'retained', 'failed', 'expired')),
    UNIQUE(session_id, turn_id)
) STRICT;

CREATE TABLE recording_artifacts (
    recording_id TEXT NOT NULL REFERENCES recording_audit(recording_id) ON DELETE CASCADE,
    artifact_path TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    created_at_unix_nanos INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    byte_size INTEGER NOT NULL,
    retention_state TEXT NOT NULL CHECK (retention_state IN ('retained', 'expired')),
    PRIMARY KEY(recording_id, artifact_path)
) STRICT;

CREATE INDEX recording_audit_retention
ON recording_audit(status, expires_at_unix_nanos);
