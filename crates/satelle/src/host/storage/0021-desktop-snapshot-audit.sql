ALTER TABLE control_leases RENAME TO control_leases_v20;
DROP INDEX control_lease_turn_owner;
DROP INDEX control_lease_provider_probe_owner;
DROP INDEX control_lease_native_probe_owner;

CREATE TABLE control_leases (
    host_identity_ref TEXT NOT NULL
        REFERENCES daemon_identity(host_identity_ref) ON DELETE RESTRICT,
    desktop_binding_ref TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    owner_process_id INTEGER NOT NULL CHECK (owner_process_id > 0),
    owner_process_start_ref TEXT NOT NULL,
    owner_boot_identity_ref TEXT NOT NULL,
    acquired_at TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL,
    lease_state TEXT NOT NULL CHECK (lease_state IN ('active', 'recovery_pending')),
    owner_kind TEXT NOT NULL
        CHECK (owner_kind IN ('turn', 'provider_probe', 'native_probe', 'desktop_snapshot')),
    session_id TEXT,
    turn_id TEXT,
    provider_probe_ref TEXT,
    native_probe_ref TEXT,
    desktop_snapshot_ref TEXT,
    upstream_thread_ref TEXT,
    upstream_turn_ref TEXT,
    PRIMARY KEY (host_identity_ref, desktop_binding_ref),
    FOREIGN KEY (session_id, turn_id)
        REFERENCES turns(session_id, turn_id) ON DELETE RESTRICT,
    CHECK (
        (owner_kind = 'turn'
            AND session_id IS NOT NULL AND turn_id IS NOT NULL
            AND provider_probe_ref IS NULL AND native_probe_ref IS NULL
            AND desktop_snapshot_ref IS NULL
            AND upstream_thread_ref IS NULL AND upstream_turn_ref IS NULL)
        OR (owner_kind = 'provider_probe'
            AND session_id IS NULL AND turn_id IS NULL
            AND provider_probe_ref IS NOT NULL AND native_probe_ref IS NULL
            AND desktop_snapshot_ref IS NULL)
        OR (owner_kind = 'native_probe'
            AND session_id IS NULL AND turn_id IS NULL
            AND provider_probe_ref IS NULL AND native_probe_ref IS NOT NULL
            AND desktop_snapshot_ref IS NULL)
        OR (owner_kind = 'desktop_snapshot'
            AND session_id IS NULL AND turn_id IS NULL
            AND provider_probe_ref IS NULL AND native_probe_ref IS NULL
            AND desktop_snapshot_ref IS NOT NULL
            AND upstream_thread_ref IS NULL AND upstream_turn_ref IS NULL)
    )
) STRICT;

CREATE UNIQUE INDEX control_lease_turn_owner ON control_leases(turn_id)
    WHERE owner_kind = 'turn';
CREATE UNIQUE INDEX control_lease_provider_probe_owner ON control_leases(provider_probe_ref)
    WHERE owner_kind = 'provider_probe';
CREATE UNIQUE INDEX control_lease_native_probe_owner ON control_leases(native_probe_ref)
    WHERE owner_kind = 'native_probe';
CREATE UNIQUE INDEX control_lease_desktop_snapshot_owner ON control_leases(desktop_snapshot_ref)
    WHERE owner_kind = 'desktop_snapshot';

INSERT INTO control_leases (
    host_identity_ref, desktop_binding_ref, operation_id, owner_process_id,
    owner_process_start_ref, owner_boot_identity_ref, acquired_at, heartbeat_at,
    lease_state, owner_kind, session_id, turn_id, provider_probe_ref,
    native_probe_ref, upstream_thread_ref, upstream_turn_ref
)
SELECT
    host_identity_ref, desktop_binding_ref, operation_id, owner_process_id,
    owner_process_start_ref, owner_boot_identity_ref, acquired_at, heartbeat_at,
    lease_state, owner_kind, session_id, turn_id, provider_probe_ref,
    native_probe_ref, upstream_thread_ref, upstream_turn_ref
FROM control_leases_v20;

DROP TABLE control_leases_v20;

CREATE TABLE desktop_snapshot_audit (
    snapshot_id TEXT PRIMARY KEY,
    principal_ref TEXT NOT NULL,
    host_alias TEXT NOT NULL,
    host_identity_ref TEXT NOT NULL,
    desktop_binding_ref TEXT NOT NULL,
    desktop_session_ref TEXT,
    data_categories TEXT NOT NULL,
    redaction_policy_version TEXT NOT NULL,
    redaction_categories TEXT NOT NULL,
    unredacted_risk_categories TEXT NOT NULL,
    created_at_unix_nanos INTEGER NOT NULL,
    completed_at_unix_nanos INTEGER,
    artifact_format TEXT NOT NULL CHECK (artifact_format = 'image/png'),
    artifact_byte_size INTEGER CHECK (artifact_byte_size BETWEEN 0 AND 33554432),
    status TEXT NOT NULL CHECK (status IN ('capturing', 'prepared', 'exported', 'failed'))
) STRICT;

CREATE INDEX desktop_snapshot_audit_retention
    ON desktop_snapshot_audit(created_at_unix_nanos);
