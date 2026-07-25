ALTER TABLE control_leases RENAME TO control_leases_v4;
DROP INDEX IF EXISTS control_lease_turn_owner;
DROP INDEX IF EXISTS control_lease_provider_probe_owner;

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
    lease_state TEXT NOT NULL
        CHECK (lease_state IN ('active', 'recovery_pending')),
    owner_kind TEXT NOT NULL CHECK (owner_kind IN ('turn', 'provider_probe')),
    session_id TEXT,
    turn_id TEXT,
    provider_probe_ref TEXT,
    upstream_thread_ref TEXT,
    upstream_turn_ref TEXT,
    PRIMARY KEY (host_identity_ref, desktop_binding_ref),
    FOREIGN KEY (session_id, turn_id)
        REFERENCES turns(session_id, turn_id) ON DELETE RESTRICT,
    CHECK (
        (owner_kind = 'turn'
            AND session_id IS NOT NULL
            AND turn_id IS NOT NULL
            AND provider_probe_ref IS NULL
            AND upstream_thread_ref IS NULL
            AND upstream_turn_ref IS NULL)
        OR (owner_kind = 'provider_probe'
            AND session_id IS NULL
            AND turn_id IS NULL
            AND provider_probe_ref IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX control_lease_turn_owner
    ON control_leases(turn_id)
    WHERE owner_kind = 'turn';

CREATE UNIQUE INDEX control_lease_provider_probe_owner
    ON control_leases(provider_probe_ref)
    WHERE owner_kind = 'provider_probe';

INSERT INTO control_leases (
    host_identity_ref, desktop_binding_ref, operation_id, owner_process_id,
    owner_process_start_ref, owner_boot_identity_ref, acquired_at, heartbeat_at,
    lease_state, owner_kind, session_id, turn_id
)
SELECT
    host_identity_ref, desktop_binding_ref, operation_id, owner_process_id,
    owner_process_start_ref, owner_boot_identity_ref, acquired_at, heartbeat_at,
    lease_state, 'turn', session_id, turn_id
FROM control_leases_v4;

DROP TABLE control_leases_v4;

ALTER TABLE provider_smoke_results RENAME TO provider_smoke_results_v4;
DROP INDEX provider_smoke_reuse;

CREATE TABLE provider_smoke_results (
    result_id TEXT PRIMARY KEY,
    host_identity_ref TEXT NOT NULL
        REFERENCES daemon_identity(host_identity_ref) ON DELETE CASCADE,
    desktop_binding_ref TEXT NOT NULL,
    provider_binding_ref TEXT NOT NULL,
    effective_model_ref TEXT NOT NULL,
    codex_version TEXT NOT NULL,
    native_runtime_version TEXT NOT NULL,
    provider_config_fingerprint TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (status IN ('passed', 'failed', 'timed_out', 'outcome_unknown')),
    failure_code TEXT,
    failure_reason TEXT,
    observed_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    CHECK (expires_at > observed_at),
    CHECK (
        (status = 'passed' AND failure_code IS NULL AND failure_reason IS NULL)
        OR (status IN ('failed', 'timed_out', 'outcome_unknown')
            AND failure_code IS NOT NULL
            AND failure_reason IS NOT NULL)
    )
) STRICT;

CREATE INDEX provider_smoke_reuse
ON provider_smoke_results (
    host_identity_ref,
    desktop_binding_ref,
    provider_binding_ref,
    effective_model_ref,
    codex_version,
    native_runtime_version,
    provider_config_fingerprint,
    expires_at
);

INSERT INTO provider_smoke_results
SELECT * FROM provider_smoke_results_v4;

DROP TABLE provider_smoke_results_v4;
