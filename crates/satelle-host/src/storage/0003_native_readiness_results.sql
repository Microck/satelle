DROP TABLE readiness_successes;

CREATE TABLE native_readiness_results (
    result_id TEXT PRIMARY KEY,
    host_identity_ref TEXT NOT NULL
        REFERENCES daemon_identity(host_identity_ref) ON DELETE CASCADE,
    desktop_binding_ref TEXT NOT NULL,
    adapter_ref TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('passed', 'failed')),
    failure_reason TEXT,
    codex_version TEXT NOT NULL,
    native_runtime_version TEXT NOT NULL,
    plugin_version TEXT,
    os_permission_fingerprint TEXT NOT NULL,
    app_approval_fingerprint TEXT NOT NULL,
    observed_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    CHECK (expires_at > observed_at),
    CHECK (
        (status = 'passed' AND failure_reason IS NULL)
        OR (status = 'failed' AND failure_reason IS NOT NULL)
    )
) STRICT;

CREATE INDEX native_readiness_reuse
ON native_readiness_results (
    host_identity_ref,
    desktop_binding_ref,
    adapter_ref,
    codex_version,
    native_runtime_version,
    plugin_version,
    os_permission_fingerprint,
    app_approval_fingerprint,
    status,
    expires_at
);
