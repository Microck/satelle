DROP TABLE provider_smoke_successes;

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
    provider_credential_fingerprint TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('passed', 'failed')),
    failure_code TEXT,
    failure_reason TEXT,
    observed_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    CHECK (expires_at > observed_at),
    CHECK (
        (status = 'passed' AND failure_code IS NULL AND failure_reason IS NULL)
        OR (status = 'failed' AND failure_code IS NOT NULL AND failure_reason IS NOT NULL)
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
