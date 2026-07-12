CREATE TABLE readiness_successes (
    result_id TEXT PRIMARY KEY,
    host_identity_ref TEXT NOT NULL
        REFERENCES daemon_identity(host_identity_ref) ON DELETE CASCADE,
    desktop_binding_ref TEXT NOT NULL,
    adapter_ref TEXT NOT NULL,
    codex_version TEXT NOT NULL,
    native_runtime_version TEXT NOT NULL,
    plugin_version TEXT,
    os_permission_fingerprint TEXT NOT NULL,
    app_approval_fingerprint TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    CHECK (expires_at > observed_at)
) STRICT;

CREATE TABLE provider_smoke_successes (
    result_id TEXT PRIMARY KEY,
    host_identity_ref TEXT NOT NULL
        REFERENCES daemon_identity(host_identity_ref) ON DELETE CASCADE,
    desktop_binding_ref TEXT NOT NULL,
    provider_binding_ref TEXT NOT NULL,
    effective_model_ref TEXT NOT NULL,
    codex_version TEXT NOT NULL,
    native_runtime_version TEXT NOT NULL,
    provider_config_fingerprint TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    CHECK (expires_at > observed_at)
) STRICT;
