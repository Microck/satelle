CREATE TABLE turn_admission_readiness (
    turn_id TEXT PRIMARY KEY
        REFERENCES turns(turn_id) ON DELETE CASCADE,
    native_result_id TEXT NOT NULL,
    native_observed_at TEXT NOT NULL,
    native_source TEXT NOT NULL CHECK (native_source IN ('cache', 'live')),
    provider_result_id TEXT,
    provider_observed_at TEXT,
    provider_source TEXT CHECK (
        provider_source IS NULL OR provider_source IN ('cache', 'live', 'refresh')
    ),
    CHECK (
        (provider_result_id IS NULL
            AND provider_observed_at IS NULL
            AND provider_source IS NULL)
        OR (provider_result_id IS NOT NULL
            AND provider_observed_at IS NOT NULL
            AND provider_source IS NOT NULL)
    )
) STRICT;
