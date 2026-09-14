CREATE TABLE setup_runs (
    run_id TEXT PRIMARY KEY,
    host_identity_ref TEXT NOT NULL
        REFERENCES daemon_identity(host_identity_ref) ON DELETE CASCADE,
    desktop_binding_ref TEXT,
    satelle_version TEXT NOT NULL,
    operation_kind TEXT NOT NULL
        CHECK (operation_kind IN ('setup', 'repair')),
    status TEXT NOT NULL
        CHECK (status IN (
            'running',
            'completed',
            'failed',
            'partial_failure',
            'outcome_unknown'
        )),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    CHECK (
        (status = 'running' AND finished_at IS NULL)
        OR (status != 'running' AND finished_at IS NOT NULL)
    )
) STRICT;

CREATE TABLE setup_actions (
    run_id TEXT NOT NULL
        REFERENCES setup_runs(run_id) ON DELETE CASCADE,
    action_id TEXT NOT NULL,
    action_order INTEGER NOT NULL CHECK (action_order >= 0),
    action_label TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (status IN (
            'planned',
            'started',
            'completed',
            'failed',
            'skipped',
            'outcome_unknown'
        )),
    started_at TEXT,
    finished_at TEXT,
    retry_safe INTEGER NOT NULL CHECK (retry_safe IN (0, 1)),
    error_code TEXT,
    exit_status INTEGER,
    recovery_hint TEXT,
    skip_reason TEXT,
    PRIMARY KEY (run_id, action_id),
    UNIQUE (run_id, action_order),
    CHECK (
        (status = 'planned'
            AND started_at IS NULL
            AND finished_at IS NULL
            AND error_code IS NULL
            AND exit_status IS NULL
            AND recovery_hint IS NULL
            AND skip_reason IS NULL)
        OR (status = 'started'
            AND started_at IS NOT NULL
            AND finished_at IS NULL
            AND error_code IS NULL
            AND exit_status IS NULL
            AND recovery_hint IS NULL
            AND skip_reason IS NULL)
        OR (status = 'completed'
            AND started_at IS NOT NULL
            AND finished_at IS NOT NULL
            AND error_code IS NULL
            AND exit_status IS NULL
            AND recovery_hint IS NULL
            AND skip_reason IS NULL)
        OR (status = 'failed'
            AND started_at IS NOT NULL
            AND finished_at IS NOT NULL
            AND error_code IS NOT NULL
            AND skip_reason IS NULL)
        OR (status = 'skipped'
            AND started_at IS NULL
            AND finished_at IS NOT NULL
            AND error_code IS NULL
            AND exit_status IS NULL
            AND recovery_hint IS NULL
            AND skip_reason IS NOT NULL)
        OR (status = 'outcome_unknown'
            AND started_at IS NOT NULL
            AND finished_at IS NOT NULL
            AND error_code IS NULL
            AND exit_status IS NULL
            AND skip_reason IS NULL)
    )
) STRICT;

CREATE INDEX setup_runs_host_started_idx
    ON setup_runs(host_identity_ref, started_at DESC);

CREATE INDEX setup_actions_run_order_idx
    ON setup_actions(run_id, action_order);
