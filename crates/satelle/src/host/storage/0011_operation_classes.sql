CREATE TABLE idempotency_records_v11 (
    principal_ref TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN (
        'run',
        'steer',
        'stop',
        'setup',
        'repair',
        'host_update',
        'storage_migration',
        'destructive_maintenance'
    )),
    idempotency_key TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    request_digest TEXT NOT NULL
        CHECK (
            length(request_digest) = 64
            AND request_digest NOT GLOB '*[^0-9a-f]*'
        ),
    digest_schema_version INTEGER NOT NULL CHECK (digest_schema_version > 0),
    hmac_key_version INTEGER NOT NULL CHECK (hmac_key_version > 0),
    status TEXT NOT NULL CHECK (status IN ('in_progress', 'terminal')),
    durable_outcome TEXT NOT NULL CHECK (durable_outcome IN (
        'v1.turn.starting',
        'v1.turn.running',
        'v1.turn.recovery_pending',
        'v1.turn.completed',
        'v1.turn.blocked',
        'v1.turn.failed',
        'v1.turn.stopped',
        'v1.stop.pending',
        'v1.stop.stopped_from_starting',
        'v1.stop.stopped_from_running',
        'v1.stop.stopped_from_recovery_pending',
        'v1.stop.already_completed',
        'v1.stop.already_blocked',
        'v1.stop.already_failed',
        'v1.stop.already_stopped',
        'v1.stop.not_confirmed_active_changed',
        'v1.stop.not_confirmed_active_unchanged',
        'v1.stop.not_confirmed_recovery_pending_changed',
        'v1.stop.not_confirmed_recovery_pending_unchanged'
    )),
    session_id TEXT REFERENCES sessions(session_id) ON DELETE RESTRICT,
    turn_id TEXT REFERENCES turns(turn_id) ON DELETE RESTRICT,
    result_session_state_revision TEXT
        CHECK (
            result_session_state_revision IS NULL
            OR (
                length(result_session_state_revision) = 16
                AND result_session_state_revision NOT GLOB '*[^0-9a-f]*'
                AND result_session_state_revision <> '0000000000000000'
            )
        ),
    result_session_updated_at TEXT,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    expires_at TEXT NOT NULL,
    FOREIGN KEY (hmac_key_version)
        REFERENCES idempotency_hmac_keys(key_version) ON DELETE RESTRICT,
    PRIMARY KEY (principal_ref, operation, idempotency_key),
    CHECK (
        (status = 'in_progress' AND completed_at IS NULL)
        OR (status = 'terminal' AND completed_at IS NOT NULL)
    ),
    CHECK (
        operation = 'stop'
        OR (
            status = 'in_progress'
            AND result_session_state_revision IS NULL
            AND result_session_updated_at IS NULL
        )
        OR (
            status = 'terminal'
            AND result_session_state_revision IS NOT NULL
            AND result_session_updated_at IS NOT NULL
        )
    )
) STRICT;

INSERT INTO idempotency_records_v11
SELECT * FROM idempotency_records;

DROP TABLE idempotency_records;
ALTER TABLE idempotency_records_v11 RENAME TO idempotency_records;

CREATE INDEX idempotency_expiry
    ON idempotency_records(expires_at);

ALTER TABLE setup_actions RENAME TO setup_actions_v10;
ALTER TABLE setup_runs RENAME TO setup_runs_v10;
DROP INDEX setup_actions_run_order_idx;
DROP INDEX setup_runs_host_started_idx;

CREATE TABLE setup_runs (
    run_id TEXT PRIMARY KEY,
    host_identity_ref TEXT NOT NULL
        REFERENCES daemon_identity(host_identity_ref) ON DELETE CASCADE,
    desktop_binding_ref TEXT,
    satelle_version TEXT NOT NULL,
    operation_kind TEXT NOT NULL
        CHECK (operation_kind IN (
            'setup',
            'repair',
            'host_update',
            'storage_migration',
            'service_stop',
            'service_restart'
        )),
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

INSERT INTO setup_runs
SELECT * FROM setup_runs_v10;

INSERT INTO setup_actions
SELECT * FROM setup_actions_v10;

DROP TABLE setup_actions_v10;
DROP TABLE setup_runs_v10;

CREATE INDEX setup_runs_host_started_idx
    ON setup_runs(host_identity_ref, started_at DESC);

CREATE INDEX setup_actions_run_order_idx
    ON setup_actions(run_id, action_order);
