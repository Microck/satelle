CREATE TABLE turn_admission_queue (
    queue_request_id TEXT PRIMARY KEY NOT NULL,
    lease_key TEXT NOT NULL,
    token_id TEXT NOT NULL,
    credential_revision INTEGER NOT NULL CHECK (credential_revision >= 1),
    principal_ref TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('run', 'steer')),
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    payload_file TEXT NOT NULL UNIQUE,
    payload_sha256 TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('queued', 'admitted', 'cancelled', 'expired', 'validation_failed')
    ),
    enqueued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    session_id TEXT,
    turn_id TEXT,
    failure_code TEXT,
    failure_message TEXT,
    state_revision INTEGER NOT NULL CHECK (state_revision >= 1),
    UNIQUE (principal_ref, operation, idempotency_key),
    CHECK ((operation = 'steer' AND session_id IS NOT NULL) OR operation = 'run'),
    CHECK (
        (status = 'admitted' AND session_id IS NOT NULL AND turn_id IS NOT NULL)
        OR (status != 'admitted' AND turn_id IS NULL)
    ),
    CHECK (
        (status = 'validation_failed' AND failure_code IS NOT NULL AND failure_message IS NOT NULL)
        OR (status != 'validation_failed' AND failure_code IS NULL AND failure_message IS NULL)
    )
) STRICT;

CREATE INDEX turn_admission_queue_fifo
ON turn_admission_queue(lease_key, status, rtrim(enqueued_at, 'Z'), queue_request_id);

CREATE INDEX turn_admission_queue_expiry
ON turn_admission_queue(status, expires_at);

-- Queue lifecycle logs use the normal authoritative Log Cursor stream. The
-- queue status JSON is the same redacted public object returned by queue
-- status, which keeps its position, timing, and typed failure together.
ALTER TABLE logs RENAME TO logs_v22;

CREATE TABLE logs (
    log_cursor INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at TEXT NOT NULL,
    recorded_at_unix_nanos INTEGER NOT NULL,
    source TEXT NOT NULL
        CHECK (source IN ('host_daemon', 'storage', 'codex_adapter')),
    severity TEXT NOT NULL
        CHECK (severity IN ('info', 'warning', 'error')),
    event_kind TEXT NOT NULL
        CHECK (event_kind IN (
            'session_started',
            'follow_up_started',
            'native_readiness_summary',
            'provider_smoke_summary',
            'turn_state_committed',
            'structured_execution_error',
            'stop_confirmed',
            'stop_not_confirmed',
            'restart_recovery_pending',
            'turn_queued',
            'queue_position_changed',
            'turn_dequeued',
            'turn_queue_cancelled',
            'turn_queue_expired',
            'turn_queue_validation_failed',
            'store_opened'
        )),
    session_id TEXT REFERENCES sessions(session_id) ON DELETE SET NULL,
    turn_id TEXT REFERENCES turns(turn_id) ON DELETE SET NULL,
    session_state_revision TEXT,
    turn_state_revision TEXT,
    queue_status_json TEXT,
    redacted INTEGER NOT NULL DEFAULT 1 CHECK (redacted = 1),
    CHECK (
        (
            event_kind = 'store_opened'
            AND session_id IS NULL
            AND turn_id IS NULL
            AND session_state_revision IS NULL
            AND turn_state_revision IS NULL
            AND queue_status_json IS NULL
        )
        OR (
            event_kind IN (
                'turn_queued',
                'queue_position_changed',
                'turn_dequeued',
                'turn_queue_cancelled',
                'turn_queue_expired',
                'turn_queue_validation_failed'
            )
            AND session_state_revision IS NULL
            AND turn_state_revision IS NULL
            AND queue_status_json IS NOT NULL
            AND (turn_id IS NULL OR session_id IS NOT NULL)
        )
        OR (
            event_kind NOT IN (
                'store_opened',
                'turn_queued',
                'queue_position_changed',
                'turn_dequeued',
                'turn_queue_cancelled',
                'turn_queue_expired',
                'turn_queue_validation_failed'
            )
            AND session_id IS NOT NULL
            AND turn_id IS NOT NULL
            AND session_state_revision IS NOT NULL
            AND turn_state_revision IS NOT NULL
            AND queue_status_json IS NULL
        )
    )
) STRICT;

INSERT INTO logs (
    log_cursor,
    recorded_at,
    recorded_at_unix_nanos,
    source,
    severity,
    event_kind,
    session_id,
    turn_id,
    session_state_revision,
    turn_state_revision,
    queue_status_json,
    redacted
)
SELECT
    log_cursor,
    recorded_at,
    recorded_at_unix_nanos,
    source,
    severity,
    event_kind,
    session_id,
    turn_id,
    session_state_revision,
    turn_state_revision,
    NULL,
    redacted
FROM logs_v22
ORDER BY log_cursor;

DROP TABLE logs_v22;

CREATE INDEX logs_by_cursor
    ON logs(log_cursor);

CREATE INDEX logs_by_session_cursor
    ON logs(session_id, log_cursor);

CREATE INDEX logs_by_recorded_at_cursor
    ON logs(recorded_at_unix_nanos, log_cursor);
