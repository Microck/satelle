ALTER TABLE logs RENAME TO logs_v15;

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
            'store_opened'
        )),
    session_id TEXT REFERENCES sessions(session_id) ON DELETE SET NULL,
    turn_id TEXT REFERENCES turns(turn_id) ON DELETE SET NULL,
    session_state_revision TEXT,
    turn_state_revision TEXT,
    redacted INTEGER NOT NULL DEFAULT 1 CHECK (redacted = 1),
    CHECK (
        (
            event_kind = 'store_opened'
            AND session_id IS NULL
            AND turn_id IS NULL
            AND session_state_revision IS NULL
            AND turn_state_revision IS NULL
        )
        OR (
            event_kind != 'store_opened'
            AND session_id IS NOT NULL
            AND turn_id IS NOT NULL
            AND session_state_revision IS NOT NULL
            AND turn_state_revision IS NOT NULL
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
    redacted
FROM logs_v15
ORDER BY log_cursor;

DROP TABLE logs_v15;

CREATE INDEX logs_by_cursor
    ON logs(log_cursor);

CREATE INDEX logs_by_session_cursor
    ON logs(session_id, log_cursor);

CREATE INDEX logs_by_recorded_at_cursor
    ON logs(recorded_at_unix_nanos, log_cursor);
