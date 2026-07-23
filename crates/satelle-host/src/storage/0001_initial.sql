CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    session_state_revision TEXT NOT NULL
        CHECK (
            length(session_state_revision) = 16
            AND session_state_revision NOT GLOB '*[^0-9a-f]*'
            AND session_state_revision <> '0000000000000000'
        ),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE daemon_identity (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    host_identity_ref TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE api_tokens (
    token_id TEXT PRIMARY KEY,
    principal_ref TEXT NOT NULL,
    credential_revision INTEGER NOT NULL CHECK (credential_revision > 0),
    verifier BLOB NOT NULL UNIQUE CHECK (length(verifier) = 32),
    scopes INTEGER NOT NULL CHECK (scopes BETWEEN 1 AND 15),
    created_at TEXT NOT NULL,
    credential_updated_at TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT
) STRICT;

CREATE TABLE idempotency_hmac_keys (
    key_version INTEGER PRIMARY KEY CHECK (key_version > 0),
    key_material BLOB NOT NULL CHECK (length(key_material) = 32),
    created_at TEXT NOT NULL,
    retired_at TEXT,
    CHECK (retired_at IS NULL OR retired_at >= created_at)
) STRICT;

CREATE UNIQUE INDEX one_active_idempotency_hmac_key
    ON idempotency_hmac_keys((retired_at IS NULL))
    WHERE retired_at IS NULL;

CREATE TABLE session_private_refs (
    session_id TEXT PRIMARY KEY
        REFERENCES sessions(session_id) ON DELETE CASCADE,
    host_identity_ref TEXT NOT NULL
        REFERENCES daemon_identity(host_identity_ref) ON DELETE RESTRICT,
    desktop_binding_ref TEXT NOT NULL,
    upstream_thread_ref TEXT UNIQUE
) STRICT;

CREATE TABLE turns (
    turn_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL
        REFERENCES sessions(session_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    turn_state_revision TEXT NOT NULL
        CHECK (
            length(turn_state_revision) = 16
            AND turn_state_revision NOT GLOB '*[^0-9a-f]*'
            AND turn_state_revision <> '0000000000000000'
        ),
    state TEXT NOT NULL
        CHECK (state IN (
            'starting',
            'running',
            'recovery_pending',
            'completed',
            'blocked',
            'failed',
            'stopped'
        )),
    started_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    terminal_at TEXT,
    safe_summary TEXT
        CHECK (safe_summary IS NULL OR safe_summary IN (
            'task_completed',
            'blocked_by_policy',
            'execution_failed',
            'daemon_restart_recovery_failed'
        )),
    UNIQUE (session_id, ordinal),
    UNIQUE (session_id, turn_id),
    CHECK (
        (state IN ('starting', 'running', 'recovery_pending')
            AND terminal_at IS NULL
            AND safe_summary IS NULL)
        OR (state = 'completed'
            AND terminal_at IS NOT NULL
            AND safe_summary = 'task_completed')
        OR (state = 'blocked'
            AND terminal_at IS NOT NULL
            AND safe_summary = 'blocked_by_policy')
        OR (state = 'failed'
            AND terminal_at IS NOT NULL
            AND safe_summary IN (
                'execution_failed',
                'daemon_restart_recovery_failed'
            ))
        OR (state = 'stopped'
            AND terminal_at IS NOT NULL
            AND safe_summary IS NULL)
    )
) STRICT;

CREATE UNIQUE INDEX one_active_turn_per_session
    ON turns(session_id)
    WHERE state IN ('starting', 'running', 'recovery_pending');

CREATE INDEX turns_by_session_ordinal
    ON turns(session_id, ordinal);

CREATE TABLE turn_private_refs (
    turn_id TEXT PRIMARY KEY
        REFERENCES turns(turn_id) ON DELETE CASCADE,
    request_token TEXT NOT NULL UNIQUE,
    upstream_turn_ref TEXT UNIQUE
) STRICT;

CREATE TABLE turn_policies (
    turn_id TEXT PRIMARY KEY
        REFERENCES turns(turn_id) ON DELETE CASCADE,
    effective_model_ref TEXT NOT NULL,
    provider_binding_ref TEXT NOT NULL,
    desktop_binding_ref TEXT NOT NULL,
    desktop_session_id TEXT NOT NULL,
    approval_policy TEXT NOT NULL
        CHECK (approval_policy IN ('untrusted', 'on_failure', 'on_request', 'never')),
    sandbox_policy TEXT NOT NULL
        CHECK (sandbox_policy IN ('read_only', 'workspace_write', 'danger_full_access')),
    timeout_seconds INTEGER NOT NULL CHECK (timeout_seconds > 0),
    computer_use_enabled INTEGER NOT NULL CHECK (computer_use_enabled IN (0, 1)),
    provider_computer_use_enabled INTEGER NOT NULL
        CHECK (provider_computer_use_enabled IN (0, 1))
) STRICT;

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
    session_id TEXT NOT NULL,
    turn_id TEXT NOT NULL UNIQUE,
    PRIMARY KEY (host_identity_ref, desktop_binding_ref),
    FOREIGN KEY (session_id, turn_id)
        REFERENCES turns(session_id, turn_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE maintenance_leases (
    host_identity_ref TEXT PRIMARY KEY
        REFERENCES daemon_identity(host_identity_ref) ON DELETE RESTRICT,
    operation_id TEXT NOT NULL UNIQUE,
    owner_process_id INTEGER NOT NULL CHECK (owner_process_id > 0),
    owner_process_start_ref TEXT NOT NULL,
    owner_boot_identity_ref TEXT NOT NULL,
    acquired_at TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL,
    lease_state TEXT NOT NULL
        CHECK (lease_state IN ('active', 'recovery_pending'))
) STRICT;

CREATE TABLE idempotency_records (
    principal_ref TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('run', 'steer', 'stop')),
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

CREATE INDEX idempotency_expiry
    ON idempotency_records(expires_at);

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
            'turn_state_committed',
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

CREATE INDEX logs_by_cursor
    ON logs(log_cursor);

CREATE INDEX logs_by_session_cursor
    ON logs(session_id, log_cursor);

CREATE INDEX logs_by_recorded_at_cursor
    ON logs(recorded_at_unix_nanos, log_cursor);

CREATE TABLE log_retention_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    expired_through_cursor INTEGER NOT NULL CHECK (expired_through_cursor >= 0)
) STRICT;

INSERT INTO log_retention_state (singleton, expired_through_cursor)
VALUES (1, 0);
