CREATE TABLE idempotency_records_v12 (
    principal_ref TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN (
        'run',
        'steer',
        'stop',
        'setup',
        'repair',
        'host_update',
        'storage_migration',
        'destructive_maintenance',
        'provider_descriptor_validation',
        'provider_binding_authorization',
        'provider_binding_deletion'
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
        'v1.stop.not_confirmed_recovery_pending_unchanged',
        'v2.provider_descriptor_validation.pending',
        'v2.provider_descriptor_validation.completed',
        'v2.provider_descriptor_validation.failed',
        'v1.provider_binding_authorization.completed',
        'v1.provider_binding_authorization.failed',
        'v1.provider_binding_deletion.completed',
        'v1.provider_binding_deletion.failed'
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
    result_json TEXT,
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
        operation IN (
            'stop',
            'provider_descriptor_validation',
            'provider_binding_authorization',
            'provider_binding_deletion'
        )
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
    ),
    CHECK (
        (
            operation = 'provider_descriptor_validation'
            AND session_id IS NULL
            AND turn_id IS NULL
            AND result_session_state_revision IS NULL
            AND result_session_updated_at IS NULL
            AND (
                (
                    status = 'in_progress'
                    AND durable_outcome = 'v2.provider_descriptor_validation.pending'
                    AND result_json IS NULL
                )
                OR (
                    status = 'terminal'
                    AND durable_outcome IN (
                        'v2.provider_descriptor_validation.completed',
                        'v2.provider_descriptor_validation.failed'
                    )
                    AND result_json IS NOT NULL
                )
            )
        )
        OR (
            operation = 'provider_binding_authorization'
            AND status = 'terminal'
            AND durable_outcome IN (
                'v1.provider_binding_authorization.completed',
                'v1.provider_binding_authorization.failed'
            )
            AND session_id IS NULL
            AND turn_id IS NULL
            AND result_session_state_revision IS NULL
            AND result_session_updated_at IS NULL
            AND result_json IS NOT NULL
        )
        OR (
            operation = 'provider_binding_deletion'
            AND status = 'terminal'
            AND durable_outcome IN (
                'v1.provider_binding_deletion.completed',
                'v1.provider_binding_deletion.failed'
            )
            AND session_id IS NULL
            AND turn_id IS NULL
            AND result_session_state_revision IS NULL
            AND result_session_updated_at IS NULL
            AND result_json IS NOT NULL
        )
        OR (
            operation NOT IN (
                'provider_descriptor_validation',
                'provider_binding_authorization',
                'provider_binding_deletion'
            )
            AND result_json IS NULL
        )
    )
) STRICT;

INSERT INTO idempotency_records_v12 (
    principal_ref,
    operation,
    idempotency_key,
    operation_id,
    request_digest,
    digest_schema_version,
    hmac_key_version,
    status,
    durable_outcome,
    session_id,
    turn_id,
    result_session_state_revision,
    result_session_updated_at,
    result_json,
    created_at,
    completed_at,
    expires_at
)
SELECT
    principal_ref,
    operation,
    idempotency_key,
    operation_id,
    request_digest,
    digest_schema_version,
    hmac_key_version,
    status,
    durable_outcome,
    session_id,
    turn_id,
    result_session_state_revision,
    result_session_updated_at,
    NULL,
    created_at,
    completed_at,
    expires_at
FROM idempotency_records;

DROP TABLE idempotency_records;
ALTER TABLE idempotency_records_v12 RENAME TO idempotency_records;

CREATE INDEX idempotency_expiry
    ON idempotency_records(expires_at);

CREATE TABLE authorized_provider_bindings (
    provider_alias TEXT NOT NULL CHECK (length(trim(provider_alias)) > 0),
    model_alias TEXT NOT NULL CHECK (length(trim(model_alias)) > 0),
    model TEXT NOT NULL CHECK (length(trim(model)) > 0),
    model_provider TEXT NOT NULL CHECK (length(trim(model_provider)) > 0),
    endpoint TEXT,
    auth_source_json TEXT,
    source TEXT NOT NULL CHECK (source = 'user_config'),
    experimental_provider_computer_use INTEGER NOT NULL
        CHECK (experimental_provider_computer_use IN (0, 1)),
    binding_digest TEXT NOT NULL
        CHECK (
            length(binding_digest) = 64
            AND binding_digest NOT GLOB '*[^0-9a-f]*'
        ),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (provider_alias, model_alias)
) STRICT;
