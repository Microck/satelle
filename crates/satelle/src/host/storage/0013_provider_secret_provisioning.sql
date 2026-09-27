CREATE TABLE idempotency_records_v13 (
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
        'provider_secret_provisioning',
        'provider_descriptor_validation',
        'provider_binding_authorization',
        'provider_binding_deletion',
        'setup_verification',
        'native_readiness_invalidation'
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
        'v1.provider_secret_provisioning.pending',
        'v1.provider_secret_provisioning.completed',
        'v1.provider_secret_provisioning.failed',
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
        'v1.provider_binding_deletion.failed',
        'v1.setup_verification.pending',
        'v1.setup_verification.completed',
        'v1.setup_verification.failed',
        'v1.native_readiness_invalidation.completed',
        'v1.native_readiness_invalidation.failed'
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
            'provider_secret_provisioning',
            'provider_descriptor_validation',
            'provider_binding_authorization',
            'provider_binding_deletion',
            'setup_verification',
            'native_readiness_invalidation'
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
            operation = 'provider_secret_provisioning'
            AND session_id IS NULL
            AND turn_id IS NULL
            AND result_session_state_revision IS NULL
            AND result_session_updated_at IS NULL
            AND (
                (
                    status = 'in_progress'
                    AND durable_outcome = 'v1.provider_secret_provisioning.pending'
                    AND result_json IS NULL
                )
                OR (
                    status = 'terminal'
                    AND durable_outcome IN (
                        'v1.provider_secret_provisioning.completed',
                        'v1.provider_secret_provisioning.failed'
                    )
                    AND result_json IS NOT NULL
                )
            )
        )
        OR (
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
            operation = 'setup_verification'
            AND session_id IS NULL
            AND turn_id IS NULL
            AND result_session_state_revision IS NULL
            AND result_session_updated_at IS NULL
            AND (
                (
                    status = 'in_progress'
                    AND durable_outcome = 'v1.setup_verification.pending'
                    AND result_json IS NULL
                )
                OR (
                    status = 'terminal'
                    AND durable_outcome IN (
                        'v1.setup_verification.completed',
                        'v1.setup_verification.failed'
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
            operation = 'native_readiness_invalidation'
            AND status = 'terminal'
            AND durable_outcome IN (
                'v1.native_readiness_invalidation.completed',
                'v1.native_readiness_invalidation.failed'
            )
            AND session_id IS NULL
            AND turn_id IS NULL
            AND result_session_state_revision IS NULL
            AND result_session_updated_at IS NULL
            AND result_json IS NOT NULL
        )
        OR (
            operation NOT IN (
                'provider_secret_provisioning',
                'provider_descriptor_validation',
                'provider_binding_authorization',
                'provider_binding_deletion',
                'setup_verification',
                'native_readiness_invalidation'
            )
            AND result_json IS NULL
        )
    )
) STRICT;

INSERT INTO idempotency_records_v13 (
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
    result_json,
    created_at,
    completed_at,
    expires_at
FROM idempotency_records;

DROP TABLE idempotency_records;
ALTER TABLE idempotency_records_v13 RENAME TO idempotency_records;

CREATE INDEX idempotency_expiry
    ON idempotency_records(expires_at);

CREATE UNIQUE INDEX idempotency_operation_identity
    ON idempotency_records(operation_id, operation);

CREATE TABLE provider_secret_provisioning_journal (
    operation_id TEXT PRIMARY KEY,
    operation TEXT NOT NULL DEFAULT 'provider_secret_provisioning'
        CHECK (operation = 'provider_secret_provisioning'),
    host_identity_ref TEXT NOT NULL
        REFERENCES daemon_identity(host_identity_ref) ON DELETE RESTRICT,
    desktop_binding_ref TEXT NOT NULL
        CHECK (length(trim(desktop_binding_ref)) > 0),
    provider_probe_ref TEXT NOT NULL UNIQUE
        CHECK (length(trim(provider_probe_ref)) > 0),
    requested_model_alias TEXT NOT NULL
        CHECK (length(trim(requested_model_alias)) > 0),
    requested_provider_alias TEXT NOT NULL
        CHECK (length(trim(requested_provider_alias)) > 0),
    model TEXT NOT NULL CHECK (length(trim(model)) > 0),
    model_provider TEXT NOT NULL CHECK (length(trim(model_provider)) > 0),
    endpoint TEXT,
    auth_source_json TEXT NOT NULL
        CHECK (
            json_valid(auth_source_json)
            AND json_extract(auth_source_json, '$.kind') = 'file'
            AND json_type(auth_source_json, '$.path') = 'text'
            AND length(trim(json_extract(auth_source_json, '$.path'))) > 0
        ),
    experimental_provider_computer_use INTEGER NOT NULL
        CHECK (experimental_provider_computer_use IN (0, 1)),
    allow_project_selection INTEGER NOT NULL
        CHECK (allow_project_selection IN (0, 1)),
    destination_path TEXT NOT NULL UNIQUE
        CHECK (length(trim(destination_path)) > 0),
    staged_path TEXT NOT NULL UNIQUE
        CHECK (length(trim(staged_path)) > 0),
    backup_path TEXT UNIQUE
        CHECK (backup_path IS NULL OR length(trim(backup_path)) > 0),
    destination_existed INTEGER
        CHECK (destination_existed IS NULL OR destination_existed IN (0, 1)),
    expected_previous_binding_digest TEXT
        CHECK (
            expected_previous_binding_digest IS NULL
            OR (
                length(expected_previous_binding_digest) = 64
                AND expected_previous_binding_digest NOT GLOB '*[^0-9a-f]*'
            )
        ),
    candidate_binding_digest TEXT NOT NULL
        CHECK (
            length(candidate_binding_digest) = 64
            AND candidate_binding_digest NOT GLOB '*[^0-9a-f]*'
        ),
    candidate_secret_hmac TEXT NOT NULL
        CHECK (
            length(candidate_secret_hmac) = 64
            AND candidate_secret_hmac NOT GLOB '*[^0-9a-f]*'
        ),
    prior_secret_hmac TEXT
        CHECK (
            prior_secret_hmac IS NULL
            OR (
                length(prior_secret_hmac) = 64
                AND prior_secret_hmac NOT GLOB '*[^0-9a-f]*'
            )
        ),
    phase TEXT NOT NULL
        CHECK (phase IN (
            'planned',
            'staged',
            'validated',
            'publish_intent',
            'committed',
            'rollback_pending'
        )),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (operation_id, operation)
        REFERENCES idempotency_records(operation_id, operation)
        ON DELETE CASCADE,
    CHECK (destination_path <> staged_path),
    CHECK (backup_path IS NULL OR destination_path <> backup_path),
    CHECK (backup_path IS NULL OR staged_path <> backup_path),
    CHECK (
        (
            phase = 'planned'
            AND destination_existed IS NULL
            AND backup_path IS NULL
            AND prior_secret_hmac IS NULL
        )
        OR (
            phase <> 'planned'
            AND (
                (
                    destination_existed = 1
                    AND backup_path IS NOT NULL
                    AND prior_secret_hmac IS NOT NULL
                )
                OR (
                    destination_existed = 0
                    AND backup_path IS NULL
                    AND prior_secret_hmac IS NULL
                )
            )
        )
    )
) STRICT;
