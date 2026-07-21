CREATE TABLE admission_cancellations (
    principal_ref TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('run', 'steer')),
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL
        CHECK (
            length(request_digest) = 64
            AND request_digest NOT GLOB '*[^0-9a-f]*'
        ),
    digest_schema_version INTEGER NOT NULL CHECK (digest_schema_version > 0),
    hmac_key_version INTEGER NOT NULL
        REFERENCES idempotency_hmac_keys(key_version) ON DELETE RESTRICT,
    outcome TEXT NOT NULL CHECK (outcome IN ('cancelled', 'recovery_pending')),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (principal_ref, operation, idempotency_key)
) STRICT;

CREATE INDEX admission_cancellations_by_expiry
    ON admission_cancellations(expires_at);
