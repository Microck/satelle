CREATE TABLE client_certificate_audit (
    sequence INTEGER PRIMARY KEY,
    request_id TEXT NOT NULL,
    principal_ref TEXT NOT NULL,
    token_id TEXT NOT NULL,
    credential_revision INTEGER NOT NULL CHECK (credential_revision > 0),
    scopes INTEGER NOT NULL CHECK (scopes BETWEEN 1 AND 15),
    certificate_sha256 BLOB NOT NULL CHECK (length(certificate_sha256) = 32),
    recorded_at_unix_nanos INTEGER NOT NULL
) STRICT;

CREATE INDEX client_certificate_audit_retention ON client_certificate_audit(recorded_at_unix_nanos);
