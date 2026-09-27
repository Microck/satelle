ALTER TABLE api_tokens
ADD COLUMN desktop_bindings_json TEXT NOT NULL DEFAULT '[]'
    CHECK (
        json_valid(desktop_bindings_json)
        AND json_type(desktop_bindings_json) = 'array'
    );

ALTER TABLE logs ADD COLUMN desktop_binding_ref TEXT;

CREATE INDEX logs_by_desktop_binding_cursor
    ON logs(desktop_binding_ref, log_cursor);

ALTER TABLE turn_admission_queue
ADD COLUMN desktop_binding_ref TEXT
    CHECK (
        desktop_binding_ref IS NULL
        OR length(trim(desktop_binding_ref)) > 0
    );

-- Provider authorization belongs to one Desktop Binding. Old unscoped
-- authorizations cannot be assigned safely, so the hard-cut schema discards
-- them and requires fresh authorization.
DROP TABLE authorized_provider_bindings;

CREATE TABLE authorized_provider_bindings (
    desktop_binding_ref TEXT NOT NULL CHECK (length(trim(desktop_binding_ref)) > 0),
    provider_alias TEXT NOT NULL CHECK (length(trim(provider_alias)) > 0),
    model_alias TEXT NOT NULL CHECK (length(trim(model_alias)) > 0),
    model TEXT NOT NULL CHECK (length(trim(model)) > 0),
    model_provider TEXT NOT NULL CHECK (length(trim(model_provider)) > 0),
    endpoint TEXT,
    auth_source_json TEXT,
    source TEXT NOT NULL CHECK (source = 'user_config'),
    experimental_provider_computer_use INTEGER NOT NULL
        CHECK (experimental_provider_computer_use IN (0, 1)),
    allow_project_selection INTEGER NOT NULL
        CHECK (allow_project_selection IN (0, 1)),
    binding_digest TEXT NOT NULL
        CHECK (
            length(binding_digest) = 64
            AND binding_digest NOT GLOB '*[^0-9a-f]*'
        ),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (desktop_binding_ref, provider_alias, model_alias)
) STRICT;
