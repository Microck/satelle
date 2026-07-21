ALTER TABLE sessions ADD COLUMN display_name TEXT;

ALTER TABLE session_private_refs ADD COLUMN upstream_goal_ref TEXT;

CREATE UNIQUE INDEX one_session_per_upstream_goal_ref
    ON session_private_refs(upstream_goal_ref)
    WHERE upstream_goal_ref IS NOT NULL;
