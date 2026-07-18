ALTER TABLE api_tokens
ADD COLUMN token_state TEXT NOT NULL DEFAULT 'active'
    CHECK (token_state IN ('active', 'setup_pending', 'setup_active'));
