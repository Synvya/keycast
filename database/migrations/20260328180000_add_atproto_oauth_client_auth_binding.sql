ALTER TABLE atproto_oauth_sessions
    ADD COLUMN IF NOT EXISTS client_auth_method TEXT NOT NULL DEFAULT 'none';

ALTER TABLE atproto_oauth_sessions
    ADD COLUMN IF NOT EXISTS client_auth_jkt TEXT;
