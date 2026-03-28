ALTER TABLE atproto_oauth_sessions
    ADD COLUMN IF NOT EXISTS client_auth_alg TEXT;

ALTER TABLE atproto_oauth_sessions
    ADD COLUMN IF NOT EXISTS client_auth_kid TEXT;
