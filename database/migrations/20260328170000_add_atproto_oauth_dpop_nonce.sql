ALTER TABLE atproto_oauth_sessions
    ADD COLUMN IF NOT EXISTS dpop_nonce TEXT;
