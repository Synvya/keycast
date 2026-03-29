CREATE TABLE atproto_oauth_sessions (
    id SERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id),
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    state TEXT,
    code_challenge TEXT,
    code_challenge_method TEXT,
    request_uri TEXT NOT NULL UNIQUE,
    par_expires_at TIMESTAMPTZ NOT NULL,
    user_pubkey TEXT REFERENCES users(pubkey) ON DELETE CASCADE,
    atproto_did TEXT,
    approved_at TIMESTAMPTZ,
    authorization_code TEXT UNIQUE,
    authorization_code_expires_at TIMESTAMPTZ,
    access_token_jti TEXT UNIQUE,
    access_token_expires_at TIMESTAMPTZ,
    refresh_token_hash TEXT UNIQUE,
    refresh_token_expires_at TIMESTAMPTZ,
    refresh_token_revoked_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    dpop_jkt TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_atproto_oauth_sessions_tenant_id
    ON atproto_oauth_sessions (tenant_id);

CREATE INDEX idx_atproto_oauth_sessions_user_pubkey
    ON atproto_oauth_sessions (user_pubkey);

CREATE INDEX idx_atproto_oauth_sessions_request_uri
    ON atproto_oauth_sessions (request_uri);

CREATE INDEX idx_atproto_oauth_sessions_authorization_code
    ON atproto_oauth_sessions (authorization_code)
    WHERE authorization_code IS NOT NULL;

CREATE INDEX idx_atproto_oauth_sessions_refresh_token_hash
    ON atproto_oauth_sessions (refresh_token_hash)
    WHERE refresh_token_hash IS NOT NULL;

CREATE TRIGGER atproto_oauth_sessions_update_trigger
    BEFORE UPDATE ON atproto_oauth_sessions
    FOR EACH ROW
    EXECUTE FUNCTION public.update_updated_at_column();
