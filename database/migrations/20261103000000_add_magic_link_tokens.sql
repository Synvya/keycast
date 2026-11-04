-- Sign-in links for passwordless customer accounts. Only the token's hash is stored.
CREATE TABLE magic_link_tokens (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     BIGINT NOT NULL,
    email         VARCHAR(255) NOT NULL,      -- normalized: trim + lowercase
    token_hash    CHAR(64) NOT NULL UNIQUE,   -- sha256 of the token, hex
    purpose       VARCHAR(20) NOT NULL DEFAULT 'sign_in',
    app_origin    TEXT NOT NULL,              -- the page the link lands on
    expires_at    TIMESTAMPTZ NOT NULL,       -- created_at + 15 minutes
    consumed_at   TIMESTAMPTZ,
    request_ip    INET,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_magic_link_purpose CHECK (purpose IN ('sign_in', 'delete_account'))
);
CREATE INDEX idx_magic_link_tokens_email ON magic_link_tokens (tenant_id, email, created_at);
