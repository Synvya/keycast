-- Migration: Preloaded Accounts & Claim Links
-- Enables Vine user import by creating accounts without email/password
-- that users can later claim via secure links.

-- Add display_name and vine_id to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS vine_id TEXT;

-- Unique index on vine_id per tenant (only for non-null values)
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_vine_id_tenant
    ON users(tenant_id, vine_id)
    WHERE vine_id IS NOT NULL;

-- Account claim tokens table
-- Used to generate secure links for users to claim their preloaded accounts
CREATE TABLE IF NOT EXISTS account_claim_tokens (
    id SERIAL PRIMARY KEY,
    token TEXT NOT NULL UNIQUE,
    user_pubkey CHAR(64) NOT NULL REFERENCES users(pubkey),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by_pubkey CHAR(64),
    tenant_id BIGINT DEFAULT 1 NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_claim_tokens_token ON account_claim_tokens(token);
CREATE INDEX IF NOT EXISTS idx_claim_tokens_user ON account_claim_tokens(user_pubkey);
CREATE INDEX IF NOT EXISTS idx_claim_tokens_tenant ON account_claim_tokens(tenant_id);
