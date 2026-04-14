-- Add soft-delete columns to team authorizations.
-- Mirrors oauth_authorizations.revoked_at so the signer daemon can skip stale
-- team authorizations (e.g. duplicate "Synvya Client (staging)" rows) without
-- hard-deleting and losing forensic history.

ALTER TABLE authorizations
    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS revoked_reason TEXT;

-- Partial index to speed up the "active authorizations" lookup used by the
-- signer daemon and repository methods.
CREATE INDEX IF NOT EXISTS idx_authorizations_active
    ON authorizations (tenant_id, bunker_public_key)
    WHERE revoked_at IS NULL;
