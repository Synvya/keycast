-- Fresh confirmations for the buyer team routes that change members or roles.
-- Design: store-api-contract.md §14 in the Synvya docs repo (BSP-14, BSP-15).
--
-- A route that needs one answers 428 and mails the acting member a link. The member opens the
-- link (confirmed_at), and the app sends the same request again with the confirmation id
-- (spent_at). Each row is bound to one request by a SHA-256 of its method, path and body,
-- expires 10 minutes after it is made, and is used once. Only the token's SHA-256 is kept.
CREATE TABLE fresh_confirmations (
    id            CHAR(32) PRIMARY KEY,          -- the confirmation id, 16 random bytes in hex
    tenant_id     BIGINT NOT NULL,
    member_pubkey CHAR(64) NOT NULL,             -- the member who acts and who must confirm
    action        VARCHAR(40) NOT NULL,          -- team_invite, team_role, team_remove
    digest        CHAR(64) NOT NULL,             -- SHA-256 of METHOD \n path \n body
    token_hash    CHAR(64) NOT NULL UNIQUE,      -- SHA-256 of the 32-byte token in the link
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ NOT NULL,
    confirmed_at  TIMESTAMPTZ,                   -- the member opened the link
    spent_at      TIMESTAMPTZ                    -- the bound request ran
);
CREATE INDEX idx_fresh_confirmations_expires ON fresh_confirmations (expires_at);
