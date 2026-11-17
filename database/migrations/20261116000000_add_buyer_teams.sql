-- Buyer teams in the customer tenant: a team, its own key, and members who order as the team.
-- Design: docs/02-auth-and-identity/architecture/buyer-team-keys.md in the Synvya docs repo.

-- The buyer roles. 'admin' and 'member' stay valid for the owner tenant's teams. The routes
-- decide which roles a tenant may use; the database accepts all four.
ALTER TABLE team_users DROP CONSTRAINT team_users_role_check;
ALTER TABLE team_users ADD CONSTRAINT team_users_role_check
    CHECK (role IN ('admin', 'member', 'orderer', 'viewer'));

ALTER TABLE team_invitations DROP CONSTRAINT chk_invitation_role;
ALTER TABLE team_invitations ADD CONSTRAINT chk_invitation_role
    CHECK (role IN ('admin', 'member', 'orderer', 'viewer'));

-- The member a grant on a team key belongs to. NULL for every other authorization (restaurant
-- staff, support access). Removing the member revokes the rows that name them.
ALTER TABLE authorizations ADD COLUMN member_pubkey CHAR(64);
CREATE INDEX idx_authorizations_member
    ON authorizations (stored_key_id, member_pubkey)
    WHERE member_pubkey IS NOT NULL AND revoked_at IS NULL;

-- Each signature and encryption made with a team key under a member's grant. The authorization
-- names the member; the member is copied here so the row outlives a deleted authorization.
CREATE TABLE team_signing_activity (
    id               BIGSERIAL PRIMARY KEY,
    tenant_id        BIGINT NOT NULL,
    authorization_id INT NOT NULL,
    stored_key_id    INT NOT NULL,
    member_pubkey    CHAR(64) NOT NULL,
    method           VARCHAR(20) NOT NULL,   -- sign_event, nip44_encrypt, nip04_encrypt
    event_kind       INT,                    -- the signed event's kind, or the encrypted event's
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_team_signing_activity_key ON team_signing_activity (stored_key_id, created_at);
CREATE INDEX idx_team_signing_activity_member ON team_signing_activity (member_pubkey, created_at);
