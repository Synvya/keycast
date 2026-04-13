-- Team invitations for email-based team member onboarding
CREATE TABLE team_invitations (
    id              SERIAL PRIMARY KEY,
    team_id         INT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    tenant_id       BIGINT NOT NULL,
    email           VARCHAR(255) NOT NULL,
    role            VARCHAR(20) NOT NULL DEFAULT 'member',
    token           VARCHAR(64) NOT NULL UNIQUE,
    invited_by      VARCHAR(64) NOT NULL,   -- hex pubkey of the admin who sent the invite
    expires_at      TIMESTAMPTZ NOT NULL,
    accepted_at     TIMESTAMPTZ,
    accepted_by     VARCHAR(64),            -- hex pubkey of the user who accepted
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_invitation_role CHECK (role IN ('admin', 'member'))
);

-- Fast token lookup
CREATE INDEX idx_team_invitations_token ON team_invitations(token);

-- List invitations for a team
CREATE INDEX idx_team_invitations_team ON team_invitations(team_id);

-- Prevent duplicate pending invitations for the same email on the same team
CREATE UNIQUE INDEX uq_pending_invite
    ON team_invitations(team_id, email)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;
