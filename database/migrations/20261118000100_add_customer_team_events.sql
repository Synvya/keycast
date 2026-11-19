-- The team change log of the customer tenant: one row per member change of a buyer team.
-- Design: account-activity.md AA-7 and store-api-contract.md §12.8 in the Synvya docs repo.
--
-- Append-only. Synvya Server reads it in id order through GET /api/admin/customer-team-events
-- and writes the account activity records member.invited, member.joined, member.role_set and
-- member.removed from it.
CREATE TABLE customer_team_events (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     BIGINT NOT NULL,
    team_pubkey   CHAR(64) NOT NULL,             -- the team key: the buyer account's id
    action        VARCHAR(20) NOT NULL,          -- invited, joined, role_set, removed
    member_email  TEXT,                          -- the invited email, or the member's
    member_pubkey CHAR(64),                      -- null on an invitation
    role          VARCHAR(20),                   -- the role invited with, joined with, or set
    actor_pubkey  CHAR(64),                      -- who made the change; null for an admin route
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_customer_team_events_team ON customer_team_events (team_pubkey, id);
