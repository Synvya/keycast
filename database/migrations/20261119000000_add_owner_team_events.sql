-- The team change log of an owner tenant: one row per member change of a team, beside
-- customer_team_events, which holds the same for the customer tenant's buyer teams.
-- Design: account-activity.md §3 and AA-7 in the Synvya docs repo.
--
-- Append-only. Synvya Server reads it in id order through GET /api/admin/owner-team-events and
-- writes the store part's staff.* records for each team key that is a store.
CREATE TABLE owner_team_events (
    id               BIGSERIAL PRIMARY KEY,
    tenant_id        BIGINT NOT NULL,
    team_id          INTEGER NOT NULL,              -- no foreign key: the log outlives the team
    team_key_pubkeys TEXT[] NOT NULL DEFAULT '{}',  -- the team's stored keys when the change was made
    action           VARCHAR(20) NOT NULL,          -- added, joined, removed
    member_pubkey    CHAR(64) NOT NULL,
    role             VARCHAR(20),                   -- the role added or joined with, or held when removed
    actor_pubkey     CHAR(64),                      -- who made the change
    by_support       BOOLEAN NOT NULL DEFAULT FALSE, -- a Synvya support admin's access grant or release
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_owner_team_events_tenant ON owner_team_events (tenant_id, id);
