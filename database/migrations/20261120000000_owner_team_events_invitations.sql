-- The owner team change log also holds a team's invitations: `invited` when an invitation to a
-- new email is made, and `invitation_withdrawn` when an admin withdraws one. An invitation has no
-- member key yet, so the key may be null and the row names the invited email instead.
-- Design: account-activity.md §3 and stores-onboarding.md §13.3 in the Synvya docs repo.
ALTER TABLE owner_team_events ALTER COLUMN member_pubkey DROP NOT NULL;  -- null on an invitation
ALTER TABLE owner_team_events ADD COLUMN member_email TEXT;               -- the invited email, or the member's
