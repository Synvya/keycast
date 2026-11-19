-- The id of the event a team key signed, on the signing log, so support can name the member
-- behind one message. Design: buyer-team-keys.md §5.7 and store-api-contract.md §12.8 in the
-- Synvya docs repo. Null for an encryption, and for rows written before this column.
ALTER TABLE team_signing_activity ADD COLUMN event_id CHAR(64);
CREATE INDEX idx_team_signing_activity_event ON team_signing_activity (event_id) WHERE event_id IS NOT NULL;
