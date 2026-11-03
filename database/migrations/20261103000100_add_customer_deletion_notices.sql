-- Customer accounts deleted here, waiting to be acknowledged by Synvya Server, which then
-- cancels their subscriptions and removes their saved card. A row goes once acknowledged.
CREATE TABLE customer_deletion_notices (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL,
    pubkey          CHAR(64) NOT NULL,
    deleted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attempts        INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_customer_deletion_notices_next_attempt ON customer_deletion_notices (next_attempt_at);
