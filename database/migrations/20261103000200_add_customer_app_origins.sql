-- The merchants' orders apps allowed to use the customer tenant. A row here is all it takes
-- to add a merchant: read at request time, so no deploy is needed.
CREATE TABLE customer_app_origins (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     BIGINT NOT NULL,
    origin        TEXT NOT NULL,              -- e.g. https://orders.example.com
    merchant_name TEXT NOT NULL,              -- what a customer knows the merchant by
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, origin)
);
