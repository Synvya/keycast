-- The merchants each approved origin sells for. One origin can sell for many merchants (Synvya's
-- multi-store site), so a grant is checked against this list, not against a column on the origin.
-- customer_app_origins.merchant_name stays: it is now the origin's own name, used in the email.

-- Lets the list name its origin and tenant together, so a list row cannot sit in another tenant.
ALTER TABLE customer_app_origins ADD CONSTRAINT customer_app_origins_id_tenant_key
    UNIQUE (id, tenant_id);

CREATE TABLE customer_app_origin_merchants (
    id              BIGSERIAL PRIMARY KEY,
    origin_id       BIGINT NOT NULL,
    tenant_id       BIGINT NOT NULL,
    merchant_pubkey CHAR(64) NOT NULL,        -- hex
    merchant_name   TEXT NOT NULL,            -- what a customer knows this merchant by
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (origin_id, merchant_pubkey),
    FOREIGN KEY (origin_id, tenant_id)
        REFERENCES customer_app_origins (id, tenant_id) ON DELETE CASCADE
);

-- Every origin approved so far sells for one merchant: it keeps that merchant, with no admin action
INSERT INTO customer_app_origin_merchants (origin_id, tenant_id, merchant_pubkey, merchant_name, created_at)
SELECT id, tenant_id, merchant_pubkey, merchant_name, created_at FROM customer_app_origins;

-- The list is the only record of an origin's merchants
ALTER TABLE customer_app_origins DROP COLUMN merchant_pubkey;
