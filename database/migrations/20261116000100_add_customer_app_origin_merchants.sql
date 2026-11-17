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

-- No origin has been approved anywhere yet, so there is no merchant to carry over. Refuse to run
-- rather than drop a binding: an approved origin here means this assumption is wrong.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM customer_app_origins) THEN
        RAISE EXCEPTION 'customer_app_origins is not empty: add its merchants to customer_app_origin_merchants before dropping merchant_pubkey';
    END IF;
END
$$;

-- The list is the only record of an origin's merchants
ALTER TABLE customer_app_origins DROP COLUMN merchant_pubkey;
