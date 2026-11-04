-- The merchant each orders app sells for, so an app cannot ask for another merchant at sign-in.
-- No default: this fails if a row exists, because a row needs its real merchant. The table is
-- empty everywhere (customer accounts are off until the customer hostname is set); delete a
-- test row and add it again.
ALTER TABLE customer_app_origins ADD COLUMN merchant_pubkey CHAR(64) NOT NULL;
