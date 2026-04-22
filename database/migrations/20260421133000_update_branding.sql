-- ABOUTME: Rebrands the default tenant from diVine to Synvya
-- ABOUTME: This is the correct way to update branding without breaking migration checksums

UPDATE tenants SET name = 'Synvya' WHERE id = 1;

-- If there are other system-wide display names in the DB, update them here too.
-- For example, if we have any admin-created OAuth clients representing the server itself.
UPDATE oauth_authorizations SET client_id = 'Synvya' WHERE client_id = 'diVine';
