-- Drop unused key export tables (email-code flow was never used in production)
-- The password-only export endpoint (/user/export-key) remains functional

DROP TABLE IF EXISTS key_export_codes CASCADE;
DROP TABLE IF EXISTS key_export_tokens CASCADE;
DROP TABLE IF EXISTS key_export_log CASCADE;
