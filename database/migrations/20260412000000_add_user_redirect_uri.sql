-- Add redirect_uri to users table for post-verification redirect
-- When a client app registers a user, it can specify where to redirect after email verification
ALTER TABLE users ADD COLUMN redirect_uri TEXT;
