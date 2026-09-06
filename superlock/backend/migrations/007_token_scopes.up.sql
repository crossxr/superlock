-- Bind an API token to the role its creator held at creation time.
--
-- Until now a token carried whatever role its creating user has *right now*,
-- read live from the users table on every request. Two consequences: promoting
-- a user silently upgraded every token they had ever created, and demoting one
-- did nothing to tokens already issued.
--
-- The effective role of a request is now the lower of this snapshot and the
-- user's current role, so a promotion cannot leak backwards into old tokens and
-- a demotion takes effect immediately.

ALTER TABLE api_tokens
    ADD COLUMN role TEXT NOT NULL DEFAULT 'reader'
        CHECK (role IN ('owner', 'admin', 'developer', 'reader'));

-- Existing tokens keep working: snapshot each creator's current role. This is
-- the same authority they have today, so the migration is not a privilege
-- change for anyone.
UPDATE api_tokens t
SET role = u.role
FROM users u
WHERE u.id = t.user_id;
