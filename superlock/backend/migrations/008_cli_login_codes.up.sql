-- P0-8: the CLI loopback login used to accept `?token=` from any caller —
-- no state, no PKCE, bound on all interfaces. This table backs the
-- replacement: a one-time PKCE authorization code standing between browser
-- approval and API token issuance, so the real token is only minted once the
-- CLI proves possession of the code_verifier, and a code by itself (browser
-- history, a referrer leak, a proxy log) redeems nothing.
CREATE TABLE IF NOT EXISTS cli_login_codes (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role           TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'developer', 'reader')),
    code_hash      TEXT NOT NULL UNIQUE,
    code_challenge TEXT NOT NULL,
    used_at        TIMESTAMPTZ,
    expires_at     TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cli_login_codes_code_hash ON cli_login_codes(code_hash);
