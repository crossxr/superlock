-- 005_shared_secrets.up.sql
-- Secret sharing links

CREATE TABLE shared_secrets (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_by    UUID NOT NULL REFERENCES users(id),
    label         TEXT NOT NULL DEFAULT '',
    secrets_enc   TEXT NOT NULL,             -- AES-encrypted JSON blob of key-value pairs
    encrypted_dek TEXT NOT NULL,             -- envelope-encrypted DEK
    expires_at    TIMESTAMPTZ NOT NULL,
    max_views     INT NOT NULL DEFAULT 0,    -- 0 = unlimited
    view_count    INT NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_shared_secrets_org ON shared_secrets(org_id);
CREATE INDEX idx_shared_secrets_expires ON shared_secrets(expires_at);
