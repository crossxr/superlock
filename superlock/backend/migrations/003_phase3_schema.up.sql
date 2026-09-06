-- 003_phase3_schema.up.sql
-- Nano Phase 3: Dynamic secrets, secret references, access analytics

-- Dynamic secret leases (short-lived credentials generated on demand)
CREATE TABLE dynamic_secret_leases (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    backend      TEXT NOT NULL CHECK (backend IN ('postgres', 'mysql')),
    config_id    UUID NOT NULL,        -- references dynamic_secret_configs.id
    username     TEXT NOT NULL,
    database_url TEXT NOT NULL,        -- DSN without password, for revocation
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ,
    created_by   UUID NOT NULL REFERENCES users(id),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_dynamic_leases_org ON dynamic_secret_leases(org_id);
CREATE INDEX idx_dynamic_leases_expires ON dynamic_secret_leases(expires_at) WHERE revoked_at IS NULL;

-- Dynamic secret backend configs (stored per project/env)
CREATE TABLE dynamic_secret_configs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id       UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    backend      TEXT NOT NULL CHECK (backend IN ('postgres', 'mysql')),
    config_json  JSONB NOT NULL DEFAULT '{}',  -- encrypted DSN, role, TTL
    created_by   UUID NOT NULL REFERENCES users(id),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (env_id, name)
);
CREATE INDEX idx_dynamic_configs_env ON dynamic_secret_configs(env_id);

-- Secret access tracking (for analytics)
CREATE TABLE secret_access_log (
    id          BIGSERIAL PRIMARY KEY,
    secret_id   UUID NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_id    UUID NOT NULL,
    actor_type  TEXT NOT NULL DEFAULT 'user',
    accessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    env_id      UUID NOT NULL
);
CREATE INDEX idx_access_log_secret ON secret_access_log(secret_id, accessed_at DESC);
CREATE INDEX idx_access_log_org ON secret_access_log(org_id, accessed_at DESC);
CREATE INDEX idx_access_log_env ON secret_access_log(env_id, accessed_at DESC);

-- CI/CD integration tokens (scoped, named differently from API tokens for clarity)
CREATE TABLE integration_configs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    provider    TEXT NOT NULL CHECK (provider IN ('github_actions', 'gitlab_ci', 'circleci')),
    config_json JSONB NOT NULL DEFAULT '{}',
    created_by  UUID NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_integration_configs_org ON integration_configs(org_id);

-- Trigger for dynamic_secret_configs updated_at
CREATE TRIGGER trg_dynamic_secret_configs_updated_at
    BEFORE UPDATE ON dynamic_secret_configs
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();