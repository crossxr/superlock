-- 001_initial_schema.up.sql
-- Nano Phase 1 - Initial schema

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Organizations (top-level billing entity)
CREATE TABLE organizations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    plan_tier   TEXT NOT NULL DEFAULT 'free' CHECK (plan_tier IN ('free', 'team', 'business', 'enterprise')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Users (linked to Supabase Auth via same UUID)
CREATE TABLE users (
    id            UUID PRIMARY KEY,
    org_id        UUID REFERENCES organizations(id) ON DELETE SET NULL,
    email         TEXT NOT NULL UNIQUE,
    role          TEXT NOT NULL DEFAULT 'owner' CHECK (role IN ('owner', 'admin', 'developer', 'reader')),
    mfa_enabled   BOOLEAN NOT NULL DEFAULT FALSE,
    last_login_at TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_org_id ON users(org_id);
CREATE INDEX idx_users_email ON users(email);

-- Projects
CREATE TABLE projects (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_by  UUID NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ,
    UNIQUE (org_id, slug)
);

CREATE INDEX idx_projects_org_id ON projects(org_id);

-- Environments
CREATE TABLE environments (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id   UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    slug         TEXT NOT NULL,
    is_protected BOOLEAN NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, slug)
);

CREATE INDEX idx_environments_project_id ON environments(project_id);

-- Secrets (encrypted at rest)
CREATE TABLE secrets (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id           UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    key              TEXT NOT NULL,
    encrypted_value  TEXT NOT NULL,
    encrypted_dek    TEXT NOT NULL,
    version          INTEGER NOT NULL DEFAULT 1,
    expires_at       TIMESTAMPTZ,
    created_by       UUID NOT NULL REFERENCES users(id),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at       TIMESTAMPTZ,
    UNIQUE (env_id, key)
);

CREATE INDEX idx_secrets_env_id ON secrets(env_id);
CREATE INDEX idx_secrets_key ON secrets(env_id, key) WHERE deleted_at IS NULL;

-- Secret version history
CREATE TABLE secret_versions (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id        UUID NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    encrypted_value  TEXT NOT NULL,
    encrypted_dek    TEXT NOT NULL,
    version          INTEGER NOT NULL,
    created_by       UUID NOT NULL REFERENCES users(id),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_secret_versions_secret_id ON secret_versions(secret_id);

-- API Tokens
CREATE TABLE api_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    scopes       TEXT[] NOT NULL DEFAULT '{}',
    last_used_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_tokens_user_id ON api_tokens(user_id);
CREATE INDEX idx_api_tokens_hash ON api_tokens(token_hash);

-- Audit log (append-only, HMAC chain)
CREATE TABLE audit_events (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_id      UUID NOT NULL,
    actor_type    TEXT NOT NULL DEFAULT 'user' CHECK (actor_type IN ('user', 'api_token', 'system')),
    action        TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id   UUID,
    metadata      JSONB NOT NULL DEFAULT '{}',
    ip_address    TEXT NOT NULL DEFAULT '',
    user_agent    TEXT NOT NULL DEFAULT '',
    ts            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    prev_hmac     TEXT NOT NULL DEFAULT '',
    hmac          TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_audit_events_org_id ON audit_events(org_id);
CREATE INDEX idx_audit_events_ts ON audit_events(org_id, ts DESC);
CREATE INDEX idx_audit_events_action ON audit_events(org_id, action);

-- Project members (project-scoped RBAC overrides)
CREATE TABLE project_members (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'developer', 'reader')),
    granted_by UUID NOT NULL REFERENCES users(id),
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, user_id)
);

-- Trigger to auto-update updated_at
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_organizations_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_projects_updated_at
    BEFORE UPDATE ON projects
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_secrets_updated_at
    BEFORE UPDATE ON secrets
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
