-- 002_phase2_schema.up.sql
-- Nano Phase 2: Rotation, Approvals, Billing, Invites, WebSocket

-- Rotation schedules
CREATE TABLE rotation_schedules (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id        UUID NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    interval_hours   INTEGER NOT NULL DEFAULT 720,
    backend          TEXT NOT NULL DEFAULT 'webhook' CHECK (backend IN ('webhook', 'postgres', 'redis')),
    config_json      JSONB NOT NULL DEFAULT '{}',
    last_rotated_at  TIMESTAMPTZ,
    next_rotation_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    created_by       UUID NOT NULL REFERENCES users(id),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_rotation_schedules_next ON rotation_schedules(next_rotation_at) WHERE enabled = TRUE;
CREATE INDEX idx_rotation_schedules_secret ON rotation_schedules(secret_id);

-- Rotation history
CREATE TABLE rotation_history (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id    UUID NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    schedule_id  UUID REFERENCES rotation_schedules(id) ON DELETE SET NULL,
    status       TEXT NOT NULL CHECK (status IN ('success', 'failed', 'pending')),
    backend      TEXT NOT NULL,
    error_msg    TEXT,
    triggered_by TEXT NOT NULL DEFAULT 'scheduler',
    started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at  TIMESTAMPTZ
);
CREATE INDEX idx_rotation_history_secret ON rotation_history(secret_id);

-- Pending approvals (2-person for protected envs)
CREATE TABLE pending_approvals (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    env_id        UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    secret_id     UUID REFERENCES secrets(id) ON DELETE CASCADE,
    requested_by  UUID NOT NULL REFERENCES users(id),
    approved_by   UUID REFERENCES users(id),
    action        TEXT NOT NULL CHECK (action IN ('create', 'update', 'delete')),
    payload_json  JSONB NOT NULL DEFAULT '{}',
    status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
    expires_at    TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours',
    resolved_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_pending_approvals_org ON pending_approvals(org_id, status);
CREATE INDEX idx_pending_approvals_env ON pending_approvals(env_id, status);

-- Invitations
CREATE TABLE invitations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'developer' CHECK (role IN ('admin', 'developer', 'reader')),
    token_hash  TEXT NOT NULL UNIQUE,
    invited_by  UUID NOT NULL REFERENCES users(id),
    accepted_at TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '7 days',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_invitations_org ON invitations(org_id);
CREATE INDEX idx_invitations_email ON invitations(email);
CREATE INDEX idx_invitations_token ON invitations(token_hash);

-- Billing: add LemonSqueezy columns to organizations
ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS ls_customer_id    TEXT,
    ADD COLUMN IF NOT EXISTS ls_subscription_id TEXT,
    ADD COLUMN IF NOT EXISTS ls_variant_id      TEXT,
    ADD COLUMN IF NOT EXISTS seat_count         INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS billing_email      TEXT;

CREATE INDEX idx_organizations_ls_customer ON organizations(ls_customer_id) WHERE ls_customer_id IS NOT NULL;

-- Audit retention policy per plan (stored on org)
ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS audit_retention_days INTEGER NOT NULL DEFAULT 7;

-- Trigger for rotation_schedules updated_at
CREATE TRIGGER trg_rotation_schedules_updated_at
    BEFORE UPDATE ON rotation_schedules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();