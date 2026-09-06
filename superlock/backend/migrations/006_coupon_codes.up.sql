-- 006_coupon_codes.up.sql
-- Coupon codes for instant plan upgrades

CREATE TABLE IF NOT EXISTS coupons (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code            TEXT UNIQUE NOT NULL,
    plan_tier       TEXT NOT NULL CHECK (plan_tier IN ('free', 'starter', 'business', 'enterprise')),
    description     TEXT NOT NULL DEFAULT '',
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS coupon_redemptions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    coupon_id       UUID NOT NULL REFERENCES coupons(id) ON DELETE CASCADE,
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id),
    redeemed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_coupon_org UNIQUE(coupon_id, org_id)
);

CREATE INDEX IF NOT EXISTS idx_coupons_code ON coupons(LOWER(code));
CREATE INDEX IF NOT EXISTS idx_coupon_redemptions_org ON coupon_redemptions(org_id);

-- Seed predefined coupons
INSERT INTO coupons (code, plan_tier, description)
VALUES 
    ('SUPERXEPIC', 'business', 'Free Pro Plan Upgrade (SuperXEpic Exclusive)'),
    ('SUPERXPEIC', 'business', 'Free Pro Plan Upgrade (Alias)'),
    ('VIPSTARTER', 'starter', 'Free Starter Plan Upgrade')
ON CONFLICT (code) DO UPDATE SET plan_tier = EXCLUDED.plan_tier, is_active = true;
