-- 004_razorpay_billing.down.sql
-- Revert Razorpay billing changes

ALTER TABLE organizations
    DROP COLUMN IF EXISTS rzp_customer_id,
    DROP COLUMN IF EXISTS rzp_subscription_id,
    DROP COLUMN IF EXISTS rzp_plan_id,
    DROP COLUMN IF EXISTS subscription_status,
    DROP COLUMN IF EXISTS current_period_end;

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS ls_customer_id    TEXT,
    ADD COLUMN IF NOT EXISTS ls_subscription_id TEXT,
    ADD COLUMN IF NOT EXISTS ls_variant_id      TEXT;

ALTER TABLE organizations DROP CONSTRAINT IF EXISTS organizations_plan_tier_check;
ALTER TABLE organizations ADD CONSTRAINT organizations_plan_tier_check
    CHECK (plan_tier IN ('free', 'team', 'business', 'enterprise'));

UPDATE organizations SET plan_tier = 'team' WHERE plan_tier = 'starter';

CREATE INDEX IF NOT EXISTS idx_organizations_ls_customer
    ON organizations(ls_customer_id) WHERE ls_customer_id IS NOT NULL;

DROP INDEX IF EXISTS idx_organizations_rzp_sub;
DROP INDEX IF EXISTS idx_organizations_rzp_customer;
