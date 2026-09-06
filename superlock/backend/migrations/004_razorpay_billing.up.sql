-- 004_razorpay_billing.up.sql
-- Replace LemonSqueezy billing with Razorpay + enforce plan limits

-- Drop old LemonSqueezy columns
ALTER TABLE organizations
    DROP COLUMN IF EXISTS ls_customer_id,
    DROP COLUMN IF EXISTS ls_subscription_id,
    DROP COLUMN IF EXISTS ls_variant_id;

-- Add Razorpay columns
ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS rzp_customer_id      TEXT,
    ADD COLUMN IF NOT EXISTS rzp_subscription_id   TEXT,
    ADD COLUMN IF NOT EXISTS rzp_plan_id           TEXT,
    ADD COLUMN IF NOT EXISTS subscription_status   TEXT DEFAULT 'inactive',
    ADD COLUMN IF NOT EXISTS current_period_end    TIMESTAMPTZ;

-- Update plan_tier check constraint to include 'starter'
ALTER TABLE organizations DROP CONSTRAINT IF EXISTS organizations_plan_tier_check;
ALTER TABLE organizations ADD CONSTRAINT organizations_plan_tier_check
    CHECK (plan_tier IN ('free', 'starter', 'business', 'enterprise'));

-- Migrate existing 'team' plans to 'starter'
UPDATE organizations SET plan_tier = 'starter' WHERE plan_tier = 'team';

-- Index for subscription lookups
CREATE INDEX IF NOT EXISTS idx_organizations_rzp_sub
    ON organizations(rzp_subscription_id) WHERE rzp_subscription_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_organizations_rzp_customer
    ON organizations(rzp_customer_id) WHERE rzp_customer_id IS NOT NULL;

-- Drop old LS index
DROP INDEX IF EXISTS idx_organizations_ls_customer;
