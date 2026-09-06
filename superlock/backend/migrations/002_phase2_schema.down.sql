ALTER TABLE organizations
    DROP COLUMN IF EXISTS ls_customer_id,
    DROP COLUMN IF EXISTS ls_subscription_id,
    DROP COLUMN IF EXISTS ls_variant_id,
    DROP COLUMN IF EXISTS seat_count,
    DROP COLUMN IF EXISTS billing_email,
    DROP COLUMN IF EXISTS audit_retention_days;

DROP TABLE IF EXISTS invitations;
DROP TABLE IF EXISTS pending_approvals;
DROP TABLE IF EXISTS rotation_history;
DROP TABLE IF EXISTS rotation_schedules;