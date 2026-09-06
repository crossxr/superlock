package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/nan0/backend/internal/model"
)

// UpdateOrgBilling stores Razorpay subscription details on the org.
func (s *Store) UpdateOrgBilling(ctx context.Context, orgID uuid.UUID, customerID, subscriptionID, planID string, plan model.PlanTier, retentionDays int, status string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE organizations
		SET rzp_customer_id=$2, rzp_subscription_id=$3, rzp_plan_id=$4,
		    plan_tier=$5, audit_retention_days=$6, subscription_status=$7, updated_at=NOW()
		WHERE id=$1`,
		orgID, customerID, subscriptionID, planID, plan, retentionDays, status)
	return err
}

// UpdateOrgPlan downgrades/upgrades the plan tier.
func (s *Store) UpdateOrgPlan(ctx context.Context, orgID uuid.UUID, plan model.PlanTier, retentionDays int) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE organizations SET plan_tier=$2, audit_retention_days=$3, updated_at=NOW() WHERE id=$1`,
		orgID, plan, retentionDays)
	return err
}

// UpdateOrgSubscriptionStatus updates only the subscription status field.
func (s *Store) UpdateOrgSubscriptionStatus(ctx context.Context, orgID uuid.UUID, status string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE organizations SET subscription_status=$2, updated_at=NOW() WHERE id=$1`,
		orgID, status)
	return err
}

// GetOrgByRzpSubscriptionID looks up an org by its Razorpay subscription ID.
func (s *Store) GetOrgByRzpSubscriptionID(ctx context.Context, subID string) (*model.Organization, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, name, plan_tier, rzp_customer_id, rzp_subscription_id, rzp_plan_id,
		       seat_count, billing_email, audit_retention_days, subscription_status, current_period_end,
		       created_at, updated_at
		FROM organizations WHERE rzp_subscription_id=$1`, subID)
	return scanOrg(row)
}

// GetOrgByRzpCustomerID looks up an org by its Razorpay customer ID.
func (s *Store) GetOrgByRzpCustomerID(ctx context.Context, customerID string) (*model.Organization, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, name, plan_tier, rzp_customer_id, rzp_subscription_id, rzp_plan_id,
		       seat_count, billing_email, audit_retention_days, subscription_status, current_period_end,
		       created_at, updated_at
		FROM organizations WHERE rzp_customer_id=$1`, customerID)
	return scanOrg(row)
}

func (s *Store) UpdateOrgSeatCount(ctx context.Context, orgID uuid.UUID, count int) error {
	_, err := s.pool.Exec(ctx, `UPDATE organizations SET seat_count=$2, updated_at=NOW() WHERE id=$1`, orgID, count)
	return err
}

// --- Counting queries for plan enforcement ---

// CountOrgSecrets returns total non-deleted secrets across all projects in this org.
func (s *Store) CountOrgSecrets(ctx context.Context, orgID uuid.UUID) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM secrets s
		JOIN environments e ON e.id = s.env_id
		JOIN projects p ON p.id = e.project_id
		WHERE p.org_id = $1 AND p.deleted_at IS NULL AND s.deleted_at IS NULL
	`, orgID).Scan(&count)
	return count, err
}

// CountOrgProjects returns the count of active projects in this org.
func (s *Store) CountOrgProjects(ctx context.Context, orgID uuid.UUID) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM projects WHERE org_id = $1 AND deleted_at IS NULL
	`, orgID).Scan(&count)
	return count, err
}

// CountProjectEnvs returns the count of environments in a project.
func (s *Store) CountProjectEnvs(ctx context.Context, projectID uuid.UUID) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM environments WHERE project_id = $1
	`, projectID).Scan(&count)
	return count, err
}

// CountOrgAPITokens returns total active (non-revoked) API tokens for this org.
func (s *Store) CountOrgAPITokens(ctx context.Context, orgID uuid.UUID) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM api_tokens WHERE org_id = $1 AND revoked_at IS NULL
	`, orgID).Scan(&count)
	return count, err
}

// --- Org scanner ---

type orgRow interface {
	Scan(dest ...any) error
}

func scanOrg(row orgRow) (*model.Organization, error) {
	var org model.Organization
	if err := row.Scan(&org.ID, &org.Name, &org.PlanTier, &org.RzpCustomerID, &org.RzpSubscriptionID,
		&org.RzpPlanID, &org.SeatCount, &org.BillingEmail, &org.AuditRetentionDays,
		&org.SubscriptionStatus, &org.CurrentPeriodEnd,
		&org.CreatedAt, &org.UpdatedAt); err != nil {
		return nil, err
	}
	return &org, nil
}
