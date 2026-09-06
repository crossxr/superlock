package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/nan0/backend/internal/model"
)

func (s *Store) CreateOrganization(ctx context.Context, name string, plan model.PlanTier) (*model.Organization, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO organizations (name, plan_tier, audit_retention_days)
		VALUES ($1, $2, $3)
		RETURNING id, name, plan_tier, rzp_customer_id, rzp_subscription_id, rzp_plan_id,
		          seat_count, billing_email, audit_retention_days, subscription_status, current_period_end,
		          created_at, updated_at`,
		name, plan, retentionForPlan(plan))
	return scanOrg(row)
}

func (s *Store) GetOrganizationByID(ctx context.Context, id uuid.UUID) (*model.Organization, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, name, plan_tier, rzp_customer_id, rzp_subscription_id, rzp_plan_id,
		       seat_count, billing_email, audit_retention_days, subscription_status, current_period_end,
		       created_at, updated_at
		FROM organizations WHERE id=$1`, id)
	return scanOrg(row)
}

func retentionForPlan(p model.PlanTier) int {
	switch p {
	case model.PlanStarter:
		return 90
	case model.PlanBusiness:
		return 365
	case model.PlanEnterprise:
		return 3650
	default:
		return 7
	}
}
