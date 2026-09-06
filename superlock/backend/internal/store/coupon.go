package store

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/nan0/backend/internal/model"
)

var (
	ErrCouponNotFound = errors.New("coupon not found or inactive")
	ErrCouponRedeemed = errors.New("coupon already redeemed by your organization")
)

// GetCouponByCode looks up an active coupon by its code (case-insensitive).
func (s *Store) GetCouponByCode(ctx context.Context, code string) (*model.Coupon, error) {
	var c model.Coupon
	err := s.pool.QueryRow(ctx, `
		SELECT id, code, plan_tier, description, is_active, created_at
		FROM coupons
		WHERE LOWER(code) = LOWER($1) AND is_active = true`,
		strings.TrimSpace(code)).
		Scan(&c.ID, &c.Code, &c.PlanTier, &c.Description, &c.IsActive, &c.CreatedAt)
	if err != nil {
		return nil, ErrCouponNotFound
	}
	return &c, nil
}

// RedeemCoupon applies or re-activates the coupon for the organization in an atomic transaction.
func (s *Store) RedeemCoupon(ctx context.Context, coupon *model.Coupon, orgID, userID uuid.UUID, retentionDays int) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Check if already active on this exact plan
	var currentPlan string
	var currentStatus *string
	err = tx.QueryRow(ctx, `SELECT plan_tier, subscription_status FROM organizations WHERE id = $1`, orgID).Scan(&currentPlan, &currentStatus)
	if err != nil {
		return err
	}
	if currentPlan == string(coupon.PlanTier) && currentStatus != nil && *currentStatus == "active" {
		return ErrCouponRedeemed
	}

	// Record or update redemption
	_, err = tx.Exec(ctx, `
		INSERT INTO coupon_redemptions (coupon_id, org_id, user_id, redeemed_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (coupon_id, org_id) DO UPDATE
		SET redeemed_at = NOW(), user_id = EXCLUDED.user_id`,
		coupon.ID, orgID, userID)
	if err != nil {
		return err
	}

	// Update org plan tier and reactivate
	_, err = tx.Exec(ctx, `
		UPDATE organizations
		SET plan_tier = $2,
		    audit_retention_days = $3,
		    subscription_status = 'active',
		    updated_at = NOW()
		WHERE id = $1`,
		orgID, coupon.PlanTier, retentionDays)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}
