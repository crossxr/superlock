package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/nan0/backend/internal/billing"
	"github.com/nan0/backend/internal/model"
	"github.com/nan0/backend/internal/respond"
	"github.com/nan0/backend/internal/store"
)

// CreateSubscription creates a Razorpay subscription and returns the hosted page URL.
func (h *Handler) CreateSubscription(w http.ResponseWriter, r *http.Request) {
	orgID, ok := getOrgID(r)
	if !ok {
		respond.Error(w, http.StatusForbidden, "no organization")
		return
	}

	var req struct {
		PlanTier string `json:"plan_tier"` // "starter" or "business"
	}
	if err := respond.Decode(r, &req); err != nil || req.PlanTier == "" {
		respond.Error(w, http.StatusBadRequest, "plan_tier required (starter or business)")
		return
	}

	// Map tier to Razorpay plan ID
	var rzpPlanID string
	switch model.PlanTier(req.PlanTier) {
	case model.PlanStarter:
		rzpPlanID = os.Getenv("RZP_PLAN_STARTER")
	case model.PlanBusiness:
		rzpPlanID = os.Getenv("RZP_PLAN_BUSINESS")
	default:
		respond.Error(w, http.StatusBadRequest, "invalid plan_tier: must be starter or business")
		return
	}

	if rzpPlanID == "" {
		respond.Error(w, http.StatusServiceUnavailable, "billing plan not configured")
		return
	}

	email, _ := r.Context().Value(model.CtxEmail).(string)

	// Get current seat count
	members, _ := h.Store.ListOrgUsers(r.Context(), orgID)
	quantity := len(members)
	if quantity < 1 {
		quantity = 1
	}

	rzpClient := billing.New(
		os.Getenv("RAZORPAY_KEY_ID"),
		os.Getenv("RAZORPAY_KEY_SECRET"),
		os.Getenv("RAZORPAY_WEBHOOK_SECRET"),
	)

	sub, err := rzpClient.CreateSubscription(r.Context(), rzpPlanID, quantity, orgID.String(), email)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, fmt.Sprintf("subscription error: %v", err))
		return
	}

	// Get current org to preserve plan during 'created' phase
	org, err := h.Store.GetOrganizationByID(r.Context(), orgID)
	if err != nil || org == nil {
		respond.Error(w, http.StatusInternalServerError, "failed to get organization")
		return
	}

	// Store the subscription ID on the org immediately (status = created)
	// IMPORTANT: We do NOT update the plan_tier here. That only happens via webhook on payment.
	_ = h.Store.UpdateOrgBilling(r.Context(), orgID, sub.CustomerID, sub.ID, rzpPlanID,
		org.PlanTier, org.AuditRetentionDays, "created")

	userID, _ := getUserID(r)
	h.writeAudit(r, orgID, userID, "user", "billing.subscription_created", "organization", &orgID, map[string]any{
		"plan":            req.PlanTier,
		"subscription_id": sub.ID,
	})

	respond.OK(w, map[string]string{
		"subscription_id": sub.ID,
		"short_url":       sub.ShortURL,
	})
}

// CancelSubscription cancels the subscription and downgrades the organization to Free plan.
func (h *Handler) CancelSubscription(w http.ResponseWriter, r *http.Request) {
	orgID, ok := getOrgID(r)
	if !ok {
		respond.Error(w, http.StatusForbidden, "no organization")
		return
	}

	org, err := h.Store.GetOrganizationByID(r.Context(), orgID)
	if err != nil || org == nil {
		respond.Error(w, http.StatusInternalServerError, "failed to get organization")
		return
	}

	if org.PlanTier == model.PlanFree && ((org.SubscriptionStatus != nil && *org.SubscriptionStatus == "cancelled") || org.RzpSubscriptionID == nil || *org.RzpSubscriptionID == "") {
		respond.Error(w, http.StatusBadRequest, "no active paid subscription to cancel")
		return
	}

	// If linked to a real Razorpay subscription, attempt to cancel on Razorpay
	if org.RzpSubscriptionID != nil && strings.HasPrefix(*org.RzpSubscriptionID, "sub_") {
		rzpClient := billing.New(
			os.Getenv("RAZORPAY_KEY_ID"),
			os.Getenv("RAZORPAY_KEY_SECRET"),
			os.Getenv("RAZORPAY_WEBHOOK_SECRET"),
		)
		if err := rzpClient.CancelSubscription(r.Context(), *org.RzpSubscriptionID, false); err != nil {
			// Log Razorpay error but do not block internal downgrade
			fmt.Printf("[billing] Warning: Razorpay cancel failed for %s: %v\n", *org.RzpSubscriptionID, err)
		}
	}

	// Downgrade organization plan to Free immediately
	_ = h.Store.UpdateOrgPlan(r.Context(), orgID, model.PlanFree, 7)
	_ = h.Store.UpdateOrgSubscriptionStatus(r.Context(), orgID, "cancelled")

	userID, _ := getUserID(r)
	h.writeAudit(r, orgID, userID, "user", "billing.subscription_cancelled", "organization", &orgID, map[string]any{
		"previous_plan": org.PlanTier,
	})

	respond.OK(w, map[string]string{
		"status":  "cancelled",
		"message": "Subscription cancelled and downgraded to Free plan.",
	})
}

// GetSubscriptionStatus returns the current billing/subscription info.
func (h *Handler) GetSubscriptionStatus(w http.ResponseWriter, r *http.Request) {
	orgID, ok := getOrgID(r)
	if !ok {
		respond.Error(w, http.StatusForbidden, "no organization")
		return
	}

	org, err := h.Store.GetOrganizationByID(r.Context(), orgID)
	if err != nil || org == nil {
		respond.Error(w, http.StatusInternalServerError, "failed to get org")
		return
	}

	limits := billing.GetLimits(org.PlanTier)
	members, _ := h.Store.ListOrgUsers(r.Context(), orgID)
	secretCount, _ := h.Store.CountOrgSecrets(r.Context(), orgID)
	projectCount, _ := h.Store.CountOrgProjects(r.Context(), orgID)
	tokenCount, _ := h.Store.CountOrgAPITokens(r.Context(), orgID)

	respond.OK(w, map[string]any{
		"plan_tier":           org.PlanTier,
		"subscription_status": org.SubscriptionStatus,
		"current_period_end":  org.CurrentPeriodEnd,
		"usage": map[string]any{
			"seats":      len(members),
			"secrets":    secretCount,
			"projects":   projectCount,
			"api_tokens": tokenCount,
		},
		"limits": map[string]any{
			"max_seats":         limits.MaxSeats,
			"max_secrets":       limits.MaxSecrets,
			"max_projects":      limits.MaxProjects,
			"max_envs_per_proj": limits.MaxEnvsPerProj,
			"max_api_tokens":    limits.MaxAPITokens,
			"audit_retention":   limits.AuditRetention,
			"rotation":          limits.Rotation,
			"dynamic_secrets":   limits.DynamicSecrets,
			"ci_integrations":   limits.CIIntegrations,
			"approvals":         limits.Approvals,
			"analytics":         limits.Analytics,
			"secret_versioning": limits.SecretVersioning,
		},
	})
}

// RazorpayWebhook handles Razorpay event webhooks.
func (h *Handler) RazorpayWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "cannot read body")
		return
	}

	rzpClient := billing.New(
		os.Getenv("RAZORPAY_KEY_ID"),
		os.Getenv("RAZORPAY_KEY_SECRET"),
		os.Getenv("RAZORPAY_WEBHOOK_SECRET"),
	)
	sig := r.Header.Get("X-Razorpay-Signature")
	if !rzpClient.VerifyWebhookSignature(body, sig) {
		respond.Error(w, http.StatusUnauthorized, "invalid signature")
		return
	}

	var event billing.WebhookEvent
	if err := json.Unmarshal(body, &event); err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid webhook payload")
		return
	}

	switch event.Event {
	case "subscription.activated", "subscription.charged", "subscription.resumed":
		h.handleRzpSubscriptionActive(r, event)
	case "subscription.cancelled", "subscription.completed", "subscription.expired":
		h.handleRzpSubscriptionCancelled(r, event)
	case "subscription.paused":
		h.handleRzpSubscriptionPaused(r, event)
	}

	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleRzpSubscriptionActive(r *http.Request, event billing.WebhookEvent) {
	var sub billing.Subscription
	if err := json.Unmarshal(event.Payload.Subscription.Entity, &sub); err != nil {
		return
	}

	orgIDStr := sub.Notes["org_id"]
	if orgIDStr == "" {
		// Try lookup by subscription ID
		org, err := h.Store.GetOrgByRzpSubscriptionID(r.Context(), sub.ID)
		if err != nil || org == nil {
			return
		}
		orgIDStr = org.ID.String()
	}

	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		return
	}

	starterPlanID := os.Getenv("RZP_PLAN_STARTER")
	businessPlanID := os.Getenv("RZP_PLAN_BUSINESS")
	planTier, retentionDays := billing.PlanFromRazorpayPlanID(sub.PlanID, starterPlanID, businessPlanID)

	_ = h.Store.UpdateOrgBilling(r.Context(), orgID, sub.CustomerID, sub.ID, sub.PlanID,
		planTier, retentionDays, "active")
}

func (h *Handler) handleRzpSubscriptionCancelled(r *http.Request, event billing.WebhookEvent) {
	var sub billing.Subscription
	if err := json.Unmarshal(event.Payload.Subscription.Entity, &sub); err != nil {
		return
	}

	org, err := h.Store.GetOrgByRzpSubscriptionID(r.Context(), sub.ID)
	if err != nil || org == nil {
		return
	}

	// Downgrade to free
	_ = h.Store.UpdateOrgPlan(r.Context(), org.ID, model.PlanFree, 7)
	_ = h.Store.UpdateOrgSubscriptionStatus(r.Context(), org.ID, "cancelled")
}

func (h *Handler) handleRzpSubscriptionPaused(r *http.Request, event billing.WebhookEvent) {
	var sub billing.Subscription
	if err := json.Unmarshal(event.Payload.Subscription.Entity, &sub); err != nil {
		return
	}

	org, err := h.Store.GetOrgByRzpSubscriptionID(r.Context(), sub.ID)
	if err != nil || org == nil {
		return
	}

	_ = h.Store.UpdateOrgSubscriptionStatus(r.Context(), org.ID, "paused")
}

// RedeemCoupon handles promo/coupon code validation and instant plan upgrade.
func (h *Handler) RedeemCoupon(w http.ResponseWriter, r *http.Request) {
	orgID, ok := getOrgID(r)
	if !ok {
		respond.Error(w, http.StatusForbidden, "no organization")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := respond.Decode(r, &req); err != nil || strings.TrimSpace(req.Code) == "" {
		respond.Error(w, http.StatusBadRequest, "coupon code is required")
		return
	}

	coupon, err := h.Store.GetCouponByCode(r.Context(), req.Code)
	if err != nil {
		respond.Error(w, http.StatusNotFound, "invalid or expired coupon code")
		return
	}

	userID, _ := getUserID(r)

	// Determine retention days for the unlocked plan
	retentionDays := 7
	switch coupon.PlanTier {
	case model.PlanStarter:
		retentionDays = 90
	case model.PlanBusiness:
		retentionDays = 365
	case model.PlanEnterprise:
		retentionDays = 730
	}

	if err := h.Store.RedeemCoupon(r.Context(), coupon, orgID, userID, retentionDays); err != nil {
		if errors.Is(err, store.ErrCouponRedeemed) {
			respond.Error(w, http.StatusConflict, fmt.Sprintf("Your organization is already active on the %s plan", strings.ToUpper(string(coupon.PlanTier))))
			return
		}
		respond.Error(w, http.StatusInternalServerError, "failed to apply coupon")
		return
	}

	h.writeAudit(r, orgID, userID, "user", "billing.coupon_redeemed", "organization", &orgID, map[string]any{
		"coupon_code": coupon.Code,
		"plan_tier":   coupon.PlanTier,
	})

	respond.OK(w, map[string]any{
		"status":      "redeemed",
		"plan_tier":   coupon.PlanTier,
		"description": coupon.Description,
		"message":     fmt.Sprintf("Successfully upgraded to %s plan!", strings.ToUpper(string(coupon.PlanTier))),
	})
}

