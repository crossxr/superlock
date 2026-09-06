package billing

import "github.com/nan0/backend/internal/model"

// PlanLimits defines the resource quotas and feature gates for a plan tier.
type PlanLimits struct {
	MaxSecrets       int  // 0 = unlimited
	MaxProjects      int  // 0 = unlimited
	MaxEnvsPerProj   int  // 0 = unlimited
	MaxSeats         int  // 0 = unlimited
	MaxAPITokens     int  // 0 = unlimited
	AuditRetention   int  // days
	Rotation         bool // secret rotation engine
	DynamicSecrets   bool // postgres/mysql dynamic secrets
	CIIntegrations   bool // github, gitlab, circleci
	Approvals        bool // 2-person approval workflow
	Analytics        bool // usage analytics + anomaly detection
	BasicAnalytics   bool // basic usage stats
	SecretVersioning bool // secret version history
	WebSocket        bool // cache invalidation via websocket
	EmailInvites     bool // team invitations
	MFAEnforcement   bool // require MFA
	SecretSharing    bool // shareable secret links
}

var planLimitsMap = map[model.PlanTier]PlanLimits{
	model.PlanFree: {
		MaxSecrets:       50,
		MaxProjects:      1,
		MaxEnvsPerProj:   2,
		MaxSeats:         1,
		MaxAPITokens:     3,
		AuditRetention:   7,
		Rotation:         false,
		DynamicSecrets:   false,
		CIIntegrations:   false,
		Approvals:        false,
		Analytics:        false,
		BasicAnalytics:   false,
		SecretVersioning: false,
		WebSocket:        false,
		EmailInvites:     false,
		MFAEnforcement:   false,
		SecretSharing:    false,
	},
	model.PlanStarter: {
		MaxSecrets:       0, // unlimited
		MaxProjects:      5,
		MaxEnvsPerProj:   5,
		MaxSeats:         10,
		MaxAPITokens:     10,
		AuditRetention:   90,
		Rotation:         true,
		DynamicSecrets:   false,
		CIIntegrations:   false,
		Approvals:        false,
		Analytics:        false,
		BasicAnalytics:   true,
		SecretVersioning: true,
		WebSocket:        true,
		EmailInvites:     true,
		MFAEnforcement:   true,
		SecretSharing:    true,
	},
	model.PlanBusiness: {
		MaxSecrets:       0, // unlimited
		MaxProjects:      0, // unlimited
		MaxEnvsPerProj:   0, // unlimited
		MaxSeats:         100,
		MaxAPITokens:     0, // unlimited
		AuditRetention:   365,
		Rotation:         true,
		DynamicSecrets:   true,
		CIIntegrations:   true,
		Approvals:        true,
		Analytics:        true,
		BasicAnalytics:   true,
		SecretVersioning: true,
		WebSocket:        true,
		EmailInvites:     true,
		MFAEnforcement:   true,
		SecretSharing:    true,
	},
	model.PlanEnterprise: {
		MaxSecrets:       0,
		MaxProjects:      0,
		MaxEnvsPerProj:   0,
		MaxSeats:         0,
		MaxAPITokens:     0,
		AuditRetention:   3650,
		Rotation:         true,
		DynamicSecrets:   true,
		CIIntegrations:   true,
		Approvals:        true,
		Analytics:        true,
		BasicAnalytics:   true,
		SecretVersioning: true,
		WebSocket:        true,
		EmailInvites:     true,
		MFAEnforcement:   true,
		SecretSharing:    true,
	},
}

// GetLimits returns the plan limits for the given tier.
func GetLimits(plan model.PlanTier) PlanLimits {
	if l, ok := planLimitsMap[plan]; ok {
		return l
	}
	return planLimitsMap[model.PlanFree]
}

// ExceedsLimit checks if current count exceeds the plan limit.
// A limit of 0 means unlimited.
func ExceedsLimit(limit, current int) bool {
	return limit > 0 && current >= limit
}

// PlanRank returns the numeric tier level for comparison.
func PlanRank(plan model.PlanTier) int {
	switch plan {
	case model.PlanFree:
		return 0
	case model.PlanStarter:
		return 1
	case model.PlanBusiness:
		return 2
	case model.PlanEnterprise:
		return 3
	default:
		return 0
	}
}

// IsAtLeastPlan checks if the org's plan meets the minimum required tier.
func IsAtLeastPlan(current, minimum model.PlanTier) bool {
	return PlanRank(current) >= PlanRank(minimum)
}
