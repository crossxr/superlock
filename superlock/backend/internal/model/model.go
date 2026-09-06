package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type PlanTier string

const (
	PlanFree       PlanTier = "free"
	PlanStarter    PlanTier = "starter"
	PlanBusiness   PlanTier = "business"
	PlanEnterprise PlanTier = "enterprise"
)

type Role string

const (
	RoleOwner     Role = "owner"
	RoleAdmin     Role = "admin"
	RoleDeveloper Role = "developer"
	RoleReader    Role = "reader"
)

type Organization struct {
	ID                 uuid.UUID  `json:"id" db:"id"`
	Name               string     `json:"name" db:"name"`
	PlanTier           PlanTier   `json:"plan_tier" db:"plan_tier"`
	RzpCustomerID      *string    `json:"rzp_customer_id,omitempty" db:"rzp_customer_id"`
	RzpSubscriptionID  *string    `json:"rzp_subscription_id,omitempty" db:"rzp_subscription_id"`
	RzpPlanID          *string    `json:"rzp_plan_id,omitempty" db:"rzp_plan_id"`
	SeatCount          int        `json:"seat_count" db:"seat_count"`
	BillingEmail       *string    `json:"billing_email,omitempty" db:"billing_email"`
	AuditRetentionDays int        `json:"audit_retention_days" db:"audit_retention_days"`
	SubscriptionStatus *string    `json:"subscription_status,omitempty" db:"subscription_status"`
	CurrentPeriodEnd   *time.Time `json:"current_period_end,omitempty" db:"current_period_end"`
	CreatedAt          time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at" db:"updated_at"`
}

type User struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	OrgID       *uuid.UUID `json:"org_id" db:"org_id"`
	Email       string     `json:"email" db:"email"`
	Role        Role       `json:"role" db:"role"`
	MFAEnabled  bool       `json:"mfa_enabled" db:"mfa_enabled"`
	LastLoginAt *time.Time `json:"last_login_at" db:"last_login_at"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
}

type Project struct {
	ID          uuid.UUID `json:"id" db:"id"`
	OrgID       uuid.UUID `json:"org_id" db:"org_id"`
	Name        string    `json:"name" db:"name"`
	Slug        string    `json:"slug" db:"slug"`
	Description string    `json:"description" db:"description"`
	CreatedBy   uuid.UUID `json:"created_by" db:"created_by"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

type Environment struct {
	ID          uuid.UUID `json:"id" db:"id"`
	ProjectID   uuid.UUID `json:"project_id" db:"project_id"`
	Name        string    `json:"name" db:"name"`
	Slug        string    `json:"slug" db:"slug"`
	IsProtected bool      `json:"is_protected" db:"is_protected"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

type Secret struct {
	ID             uuid.UUID  `json:"id" db:"id"`
	EnvID          uuid.UUID  `json:"env_id" db:"env_id"`
	Key            string     `json:"key" db:"key"`
	EncryptedValue string     `json:"-" db:"encrypted_value"`
	EncryptedDEK   string     `json:"-" db:"encrypted_dek"`
	Version        int        `json:"version" db:"version"`
	ExpiresAt      *time.Time `json:"expires_at" db:"expires_at"`
	CreatedBy      uuid.UUID  `json:"created_by" db:"created_by"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at" db:"updated_at"`
	Value          string     `json:"value,omitempty"`
}

type SecretVersion struct {
	ID             uuid.UUID `json:"id" db:"id"`
	SecretID       uuid.UUID `json:"secret_id" db:"secret_id"`
	EncryptedValue string    `json:"-" db:"encrypted_value"`
	EncryptedDEK   string    `json:"-" db:"encrypted_dek"`
	Version        int       `json:"version" db:"version"`
	CreatedBy      uuid.UUID `json:"created_by" db:"created_by"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
}

type AuditEvent struct {
	ID           uuid.UUID       `json:"id" db:"id"`
	OrgID        uuid.UUID       `json:"org_id" db:"org_id"`
	ActorID      uuid.UUID       `json:"actor_id" db:"actor_id"`
	ActorType    string          `json:"actor_type" db:"actor_type"`
	Action       string          `json:"action" db:"action"`
	ResourceType string          `json:"resource_type" db:"resource_type"`
	ResourceID   *uuid.UUID      `json:"resource_id" db:"resource_id"`
	Metadata     json.RawMessage `json:"metadata" db:"metadata"`
	IPAddress    string          `json:"ip_address" db:"ip_address"`
	UserAgent    string          `json:"user_agent" db:"user_agent"`
	Ts           time.Time       `json:"ts" db:"ts"`
	PrevHMAC     string          `json:"-" db:"prev_hmac"`
	HMAC         string          `json:"-" db:"hmac"`
}

type APIToken struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	OrgID      uuid.UUID  `json:"org_id" db:"org_id"`
	UserID     uuid.UUID  `json:"user_id" db:"user_id"`
	Name       string     `json:"name" db:"name"`
	TokenHash  string     `json:"-" db:"token_hash"`
	Scopes     []string   `json:"scopes" db:"scopes"`
	Role       Role       `json:"role" db:"role"`
	LastUsedAt *time.Time `json:"last_used_at" db:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	PlainToken string     `json:"token,omitempty"`
}

type ProjectMember struct {
	ID        uuid.UUID `json:"id" db:"id"`
	ProjectID uuid.UUID `json:"project_id" db:"project_id"`
	UserID    uuid.UUID `json:"user_id" db:"user_id"`
	Role      Role      `json:"role" db:"role"`
	GrantedBy uuid.UUID `json:"granted_by" db:"granted_by"`
	GrantedAt time.Time `json:"granted_at" db:"granted_at"`
}

// Phase 2 models

type RotationBackend string

const (
	RotationWebhook  RotationBackend = "webhook"
	RotationPostgres RotationBackend = "postgres"
	RotationRedis    RotationBackend = "redis"
)

type RotationSchedule struct {
	ID             uuid.UUID       `json:"id" db:"id"`
	SecretID       uuid.UUID       `json:"secret_id" db:"secret_id"`
	IntervalHours  int             `json:"interval_hours" db:"interval_hours"`
	Backend        RotationBackend `json:"backend" db:"backend"`
	ConfigJSON     json.RawMessage `json:"-" db:"config_json"`
	LastRotatedAt  *time.Time      `json:"last_rotated_at" db:"last_rotated_at"`
	NextRotationAt time.Time       `json:"next_rotation_at" db:"next_rotation_at"`
	Enabled        bool            `json:"enabled" db:"enabled"`
	CreatedBy      uuid.UUID       `json:"created_by" db:"created_by"`
	CreatedAt      time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at" db:"updated_at"`
}

type RotationHistory struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	SecretID    uuid.UUID  `json:"secret_id" db:"secret_id"`
	ScheduleID  *uuid.UUID `json:"schedule_id" db:"schedule_id"`
	Status      string     `json:"status" db:"status"`
	Backend     string     `json:"backend" db:"backend"`
	ErrorMsg    *string    `json:"error_msg" db:"error_msg"`
	TriggeredBy string     `json:"triggered_by" db:"triggered_by"`
	StartedAt   time.Time  `json:"started_at" db:"started_at"`
	FinishedAt  *time.Time `json:"finished_at" db:"finished_at"`
}

type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalRejected ApprovalStatus = "rejected"
	ApprovalExpired  ApprovalStatus = "expired"
)

type PendingApproval struct {
	ID          uuid.UUID       `json:"id" db:"id"`
	OrgID       uuid.UUID       `json:"org_id" db:"org_id"`
	EnvID       uuid.UUID       `json:"env_id" db:"env_id"`
	SecretID    *uuid.UUID      `json:"secret_id" db:"secret_id"`
	RequestedBy uuid.UUID       `json:"requested_by" db:"requested_by"`
	ApprovedBy  *uuid.UUID      `json:"approved_by" db:"approved_by"`
	Action      string          `json:"action" db:"action"`
	PayloadJSON json.RawMessage `json:"payload_json" db:"payload_json"`
	Status      ApprovalStatus  `json:"status" db:"status"`
	ExpiresAt   time.Time       `json:"expires_at" db:"expires_at"`
	ResolvedAt  *time.Time      `json:"resolved_at" db:"resolved_at"`
	CreatedAt   time.Time       `json:"created_at" db:"created_at"`
}

type Invitation struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	OrgID      uuid.UUID  `json:"org_id" db:"org_id"`
	Email      string     `json:"email" db:"email"`
	Role       Role       `json:"role" db:"role"`
	TokenHash  string     `json:"-" db:"token_hash"`
	InvitedBy  uuid.UUID  `json:"invited_by" db:"invited_by"`
	AcceptedAt *time.Time `json:"accepted_at" db:"accepted_at"`
	ExpiresAt  time.Time  `json:"expires_at" db:"expires_at"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	// Set only on creation
	PlainToken string `json:"token,omitempty"`
}

// Auth context key
type ContextKey string

const (
	CtxUserID ContextKey = "user_id"
	CtxOrgID  ContextKey = "org_id"
	CtxRole   ContextKey = "role"
	CtxEmail  ContextKey = "email"
	// CtxScopes holds the API token's scopes. It is absent for user JWTs,
	// which are not scope-limited — see rbac.ScopesAllow.
	CtxScopes ContextKey = "scopes"
)

// ── Phase 3 models — append to existing model.go ────────────────────────────

type DynamicBackend string

const (
	DynamicBackendPostgres DynamicBackend = "postgres"
	DynamicBackendMySQL    DynamicBackend = "mysql"
)

type DynamicSecretConfig struct {
	ID         uuid.UUID       `json:"id" db:"id"`
	EnvID      uuid.UUID       `json:"env_id" db:"env_id"`
	Name       string          `json:"name" db:"name"`
	Backend    DynamicBackend  `json:"backend" db:"backend"`
	ConfigJSON json.RawMessage `json:"-" db:"config_json"` // never expose DSN
	CreatedBy  uuid.UUID       `json:"created_by" db:"created_by"`
	CreatedAt  time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at" db:"updated_at"`
}

type DynamicSecretLease struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	OrgID       uuid.UUID  `json:"org_id" db:"org_id"`
	Backend     string     `json:"backend" db:"backend"`
	ConfigID    uuid.UUID  `json:"config_id" db:"config_id"`
	Username    string     `json:"username" db:"username"`
	DatabaseURL string     `json:"-" db:"database_url"`
	ExpiresAt   time.Time  `json:"expires_at" db:"expires_at"`
	RevokedAt   *time.Time `json:"revoked_at" db:"revoked_at"`
	CreatedBy   uuid.UUID  `json:"created_by" db:"created_by"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	// Only set on creation response
	Password string `json:"password,omitempty"`
}

type SecretAccessLog struct {
	ID         int64     `json:"id" db:"id"`
	SecretID   uuid.UUID `json:"secret_id" db:"secret_id"`
	OrgID      uuid.UUID `json:"org_id" db:"org_id"`
	ActorID    uuid.UUID `json:"actor_id" db:"actor_id"`
	ActorType  string    `json:"actor_type" db:"actor_type"`
	AccessedAt time.Time `json:"accessed_at" db:"accessed_at"`
	EnvID      uuid.UUID `json:"env_id" db:"env_id"`
}

// Analytics aggregation types (not DB-backed, computed)

type SecretHeatmapEntry struct {
	SecretID   uuid.UUID  `json:"secret_id"`
	SecretKey  string     `json:"secret_key"`
	EnvID      uuid.UUID  `json:"env_id"`
	EnvName    string     `json:"env_name"`
	Count      int        `json:"count"`
	LastAccess *time.Time `json:"last_access"`
}

type UnusedSecret struct {
	SecretID        uuid.UUID  `json:"secret_id"`
	SecretKey       string     `json:"secret_key"`
	EnvID           uuid.UUID  `json:"env_id"`
	EnvName         string     `json:"env_name"`
	CreatedAt       time.Time  `json:"created_at"`
	LastAccess      *time.Time `json:"last_access"`
	DaysSinceAccess *int       `json:"days_since_access"`
}

type IntegrationProvider string

const (
	ProviderGitHubActions IntegrationProvider = "github_actions"
	ProviderGitLabCI      IntegrationProvider = "gitlab_ci"
	ProviderCircleCI      IntegrationProvider = "circleci"
)

type IntegrationConfig struct {
	ID         uuid.UUID           `json:"id" db:"id"`
	OrgID      uuid.UUID           `json:"org_id" db:"org_id"`
	Name       string              `json:"name" db:"name"`
	Provider   IntegrationProvider `json:"provider" db:"provider"`
	ConfigJSON json.RawMessage     `json:"config_json" db:"config_json"`
	CreatedBy  uuid.UUID           `json:"created_by" db:"created_by"`
	CreatedAt  time.Time           `json:"created_at" db:"created_at"`
}

// ── Phase 4: Secret Sharing ──────────────────────────────────────────────────

type SharedSecret struct {
	ID           uuid.UUID `json:"id" db:"id"`
	OrgID        uuid.UUID `json:"org_id" db:"org_id"`
	CreatedBy    uuid.UUID `json:"created_by" db:"created_by"`
	Label        string    `json:"label" db:"label"`
	SecretsEnc   string    `json:"-" db:"secrets_enc"`   // encrypted
	EncryptedDEK string    `json:"-" db:"encrypted_dek"` // envelope key
	ExpiresAt    time.Time `json:"expires_at" db:"expires_at"`
	MaxViews     int       `json:"max_views" db:"max_views"`
	ViewCount    int       `json:"view_count" db:"view_count"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	// Only set on retrieval (decrypted)
	Secrets map[string]string `json:"secrets,omitempty"`
}

// ── Coupons / Promo Codes ───────────────────────────────────────────────────

type Coupon struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Code        string    `json:"code" db:"code"`
	PlanTier    PlanTier  `json:"plan_tier" db:"plan_tier"`
	Description string    `json:"description" db:"description"`
	IsActive    bool      `json:"is_active" db:"is_active"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

type CouponRedemption struct {
	ID         uuid.UUID `json:"id" db:"id"`
	CouponID   uuid.UUID `json:"coupon_id" db:"coupon_id"`
	OrgID      uuid.UUID `json:"org_id" db:"org_id"`
	UserID     uuid.UUID `json:"user_id" db:"user_id"`
	RedeemedAt time.Time `json:"redeemed_at" db:"redeemed_at"`
}
