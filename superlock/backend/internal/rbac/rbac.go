package rbac

import (
	"github.com/nan0/backend/internal/model"
)

// Permission constants for actions
type Permission string

const (
	PermReadSecrets   Permission = "secrets:read"
	PermWriteSecrets  Permission = "secrets:write"
	PermDeleteSecrets Permission = "secrets:delete"
	PermViewAudit     Permission = "audit:read"
	PermManageMembers Permission = "members:manage"
	PermManageBilling Permission = "billing:manage"
	PermManageTokens  Permission = "tokens:manage"
)

// rolePermissions maps roles to their allowed permissions.
var rolePermissions = map[model.Role][]Permission{
	model.RoleOwner: {
		PermReadSecrets, PermWriteSecrets, PermDeleteSecrets,
		PermViewAudit, PermManageMembers, PermManageBilling, PermManageTokens,
	},
	model.RoleAdmin: {
		PermReadSecrets, PermWriteSecrets, PermDeleteSecrets,
		PermViewAudit, PermManageMembers, PermManageTokens,
	},
	model.RoleDeveloper: {
		PermReadSecrets, PermWriteSecrets, PermManageTokens,
	},
	model.RoleReader: {
		PermReadSecrets,
	},
}

// HasPermission checks if a role has a given permission.
func HasPermission(role model.Role, perm Permission) bool {
	perms, ok := rolePermissions[role]
	if !ok {
		return false
	}
	for _, p := range perms {
		if p == perm {
			return true
		}
	}
	return false
}

// CanReadSecret checks if a role and scope set can read secrets.
//
// Protected environments are restricted to owner and admin regardless of the
// role table, and the scope must permit the read either way. Pass nil scopes
// for a request that is not scope-limited.
func CanReadSecret(role model.Role, scopes []string, isProtected bool) bool {
	if !ScopesAllow(scopes, PermReadSecrets) {
		return false
	}
	if !isProtected {
		return HasPermission(role, PermReadSecrets)
	}
	return role == model.RoleOwner || role == model.RoleAdmin
}

// CanWriteSecret checks if a role and scope set can write secrets.
func CanWriteSecret(role model.Role, scopes []string, isProtected bool) bool {
	if !ScopesAllow(scopes, PermWriteSecrets) {
		return false
	}
	if !isProtected {
		return HasPermission(role, PermWriteSecrets)
	}
	return role == model.RoleOwner || role == model.RoleAdmin
}

// CanDeleteSecret checks if a role and scope set can delete secrets.
func CanDeleteSecret(role model.Role, scopes []string) bool {
	if !ScopesAllow(scopes, PermDeleteSecrets) {
		return false
	}
	return role == model.RoleOwner || role == model.RoleAdmin
}

// IsAtLeast checks if a role is at least as privileged as minRole.
func IsAtLeast(role, minRole model.Role) bool {
	order := map[model.Role]int{
		model.RoleReader:    1,
		model.RoleDeveloper: 2,
		model.RoleAdmin:     3,
		model.RoleOwner:     4,
	}
	return order[role] >= order[minRole]
}

// ── API token scopes ─────────────────────────────────────────────────────────
//
// Scopes and permissions deliberately share a vocabulary: a scope names a
// permission the token is allowed to exercise. The authority of a request is
// the intersection of the two — the role says what the person may do, the scope
// says how much of that authority this particular credential carries.
//
// A request authenticated by a user JWT has no token and therefore no scope
// restriction; its authority is its role alone.

// AllScopes is every scope a token may be granted, in the order the dashboard
// should present them.
var AllScopes = []Permission{
	PermReadSecrets,
	PermWriteSecrets,
	PermDeleteSecrets,
	PermViewAudit,
	PermManageTokens,
	PermManageMembers,
	PermManageBilling,
}

// ValidScope reports whether s names a scope we recognise. Unknown scopes are
// rejected at token creation rather than silently ignored: a token created with
// a typo'd scope would otherwise appear to grant something it does not.
func ValidScope(s string) bool {
	for _, p := range AllScopes {
		if string(p) == s {
			return true
		}
	}
	return false
}

// ScopesForRole returns every scope a role may be granted, in AllScopes
// order. Used by flows that mint a token on a role's behalf without an
// explicit scope list — e.g. the CLI login exchange — so the token carries
// exactly what the role allows, never more.
func ScopesForRole(role model.Role) []string {
	scopes := make([]string, 0, len(AllScopes))
	for _, p := range AllScopes {
		if HasPermission(role, p) {
			scopes = append(scopes, string(p))
		}
	}
	return scopes
}

// ScopesAllow reports whether a token carrying these scopes may exercise perm.
//
// A nil slice means "not scope-limited" — a user JWT rather than an API token.
// An empty non-nil slice means a token that was granted nothing, and is denied
// everything; that distinction is why the parameter is a slice and not a set.
func ScopesAllow(scopes []string, perm Permission) bool {
	if scopes == nil {
		return true
	}
	for _, s := range scopes {
		if s == string(perm) {
			return true
		}
	}
	return false
}

// Allows is the single authority check: the role must grant the permission and
// the token's scopes must include it. Call this rather than HasPermission
// anywhere a request is being authorized, so a scoped token cannot exercise
// authority its role happens to have.
func Allows(role model.Role, scopes []string, perm Permission) bool {
	return HasPermission(role, perm) && ScopesAllow(scopes, perm)
}

// LowerRole returns whichever of the two roles is less privileged. It is used
// to combine a token's role snapshot with its user's current role, so neither a
// later promotion nor a stale snapshot can grant more than both allow.
func LowerRole(a, b model.Role) model.Role {
	if IsAtLeast(a, b) {
		return b
	}
	return a
}
