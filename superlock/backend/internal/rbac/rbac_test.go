package rbac

import (
	"testing"

	"github.com/nan0/backend/internal/model"
)

// The regression this file exists for: a token minted with secrets:read used to
// carry its creator's entire role, so a read-only CI credential could write,
// delete, mint further tokens and change billing.
func TestScopedTokenCannotExceedItsScope(t *testing.T) {
	readOnly := []string{string(PermReadSecrets)}

	if !Allows(model.RoleOwner, readOnly, PermReadSecrets) {
		t.Error("owner with secrets:read should be able to read")
	}

	denied := []Permission{
		PermWriteSecrets, PermDeleteSecrets, PermViewAudit,
		PermManageTokens, PermManageMembers, PermManageBilling,
	}
	for _, perm := range denied {
		if Allows(model.RoleOwner, readOnly, perm) {
			t.Errorf("owner with only secrets:read was allowed %s", perm)
		}
	}
}

// A scope cannot grant authority the role lacks either — the check is an
// intersection, not an override.
func TestScopeCannotExceedRole(t *testing.T) {
	everything := make([]string, 0, len(AllScopes))
	for _, p := range AllScopes {
		everything = append(everything, string(p))
	}

	if Allows(model.RoleReader, everything, PermWriteSecrets) {
		t.Error("reader with a write scope was allowed to write")
	}
	if Allows(model.RoleDeveloper, everything, PermDeleteSecrets) {
		t.Error("developer with a delete scope was allowed to delete")
	}
	if Allows(model.RoleDeveloper, everything, PermManageBilling) {
		t.Error("developer with a billing scope was allowed to manage billing")
	}
	if !Allows(model.RoleOwner, everything, PermManageBilling) {
		t.Error("owner with a billing scope should be allowed to manage billing")
	}
}

func TestScopesAllowDistinguishesNilFromEmpty(t *testing.T) {
	// nil means "not scope-limited" — a user JWT.
	if !ScopesAllow(nil, PermManageBilling) {
		t.Error("nil scopes should not restrict; that is a JWT, not a token")
	}
	// An empty non-nil slice is a token granted nothing.
	if ScopesAllow([]string{}, PermReadSecrets) {
		t.Error("a token with no scopes was allowed to read")
	}
}

// The full role × scope × protected matrix for secret access.
func TestSecretAccessMatrix(t *testing.T) {
	read := []string{string(PermReadSecrets)}
	write := []string{string(PermWriteSecrets)}
	del := []string{string(PermDeleteSecrets)}
	rw := []string{string(PermReadSecrets), string(PermWriteSecrets)}

	tests := []struct {
		name      string
		role      model.Role
		scopes    []string
		protected bool
		canRead   bool
		canWrite  bool
		canDelete bool
	}{
		{"owner, JWT, normal env", model.RoleOwner, nil, false, true, true, true},
		{"owner, JWT, protected env", model.RoleOwner, nil, true, true, true, true},
		{"admin, JWT, protected env", model.RoleAdmin, nil, true, true, true, true},

		{"developer, JWT, normal env", model.RoleDeveloper, nil, false, true, true, false},
		{"developer, JWT, protected env", model.RoleDeveloper, nil, true, false, false, false},

		{"reader, JWT, normal env", model.RoleReader, nil, false, true, false, false},
		{"reader, JWT, protected env", model.RoleReader, nil, true, false, false, false},

		{"owner token, read scope, normal", model.RoleOwner, read, false, true, false, false},
		{"owner token, read scope, protected", model.RoleOwner, read, true, true, false, false},
		{"owner token, write scope, normal", model.RoleOwner, write, false, false, true, false},
		{"owner token, delete scope, normal", model.RoleOwner, del, false, false, false, true},
		{"owner token, read+write, protected", model.RoleOwner, rw, true, true, true, false},

		// A protected environment overrides the role table even when the scope
		// is present: developer is not owner or admin.
		{"developer token, read scope, protected", model.RoleDeveloper, read, true, false, false, false},
		{"developer token, write scope, normal", model.RoleDeveloper, write, false, false, true, false},

		// A delete scope does not make a developer an admin.
		{"developer token, delete scope", model.RoleDeveloper, del, false, false, false, false},

		{"token with no scopes", model.RoleOwner, []string{}, false, false, false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := CanReadSecret(tc.role, tc.scopes, tc.protected); got != tc.canRead {
				t.Errorf("CanReadSecret = %v, want %v", got, tc.canRead)
			}
			if got := CanWriteSecret(tc.role, tc.scopes, tc.protected); got != tc.canWrite {
				t.Errorf("CanWriteSecret = %v, want %v", got, tc.canWrite)
			}
			if got := CanDeleteSecret(tc.role, tc.scopes); got != tc.canDelete {
				t.Errorf("CanDeleteSecret = %v, want %v", got, tc.canDelete)
			}
		})
	}
}

func TestValidScope(t *testing.T) {
	for _, p := range AllScopes {
		if !ValidScope(string(p)) {
			t.Errorf("ValidScope(%q) = false, want true", p)
		}
	}
	for _, bad := range []string{"", "secrets", "secrets:*", "SECRETS:READ", "admin", "secrets:read ", "*"} {
		if ValidScope(bad) {
			t.Errorf("ValidScope(%q) = true, want false", bad)
		}
	}
}

// LowerRole is what stops a promotion from leaking backwards into tokens minted
// earlier, and what makes a demotion take effect on tokens already in the wild.
func TestLowerRole(t *testing.T) {
	tests := []struct{ a, b, want model.Role }{
		{model.RoleOwner, model.RoleReader, model.RoleReader},
		{model.RoleReader, model.RoleOwner, model.RoleReader},
		{model.RoleAdmin, model.RoleDeveloper, model.RoleDeveloper},
		{model.RoleOwner, model.RoleOwner, model.RoleOwner},
		{model.RoleDeveloper, model.RoleAdmin, model.RoleDeveloper},
	}
	for _, tc := range tests {
		if got := LowerRole(tc.a, tc.b); got != tc.want {
			t.Errorf("LowerRole(%s, %s) = %s, want %s", tc.a, tc.b, got, tc.want)
		}
	}
}

// The two scenarios the role snapshot exists for.
func TestRoleSnapshotSemantics(t *testing.T) {
	// Token minted while the user was a developer. The user is later promoted
	// to owner; the old token must not gain owner authority.
	if got := LowerRole(model.RoleDeveloper, model.RoleOwner); got != model.RoleDeveloper {
		t.Errorf("promotion leaked into an old token: got %s", got)
	}

	// Token minted while the user was an owner. The user is later demoted to
	// reader; the token must lose its authority immediately.
	if got := LowerRole(model.RoleOwner, model.RoleReader); got != model.RoleReader {
		t.Errorf("demotion did not reach an existing token: got %s", got)
	}
}

// ScopesForRole backs the CLI login exchange, which mints a token on the
// user's behalf with no explicit scope list — it must carry exactly what
// HasPermission grants the role, nothing more and nothing less.
func TestScopesForRole(t *testing.T) {
	for role, want := range rolePermissions {
		got := ScopesForRole(role)
		if len(got) != len(want) {
			t.Fatalf("ScopesForRole(%s) = %v, want %v", role, got, want)
		}
		for _, perm := range want {
			if !Allows(role, got, perm) {
				t.Errorf("ScopesForRole(%s) omitted %s", role, perm)
			}
		}
		for _, s := range got {
			if !HasPermission(role, Permission(s)) {
				t.Errorf("ScopesForRole(%s) included %s the role does not have", role, s)
			}
		}
	}
}
