package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nan0/backend/internal/model"
	"github.com/nan0/backend/internal/rbac"
)

func requestWithScopes(scopes []string, scoped bool) *http.Request {
	r := httptest.NewRequest("GET", "/v1/projects", nil)
	if !scoped {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), model.CtxScopes, scopes))
}

func TestRequireScope(t *testing.T) {
	tests := []struct {
		name       string
		scopes     []string
		scoped     bool
		required   rbac.Permission
		wantStatus int
	}{
		{
			name:     "user JWT is not scope-limited",
			scoped:   false,
			required: rbac.PermManageBilling, wantStatus: http.StatusOK,
		},
		{
			name:   "token carrying the scope passes",
			scopes: []string{string(rbac.PermReadSecrets)}, scoped: true,
			required: rbac.PermReadSecrets, wantStatus: http.StatusOK,
		},
		{
			name:   "token missing the scope is refused",
			scopes: []string{string(rbac.PermReadSecrets)}, scoped: true,
			required: rbac.PermWriteSecrets, wantStatus: http.StatusForbidden,
		},
		{
			name:   "token with no scopes is refused everything",
			scopes: []string{}, scoped: true,
			required: rbac.PermReadSecrets, wantStatus: http.StatusForbidden,
		},
		{
			name: "one of several scopes matches",
			scopes: []string{
				string(rbac.PermReadSecrets),
				string(rbac.PermWriteSecrets),
			}, scoped: true,
			required: rbac.PermWriteSecrets, wantStatus: http.StatusOK,
		},
		{
			name:   "a read scope does not imply delete",
			scopes: []string{string(rbac.PermReadSecrets), string(rbac.PermWriteSecrets)}, scoped: true,
			required: rbac.PermDeleteSecrets, wantStatus: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reached := false
			h := RequireScope(tc.required)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			}))

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, requestWithScopes(tc.scopes, tc.scoped))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if reached != (tc.wantStatus == http.StatusOK) {
				t.Fatalf("handler reached = %v, want %v", reached, tc.wantStatus == http.StatusOK)
			}
		})
	}
}

// A denial must not disclose which scopes the token does carry.
func TestRequireScopeDenialNamesOnlyTheMissingScope(t *testing.T) {
	h := RequireScope(rbac.PermManageBilling)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler should not have been reached")
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, requestWithScopes([]string{
		string(rbac.PermReadSecrets),
		string(rbac.PermManageTokens),
	}, true))

	body := rec.Body.String()
	if !contains(body, string(rbac.PermManageBilling)) {
		t.Errorf("response should name the required scope, got %q", body)
	}
	for _, held := range []string{string(rbac.PermReadSecrets), string(rbac.PermManageTokens)} {
		if contains(body, held) {
			t.Errorf("response disclosed a held scope %q: %s", held, body)
		}
	}
}

func TestGetScopes(t *testing.T) {
	if _, scoped := GetScopes(requestWithScopes(nil, false)); scoped {
		t.Error("a JWT request reported itself as scope-limited")
	}
	scopes, scoped := GetScopes(requestWithScopes([]string{"secrets:read"}, true))
	if !scoped {
		t.Fatal("a token request reported itself as unscoped")
	}
	if len(scopes) != 1 || scopes[0] != "secrets:read" {
		t.Fatalf("scopes = %v, want [secrets:read]", scopes)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		}()
}
