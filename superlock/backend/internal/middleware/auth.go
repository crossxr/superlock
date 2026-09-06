package middleware

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/nan0/backend/internal/crypto"
	"github.com/nan0/backend/internal/model"
	"github.com/nan0/backend/internal/rbac"
	"github.com/nan0/backend/internal/respond"
	"github.com/nan0/backend/internal/store"
)

type jwksCache struct {
	mu        sync.RWMutex
	keys      map[string]interface{}
	fetchedAt time.Time
}

var globalJWKSCache = &jwksCache{keys: make(map[string]interface{})}

const jwksCacheTTL = 10 * time.Minute

// AuthMiddleware verifies Supabase JWT tokens and loads the user into context.
func AuthMiddleware(jwtSecret, supabaseURL string, db *store.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr := extractBearerToken(r)
			if tokenStr == "" {
				respond.Error(w, http.StatusUnauthorized, "missing authorization token")
				return
			}

			claims, err := verifySupabaseJWT(tokenStr, jwtSecret, supabaseURL)
			if err != nil {
				sentry.CaptureException(fmt.Errorf("JWT Verification Error: %v", err))
				respond.Error(w, http.StatusUnauthorized, "invalid token")
				return
			}

			userID, err := uuid.Parse(claims.Subject)
			if err != nil {
				respond.Error(w, http.StatusUnauthorized, "invalid user ID in token")
				return
			}

			email := claims.Email
			if email == "" {
				// Fallback to user_metadata
				if metaEmail, ok := claims.UserMetadata["email"].(string); ok {
					email = metaEmail
				}
			}

			if email == "" {
				sentry.CaptureMessage(fmt.Sprintf("CRITICAL: No email found in JWT for user %s", userID))
				respond.Error(w, http.StatusUnauthorized, "email required but missing from token")
				return
			}

			// Load or create user in our DB
			user, err := db.GetUserByID(r.Context(), userID)
			if err != nil {
				sentry.CaptureException(fmt.Errorf("DB ERROR: GetUserByID failed for %s: %v", userID, err))
				respond.Error(w, http.StatusInternalServerError, "database error")
				return
			}

			if user == nil {
				// Auto-provision user on first login
				if email == "" {
					sentry.CaptureMessage(fmt.Sprintf("PROVISION FAILED: No email for user %s", userID))
					respond.Error(w, http.StatusUnauthorized, "email required for provisioning")
					return
				}

				sentry.CaptureMessage(fmt.Sprintf("AUTO-PROVISION: Creating user %s (%s)", userID, email))
				user, err = db.UpsertUser(r.Context(), userID, email, nil, model.RoleOwner)
				if err != nil {
					sentry.CaptureException(fmt.Errorf("AUTO-PROVISION ERROR: UpsertUser failed for %s: %v", userID, err))
					respond.Error(w, http.StatusInternalServerError, "failed to provision user")
					return
				}
			} else {
				// Update email or touch last_login_at if needed
				shouldTouch := user.Email != email || user.Email == "" || user.LastLoginAt == nil || time.Since(*user.LastLoginAt) > 1*time.Hour
				if shouldTouch && email != "" {
					user, _ = db.UpsertUser(r.Context(), userID, email, user.OrgID, user.Role)
				}
			}

			// ── Auto-provision Organization if missing ──
			if user.OrgID == nil {
				sentry.CaptureMessage(fmt.Sprintf("AUTO-PROVISION: Creating org for user %s (%s)", userID, email))
				orgName := "Personal"
				if parts := strings.Split(email, "@"); len(parts) > 0 {
					orgName = fmt.Sprintf("%s's Org", strings.Title(parts[0]))
				}

				org, err := db.CreateOrganization(r.Context(), orgName, model.PlanFree)
				if err != nil {
					sentry.CaptureException(fmt.Errorf("AUTO-PROVISION ERROR: CreateOrganization failed for user %s: %v", userID, err))
				} else {
					if err := db.UpdateUserOrg(r.Context(), user.ID, org.ID, model.RoleOwner); err != nil {
						sentry.CaptureException(fmt.Errorf("AUTO-PROVISION ERROR: UpdateUserOrg failed for user %s, org %s: %v", userID, org.ID, err))
					} else {
						user.OrgID = &org.ID
						user.Role = model.RoleOwner
					}
				}
			}

			// Inject into context
			ctx := context.WithValue(r.Context(), model.CtxUserID, userID)
			ctx = context.WithValue(ctx, model.CtxEmail, email)
			if user.OrgID != nil {
				ctx = context.WithValue(ctx, model.CtxOrgID, *user.OrgID)
			}
			ctx = context.WithValue(ctx, model.CtxRole, user.Role)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// APITokenMiddleware validates API tokens (for SDK/CLI access).
func APITokenMiddleware(db *store.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr := extractBearerToken(r)
			if tokenStr == "" {
				respond.Error(w, http.StatusUnauthorized, "missing authorization token")
				return
			}

			// Hash the token and look it up
			tokenHash := crypto.HashToken(tokenStr)
			token, err := db.GetAPITokenByHash(r.Context(), tokenHash)
			if err != nil || token == nil {
				respond.Error(w, http.StatusUnauthorized, "invalid or expired API token")
				return
			}

			// Update last_used_at async
			go func() {
				_ = db.TouchAPIToken(context.Background(), token.ID)
			}()

			// Load user
			user, err := db.GetUserByID(r.Context(), token.UserID)
			if err != nil || user == nil {
				respond.Error(w, http.StatusUnauthorized, "token user not found")
				return
			}

			next.ServeHTTP(w, r.WithContext(tokenContext(r, token, user)))
		})
	}
}

// tokenContext builds the request context for an API-token-authenticated
// request.
//
// Two things are deliberate here. The role is the *lower* of the snapshot taken
// when the token was minted and the user's current role: the snapshot stops a
// later promotion from silently upgrading tokens issued earlier, and the live
// role makes a demotion take effect immediately on credentials already in the
// wild. Previously only the live role was consulted, so tokens tracked their
// creator's authority upward forever.
//
// The scopes are placed in the context so downstream authorization can
// intersect them with the role. A user JWT sets no scopes at all, which
// rbac.ScopesAllow reads as "not scope-limited".
func tokenContext(r *http.Request, token *model.APIToken, user *model.User) context.Context {
	ctx := context.WithValue(r.Context(), model.CtxUserID, token.UserID)
	if user.OrgID != nil {
		ctx = context.WithValue(ctx, model.CtxOrgID, *user.OrgID)
	}
	ctx = context.WithValue(ctx, model.CtxRole, rbac.LowerRole(token.Role, user.Role))

	// Always set scopes, even when empty: an empty non-nil slice is a token
	// that was granted nothing and must be denied everything, which is a
	// different thing from an unscoped JWT.
	scopes := token.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	return context.WithValue(ctx, model.CtxScopes, scopes)
}

// FlexAuthMiddleware tries Supabase JWT first; if that fails, falls back to
// API token validation. This allows both browser (JWT) and CLI (API token)
// callers to access the same routes.
func FlexAuthMiddleware(jwtSecret, supabaseURL string, db *store.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr := extractBearerToken(r)
			if tokenStr == "" {
				respond.Error(w, http.StatusUnauthorized, "missing authorization token")
				return
			}

			// ── Attempt 1: Supabase JWT ──
			claims, jwtErr := verifySupabaseJWT(tokenStr, jwtSecret, supabaseURL)
			if jwtErr == nil && claims != nil {
				userID, err := uuid.Parse(claims.Subject)
				if err != nil {
					respond.Error(w, http.StatusUnauthorized, "invalid user ID in token")
					return
				}
				email := claims.Email
				if email == "" {
					if metaEmail, ok := claims.UserMetadata["email"].(string); ok {
						email = metaEmail
					}
				}

				if email == "" {
					sentry.CaptureMessage(fmt.Sprintf("CRITICAL: No email found in JWT for user %s", userID))
					respond.Error(w, http.StatusUnauthorized, "email required but missing from token")
					return
				}

				user, err := db.GetUserByID(r.Context(), userID)
				if err != nil || user == nil {
					sentry.CaptureMessage(fmt.Sprintf("FLEX AUTO-PROVISION: Creating user %s with email %s", userID, email))
					user, err = db.UpsertUser(r.Context(), userID, email, nil, model.RoleOwner)
					if err != nil {
						sentry.CaptureException(fmt.Errorf("FLEX AUTO-PROVISION ERROR: UpsertUser failed for %s: %v", userID, err))
						respond.Error(w, http.StatusInternalServerError, "failed to provision user")
						return
					}
				} else {
					// Update email or touch last_login_at if needed
					shouldTouch := user.Email != email || user.Email == "" || user.LastLoginAt == nil || time.Since(*user.LastLoginAt) > 1*time.Hour
					if shouldTouch {
						user, _ = db.UpsertUser(r.Context(), userID, email, user.OrgID, user.Role)
					}
				}

				// ── Auto-provision Organization if missing ──
				if user.OrgID == nil {
					sentry.CaptureMessage(fmt.Sprintf("FLEX AUTO-PROVISION: Creating org for user %s (%s)", userID, email))
					org, err := db.CreateOrganization(r.Context(), "Personal", model.PlanFree)
					if err != nil {
						sentry.CaptureException(fmt.Errorf("FLEX AUTO-PROVISION ERROR: CreateOrganization failed for user %s: %v", userID, err))
					} else {
						if err := db.UpdateUserOrg(r.Context(), user.ID, org.ID, model.RoleOwner); err != nil {
							sentry.CaptureException(fmt.Errorf("FLEX AUTO-PROVISION ERROR: UpdateUserOrg failed for user %s, org %s: %v", userID, org.ID, err))
						} else {
							user.OrgID = &org.ID
							user.Role = model.RoleOwner
						}
					}
				}

				ctx := context.WithValue(r.Context(), model.CtxUserID, userID)
				ctx = context.WithValue(ctx, model.CtxEmail, email)
				if user.OrgID != nil {
					ctx = context.WithValue(ctx, model.CtxOrgID, *user.OrgID)
				}
				ctx = context.WithValue(ctx, model.CtxRole, user.Role)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// ── Attempt 2: API token ──
			tokenHash := crypto.HashToken(tokenStr)
			token, err := db.GetAPITokenByHash(r.Context(), tokenHash)
			if err != nil || token == nil {
				respond.Error(w, http.StatusUnauthorized, "invalid token")
				return
			}

			go func() {
				_ = db.TouchAPIToken(context.Background(), token.ID)
			}()

			user, err := db.GetUserByID(r.Context(), token.UserID)
			if err != nil || user == nil {
				respond.Error(w, http.StatusUnauthorized, "token user not found")
				return
			}

			next.ServeHTTP(w, r.WithContext(tokenContext(r, token, user)))
		})
	}
}

// RequireOrg ensures the user has an org. Used after AuthMiddleware.
func RequireOrg(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		orgID, ok := r.Context().Value(model.CtxOrgID).(uuid.UUID)
		if !ok || orgID == uuid.Nil {
			respond.Error(w, http.StatusForbidden, "no organization — create one first")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// GetScopes returns the API token scopes on the request, and whether the
// request was scope-limited at all. A user JWT is not, and reports false.
func GetScopes(r *http.Request) ([]string, bool) {
	scopes, ok := r.Context().Value(model.CtxScopes).([]string)
	return scopes, ok
}

// RequireScope blocks a request whose credential does not carry perm.
//
// This is the token half of authorization and is applied at the router, so a
// route is protected by virtue of being registered rather than by a handler
// remembering to check. Role checks stay in the handlers, where the resource —
// and whether its environment is protected — is known. A request must pass
// both.
func RequireScope(perm rbac.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scopes, scoped := GetScopes(r)
			if scoped && !rbac.ScopesAllow(scopes, perm) {
				respond.Error(w, http.StatusForbidden,
					"this token is missing the required scope: "+string(perm))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole ensures the user has at least the given role.
func RequireRole(minRole model.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role, _ := r.Context().Value(model.CtxRole).(model.Role)
			order := map[model.Role]int{
				model.RoleReader: 1, model.RoleDeveloper: 2,
				model.RoleAdmin: 3, model.RoleOwner: 4,
			}
			if order[role] < order[minRole] {
				respond.Error(w, http.StatusForbidden, "insufficient permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SupabaseClaims represents the JWT claims from Supabase.
type SupabaseClaims struct {
	jwt.RegisteredClaims
	Email        string                 `json:"email"`
	UserMetadata map[string]interface{} `json:"user_metadata"`
	RawClaims    map[string]interface{} `json:"-"`
}

func verifySupabaseJWT(tokenStr, secret, supabaseURL string) (*SupabaseClaims, error) {
	claims := &SupabaseClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		switch t.Method.(type) {
		case *jwt.SigningMethodHMAC:
			if secret == "" {
				return nil, fmt.Errorf("SUPABASE_JWT_SECRET not configured")
			}
			return []byte(secret), nil
		case *jwt.SigningMethodRSA, *jwt.SigningMethodECDSA:
			kid, _ := t.Header["kid"].(string)
			if kid == "" {
				return nil, fmt.Errorf("missing kid in token header")
			}
			pubKey, keyErr := getPublicKeyFromJWKS(supabaseURL, kid)
			if keyErr != nil {
				return nil, fmt.Errorf("JWKS lookup failed: %w", keyErr)
			}
			return pubKey, nil
		default:
			return nil, fmt.Errorf("unsupported alg: %v", t.Method.Alg())
		}
	})

	if err != nil || token == nil || !token.Valid {
		return nil, err
	}

	// Extract all claims for context
	if mapClaims, ok := token.Claims.(jwt.MapClaims); ok {
		claims.RawClaims = mapClaims
	}

	return claims, nil
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Crv string `json:"crv"`
}

func getPublicKeyFromJWKS(supabaseURL, kid string) (interface{}, error) {
	if supabaseURL == "" {
		return nil, fmt.Errorf("SUPABASE_URL is required for token verification")
	}

	now := time.Now()
	globalJWKSCache.mu.RLock()
	if now.Sub(globalJWKSCache.fetchedAt) < jwksCacheTTL {
		if key, ok := globalJWKSCache.keys[kid]; ok {
			globalJWKSCache.mu.RUnlock()
			return key, nil
		}
	}
	globalJWKSCache.mu.RUnlock()

	if err := refreshJWKSCache(supabaseURL); err != nil {
		return nil, err
	}

	globalJWKSCache.mu.RLock()
	defer globalJWKSCache.mu.RUnlock()
	key, ok := globalJWKSCache.keys[kid]
	if !ok {
		return nil, fmt.Errorf("kid not found in JWKS: %s", kid)
	}
	return key, nil
}

func refreshJWKSCache(supabaseURL string) error {
	url := strings.TrimRight(supabaseURL, "/") + "/auth/v1/.well-known/jwks.json"

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks request failed: %s", resp.Status)
	}

	var set jwkSet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return err
	}

	newKeys := make(map[string]interface{})
	for _, key := range set.Keys {
		if key.Kid == "" {
			continue
		}
		if key.Kty == "RSA" && key.N != "" && key.E != "" {
			pub, err := rsaPublicKeyFromJWK(key.N, key.E)
			if err == nil {
				newKeys[key.Kid] = pub
			}
		} else if key.Kty == "EC" && key.X != "" && key.Y != "" && key.Crv != "" {
			pub, err := ecdsaPublicKeyFromJWK(key.Crv, key.X, key.Y)
			if err == nil {
				newKeys[key.Kid] = pub
			}
		}
	}

	if len(newKeys) == 0 {
		return fmt.Errorf("jwks did not contain usable keys")
	}

	globalJWKSCache.mu.Lock()
	globalJWKSCache.keys = newKeys
	globalJWKSCache.fetchedAt = time.Now()
	globalJWKSCache.mu.Unlock()

	return nil
}

func rsaPublicKeyFromJWK(nBase64URL, eBase64URL string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nBase64URL)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eBase64URL)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() {
		return nil, fmt.Errorf("invalid RSA exponent")
	}

	pub := &rsa.PublicKey{N: n, E: int(e.Int64())}
	if pub.E <= 0 {
		return nil, fmt.Errorf("invalid RSA exponent value")
	}
	return pub, nil
}

func ecdsaPublicKeyFromJWK(crv, xBase64URL, yBase64URL string) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xBase64URL)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yBase64URL)
	if err != nil {
		return nil, err
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("invalid ECDSA public key")
	}
	return pub, nil
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	// Also allow superlock_token_ prefix for API tokens in query string (CLI use)
	if q := r.URL.Query().Get("token"); q != "" {
		return q
	}
	return ""
}
