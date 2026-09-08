package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/nan0/backend/internal/crypto"
	"github.com/nan0/backend/internal/rbac"
	"github.com/nan0/backend/internal/respond"
)

// cliLoginCodeTTL bounds how long a browser-approved CLI login code is
// redeemable. The exchange happens within milliseconds of the redirect in
// the happy path — this only needs to survive network jitter, not idle time.
const cliLoginCodeTTL = 60 * time.Second

type cliAuthorizeRequest struct {
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

// CLIAuthorize mints a one-time PKCE code for the CLI loopback login flow.
// The dashboard calls this, authenticated as the approving user, once they
// accept the request shown by `superlock auth login`. No API token is
// created here — only on a successful exchange (CLIAuthToken) — so nothing
// sensitive exists until the CLI proves possession of the code_verifier that
// matches the code_challenge it generated.
func (h *Handler) CLIAuthorize(w http.ResponseWriter, r *http.Request) {
	orgID, ok := getOrgID(r)
	if !ok {
		respond.Error(w, http.StatusForbidden, "no organization")
		return
	}
	userID, _ := getUserID(r)
	role := getRole(r)

	var req cliAuthorizeRequest
	if err := respond.Decode(r, &req); err != nil || req.CodeChallenge == "" {
		respond.Error(w, http.StatusBadRequest, "code_challenge is required")
		return
	}
	if req.CodeChallengeMethod != "" && req.CodeChallengeMethod != "S256" {
		respond.Error(w, http.StatusBadRequest, "unsupported code_challenge_method")
		return
	}

	rawCode, err := crypto.GenerateSecureToken(32)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to generate code")
		return
	}
	plainCode := "cliauth_" + rawCode
	codeHash := crypto.HashToken(plainCode)

	if err := h.Store.CreateCLILoginCode(r.Context(), orgID, userID, role, codeHash, req.CodeChallenge, time.Now().Add(cliLoginCodeTTL)); err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to create login code")
		return
	}

	respond.Created(w, map[string]interface{}{
		"code":       plainCode,
		"expires_in": int(cliLoginCodeTTL.Seconds()),
	})
}

type cliTokenExchangeRequest struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
}

// CLIAuthToken exchanges a one-time PKCE code for a real API token. It is
// deliberately unauthenticated — the CLI has no credentials yet at this
// point — and is safe because the code is single-use (claimed atomically),
// short-lived, and redeems nothing without the code_verifier that only the
// initiating CLI process holds.
func (h *Handler) CLIAuthToken(w http.ResponseWriter, r *http.Request) {
	var req cliTokenExchangeRequest
	if err := respond.Decode(r, &req); err != nil || req.Code == "" || req.CodeVerifier == "" {
		respond.Error(w, http.StatusBadRequest, "code and code_verifier are required")
		return
	}

	codeHash := crypto.HashToken(req.Code)
	claimed, err := h.Store.ClaimCLILoginCode(r.Context(), codeHash)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to redeem code")
		return
	}
	if claimed == nil {
		respond.Error(w, http.StatusUnauthorized, "code is invalid, expired, or already used")
		return
	}

	sum := sha256.Sum256([]byte(req.CodeVerifier))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])
	if expected != claimed.CodeChallenge {
		respond.Error(w, http.StatusUnauthorized, "code_verifier does not match")
		return
	}

	scopes := rbac.ScopesForRole(claimed.Role)
	rawToken, err := crypto.GenerateSecureToken(32)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to generate token")
		return
	}
	plainToken := "superlock_" + rawToken
	tokenHash := crypto.HashToken(plainToken)

	token, err := h.Store.CreateAPIToken(r.Context(), claimed.OrgID, claimed.UserID, "CLI Login", tokenHash, scopes, nil, claimed.Role)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to create token")
		return
	}

	h.writeAudit(r, claimed.OrgID, claimed.UserID, "user", "token.created", "token", &token.ID, map[string]interface{}{
		"token_name": token.Name,
		"scopes":     token.Scopes,
		"role":       token.Role,
		"via":        "cli_login",
	})

	respond.OK(w, map[string]interface{}{"token": plainToken})
}
