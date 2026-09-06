package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nan0/backend/internal/model"
	"github.com/nan0/backend/internal/respond"
)

// ── Secret Sharing ──────────────────────────────────────────────────────────

type createShareRequest struct {
	Label     string            `json:"label"`
	Secrets   map[string]string `json:"secrets"`
	ExpiresIn string            `json:"expires_in"` // "1h", "24h", "7d", "30d"
	MaxViews  int               `json:"max_views"`  // 0 = unlimited
}

func parseExpiry(expiresIn string) time.Time {
	now := time.Now().UTC()
	switch expiresIn {
	case "1h":
		return now.Add(1 * time.Hour)
	case "24h":
		return now.Add(24 * time.Hour)
	case "7d":
		return now.Add(7 * 24 * time.Hour)
	case "30d":
		return now.Add(30 * 24 * time.Hour)
	default:
		return now.Add(24 * time.Hour) // default 24h
	}
}

func (h *Handler) CreateSharedSecret(w http.ResponseWriter, r *http.Request) {
	orgID, _ := getOrgID(r)
	userID, _ := getUserID(r)

	var req createShareRequest
	if err := respond.Decode(r, &req); err != nil || len(req.Secrets) == 0 {
		respond.Error(w, http.StatusBadRequest, "at least one secret key-value pair is required")
		return
	}

	if h.Crypto == nil {
		respond.Error(w, http.StatusServiceUnavailable, "encryption engine not configured")
		return
	}

	// Encrypt the secrets JSON blob
	secretsJSON, err := json.Marshal(req.Secrets)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to serialize secrets")
		return
	}

	encValue, encDEK, err := h.Crypto.Encrypt(string(secretsJSON))
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "encryption failed")
		return
	}

	expiresAt := parseExpiry(req.ExpiresIn)
	maxViews := req.MaxViews
	if maxViews < 0 {
		maxViews = 0
	}

	label := req.Label
	if label == "" {
		label = "Shared Secrets"
	}

	ss, err := h.Store.CreateSharedSecret(r.Context(), orgID, userID, label, encValue, encDEK, expiresAt.Format(time.RFC3339), maxViews)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to create shared secret")
		return
	}

	h.writeAudit(r, orgID, userID, "user", "share.created", "shared_secret", &ss.ID, map[string]interface{}{
		"label":      label,
		"key_count":  len(req.Secrets),
		"expires_in": req.ExpiresIn,
		"max_views":  maxViews,
	})

	respond.Created(w, ss)
}

// GetSharedSecret is a PUBLIC endpoint — no auth required.
func (h *Handler) GetSharedSecret(w http.ResponseWriter, r *http.Request) {
	shareID, err := uuid.Parse(chi.URLParam(r, "shareId"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid share ID")
		return
	}

	ss, err := h.Store.GetSharedSecret(r.Context(), shareID)
	if err != nil || ss == nil {
		respond.Error(w, http.StatusNotFound, "shared secret not found or expired")
		return
	}

	// Check expiry
	if time.Now().UTC().After(ss.ExpiresAt) {
		respond.Error(w, http.StatusGone, "this shared secret link has expired")
		return
	}

	// Check max views
	if ss.MaxViews > 0 && ss.ViewCount >= ss.MaxViews {
		respond.Error(w, http.StatusGone, "this shared secret link has reached its view limit")
		return
	}

	// Increment view count
	_, _ = h.Store.IncrementShareViewCount(r.Context(), shareID)

	// Decrypt
	if h.Crypto == nil {
		respond.Error(w, http.StatusServiceUnavailable, "decryption engine not available")
		return
	}

	plaintext, err := h.Crypto.Decrypt(ss.SecretsEnc, ss.EncryptedDEK)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "decryption failed")
		return
	}

	var secrets map[string]string
	if err := json.Unmarshal([]byte(plaintext), &secrets); err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to parse secrets")
		return
	}

	respond.OK(w, map[string]interface{}{
		"id":         ss.ID,
		"label":      ss.Label,
		"secrets":    secrets,
		"expires_at": ss.ExpiresAt,
		"view_count": ss.ViewCount + 1,
		"max_views":  ss.MaxViews,
		"created_at": ss.CreatedAt,
	})
}

// DeleteSharedSecret removes a share link (org member only).
func (h *Handler) DeleteSharedSecret(w http.ResponseWriter, r *http.Request) {
	shareID, err := uuid.Parse(chi.URLParam(r, "shareId"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid share ID")
		return
	}

	orgID, _ := getOrgID(r)
	userID, _ := getUserID(r)

	// Verify ownership
	ss, err := h.Store.GetSharedSecret(r.Context(), shareID)
	if err != nil || ss == nil || ss.OrgID != orgID {
		respond.Error(w, http.StatusNotFound, "shared secret not found")
		return
	}

	if err := h.Store.DeleteSharedSecret(r.Context(), shareID); err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to delete shared secret")
		return
	}

	h.writeAudit(r, orgID, userID, "user", "share.deleted", "shared_secret", &shareID, nil)

	respond.NoContent(w)
}

// ListSharedSecrets returns all share links for the org.
func (h *Handler) ListSharedSecrets(w http.ResponseWriter, r *http.Request) {
	orgID, _ := getOrgID(r)

	items, err := h.Store.ListSharedSecretsByOrg(r.Context(), orgID)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to list shared secrets")
		return
	}
	if items == nil {
		items = []*model.SharedSecret{}
	}

	respond.OK(w, items)
}
