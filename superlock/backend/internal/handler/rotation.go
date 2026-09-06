package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nan0/backend/internal/crypto"
	"github.com/nan0/backend/internal/model"
	"github.com/nan0/backend/internal/netguard"
	"github.com/nan0/backend/internal/respond"
)

type createRotationRequest struct {
	IntervalHours int                   `json:"interval_hours"`
	Backend       model.RotationBackend `json:"backend"`
	Config        json.RawMessage       `json:"config"`
}

// rotationView is the API representation of a schedule. It deliberately omits
// config_json: that blob holds customer credentials (database DSNs, webhook
// headers, the signing secret) and must never leave the server after creation.
type rotationView struct {
	*model.RotationSchedule
	Config map[string]any `json:"config"`
	// SigningSecret is populated only in the create response.
	SigningSecret string `json:"signing_secret,omitempty"`
}

// safeConfig returns the non-credential fields of a rotation config, so the
// dashboard can show what was configured without echoing secrets back.
func safeConfig(backend model.RotationBackend, raw json.RawMessage) map[string]any {
	out := map[string]any{}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return out
	}

	switch backend {
	case model.RotationWebhook:
		// The URL is the customer's own endpoint, not a credential. Headers and
		// the signing secret are.
		if u, ok := cfg["url"].(string); ok {
			out["url"] = u
		}
		if hdrs, ok := cfg["headers"].(map[string]any); ok && len(hdrs) > 0 {
			names := make([]string, 0, len(hdrs))
			for k := range hdrs {
				names = append(names, k)
			}
			out["header_names"] = names
		}
	case model.RotationPostgres:
		if u, ok := cfg["username"].(string); ok {
			out["username"] = u
		}
	}
	return out
}

func newRotationView(s *model.RotationSchedule) *rotationView {
	return &rotationView{RotationSchedule: s, Config: safeConfig(s.Backend, s.ConfigJSON)}
}

func (h *Handler) CreateRotationSchedule(w http.ResponseWriter, r *http.Request) {
	orgID, ok := getOrgID(r)
	if !ok {
		respond.Error(w, http.StatusForbidden, "no organization")
		return
	}
	role := getRole(r)
	if !isAdminOrAbove(role) {
		respond.Error(w, http.StatusForbidden, "admin required")
		return
	}

	secretID, err := uuid.Parse(chi.URLParam(r, "sid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid secret id")
		return
	}

	secret, _ := h.verifySecretAccess(w, r, secretID)
	if secret == nil {
		return
	}

	var req createRotationRequest
	if err := respond.Decode(r, &req); err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.IntervalHours <= 0 {
		req.IntervalHours = 720
	}
	if req.Backend == "" {
		req.Backend = model.RotationWebhook
	}
	if req.Config == nil {
		req.Config = json.RawMessage("{}")
	}

	// Webhook schedules get their destination validated now rather than at the
	// first rotation, and are issued a signing secret so the receiver can prove
	// the request came from us.
	var signingSecret string
	if req.Backend == model.RotationWebhook {
		cfg := map[string]any{}
		if err := json.Unmarshal(req.Config, &cfg); err != nil {
			respond.Error(w, http.StatusBadRequest, "config must be a JSON object")
			return
		}

		rawURL, _ := cfg["url"].(string)
		if rawURL == "" {
			respond.Error(w, http.StatusBadRequest, "webhook config requires a url")
			return
		}
		guard := h.Guard
		if guard == nil {
			guard = netguard.New(false)
		}
		if _, err := guard.ParseURL(rawURL); err != nil {
			respond.Error(w, http.StatusBadRequest, "webhook url rejected: "+err.Error())
			return
		}

		token, err := crypto.GenerateSecureToken(32)
		if err != nil {
			respond.Error(w, http.StatusInternalServerError, "failed to generate signing secret")
			return
		}
		signingSecret = "whsec_" + token
		cfg["signing_secret"] = signingSecret

		merged, err := json.Marshal(cfg)
		if err != nil {
			respond.Error(w, http.StatusInternalServerError, "failed to encode config")
			return
		}
		req.Config = merged
	}

	userID, _ := getUserID(r)
	sched, err := h.Store.CreateRotationSchedule(r.Context(), secretID, userID, req.IntervalHours, req.Backend, req.Config)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to create schedule")
		return
	}

	h.writeAudit(r, orgID, userID, "user", "rotation.created", "secret", &secretID, map[string]any{
		"backend": req.Backend,
	})

	// The signing secret is returned exactly once: it is redacted from every
	// subsequent read, so a lost secret means recreating the schedule.
	view := newRotationView(sched)
	view.SigningSecret = signingSecret
	respond.Created(w, view)
}

func (h *Handler) TriggerRotation(w http.ResponseWriter, r *http.Request) {
	orgID, ok := getOrgID(r)
	if !ok {
		respond.Error(w, http.StatusForbidden, "no organization")
		return
	}
	role := getRole(r)
	if !isAdminOrAbove(role) {
		respond.Error(w, http.StatusForbidden, "admin required")
		return
	}

	secretID, err := uuid.Parse(chi.URLParam(r, "sid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid secret id")
		return
	}

	secret, _ := h.verifySecretAccess(w, r, secretID)
	if secret == nil {
		return
	}

	if h.Rotation == nil {
		respond.Error(w, http.StatusServiceUnavailable, "rotation worker not available")
		return
	}

	if err := h.Rotation.TriggerManual(r.Context(), secretID); err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to trigger rotation")
		return
	}

	userID, _ := getUserID(r)
	h.writeAudit(r, orgID, userID, "user", "rotation.triggered", "secret", &secretID, nil)
	respond.OK(w, map[string]string{"status": "rotation triggered"})
}

func (h *Handler) GetRotationSchedule(w http.ResponseWriter, r *http.Request) {
	secretID, err := uuid.Parse(chi.URLParam(r, "sid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid secret id")
		return
	}

	secret, _ := h.verifySecretAccess(w, r, secretID)
	if secret == nil {
		return
	}

	sched, err := h.Store.GetRotationScheduleBySecret(r.Context(), secretID)
	if err != nil {
		respond.Error(w, http.StatusNotFound, "no rotation schedule")
		return
	}
	respond.OK(w, newRotationView(sched))
}

func (h *Handler) ListRotationHistory(w http.ResponseWriter, r *http.Request) {
	secretID, err := uuid.Parse(chi.URLParam(r, "sid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid secret id")
		return
	}

	secret, _ := h.verifySecretAccess(w, r, secretID)
	if secret == nil {
		return
	}

	history, err := h.Store.ListRotationHistory(r.Context(), secretID, 20)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to list history")
		return
	}
	if history == nil {
		history = []*model.RotationHistory{}
	}
	respond.OK(w, history)
}

func (h *Handler) DeleteRotationSchedule(w http.ResponseWriter, r *http.Request) {
	orgID, ok := getOrgID(r)
	if !ok {
		respond.Error(w, http.StatusForbidden, "no organization")
		return
	}
	role := getRole(r)
	if !isAdminOrAbove(role) {
		respond.Error(w, http.StatusForbidden, "admin required")
		return
	}
	schedID, err := uuid.Parse(chi.URLParam(r, "schedid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid schedule id")
		return
	}

	// The route is keyed by schedule ID, so resolve it to its secret before
	// checking ownership.
	sched, err := h.Store.GetRotationScheduleByID(r.Context(), schedID)
	if err != nil || sched == nil {
		respond.Error(w, http.StatusNotFound, "rotation schedule not found")
		return
	}
	if secret, _ := h.verifySecretAccess(w, r, sched.SecretID); secret == nil {
		return
	}

	if err := h.Store.DeleteRotationSchedule(r.Context(), schedID); err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to delete schedule")
		return
	}
	userID, _ := getUserID(r)
	h.writeAudit(r, orgID, userID, "user", "rotation.deleted", "rotation_schedule", &schedID, nil)
	respond.NoContent(w)
}

func isAdminOrAbove(role model.Role) bool {
	return role == model.RoleOwner || role == model.RoleAdmin
}
