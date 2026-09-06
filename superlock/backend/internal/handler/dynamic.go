package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nan0/backend/internal/dynamic"
	"github.com/nan0/backend/internal/model"
	"github.com/nan0/backend/internal/respond"
)

// ── Dynamic secret config endpoints ─────────────────────────────────────────

type createDynamicConfigRequest struct {
	Name    string               `json:"name"`
	Backend model.DynamicBackend `json:"backend"`
	Config  json.RawMessage      `json:"config"`
}

func (h *Handler) CreateDynamicConfig(w http.ResponseWriter, r *http.Request) {
	orgID, ok := getOrgID(r)
	if !ok {
		respond.Error(w, http.StatusForbidden, "no organization")
		return
	}
	if !isAdminOrAbove(getRole(r)) {
		respond.Error(w, http.StatusForbidden, "admin required")
		return
	}

	eid, err := uuid.Parse(chi.URLParam(r, "eid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid environment id")
		return
	}

	var req createDynamicConfigRequest
	if err := respond.Decode(r, &req); err != nil || req.Name == "" {
		respond.Error(w, http.StatusBadRequest, "name and config are required")
		return
	}
	if req.Backend != model.DynamicBackendPostgres && req.Backend != model.DynamicBackendMySQL {
		respond.Error(w, http.StatusBadRequest, "backend must be 'postgres' or 'mysql'")
		return
	}

	// Encrypt the config_json (contains admin DSN) before storing
	configBytes, _ := json.Marshal(req.Config)
	encConfig, encDEK, encErr := h.Crypto.Encrypt(string(configBytes))
	if encErr != nil {
		respond.Error(w, http.StatusInternalServerError, "encryption failed")
		return
	}
	// Store as JSON with encrypted envelope
	storedConfig := json.RawMessage(fmt.Sprintf(`{"enc":"%s","dek":"%s"}`, encConfig, encDEK))

	userID, _ := getUserID(r)
	cfg, err := h.Store.CreateDynamicConfig(r.Context(), eid, userID, req.Name, req.Backend, storedConfig)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to create dynamic config")
		return
	}

	h.writeAudit(r, orgID, userID, "user", "dynamic.config.created", "dynamic_config", &cfg.ID, map[string]any{
		"backend": req.Backend,
		"name":    req.Name,
	})
	respond.Created(w, cfg)
}

func (h *Handler) ListDynamicConfigs(w http.ResponseWriter, r *http.Request) {
	eid, err := uuid.Parse(chi.URLParam(r, "eid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid environment id")
		return
	}
	configs, err := h.Store.ListDynamicConfigs(r.Context(), eid)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to list configs")
		return
	}
	if configs == nil {
		configs = []*model.DynamicSecretConfig{}
	}
	respond.OK(w, configs)
}

func (h *Handler) DeleteDynamicConfig(w http.ResponseWriter, r *http.Request) {
	if !isAdminOrAbove(getRole(r)) {
		respond.Error(w, http.StatusForbidden, "admin required")
		return
	}
	cfgID, err := uuid.Parse(chi.URLParam(r, "cfgid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid config id")
		return
	}
	if err := h.Store.DeleteDynamicConfig(r.Context(), cfgID); err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to delete config")
		return
	}
	respond.NoContent(w)
}

// ── Lease generation ─────────────────────────────────────────────────────────

func (h *Handler) GenerateDynamicSecret(w http.ResponseWriter, r *http.Request) {
	orgID, ok := getOrgID(r)
	if !ok {
		respond.Error(w, http.StatusForbidden, "no organization")
		return
	}

	cfgID, err := uuid.Parse(chi.URLParam(r, "cfgid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid config id")
		return
	}

	cfg, err := h.Store.GetDynamicConfig(r.Context(), cfgID)
	if err != nil || cfg == nil {
		respond.Error(w, http.StatusNotFound, "dynamic config not found")
		return
	}

	// Decrypt the stored config JSON
	var encEnvelope struct {
		Enc string `json:"enc"`
		DEK string `json:"dek"`
	}
	if err := json.Unmarshal(cfg.ConfigJSON, &encEnvelope); err != nil {
		respond.Error(w, http.StatusInternalServerError, "invalid config format")
		return
	}
	plainConfig, err := h.Crypto.Decrypt(encEnvelope.Enc, encEnvelope.DEK)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to decrypt config")
		return
	}

	userID, _ := getUserID(r)
	var lease *dynamic.LeaseResult

	switch cfg.Backend {
	case model.DynamicBackendPostgres:
		var pgCfg dynamic.PostgresConfig
		if err := json.Unmarshal([]byte(plainConfig), &pgCfg); err != nil {
			respond.Error(w, http.StatusInternalServerError, "invalid postgres config")
			return
		}
		lease, err = dynamic.GeneratePostgresLease(r.Context(), pgCfg)
	case model.DynamicBackendMySQL:
		var myCfg dynamic.MySQLConfig
		if err := json.Unmarshal([]byte(plainConfig), &myCfg); err != nil {
			respond.Error(w, http.StatusInternalServerError, "invalid mysql config")
			return
		}
		lease, err = dynamic.GenerateMySQLLease(r.Context(), myCfg)
	default:
		respond.Error(w, http.StatusBadRequest, "unsupported backend")
		return
	}

	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to generate credentials: "+err.Error())
		return
	}

	storedLease, err := h.Store.CreateDynamicLease(r.Context(), orgID, cfgID, userID,
		string(cfg.Backend), lease.Username, lease.DSN, lease.ExpiresAt)
	if err != nil {
		// Attempt to clean up the created DB role
		go func() {
			if cfg.Backend == model.DynamicBackendPostgres {
				var pgCfg dynamic.PostgresConfig
				_ = json.Unmarshal([]byte(plainConfig), &pgCfg)
				_ = dynamic.RevokePostgresLease(context.Background(), pgCfg.AdminDSN, lease.Username)
			}
		}()
		respond.Error(w, http.StatusInternalServerError, "failed to record lease")
		return
	}

	storedLease.Password = lease.Password // only returned once
	storedLease.DatabaseURL = lease.DSN

	h.writeAudit(r, orgID, userID, "user", "dynamic.secret.generated", "dynamic_config", &cfgID, map[string]any{
		"backend":    cfg.Backend,
		"username":   lease.Username,
		"expires_at": lease.ExpiresAt,
	})

	respond.Created(w, storedLease)
}

func (h *Handler) RevokeDynamicLease(w http.ResponseWriter, r *http.Request) {
	orgID, ok := getOrgID(r)
	if !ok {
		respond.Error(w, http.StatusForbidden, "no organization")
		return
	}
	leaseID, err := uuid.Parse(chi.URLParam(r, "lid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid lease id")
		return
	}
	// Mark revoked in DB (reaper handles actual DB role cleanup)
	if err := h.Store.RevokeLease(r.Context(), leaseID); err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to revoke lease")
		return
	}
	userID, _ := getUserID(r)
	h.writeAudit(r, orgID, userID, "user", "dynamic.secret.revoked", "dynamic_lease", &leaseID, nil)
	respond.OK(w, map[string]string{"status": "revoked"})
}

func (h *Handler) ListDynamicLeases(w http.ResponseWriter, r *http.Request) {
	orgID, ok := getOrgID(r)
	if !ok {
		respond.Error(w, http.StatusForbidden, "no organization")
		return
	}
	leases, err := h.Store.ListLeasesByOrg(r.Context(), orgID)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to list leases")
		return
	}
	if leases == nil {
		leases = []*model.DynamicSecretLease{}
	}
	respond.OK(w, leases)
}
