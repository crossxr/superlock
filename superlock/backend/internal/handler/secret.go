package handler

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nan0/backend/internal/billing"
	"github.com/nan0/backend/internal/model"
	"github.com/nan0/backend/internal/rbac"
	"github.com/nan0/backend/internal/references"
	"github.com/nan0/backend/internal/respond"
	"github.com/nan0/backend/internal/store"
)

type createSecretRequest struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type updateSecretRequest struct {
	Value string `json:"value"`
}

// verifyEnvAccess checks that the env belongs to a project owned by this org.
// Returns env and project or writes error and returns nil.
func (h *Handler) verifyEnvAccess(w http.ResponseWriter, r *http.Request, envID uuid.UUID) (*model.Environment, *model.Project) {
	orgID, _ := getOrgID(r)

	env, err := h.DB.GetEnvironmentByID(r.Context(), envID)
	if err != nil || env == nil {
		respond.Error(w, http.StatusNotFound, "environment not found")
		return nil, nil
	}

	project, err := h.DB.GetProjectByID(r.Context(), env.ProjectID)
	if err != nil || project == nil || project.OrgID != orgID {
		respond.Error(w, http.StatusForbidden, "access denied")
		return nil, nil
	}

	return env, project
}

// verifySecretAccess resolves a secret and confirms it belongs to the caller's
// org, walking secret -> environment -> project -> org. It writes the error
// response and returns nils when access is denied, mirroring verifyEnvAccess.
//
// Every handler that takes a secret ID from the URL must call this before
// touching the secret or anything hanging off it.
func (h *Handler) verifySecretAccess(w http.ResponseWriter, r *http.Request, secretID uuid.UUID) (*model.Secret, *model.Environment) {
	secret, err := h.DB.GetSecretByID(r.Context(), secretID)
	if err != nil || secret == nil {
		respond.Error(w, http.StatusNotFound, "secret not found")
		return nil, nil
	}

	env, project := h.verifyEnvAccess(w, r, secret.EnvID)
	if env == nil || project == nil {
		return nil, nil
	}

	return secret, env
}

func (h *Handler) ListSecrets(w http.ResponseWriter, r *http.Request) {
	eid, err := uuid.Parse(chi.URLParam(r, "eid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid environment ID")
		return
	}

	env, _ := h.verifyEnvAccess(w, r, eid)
	if env == nil {
		return
	}

	role := getRole(r)
	if !rbac.CanReadSecret(role, getScopes(r), env.IsProtected) {
		respond.Error(w, http.StatusForbidden, "insufficient permissions for this environment")
		return
	}

	secrets, err := h.DB.ListSecretsByEnv(r.Context(), eid)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to list secrets")
		return
	}
	if secrets == nil {
		secrets = []*model.Secret{}
	}

	// Never return values in list endpoint
	for _, s := range secrets {
		s.Value = ""
		s.EncryptedValue = ""
		s.EncryptedDEK = ""
	}

	respond.OK(w, secrets)
}

func (h *Handler) GetSecret(w http.ResponseWriter, r *http.Request) {
	sid, err := uuid.Parse(chi.URLParam(r, "sid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid secret ID")
		return
	}

	secret, err := h.DB.GetSecretByID(r.Context(), sid)
	if err != nil || secret == nil {
		respond.Error(w, http.StatusNotFound, "secret not found")
		return
	}

	env, _ := h.verifyEnvAccess(w, r, secret.EnvID)
	if env == nil {
		return
	}

	orgID, _ := getOrgID(r)
	userID, _ := getUserID(r)
	role := getRole(r)

	if !rbac.CanReadSecret(role, getScopes(r), env.IsProtected) {
		respond.Error(w, http.StatusForbidden, "insufficient permissions for this environment")
		return
	}

	// Decrypt value
	if h.Crypto != nil {
		value, err := h.Crypto.Decrypt(secret.EncryptedValue, secret.EncryptedDEK)
		if err != nil {
			respond.Error(w, http.StatusInternalServerError, "decryption failed")
			return
		}
		secret.Value = value
	}
	secret.EncryptedValue = ""
	secret.EncryptedDEK = ""

	// Resolve ${secret:KEY} references
	if references.HasReferences(secret.Value) {
		fetcher := func(ctx context.Context, envID uuid.UUID, key string) (string, error) {
			ref, err := h.Store.GetSecretByKey(ctx, envID, key)
			if err != nil || ref == nil {
				return "", fmt.Errorf("ref not found: %s", key)
			}
			return h.Crypto.Decrypt(ref.EncryptedValue, ref.EncryptedDEK)
		}
		resolved, err := references.Resolve(r.Context(), secret.Value, secret.EnvID, fetcher, 5)
		if err == nil {
			secret.Value = resolved
		}
	}

	h.writeAudit(r, orgID, userID, "user", "secret.read", "secret", &sid, map[string]interface{}{
		"key":    secret.Key,
		"env_id": secret.EnvID.String(),
	})
	// Write access analytics log (fire-and-forget)
	h.Store.WriteAccessLog(r.Context(), sid, orgID, userID, secret.EnvID, "user")

	respond.OK(w, secret)
}

func (h *Handler) CreateSecret(w http.ResponseWriter, r *http.Request) {
	eid, err := uuid.Parse(chi.URLParam(r, "eid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid environment ID")
		return
	}

	env, _ := h.verifyEnvAccess(w, r, eid)
	if env == nil {
		return
	}

	orgID, _ := getOrgID(r)
	userID, _ := getUserID(r)
	role := getRole(r)

	if !rbac.CanWriteSecret(role, getScopes(r), env.IsProtected) {
		respond.Error(w, http.StatusForbidden, "insufficient permissions for this environment")
		return
	}

	// ── Plan enforcement: secret count ──
	org, _ := h.Store.GetOrganizationByID(r.Context(), orgID)
	if org != nil {
		limits := billing.GetLimits(org.PlanTier)
		secretCount, _ := h.Store.CountOrgSecrets(r.Context(), orgID)
		if billing.ExceedsLimit(limits.MaxSecrets, secretCount) {
			respond.Error(w, http.StatusPaymentRequired, fmt.Sprintf("secret limit reached (%d on %s plan) — upgrade to create more", limits.MaxSecrets, org.PlanTier))
			return
		}
	}

	var req createSecretRequest
	if err := respond.Decode(r, &req); err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Key = strings.TrimSpace(strings.ToUpper(req.Key))
	if req.Key == "" {
		respond.Error(w, http.StatusBadRequest, "key is required")
		return
	}

	// Check for duplicate key in this env
	existing, _ := h.DB.GetSecretByKey(r.Context(), eid, req.Key)
	if existing != nil {
		respond.Error(w, http.StatusConflict, "secret with this key already exists in this environment")
		return
	}

	if h.Crypto == nil {
		respond.Error(w, http.StatusServiceUnavailable, "encryption engine not configured")
		return
	}

	encValue, encDEK, err := h.Crypto.Encrypt(req.Value)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "encryption failed")
		return
	}

	secret, err := h.DB.CreateSecret(r.Context(), eid, userID, req.Key, encValue, encDEK)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to create secret")
		return
	}

	// Invalidate env cache
	if h.Cache != nil {
		_ = h.Cache.InvalidateEnvEtag(r.Context(), eid.String())
	}

	h.writeAudit(r, orgID, userID, "user", "secret.write", "secret", &secret.ID, map[string]interface{}{
		"key":    secret.Key,
		"env_id": eid.String(),
	})

	secret.EncryptedValue = ""
	secret.EncryptedDEK = ""
	respond.Created(w, secret)
}

func (h *Handler) UpdateSecret(w http.ResponseWriter, r *http.Request) {
	sid, err := uuid.Parse(chi.URLParam(r, "sid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid secret ID")
		return
	}

	secret, err := h.DB.GetSecretByID(r.Context(), sid)
	if err != nil || secret == nil {
		respond.Error(w, http.StatusNotFound, "secret not found")
		return
	}

	env, _ := h.verifyEnvAccess(w, r, secret.EnvID)
	if env == nil {
		return
	}

	orgID, _ := getOrgID(r)
	userID, _ := getUserID(r)
	role := getRole(r)

	if !rbac.CanWriteSecret(role, getScopes(r), env.IsProtected) {
		respond.Error(w, http.StatusForbidden, "insufficient permissions for this environment")
		return
	}

	var req updateSecretRequest
	if err := respond.Decode(r, &req); err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Save old version
	_ = h.DB.SaveSecretVersion(r.Context(), secret)

	encValue, encDEK, err := h.Crypto.Encrypt(req.Value)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "encryption failed")
		return
	}

	updated, err := h.DB.UpdateSecret(r.Context(), sid, encValue, encDEK)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to update secret")
		return
	}

	if h.Cache != nil {
		_ = h.Cache.InvalidateEnvEtag(r.Context(), secret.EnvID.String())
	}

	h.writeAudit(r, orgID, userID, "user", "secret.write", "secret", &sid, map[string]interface{}{
		"key":         secret.Key,
		"env_id":      secret.EnvID.String(),
		"old_version": secret.Version,
		"new_version": updated.Version,
	})

	updated.EncryptedValue = ""
	updated.EncryptedDEK = ""
	respond.OK(w, updated)
}

func (h *Handler) DeleteSecret(w http.ResponseWriter, r *http.Request) {
	sid, err := uuid.Parse(chi.URLParam(r, "sid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid secret ID")
		return
	}

	secret, err := h.DB.GetSecretByID(r.Context(), sid)
	if err != nil || secret == nil {
		respond.Error(w, http.StatusNotFound, "secret not found")
		return
	}

	env, _ := h.verifyEnvAccess(w, r, secret.EnvID)
	if env == nil {
		return
	}

	orgID, _ := getOrgID(r)
	userID, _ := getUserID(r)
	role := getRole(r)

	if !rbac.CanDeleteSecret(role, getScopes(r)) {
		respond.Error(w, http.StatusForbidden, "admin or owner role required to delete secrets")
		return
	}

	if err := h.DB.DeleteSecret(r.Context(), sid); err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to delete secret")
		return
	}

	if h.Cache != nil {
		_ = h.Cache.InvalidateEnvEtag(r.Context(), secret.EnvID.String())
	}

	h.writeAudit(r, orgID, userID, "user", "secret.delete", "secret", &sid, map[string]interface{}{
		"key":    secret.Key,
		"env_id": secret.EnvID.String(),
	})

	respond.NoContent(w)
}

func (h *Handler) ListSecretVersions(w http.ResponseWriter, r *http.Request) {
	sid, err := uuid.Parse(chi.URLParam(r, "sid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid secret ID")
		return
	}

	secret, err := h.DB.GetSecretByID(r.Context(), sid)
	if err != nil || secret == nil {
		respond.Error(w, http.StatusNotFound, "secret not found")
		return
	}

	env, _ := h.verifyEnvAccess(w, r, secret.EnvID)
	if env == nil {
		return
	}

	versions, err := h.DB.ListSecretVersions(r.Context(), sid)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to list versions")
		return
	}
	if versions == nil {
		versions = []*model.SecretVersion{}
	}

	// Strip encrypted data from response
	for _, v := range versions {
		v.EncryptedValue = ""
		v.EncryptedDEK = ""
	}

	respond.OK(w, versions)
}

// BulkPullSecrets returns all decrypted secrets for an environment (SDK optimized).
func (h *Handler) BulkPullSecrets(w http.ResponseWriter, r *http.Request) {
	eid, err := uuid.Parse(chi.URLParam(r, "eid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid environment ID")
		return
	}

	env, _ := h.verifyEnvAccess(w, r, eid)
	if env == nil {
		return
	}

	role := getRole(r)
	if !rbac.CanReadSecret(role, getScopes(r), env.IsProtected) {
		respond.Error(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	secrets, err := h.DB.ListSecretsByEnv(r.Context(), eid)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to fetch secrets")
		return
	}

	result := make(map[string]string, len(secrets))
	for _, s := range secrets {
		if h.Crypto != nil {
			value, err := h.Crypto.Decrypt(s.EncryptedValue, s.EncryptedDEK)
			if err == nil {
				result[s.Key] = value
			}
		}
	}

	orgID, _ := getOrgID(r)
	userID, _ := getUserID(r)
	h.writeAudit(r, orgID, userID, "user", "secret.bulk_read", "environment", &eid, map[string]interface{}{
		"count": len(result),
	})

	// Log access for each secret for analytics
	actorID, _ := getUserID(r)
	for _, s := range secrets {
		h.Store.WriteAccessLog(r.Context(), s.ID, orgID, actorID, eid, "api_token")
	}

	respond.OK(w, result)
}

// WatchEnvironment upgrades the request to a WebSocket that streams cache
// invalidation events for one environment.
//
// The environment ID arrives in the URL, so ownership must be proven before
// the upgrade: without it any valid token could subscribe to any org's
// environment and watch its secret keys and change events go by.
func (h *Handler) WatchEnvironment(w http.ResponseWriter, r *http.Request) {
	if h.Hub == nil {
		respond.Error(w, http.StatusServiceUnavailable, "watch is not available")
		return
	}

	eid, err := uuid.Parse(chi.URLParam(r, "eid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid environment ID")
		return
	}

	env, _ := h.verifyEnvAccess(w, r, eid)
	if env == nil {
		return
	}

	if !rbac.CanReadSecret(getRole(r), getScopes(r), env.IsProtected) {
		respond.Error(w, http.StatusForbidden, "insufficient permissions for this environment")
		return
	}

	h.Hub.ServeWS(w, r, eid.String())
}

type bulkImportSecretPayload struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type bulkImportRequest struct {
	Secrets   []bulkImportSecretPayload `json:"secrets"`
	Overwrite bool                      `json:"overwrite"`
}

func (h *Handler) BulkImportSecrets(w http.ResponseWriter, r *http.Request) {
	eid, err := uuid.Parse(chi.URLParam(r, "eid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid environment ID")
		return
	}

	env, _ := h.verifyEnvAccess(w, r, eid)
	if env == nil {
		return
	}

	orgID, _ := getOrgID(r)
	userID, _ := getUserID(r)
	role := getRole(r)

	if !rbac.CanWriteSecret(role, getScopes(r), env.IsProtected) {
		respond.Error(w, http.StatusForbidden, "insufficient permissions for this environment")
		return
	}

	var req bulkImportRequest
	if err := respond.Decode(r, &req); err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Secrets) == 0 {
		respond.Error(w, http.StatusBadRequest, "at least one secret is required")
		return
	}

	if h.Crypto == nil {
		respond.Error(w, http.StatusServiceUnavailable, "encryption engine not configured")
		return
	}

	// Clean and normalize keys, deduplicate within payload
	cleanItems := make(map[string]string)
	for _, s := range req.Secrets {
		k := strings.TrimSpace(strings.ToUpper(s.Key))
		if k != "" {
			cleanItems[k] = s.Value
		}
	}

	if len(cleanItems) == 0 {
		respond.Error(w, http.StatusBadRequest, "no valid secrets provided")
		return
	}

	// Plan enforcement check
	org, _ := h.Store.GetOrganizationByID(r.Context(), orgID)
	if org != nil {
		limits := billing.GetLimits(org.PlanTier)
		currentCount, _ := h.Store.CountOrgSecrets(r.Context(), orgID)
		if limits.MaxSecrets > 0 && currentCount >= limits.MaxSecrets {
			respond.Error(w, http.StatusPaymentRequired, fmt.Sprintf("secret limit reached (%d on %s plan) — upgrade to create more", limits.MaxSecrets, org.PlanTier))
			return
		}
	}

	// Encrypt all secrets concurrently in memory
	type encryptedItem struct {
		key            string
		encryptedValue string
		encryptedDEK   string
		err            error
	}

	resultsChan := make(chan encryptedItem, len(cleanItems))
	var wg sync.WaitGroup

	for k, v := range cleanItems {
		wg.Add(1)
		go func(key, val string) {
			defer wg.Done()
			encVal, encDEK, err := h.Crypto.Encrypt(val)
			resultsChan <- encryptedItem{
				key:            key,
				encryptedValue: encVal,
				encryptedDEK:   encDEK,
				err:            err,
			}
		}(k, v)
	}

	wg.Wait()
	close(resultsChan)

	importItems := make([]store.BulkImportItem, 0, len(cleanItems))
	for res := range resultsChan {
		if res.err != nil {
			respond.Error(w, http.StatusInternalServerError, fmt.Sprintf("encryption failed for secret %s", res.key))
			return
		}
		importItems = append(importItems, store.BulkImportItem{
			Key:            res.key,
			EncryptedValue: res.encryptedValue,
			EncryptedDEK:   res.encryptedDEK,
		})
	}

	// Write to database in a single atomic transaction
	result, err := h.Store.BulkImportSecrets(r.Context(), eid, userID, importItems, req.Overwrite)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, fmt.Sprintf("failed to import secrets: %v", err))
		return
	}

	// Invalidate environment cache once
	if h.Cache != nil {
		_ = h.Cache.InvalidateEnvEtag(r.Context(), eid.String())
	}

	// Write single audit log
	h.writeAudit(r, orgID, userID, "user", "secret.bulk_create", "environment", &eid, map[string]interface{}{
		"count":   result.Total,
		"created": result.Created,
		"updated": result.Updated,
		"skipped": result.Skipped,
	})

	respond.OK(w, result)
}

