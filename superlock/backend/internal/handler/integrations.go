package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nan0/backend/internal/model"
	"github.com/nan0/backend/internal/respond"
)

// GetCICDConfig returns environment variable blocks for a CI/CD provider.
// The caller specifies which env and which provider; we return a formatted
// snippet they can paste into their pipeline config.
func (h *Handler) GetCICDSnippet(w http.ResponseWriter, r *http.Request) {
	eid, err := uuid.Parse(chi.URLParam(r, "eid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid environment id")
		return
	}
	provider := r.URL.Query().Get("provider")
	if provider == "" {
		provider = "github_actions"
	}

	_, _ = h.verifyEnvAccess(w, r, eid)

	// Generate a read-only API token scoped to this environment
	orgID, _ := getOrgID(r)
	userID, _ := getUserID(r)

	apiURL := os.Getenv("APP_URL")
	if apiURL == "" {
		apiURL = "https://api.superlock.dev"
	}

	snippets := buildCICDSnippet(provider, apiURL, orgID.String(), eid.String())
	h.writeAudit(r, orgID, userID, "user", "integration.snippet.viewed", "environment", &eid, map[string]any{
		"provider": provider,
	})
	respond.OK(w, snippets)
}

func buildCICDSnippet(provider, apiURL, orgID, envID string) map[string]any {
	switch provider {
	case "github_actions":
		return map[string]any{
			"provider":    "github_actions",
			"description": "Add SUPERLOCK_TOKEN to GitHub Secrets, then use this step in your workflow:",
			"workflow_step": fmt.Sprintf(`- name: Load secrets from SuperLock
  uses: actions/github-script@v7
  with:
    script: |
      const resp = await fetch('%s/v1/envs/%s/secrets/values', {
        headers: { Authorization: 'Bearer ' + process.env.SUPERLOCK_TOKEN }
      });
      const secrets = await resp.json();
      for (const [key, value] of Object.entries(secrets)) {
        core.exportVariable(key, value);
        core.setSecret(value);
      }
  env:
    SUPERLOCK_TOKEN: ${{ secrets.SUPERLOCK_TOKEN }}`, apiURL, envID),
			"env_var":        "SUPERLOCK_TOKEN",
			"secrets_to_add": []string{"SUPERLOCK_TOKEN"},
		}
	case "gitlab_ci":
		return map[string]any{
			"provider":    "gitlab_ci",
			"description": "Add SUPERLOCK_TOKEN to GitLab CI/CD Variables (masked), then add this to .gitlab-ci.yml:",
			"ci_snippet": fmt.Sprintf(`load_superlock_secrets:
  image: curlimages/curl:latest
  before_script:
    - |
      curl -s -H "Authorization: Bearer $SUPERLOCK_TOKEN" \
        %s/v1/envs/%s/secrets/values \
        | jq -r 'to_entries[] | "export \(.key)=\(.value)"' > /tmp/superlock_env
      source /tmp/superlock_env`, apiURL, envID),
			"env_var": "SUPERLOCK_TOKEN",
		}
	case "circleci":
		return map[string]any{
			"provider":    "circleci",
			"description": "Add SUPERLOCK_TOKEN to CircleCI Context or Environment Variables, then add this orb step:",
			"config_snippet": fmt.Sprintf(`- run:
    name: Load SuperLock secrets
    command: |
      SECRETS=$(curl -s -H "Authorization: Bearer $SUPERLOCK_TOKEN" \
        %s/v1/envs/%s/secrets/values)
      echo $SECRETS | jq -r 'to_entries[] | "\(.key)=\(.value)"' >> $BASH_ENV`, apiURL, envID),
			"env_var": "SUPERLOCK_TOKEN",
		}
	default:
		return map[string]any{"error": "unsupported provider"}
	}
}

// CreateIntegrationConfig saves a named integration config for the org.
func (h *Handler) CreateIntegrationConfig(w http.ResponseWriter, r *http.Request) {
	orgID, ok := getOrgID(r)
	if !ok {
		respond.Error(w, http.StatusForbidden, "no organization")
		return
	}
	if !isAdminOrAbove(getRole(r)) {
		respond.Error(w, http.StatusForbidden, "admin required")
		return
	}

	var req struct {
		Name     string                    `json:"name"`
		Provider model.IntegrationProvider `json:"provider"`
		Config   json.RawMessage           `json:"config"`
	}
	if err := respond.Decode(r, &req); err != nil || req.Name == "" {
		respond.Error(w, http.StatusBadRequest, "name and provider required")
		return
	}

	userID, _ := getUserID(r)
	row := h.Store.Pool().QueryRow(r.Context(), `
		INSERT INTO integration_configs (org_id, name, provider, config_json, created_by)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING id, org_id, name, provider, config_json, created_by, created_at`,
		orgID, req.Name, req.Provider, req.Config, userID)

	var ic model.IntegrationConfig
	if err := row.Scan(&ic.ID, &ic.OrgID, &ic.Name, &ic.Provider, &ic.ConfigJSON, &ic.CreatedBy, &ic.CreatedAt); err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to save integration")
		return
	}

	h.writeAudit(r, orgID, userID, "user", "integration.created", "integration", &ic.ID, map[string]any{
		"provider": req.Provider,
		"name":     req.Name,
	})
	respond.Created(w, ic)
}

func (h *Handler) ListIntegrationConfigs(w http.ResponseWriter, r *http.Request) {
	orgID, ok := getOrgID(r)
	if !ok {
		respond.Error(w, http.StatusForbidden, "no organization")
		return
	}
	rows, err := h.Store.Pool().Query(r.Context(), `
		SELECT id, org_id, name, provider, config_json, created_by, created_at
		FROM integration_configs WHERE org_id=$1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to list integrations")
		return
	}
	defer rows.Close()
	var result []*model.IntegrationConfig
	for rows.Next() {
		var ic model.IntegrationConfig
		if err := rows.Scan(&ic.ID, &ic.OrgID, &ic.Name, &ic.Provider, &ic.ConfigJSON, &ic.CreatedBy, &ic.CreatedAt); err != nil {
			continue
		}
		result = append(result, &ic)
	}
	if result == nil {
		result = []*model.IntegrationConfig{}
	}
	respond.OK(w, result)
}

func (h *Handler) DeleteIntegrationConfig(w http.ResponseWriter, r *http.Request) {
	orgID, ok := getOrgID(r)
	if !ok {
		respond.Error(w, http.StatusForbidden, "no organization")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "iid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid id")
		return
	}
	_, _ = h.Store.Pool().Exec(r.Context(), `DELETE FROM integration_configs WHERE id=$1 AND org_id=$2`, id, orgID)
	respond.NoContent(w)
}
