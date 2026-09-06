package handler

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nan0/backend/internal/billing"
	"github.com/nan0/backend/internal/model"
	"github.com/nan0/backend/internal/rbac"
	"github.com/nan0/backend/internal/respond"
)

var slugRegex = regexp.MustCompile(`^[a-z0-9-]+$`)

func toSlug(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(s, "-")
	return strings.Trim(s, "-")
}

// --- Project Handlers ---

type createProjectRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (h *Handler) ListProjects(w http.ResponseWriter, r *http.Request) {
	orgID, _ := getOrgID(r)
	projects, err := h.DB.ListProjectsByOrg(r.Context(), orgID)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to list projects")
		return
	}
	if projects == nil {
		projects = []*model.Project{}
	}
	respond.OK(w, projects)
}

func (h *Handler) CreateProject(w http.ResponseWriter, r *http.Request) {
	orgID, _ := getOrgID(r)
	userID, _ := getUserID(r)
	role := getRole(r)

	if !rbac.IsAtLeast(role, model.RoleAdmin) {
		respond.Error(w, http.StatusForbidden, "admin or owner role required")
		return
	}

	// ── Plan enforcement: project count ──
	org, err := h.Store.GetOrganizationByID(r.Context(), orgID)
	if err != nil || org == nil {
		respond.Error(w, http.StatusInternalServerError, "failed to get organization")
		return
	}
	limits := billing.GetLimits(org.PlanTier)
	projectCount, _ := h.Store.CountOrgProjects(r.Context(), orgID)
	if billing.ExceedsLimit(limits.MaxProjects, projectCount) {
		respond.Error(w, http.StatusPaymentRequired, fmt.Sprintf("project limit reached (%d on %s plan) — upgrade to create more", limits.MaxProjects, org.PlanTier))
		return
	}

	var req createProjectRequest
	if err := respond.Decode(r, &req); err != nil || strings.TrimSpace(req.Name) == "" {
		respond.Error(w, http.StatusBadRequest, "name is required")
		return
	}

	slug := toSlug(req.Name)
	project, err := h.DB.CreateProject(r.Context(), orgID, userID, strings.TrimSpace(req.Name), slug, req.Description)
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			respond.Error(w, http.StatusConflict, "a project with this name already exists")
			return
		}
		respond.Error(w, http.StatusInternalServerError, "failed to create project")
		return
	}

	// Create default environments
	for _, env := range []struct {
		name      string
		protected bool
	}{
		{"development", false},
		{"staging", false},
		{"production", true},
	} {
		_, _ = h.DB.CreateEnvironment(r.Context(), project.ID, env.name, env.name, env.protected)
	}

	h.writeAudit(r, orgID, userID, "user", "project.created", "project", &project.ID, map[string]interface{}{
		"project_name": project.Name,
	})

	respond.Created(w, project)
}

func (h *Handler) GetProject(w http.ResponseWriter, r *http.Request) {
	pid, err := uuid.Parse(chi.URLParam(r, "pid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid project ID")
		return
	}
	orgID, _ := getOrgID(r)

	project, err := h.DB.GetProjectByID(r.Context(), pid)
	if err != nil || project == nil {
		respond.Error(w, http.StatusNotFound, "project not found")
		return
	}
	if project.OrgID != orgID {
		respond.Error(w, http.StatusForbidden, "access denied")
		return
	}
	respond.OK(w, project)
}

func (h *Handler) DeleteProject(w http.ResponseWriter, r *http.Request) {
	pid, err := uuid.Parse(chi.URLParam(r, "pid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid project ID")
		return
	}

	orgID, _ := getOrgID(r)
	userID, _ := getUserID(r)
	role := getRole(r)

	if !rbac.IsAtLeast(role, model.RoleAdmin) {
		respond.Error(w, http.StatusForbidden, "admin or owner role required")
		return
	}

	project, err := h.DB.GetProjectByID(r.Context(), pid)
	if err != nil || project == nil || project.OrgID != orgID {
		respond.Error(w, http.StatusNotFound, "project not found")
		return
	}

	if err := h.DB.DeleteProject(r.Context(), pid); err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to delete project")
		return
	}

	h.writeAudit(r, orgID, userID, "user", "project.deleted", "project", &pid, map[string]interface{}{
		"project_name": project.Name,
	})

	respond.NoContent(w)
}

// --- Environment Handlers ---

type createEnvironmentRequest struct {
	Name        string `json:"name"`
	IsProtected bool   `json:"is_protected"`
}

func (h *Handler) ListEnvironments(w http.ResponseWriter, r *http.Request) {
	pid, err := uuid.Parse(chi.URLParam(r, "pid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid project ID")
		return
	}

	orgID, _ := getOrgID(r)
	project, err := h.DB.GetProjectByID(r.Context(), pid)
	if err != nil || project == nil || project.OrgID != orgID {
		respond.Error(w, http.StatusNotFound, "project not found")
		return
	}

	envs, err := h.DB.ListEnvironmentsByProject(r.Context(), pid)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to list environments")
		return
	}
	if envs == nil {
		envs = []*model.Environment{}
	}
	respond.OK(w, envs)
}

func (h *Handler) CreateEnvironment(w http.ResponseWriter, r *http.Request) {
	pid, err := uuid.Parse(chi.URLParam(r, "pid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid project ID")
		return
	}

	orgID, _ := getOrgID(r)
	userID, _ := getUserID(r)
	role := getRole(r)

	if !rbac.IsAtLeast(role, model.RoleAdmin) {
		respond.Error(w, http.StatusForbidden, "admin or owner role required")
		return
	}

	project, err := h.DB.GetProjectByID(r.Context(), pid)
	if err != nil || project == nil || project.OrgID != orgID {
		respond.Error(w, http.StatusNotFound, "project not found")
		return
	}

	// ── Plan enforcement: env count per project ──
	org, _ := h.Store.GetOrganizationByID(r.Context(), orgID)
	if org != nil {
		limits := billing.GetLimits(org.PlanTier)
		envCount, _ := h.Store.CountProjectEnvs(r.Context(), pid)
		if billing.ExceedsLimit(limits.MaxEnvsPerProj, envCount) {
			respond.Error(w, http.StatusPaymentRequired, fmt.Sprintf("environment limit reached (%d per project on %s plan) — upgrade to create more", limits.MaxEnvsPerProj, org.PlanTier))
			return
		}
	}

	var req createEnvironmentRequest
	if err := respond.Decode(r, &req); err != nil || strings.TrimSpace(req.Name) == "" {
		respond.Error(w, http.StatusBadRequest, "name is required")
		return
	}

	slug := toSlug(req.Name)
	env, err := h.DB.CreateEnvironment(r.Context(), pid, strings.TrimSpace(req.Name), slug, req.IsProtected)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to create environment")
		return
	}

	h.writeAudit(r, orgID, userID, "user", "environment.created", "environment", &env.ID, map[string]interface{}{
		"env_name":     env.Name,
		"project_id":   pid.String(),
		"is_protected": env.IsProtected,
	})

	respond.Created(w, env)
}
