package handler

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nan0/backend/internal/cache"
	"github.com/nan0/backend/internal/crypto"
	"github.com/nan0/backend/internal/email"
	"github.com/nan0/backend/internal/model"
	"github.com/nan0/backend/internal/netguard"
	"github.com/nan0/backend/internal/rbac"
	"github.com/nan0/backend/internal/respond"
	"github.com/nan0/backend/internal/rotation"
	"github.com/nan0/backend/internal/store"
	"github.com/nan0/backend/internal/ws"
)

type Handler struct {
	Store        *store.Store
	Cache        *cache.Cache
	Crypto       *crypto.Engine
	AuditHMACKey []byte
	Hub          *ws.Hub
	Rotation     *rotation.Worker
	Email        *email.Client
	Guard        *netguard.Guard
	// Keep DB as alias for Store for backwards compat
	DB *store.Store
}

func getUserID(r *http.Request) (uuid.UUID, bool) {
	id, ok := r.Context().Value(model.CtxUserID).(uuid.UUID)
	return id, ok && id != uuid.Nil
}

func getOrgID(r *http.Request) (uuid.UUID, bool) {
	id, ok := r.Context().Value(model.CtxOrgID).(uuid.UUID)
	return id, ok && id != uuid.Nil
}

func getRole(r *http.Request) model.Role {
	role, _ := r.Context().Value(model.CtxRole).(model.Role)
	return role
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ip := strings.TrimSpace(strings.Split(xff, ",")[0])
		return ip
	}
	if xri := r.Header.Get("X-Real-Ip"); xri != "" {
		return strings.TrimSpace(xri)
	}
	// RemoteAddr is host:port — strip the port
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		// Check it's not an IPv6 without brackets
		if strings.Contains(addr, "]") || !strings.Contains(addr, ".") {
			// IPv6 with brackets like [::1]:port
			if bi := strings.LastIndex(addr, "]:"); bi != -1 {
				return addr[1:bi]
			}
		}
		return addr[:idx]
	}
	return addr
}

// Org handlers

type createOrgRequest struct {
	Name string `json:"name"`
}

func (h *Handler) CreateOrg(w http.ResponseWriter, r *http.Request) {
	userID, ok := getUserID(r)
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req createOrgRequest
	if err := respond.Decode(r, &req); err != nil || strings.TrimSpace(req.Name) == "" {
		respond.Error(w, http.StatusBadRequest, "name is required")
		return
	}
	user, _ := h.Store.GetUserByID(r.Context(), userID)
	if user != nil && user.OrgID != nil {
		respond.Error(w, http.StatusConflict, "user already belongs to an organization")
		return
	}
	org, err := h.Store.CreateOrganization(r.Context(), strings.TrimSpace(req.Name), model.PlanFree)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to create organization")
		return
	}
	if err := h.Store.UpdateUserOrg(r.Context(), userID, org.ID, model.RoleOwner); err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to assign org")
		return
	}
	h.writeAudit(r, org.ID, userID, "user", "org.created", "organization", &org.ID, map[string]any{
		"org_name": org.Name,
	})
	respond.Created(w, org)
}

func (h *Handler) GetMyOrg(w http.ResponseWriter, r *http.Request) {
	orgID, ok := getOrgID(r)
	if !ok {
		respond.OK(w, nil)
		return
	}
	org, err := h.Store.GetOrganizationByID(r.Context(), orgID)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to get org")
		return
	}
	respond.OK(w, org)
}

func (h *Handler) GetMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := getUserID(r)
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	user, err := h.Store.GetUserByID(r.Context(), userID)
	if err != nil || user == nil {
		respond.Error(w, http.StatusNotFound, "user not found")
		return
	}
	respond.OK(w, user)
}

func (h *Handler) ListMembers(w http.ResponseWriter, r *http.Request) {
	orgID, ok := getOrgID(r)
	if !ok {
		respond.Error(w, http.StatusForbidden, "no organization")
		return
	}
	members, err := h.Store.ListOrgUsers(r.Context(), orgID)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to list members")
		return
	}
	if members == nil {
		members = []*model.User{}
	}
	respond.OK(w, members)
}

func (h *Handler) writeAudit(r *http.Request, orgID, actorID uuid.UUID, actorType, action, resourceType string, resourceID *uuid.UUID, metadata map[string]any) {
	event := store.BuildAuditEvent(orgID, actorID, actorType, action, resourceType, resourceID, metadata, clientIP(r), r.UserAgent())
	_, prevHMAC, _ := h.Store.GetLastAuditHMAC(r.Context(), orgID)
	ridStr := ""
	if resourceID != nil {
		ridStr = resourceID.String()
	}
	event.PrevHMAC = prevHMAC
	event.HMAC = crypto.HMACChain(h.AuditHMACKey, uuid.New().String(), prevHMAC, action, actorID.String(), ridStr, time.Now().UnixMicro())
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = h.Store.WriteAuditEvent(bgCtx, event)
	}()
}

// getScopes returns the API token scopes on the request. A nil result means the
// request was authenticated by a user JWT and is not scope-limited.
func getScopes(r *http.Request) []string {
	scopes, ok := r.Context().Value(model.CtxScopes).([]string)
	if !ok {
		return nil
	}
	return scopes
}

// allows is the authority check every handler should use: the role must grant
// the permission and, when the caller is an API token, its scopes must include
// it too.
func (h *Handler) allows(r *http.Request, perm rbac.Permission) bool {
	return rbac.Allows(getRole(r), getScopes(r), perm)
}
