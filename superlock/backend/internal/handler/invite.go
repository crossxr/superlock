package handler

import (
	"fmt"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nan0/backend/internal/model"
	"github.com/nan0/backend/internal/respond"
)

type inviteRequest struct {
	Email string     `json:"email"`
	Role  model.Role `json:"role"`
}

func (h *Handler) InviteMember(w http.ResponseWriter, r *http.Request) {
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

	var req inviteRequest
	if err := respond.Decode(r, &req); err != nil || req.Email == "" {
		respond.Error(w, http.StatusBadRequest, "email is required")
		return
	}
	if req.Role == "" {
		req.Role = model.RoleDeveloper
	}
	if req.Role == model.RoleOwner {
		respond.Error(w, http.StatusBadRequest, "cannot invite as owner")
		return
	}

	userID, _ := getUserID(r)

	// Check plan seat limits
	org, err := h.Store.GetOrganizationByID(r.Context(), orgID)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to get org")
		return
	}
	members, _ := h.Store.ListOrgUsers(r.Context(), orgID)
	seatLimit := seatLimitForPlan(org.PlanTier)
	if seatLimit > 0 && len(members) >= seatLimit {
		respond.Error(w, http.StatusPaymentRequired, fmt.Sprintf("seat limit reached (%d seats on %s plan)", seatLimit, org.PlanTier))
		return
	}

	inv, err := h.Store.CreateInvitation(r.Context(), orgID, req.Email, req.Role, userID)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to create invitation")
		return
	}

	// Send email
	if h.Email != nil {
		inviteURL := fmt.Sprintf("%s/invite?token=%s", os.Getenv("APP_URL"), inv.PlainToken)
		inviterEmail := r.Context().Value(model.CtxEmail).(string)
		_ = h.Email.SendInvite(r.Context(), req.Email, org.Name, inviterEmail, inviteURL)
	}

	h.writeAudit(r, orgID, userID, "user", "member.invited", "invitation", &inv.ID, map[string]any{
		"email": req.Email,
		"role":  req.Role,
	})

	// Don't expose plain token in prod response (it was emailed)
	inv.PlainToken = ""
	respond.Created(w, inv)
}

func (h *Handler) AcceptInvitation(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		respond.Error(w, http.StatusBadRequest, "token is required")
		return
	}

	inv, err := h.Store.GetInvitationByToken(r.Context(), token)
	if err != nil {
		respond.Error(w, http.StatusNotFound, "invitation not found or expired")
		return
	}

	userID, ok := getUserID(r)
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "must be logged in to accept invite")
		return
	}

	// Assign user to org
	if err := h.Store.UpdateUserOrg(r.Context(), userID, inv.OrgID, inv.Role); err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to accept invitation")
		return
	}
	_ = h.Store.AcceptInvitation(r.Context(), inv.ID)

	// Update seat count
	members, _ := h.Store.ListOrgUsers(r.Context(), inv.OrgID)
	_ = h.Store.UpdateOrgSeatCount(r.Context(), inv.OrgID, len(members))

	h.writeAudit(r, inv.OrgID, userID, "user", "member.joined", "invitation", &inv.ID, map[string]any{
		"email": inv.Email,
	})
	respond.OK(w, map[string]string{"status": "accepted", "org_id": inv.OrgID.String()})
}

func (h *Handler) ListInvitations(w http.ResponseWriter, r *http.Request) {
	orgID, ok := getOrgID(r)
	if !ok {
		respond.Error(w, http.StatusForbidden, "no organization")
		return
	}
	invites, err := h.Store.ListInvitations(r.Context(), orgID)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to list invitations")
		return
	}
	if invites == nil {
		invites = []*model.Invitation{}
	}
	respond.OK(w, invites)
}

func (h *Handler) RevokeInvitation(w http.ResponseWriter, r *http.Request) {
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
	invID, err := uuid.Parse(chi.URLParam(r, "iid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid invitation id")
		return
	}
	if err := h.Store.RevokeInvitation(r.Context(), invID, orgID); err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to revoke invitation")
		return
	}
	respond.NoContent(w)
}

func seatLimitForPlan(plan model.PlanTier) int {
	switch plan {
	case model.PlanFree:
		return 1
	case model.PlanStarter:
		return 10
	case model.PlanBusiness:
		return 100
	default:
		return 0 // unlimited for enterprise
	}
}
