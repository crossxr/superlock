package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nan0/backend/internal/model"
	"github.com/nan0/backend/internal/respond"
)

func (h *Handler) ListApprovals(w http.ResponseWriter, r *http.Request) {
	orgID, ok := getOrgID(r)
	if !ok {
		respond.Error(w, http.StatusForbidden, "no organization")
		return
	}
	approvals, err := h.Store.ListPendingApprovals(r.Context(), orgID)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to list approvals")
		return
	}
	if approvals == nil {
		approvals = []*model.PendingApproval{}
	}
	respond.OK(w, approvals)
}

func (h *Handler) ResolveApproval(w http.ResponseWriter, r *http.Request) {
	orgID, ok := getOrgID(r)
	if !ok {
		respond.Error(w, http.StatusForbidden, "no organization")
		return
	}
	role := getRole(r)
	if !isAdminOrAbove(role) {
		respond.Error(w, http.StatusForbidden, "admin required to resolve approvals")
		return
	}
	approvalID, err := uuid.Parse(chi.URLParam(r, "aid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid approval id")
		return
	}

	var req struct {
		Action string `json:"action"` // "approve" or "reject"
	}
	if err := respond.Decode(r, &req); err != nil || (req.Action != "approve" && req.Action != "reject") {
		respond.Error(w, http.StatusBadRequest, "action must be 'approve' or 'reject'")
		return
	}

	userID, _ := getUserID(r)
	approval, err := h.Store.GetApproval(r.Context(), approvalID)
	if err != nil {
		respond.Error(w, http.StatusNotFound, "approval not found")
		return
	}
	if approval.OrgID != orgID {
		respond.Error(w, http.StatusForbidden, "forbidden")
		return
	}
	if approval.RequestedBy == userID {
		respond.Error(w, http.StatusForbidden, "cannot approve your own request")
		return
	}

	status := model.ApprovalApproved
	if req.Action == "reject" {
		status = model.ApprovalRejected
	}

	if err := h.Store.ResolveApproval(r.Context(), approvalID, userID, status); err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to resolve approval")
		return
	}

	// If approved, execute the pending action
	if status == model.ApprovalApproved {
		h.executeApprovedAction(r, approval)
	}

	h.writeAudit(r, orgID, userID, "user", "approval."+req.Action+"d", "approval", &approvalID, map[string]any{
		"original_action": approval.Action,
	})
	respond.OK(w, map[string]string{"status": string(status)})
}

func (h *Handler) executeApprovedAction(r *http.Request, approval *model.PendingApproval) {
	type secretPayload struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	var payload secretPayload
	if err := json.Unmarshal(approval.PayloadJSON, &payload); err != nil {
		return
	}

	userID, _ := getUserID(r)
	encVal, encDEK, err := h.Crypto.Encrypt(payload.Value)
	if err != nil {
		return
	}

	switch approval.Action {
	case "create":
		keyUUID, err := uuid.Parse(payload.Key)
		if err != nil {
			return
		}
		h.Store.CreateSecret(r.Context(), approval.EnvID, keyUUID, encVal, encDEK, userID.String())
	case "update":
		if approval.SecretID != nil {
			h.Store.UpdateSecret(r.Context(), *approval.SecretID, encVal, encDEK)
		}
	}
}
