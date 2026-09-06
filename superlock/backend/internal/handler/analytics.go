package handler

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nan0/backend/internal/model"
	"github.com/nan0/backend/internal/respond"
)

func (h *Handler) GetSecretHeatmap(w http.ResponseWriter, r *http.Request) {
	orgID, ok := getOrgID(r)
	if !ok {
		respond.Error(w, http.StatusForbidden, "no organization")
		return
	}
	days := 30
	if d := r.URL.Query().Get("days"); d != "" {
		if n, err := strconv.Atoi(d); err == nil && n > 0 && n <= 90 {
			days = n
		}
	}
	entries, err := h.Store.GetSecretHeatmap(r.Context(), orgID, days)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to get heatmap")
		return
	}
	if entries == nil {
		entries = []*model.SecretHeatmapEntry{}
	}
	respond.OK(w, map[string]any{
		"days":    days,
		"entries": entries,
	})
}

func (h *Handler) GetUnusedSecrets(w http.ResponseWriter, r *http.Request) {
	orgID, ok := getOrgID(r)
	if !ok {
		respond.Error(w, http.StatusForbidden, "no organization")
		return
	}
	thresholdDays := 30
	if d := r.URL.Query().Get("threshold_days"); d != "" {
		if n, err := strconv.Atoi(d); err == nil && n > 0 {
			thresholdDays = n
		}
	}
	unused, err := h.Store.GetUnusedSecrets(r.Context(), orgID, thresholdDays)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to get unused secrets")
		return
	}
	if unused == nil {
		unused = []*model.UnusedSecret{}
	}
	respond.OK(w, map[string]any{
		"threshold_days": thresholdDays,
		"secrets":        unused,
	})
}

func (h *Handler) GetSecretTimeSeries(w http.ResponseWriter, r *http.Request) {
	sid, err := uuid.Parse(chi.URLParam(r, "sid"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid secret id")
		return
	}
	days := 30
	if d := r.URL.Query().Get("days"); d != "" {
		if n, err := strconv.Atoi(d); err == nil && n > 0 && n <= 90 {
			days = n
		}
	}
	series, err := h.Store.GetAccessTimeSeries(r.Context(), sid, days)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to get time series")
		return
	}
	if series == nil {
		series = []map[string]interface{}{}
	}
	respond.OK(w, map[string]any{"secret_id": sid, "days": days, "series": series})
}
