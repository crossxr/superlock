package middleware

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/nan0/backend/internal/model"
)

// GetOrgUUIDFromCtx extracts the org UUID from the request context.
func GetOrgUUIDFromCtx(r *http.Request) (uuid.UUID, bool) {
	id, ok := r.Context().Value(model.CtxOrgID).(uuid.UUID)
	return id, ok && id != uuid.Nil
}
