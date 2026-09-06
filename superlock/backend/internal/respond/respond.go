package respond

import (
	"encoding/json"
	"net/http"

	"github.com/getsentry/sentry-go"
)

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Status  int    `json:"status"`
}

type successResponse struct {
	Data interface{} `json:"data,omitempty"`
}

// JSON writes a JSON response with the given status code.
func JSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// OK writes a 200 JSON response.
func OK(w http.ResponseWriter, data interface{}) {
	JSON(w, http.StatusOK, data)
}

// Created writes a 201 JSON response.
func Created(w http.ResponseWriter, data interface{}) {
	JSON(w, http.StatusCreated, data)
}

// Error writes an RFC 9457-style error response and reports to Sentry.
func Error(w http.ResponseWriter, status int, message string) {
	// Report to Sentry
	if hub := sentry.CurrentHub(); hub != nil {
		if status >= 500 {
			hub.CaptureMessage("Backend Error: " + message)
		} else if status >= 400 {
			// Optional: client errors could be breadcrumbs or low-priority
			sentry.AddBreadcrumb(&sentry.Breadcrumb{
				Category: "auth",
				Message:  "Client Error (" + http.StatusText(status) + "): " + message,
				Level:    sentry.LevelInfo,
			})
		}
	}

	JSON(w, status, errorResponse{
		Error:   http.StatusText(status),
		Message: message,
		Status:  status,
	})
}

// NoContent writes a 204 response.
func NoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

// Decode decodes a JSON request body into the given struct.
func Decode(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}
