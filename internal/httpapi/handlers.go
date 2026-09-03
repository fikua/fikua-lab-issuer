// Package httpapi exposes the issuer's JSON API. Phase 1 only wires up the
// health check; OID4VCI endpoints land in later phases.
package httpapi

import (
	"encoding/json"
	"net/http"
)

// Handler serves the issuer's JSON API.
type Handler struct{}

// NewHandler builds an httpapi Handler.
func NewHandler() *Handler {
	return &Handler{}
}

// Routes registers this handler's endpoints on mux.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", h.health)
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
