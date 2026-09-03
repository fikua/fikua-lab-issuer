// Package httpapi exposes the issuer's JSON API. Phase 2 adds the
// Credential Issuer Metadata endpoint, sourced from
// fikua-lab-attestation-registry; OID4VCI issuance flows land in phase 3.
package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/fikua/fikua-lab-issuer/internal/credentialconfig"
	"github.com/fikua/fikua-lab-issuer/internal/oid4vci"
	"github.com/fikua/fikua-lab-issuer/internal/registryclient"
)

// Handler serves the issuer's JSON API.
type Handler struct {
	baseURL         string
	cache           *registryclient.Cache
	issuableSchemes []string
}

// NewHandler builds an httpapi Handler. cache is the attestation-registry
// scheme cache this issuer builds its credential configurations from;
// issuableSchemes is the explicit allowlist of scheme ids to build
// configurations for (the registry may define schemes this issuer isn't
// meant to issue).
func NewHandler(baseURL string, cache *registryclient.Cache, issuableSchemes []string) *Handler {
	return &Handler{baseURL: baseURL, cache: cache, issuableSchemes: issuableSchemes}
}

// Routes registers this handler's endpoints on mux.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", h.health)
	mux.HandleFunc("GET /.well-known/openid-credential-issuer", h.credentialIssuerMetadata)
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	if h.cache.Stale() {
		status = "degraded"
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": status})
}

func (h *Handler) credentialIssuerMetadata(w http.ResponseWriter, r *http.Request) {
	configs := make(map[string]any)
	for _, schemeID := range h.issuableSchemes {
		def, ok := h.cache.Get(schemeID)
		if !ok {
			continue // logged at startup instead of per-request; see main.go
		}
		for id, cfg := range credentialconfig.Build(def) {
			configs[id] = cfg
		}
	}
	metadata := oid4vci.BuildCredentialIssuerMetadata(h.baseURL, configs, false)
	writeJSON(w, http.StatusOK, metadata)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
