// Package httpapi exposes the issuer's JSON API. Phase 2 adds the
// Credential Issuer Metadata endpoint, sourced from
// fikua-lab-attestation-registry; OID4VCI issuance flows land in phase 3.
package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/fikua/fikua-lab-issuer/internal/credentialconfig"
	fikuacrypto "github.com/fikua/fikua-lab-issuer/internal/crypto"
	"github.com/fikua/fikua-lab-issuer/internal/issuance"
	"github.com/fikua/fikua-lab-issuer/internal/oid4vci"
	"github.com/fikua/fikua-lab-issuer/internal/registryclient"
)

// Handler serves the issuer's JSON API.
type Handler struct {
	baseURL         string
	cache           *registryclient.Cache
	issuableSchemes []string
	issuerKey       *fikuacrypto.SigningKey
	issuance        *issuance.Service
}

// NewHandler builds an httpapi Handler. cache is the attestation-registry
// scheme cache this issuer builds its credential configurations from;
// issuableSchemes is the explicit allowlist of scheme ids to build
// configurations for (the registry may define schemes this issuer isn't
// meant to issue); issuerKey signs credentials and serves the JWK Set;
// issuanceService implements the OID4VCI flows.
func NewHandler(baseURL string, cache *registryclient.Cache, issuableSchemes []string, issuerKey *fikuacrypto.SigningKey, issuanceService *issuance.Service) *Handler {
	return &Handler{baseURL: baseURL, cache: cache, issuableSchemes: issuableSchemes, issuerKey: issuerKey, issuance: issuanceService}
}

// Routes registers this handler's endpoints on mux.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", h.health)
	mux.HandleFunc("GET /.well-known/openid-credential-issuer", h.credentialIssuerMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", h.authServerMetadata)
	mux.HandleFunc("GET /oid4vci/v1/jwks", h.jwks)
	mux.HandleFunc("GET /oid4vci/v1/issuance", h.listIssuanceRecords)
	mux.HandleFunc("POST /oid4vci/v1/issuance", h.triggerIssuance)
	mux.HandleFunc("POST /oid4vci/v1/par", h.par)
	mux.HandleFunc("GET /oid4vci/v1/authorize", h.authorize)
	mux.HandleFunc("POST /oid4vci/v1/token", h.token)
	mux.HandleFunc("POST /oid4vci/v1/nonce", h.nonce)
	mux.HandleFunc("POST /oid4vci/v1/credential", h.credential)
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
	metadata := oid4vci.BuildCredentialIssuerMetadata(h.baseURL, configs)
	writeJSON(w, http.StatusOK, metadata)
}

func (h *Handler) authServerMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, oid4vci.BuildHAIPAuthServerMetadata(h.baseURL))
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
