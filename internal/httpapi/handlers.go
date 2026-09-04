// Package httpapi exposes the issuer's JSON API: OID4VCI/OAuth2 well-known
// metadata, the HAIP authorization_code flow (PAR, authorize, token,
// nonce, credential), and issuance triggering/listing. Credential
// configurations are sourced from fikua-lab-attestation-registry via
// internal/credentialconfig.
package httpapi

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"net/http"

	"github.com/fikua/fikua-lab-issuer/internal/credentialconfig"
	fikuacrypto "github.com/fikua/fikua-lab-issuer/internal/crypto"
	"github.com/fikua/fikua-lab-issuer/internal/issuance"
	"github.com/fikua/fikua-lab-issuer/internal/oid4vci"
	"github.com/fikua/fikua-lab-issuer/internal/registryclient"
)

//go:embed authorize_error.html
var authorizeErrorHTML string

// authorizeErrorTemplate renders authorize_error.html — a human-readable
// error page for GET /oid4vci/v1/authorize failures, since a browser (not
// a wallet backend) is the one rendering this response, unlike every
// other OAuth2/OID4VCI endpoint here which is called machine-to-machine
// and can stay plain JSON.
var authorizeErrorTemplate = template.Must(template.New("authorize_error").Parse(authorizeErrorHTML))

// Handler serves the issuer's JSON API.
type Handler struct {
	baseURL         string
	cache           *registryclient.Cache
	issuableSchemes []string
	issuerKey       *fikuacrypto.SigningKey
	issuance        *issuance.Service
	openAPISpec     []byte
}

// NewHandler builds an httpapi Handler. cache is the attestation-registry
// scheme cache this issuer builds its credential configurations from;
// issuableSchemes is the explicit allowlist of scheme ids to build
// configurations for (the registry may define schemes this issuer isn't
// meant to issue); issuerKey signs credentials and serves the JWK Set;
// issuanceService implements the OID4VCI flows; openAPISpec is served at
// /openapi.yaml and rendered by /swagger.
func NewHandler(baseURL string, cache *registryclient.Cache, issuableSchemes []string, issuerKey *fikuacrypto.SigningKey, issuanceService *issuance.Service, openAPISpec []byte) *Handler {
	return &Handler{baseURL: baseURL, cache: cache, issuableSchemes: issuableSchemes, issuerKey: issuerKey, issuance: issuanceService, openAPISpec: openAPISpec}
}

// Routes registers this handler's endpoints on mux.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", h.health)
	mux.HandleFunc("GET /.well-known/openid-credential-issuer", h.credentialIssuerMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", h.authServerMetadata)
	mux.HandleFunc("GET /oid4vci/v1/jwks", h.jwks)
	mux.HandleFunc("GET /oid4vci/v1/issuance", h.listIssuanceRecords)
	mux.HandleFunc("POST /oid4vci/v1/issuance", h.triggerIssuance)
	mux.HandleFunc("GET /oid4vci/v1/credential-offer/{id}", h.credentialOffer)
	mux.HandleFunc("POST /oid4vci/v1/par", h.par)
	mux.HandleFunc("GET /oid4vci/v1/authorize", h.authorize)
	mux.HandleFunc("GET /oid4vci/v1/identify/claims", h.identifyClaims)
	mux.HandleFunc("POST /oid4vci/v1/identify/complete", h.identifyComplete)
	mux.HandleFunc("POST /oid4vci/v1/identify/reject", h.identifyReject)
	mux.HandleFunc("POST /oid4vci/v1/token", h.token)
	mux.HandleFunc("POST /oid4vci/v1/nonce", h.nonce)
	mux.HandleFunc("POST /oid4vci/v1/credential", h.credential)
	mux.HandleFunc("POST /oid4vci/v1/notification", h.notification)
	mux.HandleFunc("GET /oid4vci/v1/status-list/{listID}", h.statusList)
	mux.HandleFunc("POST /oid4vci/v1/issuance/{id}/revoke", h.revokeIssuance)
	mux.HandleFunc("GET /openapi.yaml", h.openAPISpecHandler)
	mux.HandleFunc("GET /swagger", h.swaggerUI)
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

// credentialOffer resolves a by-reference credential_offer_uri (from
// TriggerIssuance) to the Credential Offer JSON it points at.
func (h *Handler) credentialOffer(w http.ResponseWriter, r *http.Request) {
	offerJSON, ok := h.issuance.GetCredentialOffer(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(offerJSON))
}

// notification implements the OID4VCI 1.0 Final §10.1 Notification
// Endpoint as a no-op: this issuer's credential responses never set
// notification_id (immediate, single-credential issuance only), so there
// is nothing to look up or track yet — a wallet is simply acknowledged so
// it doesn't error out following the metadata this issuer advertises.
func (h *Handler) notification(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
