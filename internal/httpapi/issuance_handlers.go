package httpapi

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/fikua/fikua-lab-issuer/internal/issuance"
	"github.com/fikua/fikua-lab-issuer/internal/oauth2"
)

func (h *Handler) jwks(w http.ResponseWriter, r *http.Request) {
	body, err := h.issuerKey.JWKSetJSON()
	if err != nil {
		writeOAuthError(w, oauth2.BadRequest(oauth2.InvalidRequest, "Failed to build JWK Set: "+err.Error()))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (h *Handler) triggerIssuance(w http.ResponseWriter, r *http.Request) {
	var req issuance.TriggerIssuanceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, oauth2.BadRequest(oauth2.InvalidRequest, "Invalid request body: "+err.Error()))
		return
	}
	result, err := h.issuance.TriggerIssuance(req)
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, oauth2.BadRequest(oauth2.InvalidRequest, "Invalid form body: "+err.Error()))
		return
	}
	form := make(map[string]string, len(r.PostForm))
	for k := range r.PostForm {
		form[k] = r.PostForm.Get(k)
	}
	req := oauth2.TokenRequestFromForm(form)
	if !req.IsPreAuthorizedCode() {
		writeOAuthError(w, oauth2.BadRequest(oauth2.UnsupportedGrantType, "Only the pre-authorized_code grant is supported"))
		return
	}
	resp, err := h.issuance.HandlePreAuthToken(req)
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) nonce(w http.ResponseWriter, r *http.Request) {
	accessToken := extractAccessToken(r.Header.Get("Authorization"))
	nonce := h.issuance.GenerateNonce(accessToken)
	writeJSON(w, http.StatusOK, map[string]string{"c_nonce": nonce})
}

func (h *Handler) credential(w http.ResponseWriter, r *http.Request) {
	accessToken := extractAccessToken(r.Header.Get("Authorization"))
	if accessToken == "" {
		writeOAuthError(w, oauth2.Unauthorized(oauth2.InvalidToken, "Missing or invalid Authorization header"))
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeOAuthError(w, oauth2.BadRequest(oauth2.InvalidCredentialRequest, "Failed to read request body: "+err.Error()))
		return
	}
	resp, issueErr := h.issuance.IssueCredential(accessToken, body)
	if issueErr != nil {
		writeOAuthError(w, issueErr)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// extractAccessToken strips a case-insensitive "Bearer " or "DPoP " prefix
// from an Authorization header, matching the Java issuer's
// IssuerController.extractAccessToken. This slice only issues Bearer
// tokens (no DPoP yet), but a wallet may still send either scheme.
func extractAccessToken(authHeader string) string {
	for _, prefix := range []string{"Bearer ", "DPoP ", "bearer ", "dpop "} {
		if len(authHeader) > len(prefix) && authHeader[:len(prefix)] == prefix {
			return authHeader[len(prefix):]
		}
	}
	return ""
}

func writeOAuthError(w http.ResponseWriter, err error) {
	exc, ok := err.(*oauth2.Exception)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, oauth2.Error{Code: oauth2.InvalidRequest, Description: err.Error()})
		return
	}
	writeJSON(w, exc.HTTPStatus, exc.Err)
}
