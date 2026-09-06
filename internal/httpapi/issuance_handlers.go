package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

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

func (h *Handler) listIssuanceRecords(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page := parseIntParam(q.Get("page"), 1)
	size := parseIntParam(q.Get("size"), 20)
	sort := q.Get("sort")
	if sort == "" {
		sort = "created_at"
	}
	order := q.Get("order")
	if order == "" {
		order = "desc"
	}
	writeJSON(w, http.StatusOK, h.issuance.ListIssuanceRecords(page, size, sort, order))
}

func parseIntParam(v string, fallback int) int {
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return fallback
	}
	return n
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

// statusList serves the signed Status List Token JWT (IETF Token Status
// List, draft-ietf-oauth-status-list-21 §8) for the {listID} path param —
// only "pid" exists today.
func (h *Handler) statusList(w http.ResponseWriter, r *http.Request) {
	token, err := h.issuance.GetStatusListToken(r.PathValue("listID"))
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/statuslist+jwt")
	w.Header().Set("Cache-Control", "max-age=60")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(token))
}

// revokeIssuance marks an issued credential's status list entry INVALID.
func (h *Handler) revokeIssuance(w http.ResponseWriter, r *http.Request) {
	if err := h.issuance.RevokeCredential(r.PathValue("id")); err != nil {
		writeOAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) nonce(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	accessToken := extractAccessToken(r.Header.Get("Authorization"))
	dpopHeader, err := oauth2.SingleDPoPHeader(r.Header.Values("DPoP"))
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	nonce, err := h.issuance.GenerateNonce(r.Context(), accessToken, dpopHeader)
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"c_nonce": nonce})
}

func (h *Handler) credential(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	authHeader := r.Header.Get("Authorization")
	accessToken := extractAccessToken(authHeader)
	if accessToken == "" {
		writeOAuthError(w, oauth2.Unauthorized(oauth2.InvalidToken, "Missing access token"))
		return
	}
	// This issuer is HAIP-only: every access token is DPoP-bound, so
	// presenting it with the Bearer scheme is rejected outright, before
	// any DPoP proof validation — matching the Java issuer's ordering.
	if hasCaseInsensitivePrefix(authHeader, "bearer ") {
		writeOAuthError(w, oauth2.Unauthorized(oauth2.InvalidToken, "DPoP-bound tokens must use DPoP authorization scheme, not Bearer"))
		return
	}
	dpopHeader, err := oauth2.SingleDPoPHeader(r.Header.Values("DPoP"))
	if err != nil {
		writeOAuthError(w, err)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeOAuthError(w, oauth2.BadRequest(oauth2.InvalidCredentialRequest, "Failed to read request body: "+err.Error()))
		return
	}
	resp, issueErr := h.issuance.IssueCredential(r.Context(), accessToken, dpopHeader, body)
	if issueErr != nil {
		writeOAuthError(w, issueErr)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// extractAccessToken strips a case-insensitive "Bearer " or "DPoP " prefix
// from an Authorization header, matching the Java issuer's
// IssuerController.extractAccessToken.
func extractAccessToken(authHeader string) string {
	for _, prefix := range []string{"Bearer ", "DPoP "} {
		if hasCaseInsensitivePrefix(authHeader, prefix) {
			return authHeader[len(prefix):]
		}
	}
	return ""
}

func hasCaseInsensitivePrefix(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		a, b := s[i], prefix[i]
		if 'A' <= a && a <= 'Z' {
			a += 'a' - 'A'
		}
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}

func writeOAuthError(w http.ResponseWriter, err error) {
	exc, ok := err.(*oauth2.Exception)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, oauth2.Error{Code: oauth2.InvalidRequest, Description: err.Error()})
		return
	}
	writeJSON(w, exc.HTTPStatus, exc.Err)
}
