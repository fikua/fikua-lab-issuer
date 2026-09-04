package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
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

func (h *Handler) par(w http.ResponseWriter, r *http.Request) {
	form, err := parseForm(r)
	if err != nil {
		writeOAuthError(w, oauth2.BadRequest(oauth2.InvalidRequest, "Invalid form body: "+err.Error()))
		return
	}
	wiaHeader, popHeader := clientAttestationHeaders(r)

	requestURI, expiresIn, err := h.issuance.HandlePar(form, wiaHeader, popHeader)
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"request_uri": requestURI, "expires_in": expiresIn})
}

func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	result, err := h.issuance.HandleAuthorize(r.URL.Query().Get("request_uri"))
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	redirect := result.RedirectURI + "?code=" + result.Code
	if result.State != "" {
		redirect += "&state=" + result.State
	}
	redirect += "&iss=" + url.QueryEscape(h.baseURL)
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	form, err := parseForm(r)
	if err != nil {
		writeOAuthError(w, oauth2.BadRequest(oauth2.InvalidRequest, "Invalid form body: "+err.Error()))
		return
	}
	req := oauth2.TokenRequestFromForm(form)
	w.Header().Set("Cache-Control", "no-store")
	if !req.IsAuthorizationCode() {
		writeOAuthError(w, oauth2.BadRequest(oauth2.UnsupportedGrantType, "Only the authorization_code grant is supported"))
		return
	}

	dpopHeader := r.Header.Get("DPoP")
	wiaHeader, popHeader := clientAttestationHeaders(r)

	resp, err := h.issuance.HandleAuthCodeToken(req, dpopHeader, wiaHeader, popHeader)
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) nonce(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	accessToken := extractAccessToken(r.Header.Get("Authorization"))
	dpopHeader := r.Header.Get("DPoP")
	nonce, err := h.issuance.GenerateNonce(accessToken, dpopHeader)
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
	dpopHeader := r.Header.Get("DPoP")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeOAuthError(w, oauth2.BadRequest(oauth2.InvalidCredentialRequest, "Failed to read request body: "+err.Error()))
		return
	}
	resp, issueErr := h.issuance.IssueCredential(accessToken, dpopHeader, body)
	if issueErr != nil {
		writeOAuthError(w, issueErr)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// parseForm parses a form-urlencoded request body into a plain map,
// taking the first value per key and dropping empty-valued keys —
// matching the Java issuer's parseFormParams.
func parseForm(r *http.Request) (map[string]string, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	form := make(map[string]string, len(r.PostForm))
	for k, values := range r.PostForm {
		if len(values) > 0 && values[0] != "" {
			form[k] = values[0]
		}
	}
	return form, nil
}

// clientAttestationHeaders extracts the ATCA draft-07 WIA/PoP headers,
// shared by /par and /token — the only two endpoints that accept
// header-based client attestation.
func clientAttestationHeaders(r *http.Request) (wia, pop string) {
	return r.Header.Get(oauth2.HeaderClientAttestation), r.Header.Get(oauth2.HeaderClientAttestationPoP)
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
