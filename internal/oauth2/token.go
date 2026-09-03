package oauth2

const PreAuthorizedCodeGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

// TokenRequest is the token-endpoint request, parsed from form parameters.
// Field names follow the OID4VCI/OAuth2 wire form keys, not Go convention —
// note "pre-authorized_code" uses a hyphen on the wire, matching the actual
// OID4VCI form parameter name.
type TokenRequest struct {
	GrantType         string
	Code              string
	RedirectURI       string
	CodeVerifier      string
	PreAuthorizedCode string
	TxCode            string
}

// TokenRequestFromForm builds a TokenRequest from parsed form values.
func TokenRequestFromForm(form map[string]string) TokenRequest {
	return TokenRequest{
		GrantType:         form["grant_type"],
		Code:              form["code"],
		RedirectURI:       form["redirect_uri"],
		CodeVerifier:      form["code_verifier"],
		PreAuthorizedCode: form["pre-authorized_code"],
		TxCode:            form["tx_code"],
	}
}

// IsPreAuthorizedCode reports whether this request uses the
// pre-authorized_code grant.
func (r TokenRequest) IsPreAuthorizedCode() bool {
	return r.GrantType == PreAuthorizedCodeGrantType
}

// TokenResponse is the token-endpoint success response.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// BearerToken builds a bearer TokenResponse (pre-authorized_code grant —
// no DPoP sender-constraining), with the same 86400s (24h) lifetime the
// Java issuer uses.
func BearerToken(accessToken string) TokenResponse {
	return TokenResponse{AccessToken: accessToken, TokenType: "Bearer", ExpiresIn: 86400}
}
