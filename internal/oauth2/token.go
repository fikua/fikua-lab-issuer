package oauth2

const AuthorizationCodeGrantType = "authorization_code"

// TokenRequest is the token-endpoint request, parsed from form parameters.
type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	CodeVerifier string
}

// TokenRequestFromForm builds a TokenRequest from parsed form values.
func TokenRequestFromForm(form map[string]string) TokenRequest {
	return TokenRequest{
		GrantType:    form["grant_type"],
		Code:         form["code"],
		RedirectURI:  form["redirect_uri"],
		CodeVerifier: form["code_verifier"],
	}
}

// IsAuthorizationCode reports whether this request uses the
// authorization_code grant — the only grant this HAIP-only issuer
// supports.
func (r TokenRequest) IsAuthorizationCode() bool {
	return r.GrantType == AuthorizationCodeGrantType
}

// TokenResponse is the token-endpoint success response.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// DPoPToken builds a DPoP-bound TokenResponse — this issuer's only token
// type, since HAIP always requires DPoP sender-constraining.
func DPoPToken(accessToken string) TokenResponse {
	return TokenResponse{AccessToken: accessToken, TokenType: "DPoP", ExpiresIn: 86400}
}
