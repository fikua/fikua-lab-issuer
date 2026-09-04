package oauth2

const AuthorizationCodeGrantType = "authorization_code"

// TokenRequest is the token-endpoint request, parsed from form parameters.
type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	CodeVerifier string
	// ClientID is the (optional) explicit client_id form parameter, per
	// RFC 6749 §5.1 — this issuer authenticates the client via its
	// attestation, not this parameter, but if present it must agree with
	// the attested client_id (RFC 6749 §5.2: a token request identifying
	// a client other than the one the attestation authenticates must be
	// rejected).
	ClientID string
	// ClientAssertionType/ClientAssertion carry a form-based client
	// attestation (ATCA draft-07 §3), the token endpoint's counterpart
	// to the OAuth-Client-Attestation/-PoP headers — the PAR endpoint
	// already accepted both transports (HandlePar reads these same form
	// keys), but the token endpoint only ever looked at headers, so a
	// client authenticating here via form-encoded assertion instead of
	// headers had its attestation silently ignored.
	ClientAssertionType string
	ClientAssertion     string
}

// TokenRequestFromForm builds a TokenRequest from parsed form values.
func TokenRequestFromForm(form map[string]string) TokenRequest {
	return TokenRequest{
		GrantType:           form["grant_type"],
		Code:                form["code"],
		RedirectURI:         form["redirect_uri"],
		CodeVerifier:        form["code_verifier"],
		ClientID:            form["client_id"],
		ClientAssertionType: form["client_assertion_type"],
		ClientAssertion:     form["client_assertion"],
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
