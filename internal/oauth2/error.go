// Package oauth2 holds the OAuth2/OID4VCI error model shared by every
// endpoint.
package oauth2

// Error codes, per OID4VCI 1.0 Final §8.3.1 and OAuth2 core.
const (
	InvalidRequest = "invalid_request"
	InvalidGrant   = "invalid_grant"
	InvalidClient  = "invalid_client"
	// InvalidClientAttestation, per ATCA draft-07 §6.2, MAY be used
	// alongside the more general invalid_client when a client
	// attestation or its proof-of-possession fails verification.
	InvalidClientAttestation       = "invalid_client_attestation"
	UnsupportedGrantType           = "unsupported_grant_type"
	InvalidToken                   = "invalid_token"
	UnsupportedCredentialType      = "unsupported_credential_type"
	UnsupportedCredentialFormat    = "unsupported_credential_format"
	InvalidProof                   = "invalid_proof"
	InvalidNonce                   = "invalid_nonce"
	UnknownCredentialConfiguration = "unknown_credential_configuration"
	UnknownCredentialIdentifier    = "unknown_credential_identifier"
	InvalidCredentialRequest       = "invalid_credential_request"
)

// Error is the OAuth2/OID4VCI error response body: {"error": "...",
// "error_description": "..."}. Description is omitted from the JSON
// entirely when empty.
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// Exception pairs an Error with the HTTP status it should be served with.
// It's a plain error value, not a panic/recover mechanism — handlers
// return it and the caller writes the response.
type Exception struct {
	HTTPStatus int
	Err        Error
}

func (e *Exception) Error() string {
	return e.Err.Code + ": " + e.Err.Description
}

// BadRequest builds a 400 Exception.
func BadRequest(code, description string) *Exception {
	return &Exception{HTTPStatus: 400, Err: Error{Code: code, Description: description}}
}

// Unauthorized builds a 401 Exception.
func Unauthorized(code, description string) *Exception {
	return &Exception{HTTPStatus: 401, Err: Error{Code: code, Description: description}}
}

// ServiceUnavailable builds a 503 Exception.
func ServiceUnavailable(code, description string) *Exception {
	return &Exception{HTTPStatus: 503, Err: Error{Code: code, Description: description}}
}
