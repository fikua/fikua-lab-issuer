package oid4vci

// CredentialResponse is the OID4VCI 1.0 Final §8.3 credential-endpoint
// response body.
type CredentialResponse struct {
	Credentials    []map[string]string `json:"credentials,omitempty"`
	TransactionID  string              `json:"transaction_id,omitempty"`
	NotificationID string              `json:"notification_id,omitempty"`
}

// SuccessResponse builds an immediate-issuance CredentialResponse for a
// single credential.
func SuccessResponse(credential string) CredentialResponse {
	return CredentialResponse{Credentials: []map[string]string{{"credential": credential}}}
}
