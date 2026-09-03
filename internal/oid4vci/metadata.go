// Package oid4vci holds OID4VCI 1.0 Final protocol types.
package oid4vci

// CredentialIssuerMetadata is the Credential Issuer Metadata document per
// OID4VCI 1.0 Final §10.2, served at
// /.well-known/openid-credential-issuer.
type CredentialIssuerMetadata struct {
	CredentialIssuer                  string         `json:"credential_issuer"`
	AuthorizationServers              []string       `json:"authorization_servers"`
	CredentialEndpoint                string         `json:"credential_endpoint"`
	NonceEndpoint                     string         `json:"nonce_endpoint"`
	NotificationEndpoint              string         `json:"notification_endpoint"`
	CredentialResponseEncryption      map[string]any `json:"credential_response_encryption,omitempty"`
	BatchCredentialIssuance           map[string]any `json:"batch_credential_issuance,omitempty"`
	CredentialConfigurationsSupported map[string]any `json:"credential_configurations_supported"`
	Display                           []Display      `json:"display"`
}

// Display is one locale's display information for the issuer itself.
type Display struct {
	Name   string `json:"name"`
	Locale string `json:"locale"`
}

// BuildCredentialIssuerMetadata assembles the Credential Issuer Metadata
// document. credential_response_encryption and batch_credential_issuance
// are deliberately omitted: this issuer does neither request/response
// encryption nor batch issuance, and advertising either without
// implementing it is worse than not advertising it — the OID4VCI 1.0
// Final schema also rejects a declared batch_size of 1 (minimum is 2,
// since a "batch" of one credential isn't a batch), which the Java
// issuer this was ported from got wrong.
func BuildCredentialIssuerMetadata(baseURL string, credentialConfigs map[string]any) CredentialIssuerMetadata {
	return CredentialIssuerMetadata{
		CredentialIssuer:                  baseURL,
		AuthorizationServers:              []string{baseURL},
		CredentialEndpoint:                baseURL + "/oid4vci/v1/credential",
		NonceEndpoint:                     baseURL + "/oid4vci/v1/nonce",
		NotificationEndpoint:              baseURL + "/oid4vci/v1/notification",
		CredentialConfigurationsSupported: credentialConfigs,
		Display:                           []Display{{Name: "Fikua Lab Issuer", Locale: "en"}},
	}
}
