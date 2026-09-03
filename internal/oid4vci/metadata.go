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
// document. haip controls whether credential_response_encryption is
// advertised (required for the HAIP profile) — phase 2 only serves the
// plain profile, so haip is always false for now; it's threaded through
// already so phase 3's profile-aware wiring doesn't need to touch this
// function's signature.
func BuildCredentialIssuerMetadata(baseURL string, credentialConfigs map[string]any, haip bool) CredentialIssuerMetadata {
	var responseEncryption map[string]any
	if haip {
		responseEncryption = map[string]any{
			"alg_values_supported": []string{"ECDH-ES"},
			"enc_values_supported": []string{"A128GCM", "A256GCM"},
			"encryption_required":  false,
		}
	}

	return CredentialIssuerMetadata{
		CredentialIssuer:                  baseURL,
		AuthorizationServers:              []string{baseURL},
		CredentialEndpoint:                baseURL + "/oid4vci/v1/credential",
		NonceEndpoint:                     baseURL + "/oid4vci/v1/nonce",
		NotificationEndpoint:              baseURL + "/oid4vci/v1/notification",
		CredentialResponseEncryption:      responseEncryption,
		BatchCredentialIssuance:           map[string]any{"batch_size": 1},
		CredentialConfigurationsSupported: credentialConfigs,
		Display:                           []Display{{Name: "Fikua Lab Issuer", Locale: "en"}},
	}
}
