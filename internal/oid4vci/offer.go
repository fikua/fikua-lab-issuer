package oid4vci

// CredentialOffer is the OID4VCI §4.1 Credential Offer.
type CredentialOffer struct {
	CredentialIssuer           string         `json:"credential_issuer"`
	CredentialConfigurationIDs []string       `json:"credential_configuration_ids"`
	Grants                     map[string]any `json:"grants"`
}

const authorizationCodeGrant = "authorization_code"

// AuthorizationCodeOffer builds a Credential Offer for the
// authorization_code grant — the only grant this HAIP-only issuer
// supports. issuerState, if non-empty, is included so the wallet's
// subsequent /authorize (via PAR) can be linked back to the issuance
// record that triggered this offer.
func AuthorizationCodeOffer(issuerURL, configID, issuerState string) CredentialOffer {
	grant := map[string]any{}
	if issuerState != "" {
		grant["issuer_state"] = issuerState
	}
	return CredentialOffer{
		CredentialIssuer:           issuerURL,
		CredentialConfigurationIDs: []string{configID},
		Grants:                     map[string]any{authorizationCodeGrant: grant},
	}
}
