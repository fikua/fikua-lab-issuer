package oid4vci

// CredentialOffer is the OID4VCI §4.1 Credential Offer.
type CredentialOffer struct {
	CredentialIssuer           string         `json:"credential_issuer"`
	CredentialConfigurationIDs []string       `json:"credential_configuration_ids"`
	Grants                     map[string]any `json:"grants"`
}

// TxCode describes the transaction code delivery mechanism, per OID4VCI
// §4.1.1's pre-authorized_code grant object.
type TxCode struct {
	InputMode   string `json:"input_mode"`
	Length      int    `json:"length"`
	Description string `json:"description"`
}

const preAuthorizedCodeGrant = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

// PreAuthorizedOffer builds a Credential Offer for the pre-authorized_code
// grant.
func PreAuthorizedOffer(issuerURL, configID, preAuthCode string, txCodeRequired bool) CredentialOffer {
	grant := map[string]any{"pre-authorized_code": preAuthCode}
	if txCodeRequired {
		grant["tx_code"] = TxCode{InputMode: "numeric", Length: 6, Description: "Enter the transaction code"}
	}
	return CredentialOffer{
		CredentialIssuer:           issuerURL,
		CredentialConfigurationIDs: []string{configID},
		Grants:                     map[string]any{preAuthorizedCodeGrant: grant},
	}
}
