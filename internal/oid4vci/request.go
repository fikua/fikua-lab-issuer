package oid4vci

// CredentialRequest is the OID4VCI §7.2 credential-endpoint request body.
type CredentialRequest struct {
	Format                       string              `json:"format,omitempty"`
	CredentialConfigurationID    string              `json:"credential_configuration_id,omitempty"`
	CredentialIdentifier         string              `json:"credential_identifier,omitempty"`
	Proof                        *Proof              `json:"proof,omitempty"`
	Proofs                       map[string][]string `json:"proofs,omitempty"`
	CredentialResponseEncryption map[string]any      `json:"credential_response_encryption,omitempty"`
}

// Proof is the draft singular proof format: {"proof_type": "jwt", "jwt": "..."}.
type Proof struct {
	ProofType string `json:"proof_type"`
	JWT       string `json:"jwt"`
}

// ExtractProofJWT returns the wallet's key-proof JWT, checking the OID4VCI
// 1.0 Final plural "proofs" format first, then falling back to the older
// singular "proof" format — matching the Java issuer's
// CredentialRequest.extractProofJwt().
func (r CredentialRequest) ExtractProofJWT() string {
	if jwts, ok := r.Proofs["jwt"]; ok && len(jwts) > 0 {
		return jwts[0]
	}
	if r.Proof != nil && r.Proof.ProofType == "jwt" {
		return r.Proof.JWT
	}
	return ""
}
