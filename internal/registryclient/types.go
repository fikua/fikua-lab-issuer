// Package registryclient fetches attestation scheme definitions from
// fikua-lab-attestation-registry over HTTP.
//
// Types here are hand-mirrored from that service's internal/model package,
// not imported from it: this is a deliberate boundary — the two services
// share no Go module and no code, only the JSON API contract, so that they
// stay independently deployable and versioned. Keep this file's shapes in
// sync with the registry's own internal/model/attestation.go and enums.go
// by hand when the contract changes.
package registryclient

// CredentialFormat is the OID4VCI issuance format identifier.
type CredentialFormat string

const (
	FormatSDJWTVC CredentialFormat = "dc+sd-jwt"
	FormatMDoc    CredentialFormat = "mso_mdoc"
)

// Presence states whether a claim is required.
type Presence string

const (
	PresenceMandatory   Presence = "mandatory"
	PresenceOptional    Presence = "optional"
	PresenceConditional Presence = "conditional"
)

// Disclosability is the SD-JWT VC selective disclosure requirement for a
// claim. Not applicable to mdoc claims.
type Disclosability string

const (
	DisclosabilityMust    Disclosability = "MUST"
	DisclosabilityMay     Disclosability = "MAY"
	DisclosabilityMustNot Disclosability = "MUST NOT"
)

// ClaimDefinition is the format-specific encoding of one attribute within an
// AttestationScheme.
type ClaimDefinition struct {
	DataIdentifier string         `json:"dataIdentifier"`
	Path           []string       `json:"path"`
	DataType       string         `json:"dataType"`
	Presence       Presence       `json:"presence"`
	Namespace      string         `json:"namespace,omitempty"`
	Disclosability Disclosability `json:"disclosability,omitempty"`
	Enum           []string       `json:"enum,omitempty"`
}

// FormatSchema is the claim set for one issuance format of an attestation
// type. TypeIdentifier is the `vct` for FormatSDJWTVC or the mdoc doctype
// for FormatMDoc.
type FormatSchema struct {
	Format         CredentialFormat  `json:"format"`
	TypeIdentifier string            `json:"typeIdentifier"`
	Claims         []ClaimDefinition `json:"claims"`
}

// SchemaFor returns the FormatSchema for the given format, or nil if the
// scheme does not support it.
func (s AttestationScheme) SchemaFor(format CredentialFormat) *FormatSchema {
	for i := range s.Schemas {
		if s.Schemas[i].Format == format {
			return &s.Schemas[i]
		}
	}
	return nil
}

// AttestationScheme is the machine-readable attestation schema, as served by
// GET /api/v1/schemes/{id}.
type AttestationScheme struct {
	ID               string             `json:"id"`
	CatalogueID      string             `json:"catalogueId,omitempty"`
	Version          string             `json:"version"`
	SupportedFormats []CredentialFormat `json:"supportedFormats"`
	Schemas          []FormatSchema     `json:"schemas"`
}

// AttestationRulebook is the human-readable metadata paired with a scheme.
// Only the fields this client actually uses are declared.
type AttestationRulebook struct {
	AttestationType string `json:"attestationType"`
}

// Definition is one catalogue entry, as served by GET /api/v1/schemes and
// GET /api/v1/schemes/{id}.
type Definition struct {
	Rulebook AttestationRulebook `json:"rulebook"`
	Scheme   AttestationScheme   `json:"scheme"`
}
