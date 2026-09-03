// Package credentialconfig converts attestation-registry scheme definitions
// into OID4VCI credential_configurations_supported entries, replacing the
// hardcoded configuration map the Java issuer used to build in
// IssuanceService.buildCredentialConfigurations().
package credentialconfig

import (
	"github.com/fikua/fikua-lab-issuer/internal/registryclient"
)

// Config is one entry of the OID4VCI
// credential_configurations_supported map, in the shape the issuance UI
// (web/static/app.js) already renders: credential_metadata.display[] and
// credential_metadata.claims[], each claim keyed by a single-segment path
// with its own display[].
type Config struct {
	Format                      string              `json:"format"`
	Scope                       string              `json:"scope"`
	CryptographicBindingMethods []string            `json:"cryptographic_binding_methods_supported"`
	CredentialSigningAlgValues  []any               `json:"credential_signing_alg_values_supported"`
	ProofTypesSupported         ProofTypesSupported `json:"proof_types_supported"`
	VCT                         string              `json:"vct,omitempty"`
	DocType                     string              `json:"doctype,omitempty"`
	CredentialMetadata          CredentialMetadata  `json:"credential_metadata"`
}

type ProofTypesSupported struct {
	JWT ProofTypeJWT `json:"jwt"`
}

type ProofTypeJWT struct {
	ProofSigningAlgValuesSupported []string `json:"proof_signing_alg_values_supported"`
}

type CredentialMetadata struct {
	Display []Display `json:"display"`
	Claims  []Claim   `json:"claims"`
}

type Display struct {
	Name        string `json:"name"`
	Locale      string `json:"locale"`
	Description string `json:"description,omitempty"`
}

type Claim struct {
	Path    []string       `json:"path"`
	Display []ClaimDisplay `json:"display,omitempty"`
}

type ClaimDisplay struct {
	Name   string `json:"name"`
	Locale string `json:"locale"`
}

// Build converts an attestation-registry scheme into
// credential_configurations_supported entries, keyed by
// credential_configuration_id, for every format the scheme supports.
//
// Only single-segment, scalar-typed claims (e.g. "given_name", a string)
// are included in credential_metadata.claims — the issuance form only
// renders flat text/date inputs today. Nested claims (address.formatted)
// and composite-typed ones despite a flat path (place_of_birth, an
// object; nationalities, an array) are present in the scheme but omitted
// from the form; the credential itself is still built with its full claim
// set once the issuance flow is ported (phase 3), this only affects what
// the form asks for.
func Build(def registryclient.Definition) map[string]Config {
	out := make(map[string]Config)
	for _, format := range def.Scheme.SupportedFormats {
		schema := def.Scheme.SchemaFor(format)
		if schema == nil {
			continue
		}
		configID := configurationID(def.Scheme.ID, format)
		out[configID] = buildConfig(def, format, schema)
	}
	return out
}

// configurationID derives a stable credential_configuration_id from the
// scheme id and format. The scheme id itself (e.g. "urn:eudi:pid:1") is
// reused as-is for the sd-jwt configuration; mdoc gets a distinguishing
// suffix so both configs can coexist in the same
// credential_configurations_supported map.
func configurationID(schemeID string, format registryclient.CredentialFormat) string {
	if format == registryclient.FormatMDoc {
		return schemeID + ".mdoc"
	}
	return schemeID
}

func buildConfig(def registryclient.Definition, format registryclient.CredentialFormat, schema *registryclient.FormatSchema) Config {
	cfg := Config{
		Scope: def.Scheme.ID,
		ProofTypesSupported: ProofTypesSupported{
			JWT: ProofTypeJWT{ProofSigningAlgValuesSupported: []string{"ES256"}},
		},
		CredentialMetadata: CredentialMetadata{
			Display: []Display{{Name: def.Rulebook.AttestationType, Locale: "en"}},
			Claims:  buildClaims(schema.Claims),
		},
	}

	switch format {
	case registryclient.FormatSDJWTVC:
		cfg.Format = "dc+sd-jwt"
		cfg.CryptographicBindingMethods = []string{"jwk"}
		cfg.CredentialSigningAlgValues = []any{"ES256"}
		cfg.VCT = schema.TypeIdentifier
	case registryclient.FormatMDoc:
		cfg.Format = "mso_mdoc"
		cfg.CryptographicBindingMethods = []string{"cose_key"}
		cfg.CredentialSigningAlgValues = []any{-7} // COSE ES256
		cfg.DocType = schema.TypeIdentifier
	}
	return cfg
}

func buildClaims(claims []registryclient.ClaimDefinition) []Claim {
	out := make([]Claim, 0, len(claims))
	for _, c := range claims {
		if len(c.Path) != 1 || !isScalarType(c.DataType) {
			continue
		}
		out = append(out, Claim{
			Path:    c.Path,
			Display: []ClaimDisplay{{Name: claimLabel(c.DataIdentifier), Locale: "en"}},
		})
	}
	return out
}
