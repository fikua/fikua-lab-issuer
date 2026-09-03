// Package config loads this service's configuration from environment
// variables.
package config

import (
	"os"
	"strings"
	"time"
)

// Config holds the issuer's runtime configuration.
type Config struct {
	Addr                    string
	BasePath                string
	BaseURL                 string
	AttestationRegistryURL  string
	RegistryRefreshInterval time.Duration
	// IssuableSchemes is the explicit allowlist of attestation-registry
	// scheme ids (AttestationScheme.ID, e.g. "urn:eudi:pid:1") this issuer
	// will build credential configurations for. The registry may define
	// schemes this issuer has no business issuing (prototypes, other
	// services' credentials) — this list is what this issuer has actually
	// decided to issue, not "whatever the registry happens to publish".
	IssuableSchemes []string
	// CertsDir holds issuer-cert.pem + issuer-key.pem for the signing key.
	// If either is missing, an ephemeral CA-signed key is generated at
	// startup instead (see internal/crypto.LoadOrGenerate).
	CertsDir string
}

// Load reads configuration from environment variables, applying defaults
// where unset.
func Load() Config {
	return Config{
		Addr:                    getenv("ADDR", ":8080"),
		BasePath:                getenv("BASE_PATH", ""),
		BaseURL:                 getenv("FIKUA_BASE_URL", "https://issuer.fikua.com"),
		AttestationRegistryURL:  getenv("FIKUA_ATTESTATION_REGISTRY_URL", "https://attestation-registry.fikua.com"),
		RegistryRefreshInterval: 5 * time.Minute,
		IssuableSchemes:         splitCSV(getenv("FIKUA_ISSUABLE_SCHEMES", "urn:eudi:pid:1,urn:fikua:padro:barcelona:1")),
		CertsDir:                getenv("FIKUA_CERTS_DIR", "./certs"),
	}
}

func splitCSV(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
