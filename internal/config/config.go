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
	// If either is missing, the issuer fails to start (see
	// internal/crypto.LoadFromPEM) — there is no ephemeral fallback.
	// Ignored when DSSURL is set — remote signing takes over instead, and
	// is what every real deployment should use.
	CertsDir string
	// DSSURL, if non-empty, switches this issuer to remote signing via a
	// Fikua Digital Signature Service (CSC v2.0) instance at this base URL
	// (e.g. "https://dss.fikua.com"), instead of the local
	// CertsDir/PEM key. DSSClientID/DSSClientSecret authenticate as
	// one CSC tenant; DSSCredentialID/DSSCredentialPassword identify and
	// authorize that tenant's signing credential.
	DSSURL                string
	DSSClientID           string
	DSSClientSecret       string
	DSSCredentialID       string
	DSSCredentialPassword string
	// DBURL, if non-empty, switches issuance-record persistence to
	// Postgres (a Go-native DSN, e.g. "postgres://fikua:pass@fikua-lab-issuer-db:5432/fikua_lab_issuer"
	// — NOT the JDBC URL format fikua-lab's Java services use). Empty
	// falls back to an in-memory store (data lost on restart), which is
	// fine for local development but not for a real deployment.
	DBURL string
	// IdentifyBaseURL, if non-empty, is the end-user identification
	// frontend /authorize redirects to when no issuer_state resolves an
	// existing issuance record — the real substitute for interactive
	// login this OID4VCI authorization_code flow otherwise has none of.
	// Empty disables it: HandleAuthorize falls back to synthesizing PID
	// data instead (see internal/issuance.defaultPIDCredentialData),
	// which is what keeps the OIDF conformance suite's automated client
	// — which cannot complete an interactive identification form —
	// working.
	IdentifyBaseURL string
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
		DSSURL:                  getenv("FIKUA_DSS_URL", ""),
		DSSClientID:             getenv("FIKUA_DSS_CLIENT_ID", ""),
		DSSClientSecret:         getenv("FIKUA_DSS_CLIENT_SECRET", ""),
		DSSCredentialID:         getenv("FIKUA_DSS_CREDENTIAL_ID", ""),
		DSSCredentialPassword:   getenv("FIKUA_DSS_CREDENTIAL_PASSWORD", ""),
		DBURL:                   getenv("FIKUA_DB_URL", ""),
		IdentifyBaseURL:         getenv("FIKUA_IDENTIFY_BASE_URL", ""),
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
