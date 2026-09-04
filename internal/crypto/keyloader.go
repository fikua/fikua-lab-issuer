package crypto

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// LoadFromPEM loads the issuer's signing key and certificate from
// <certsDir>/issuer-cert.pem + issuer-key.pem — mirroring the Java
// issuer's PemKeyLoader. There is no ephemeral fallback: a signing key
// this issuer's own credentials chain to but that no relying party
// trusts is worse than refusing to start, since it fails silently
// instead of loudly (see NewRemote/cmd/issuer/main.go's
// loadSigningKey, which prefers this only when FIKUA_DSS_URL is unset —
// remote signing via the Fikua DSS is the default in every real
// deployment).
func LoadFromPEM(certsDir string) (*SigningKey, error) {
	certPath := filepath.Join(certsDir, "issuer-cert.pem")
	keyPath := filepath.Join(certsDir, "issuer-key.pem")

	if !fileExists(certPath) || !fileExists(keyPath) {
		return nil, fmt.Errorf("crypto: no signing key configured — set FIKUA_DSS_URL for remote signing via the Fikua DSS, or place issuer-cert.pem + issuer-key.pem in %s", certsDir)
	}
	return loadFromPEM(certPath, keyPath)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func loadFromPEM(certPath, keyPath string) (*SigningKey, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("crypto: reading %s: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("crypto: reading %s: %w", keyPath, err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("crypto: %s: no PEM block found", certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: parsing certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("crypto: %s: no PEM block found", keyPath)
	}
	private, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: parsing PKCS8 private key: %w", err)
	}
	ecPrivate, ok := private.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("crypto: %s: not an EC private key", keyPath)
	}

	pub, kid, x5cChain, err := buildPublicJWK(ecPrivate, [][]byte{cert.Raw})
	if err != nil {
		return nil, err
	}
	return &SigningKey{kid: kid, signer: ecPrivate, public: pub, x5cChain: x5cChain}, nil
}
