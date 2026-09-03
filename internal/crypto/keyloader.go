package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// LoadOrGenerate loads the issuer's signing key and certificate from
// <certsDir>/issuer-cert.pem + issuer-key.pem if present, or generates an
// ephemeral one if not — mirroring the Java issuer's PemKeyLoader.
//
// The ephemeral path builds a throwaway CA that signs a separate issuer
// certificate: per HAIP §6.1.1, the x5c signing cert MUST NOT be
// self-signed. Only the issuer certificate goes into x5c — the CA
// certificate is excluded from the chain and not persisted anywhere; it
// exists only for the duration of this process.
func LoadOrGenerate(certsDir string) (*SigningKey, error) {
	certPath := filepath.Join(certsDir, "issuer-cert.pem")
	keyPath := filepath.Join(certsDir, "issuer-key.pem")

	if fileExists(certPath) && fileExists(keyPath) {
		return loadFromPEM(certPath, keyPath)
	}
	return generateEphemeral()
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

func generateEphemeral() (*SigningKey, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("crypto: generating CA key: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixMilli()),
		Subject: pkix.Name{
			CommonName:   "Fikua Lab CA (dev)",
			Organization: []string{"Fikua"},
			Country:      []string{"ES"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: creating CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parsing generated CA certificate: %w", err)
	}

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("crypto: generating issuer key: %w", err)
	}
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixMilli() + 1),
		Subject: pkix.Name{
			CommonName:   "Fikua Lab Issuer (dev)",
			Organization: []string{"Fikua"},
			Country:      []string{"ES"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	// Signed by the CA, not self-signed — the CA certificate itself is
	// never included in x5c (see buildPublicJWK call below).
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, caCert, &issuerKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: creating issuer certificate: %w", err)
	}

	pub, kid, x5cChain, err := buildPublicJWK(issuerKey, [][]byte{issuerDER})
	if err != nil {
		return nil, err
	}
	return &SigningKey{kid: kid, signer: issuerKey, public: pub, x5cChain: x5cChain}, nil
}
