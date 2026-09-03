package cscclient

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
)

// parseECPublicKey parses leafDER as an X.509 certificate and returns its
// EC public key.
func parseECPublicKey(leafDER []byte) (*ecdsa.PublicKey, error) {
	cert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate public key is %T, not EC", cert.PublicKey)
	}
	return pub, nil
}
