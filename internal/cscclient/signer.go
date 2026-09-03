package cscclient

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"io"
)

// sha256OID is the CSC hashAlgo identifying SHA-256 (2.16.840.1.101.3.4.2.1,
// id-sha256), the only digest this issuer signs with (ES256 throughout).
const sha256OID = "2.16.840.1.101.3.4.2.1"

// Signer implements crypto.Signer by delegating the actual signing
// operation to a Fikua DSS CSC credential over the network, instead of
// holding a private key in process memory. Its public key is fetched once
// from the DSS and cached — see NewSigner.
type Signer struct {
	client    *Client
	publicKey *ecdsa.PublicKey
}

// NewSigner builds a Signer backed by client, fetching and caching the
// tenant's public key from /csc/v2/credentials/info. ctx bounds only this
// setup call, not later Sign calls.
func NewSigner(ctx context.Context, client *Client) (*Signer, error) {
	info, err := client.CredentialInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("cscclient: building signer: %w", err)
	}
	if len(info.ChainDER) == 0 {
		return nil, fmt.Errorf("cscclient: credential info returned no certificate chain")
	}
	pub, err := parseECPublicKey(info.ChainDER[0])
	if err != nil {
		return nil, fmt.Errorf("cscclient: parsing leaf certificate public key: %w", err)
	}
	return &Signer{client: client, publicKey: pub}, nil
}

// Public returns the tenant's public key, as required by crypto.Signer.
func (s *Signer) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs digest (already hashed by the caller, per crypto.Signer's
// contract) via the DSS's CSC signHash endpoint. rand and opts are ignored:
// the DSS performs raw ECDSA over the given digest server-side, and this
// issuer only ever signs SHA-256 digests (ES256).
func (s *Signer) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return s.client.SignHash(context.Background(), digest, sha256OID)
}

// LeafDER re-fetches and returns only the tenant's own leaf certificate
// (DER-encoded), for embedding in x5c headers. The DSS's
// /csc/v2/credentials/info returns the full chain up to its root CA (see
// CertificateInfo.ChainDER), but HAIP §6.1.1 requires the x5c JOSE header
// to carry the signing certificate "along with a trust chain" while
// explicitly forbidding the trust anchor's certificate from appearing in
// it ("The X.509 certificate of the trust anchor MUST NOT be included in
// the x5c JOSE header of the SD-JWT VC"). Our PKI has the leaf signed
// directly by the root CA with no intermediates, so "leaf only" and "full
// chain minus the trust anchor" are the same thing here — matching the
// local-signing path in internal/crypto/keyloader.go. If an intermediate
// CA is ever introduced between the leaf and fikua-dss-root-ca, this must
// change to return every certificate except the last (root) one, not just
// index 0.
func (s *Signer) LeafDER(ctx context.Context) ([]byte, error) {
	info, err := s.client.CredentialInfo(ctx)
	if err != nil {
		return nil, err
	}
	if len(info.ChainDER) == 0 {
		return nil, fmt.Errorf("cscclient: credential info returned no certificate chain")
	}
	return info.ChainDER[0], nil
}
