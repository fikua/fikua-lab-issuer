// Package crypto provides the issuer's EC P-256/ES256 signing key: loaded
// from PEM files if present, or generated ephemerally (with a CA-signed
// issuer certificate, per HAIP §6.1.1's non-self-signed x5c requirement) if
// not.
package crypto

import (
	"crypto"
	"encoding/base64"
	"encoding/json"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func base64URLNoPadding(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// SigningKey is the issuer's signing key: either a local EC P-256 private
// key, or a crypto.Signer delegating to a remote signing service (e.g. the
// Fikua DSS over CSC — see NewRemote). Either way it carries the matching
// public JWK Set (with an optional x5c certificate chain).
type SigningKey struct {
	kid      string
	signer   crypto.Signer // *ecdsa.PrivateKey for local keys, or a remote crypto.Signer
	public   jwk.Key       // public JWK, with kid/x5c/alg/use set
	x5cChain [][]byte      // leaf-first DER chain, root CA excluded; nil if unset
}

// Algorithm is the JWS algorithm this issuer signs with — ES256 throughout,
// matching the Java issuer.
var Algorithm = jwa.ES256()

// KID returns the key's id — the RFC 7638 SHA-256 JWK thumbprint, matching
// the Java issuer's EcKeyManager (never a random UUID).
func (k *SigningKey) KID() string {
	return k.kid
}

// Signer returns the crypto.Signer backing this key — either a local
// *ecdsa.PrivateKey or a remote signer (e.g. cscclient.Signer). jwx's
// jwt.WithKey/jws.Sign accept any crypto.Signer, so callers no longer need
// to know which.
func (k *SigningKey) Signer() crypto.Signer {
	return k.signer
}

// PublicJWK returns the key's public JWK (kid/x5c/alg/use already set).
func (k *SigningKey) PublicJWK() jwk.Key {
	return k.public
}

// X5CChain returns the leaf-first DER certificate chain (root CA excluded)
// backing this key, or nil if it has none.
func (k *SigningKey) X5CChain() [][]byte {
	return k.x5cChain
}

// JWKSetJSON returns the public JWK Set as it should be served at
// /oid4vci/v1/jwks: {"keys": [<public JWK>]}.
func (k *SigningKey) JWKSetJSON() ([]byte, error) {
	set := jwk.NewSet()
	if err := set.AddKey(k.public); err != nil {
		return nil, err
	}
	return json.Marshal(set)
}

// NewRemote builds a SigningKey backed by signer (e.g. a cscclient.Signer
// delegating to the Fikua DSS), with certChainDER as its x5c chain
// (leaf-first, root CA excluded).
func NewRemote(signer crypto.Signer, certChainDER [][]byte) (*SigningKey, error) {
	pub, kid, chain, err := buildPublicJWK(signer, certChainDER)
	if err != nil {
		return nil, err
	}
	return &SigningKey{kid: kid, signer: signer, public: pub, x5cChain: chain}, nil
}

// buildPublicJWK derives the public JWK for signer (kid = RFC 7638 SHA-256
// thumbprint, alg = ES256, use = sig), attaching x5c if certChainDER is
// non-empty (leaf-first, root CA excluded, per HAIP §6.1.1 — callers must
// not include the CA certificate).
func buildPublicJWK(signer crypto.Signer, certChainDER [][]byte) (jwk.Key, string, [][]byte, error) {
	pub, err := jwk.Import(signer.Public())
	if err != nil {
		return nil, "", nil, err
	}
	thumbprint, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, "", nil, err
	}
	kid := base64URLNoPadding(thumbprint)
	if err := pub.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, "", nil, err
	}
	if err := pub.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		return nil, "", nil, err
	}
	if err := pub.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return nil, "", nil, err
	}
	if len(certChainDER) > 0 {
		chain, err := BuildX5CChain(certChainDER)
		if err != nil {
			return nil, "", nil, err
		}
		if err := pub.Set(jwk.X509CertChainKey, chain); err != nil {
			return nil, "", nil, err
		}
	}
	return pub, kid, certChainDER, nil
}
