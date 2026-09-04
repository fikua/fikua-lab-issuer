package statuslist

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	fikuacrypto "github.com/fikua/fikua-lab-issuer/internal/crypto"
)

// ttlSeconds and validitySeconds are deliberately short — unlike an
// issued credential's 1-year validity, a status list token's whole point
// is to be cheaply re-fetchable and current, so relying parties re-check
// often rather than trusting a long-lived cached copy.
const (
	ttlSeconds      = 3600 // §13.7 "ttl" claim: relying parties may cache this long
	validitySeconds = 86400
)

// Build assembles and signs a Status List Token JWT (§5.1) for entries,
// covering idx range [0,size), served at listURI (used as both the
// token's "sub" claim and, via issuerKey, signed with the same key/x5c
// chain the issuer signs credentials with — the spec's same-entity
// key-reuse guidance, §11.3).
func Build(entries map[int64]uint8, size int64, listURI string, issuerKey *fikuacrypto.SigningKey) (string, error) {
	lst, err := compressAndEncode(packBitstring(entries, size))
	if err != nil {
		return "", fmt.Errorf("statuslist: compressing bitstring: %w", err)
	}

	now := time.Now()
	token, err := jwt.NewBuilder().
		Subject(listURI).
		IssuedAt(now).
		Expiration(now.Add(validitySeconds*time.Second)).
		Claim("ttl", ttlSeconds).
		Claim("status_list", map[string]any{"bits": Bits, "lst": lst}).
		Build()
	if err != nil {
		return "", fmt.Errorf("statuslist: building claims: %w", err)
	}

	headers := jws.NewHeaders()
	if err := headers.Set(jws.TypeKey, "statuslist+jwt"); err != nil {
		return "", err
	}
	if err := headers.Set(jws.KeyIDKey, issuerKey.KID()); err != nil {
		return "", err
	}
	if chain := issuerKey.X5CChain(); len(chain) > 0 {
		x5c, err := fikuacrypto.BuildX5CChain(chain)
		if err != nil {
			return "", err
		}
		if err := headers.Set(jws.X509CertChainKey, x5c); err != nil {
			return "", err
		}
	}

	signed, err := jwt.Sign(token, jwt.WithKey(fikuacrypto.Algorithm, issuerKey.Signer(), jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", fmt.Errorf("statuslist: signing: %w", err)
	}
	return string(signed), nil
}
