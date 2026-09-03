package sdjwt

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	fikuacrypto "github.com/fikua/fikua-lab-issuer/internal/crypto"
)

// defaultValiditySeconds is 1 year, matching the Java issuer's
// SdJwtBuilder default.
const defaultValiditySeconds = 86400 * 365

// Builder builds an SD-JWT VC (dc+sd-jwt), mirroring the Java issuer's
// SdJwtBuilder fluent API and exact claim assembly order.
type Builder struct {
	issuerKey       *fikuacrypto.SigningKey
	vct             string
	issuer          string
	subject         string
	validitySeconds int64
	plainClaims     []claimEntry
	selectiveClaims []claimEntry
	holderKey       jwk.Key
	x5cChain        [][]byte
}

type claimEntry struct {
	name  string
	value any
}

// NewBuilder starts a Builder that signs with issuerKey.
func NewBuilder(issuerKey *fikuacrypto.SigningKey) *Builder {
	return &Builder{issuerKey: issuerKey, validitySeconds: defaultValiditySeconds}
}

func (b *Builder) VCT(vct string) *Builder          { b.vct = vct; return b }
func (b *Builder) Issuer(issuer string) *Builder    { b.issuer = issuer; return b }
func (b *Builder) Subject(subject string) *Builder  { b.subject = subject; return b }
func (b *Builder) HolderKey(key jwk.Key) *Builder   { b.holderKey = key; return b }
func (b *Builder) X5CChain(chain [][]byte) *Builder { b.x5cChain = chain; return b }

// PlainClaim adds an always-visible top-level claim.
func (b *Builder) PlainClaim(name string, value any) *Builder {
	b.plainClaims = append(b.plainClaims, claimEntry{name, value})
	return b
}

// SelectiveClaim adds a claim that becomes a selectively-disclosable SD-JWT
// disclosure. Claims are disclosed in the order they're added here — this
// determines the _sd digest array order, matching the Java issuer.
func (b *Builder) SelectiveClaim(name string, value any) *Builder {
	b.selectiveClaims = append(b.selectiveClaims, claimEntry{name, value})
	return b
}

// Build assembles and signs the SD-JWT, returning the combined
// "<jwt>~<disclosure>~...~" serialization (SD-JWT §4).
func (b *Builder) Build() (string, error) {
	if b.vct == "" {
		return "", fmt.Errorf("sdjwt: vct is required")
	}

	var disclosures []Disclosure
	var sdDigests []string
	for _, c := range b.selectiveClaims {
		d, err := NewDisclosure(c.name, c.value)
		if err != nil {
			return "", err
		}
		disclosures = append(disclosures, d)
		sdDigests = append(sdDigests, d.Digest())
	}

	now := time.Now()
	builder := jwt.NewBuilder().
		Issuer(b.issuer).
		IssuedAt(now).
		Expiration(now.Add(time.Duration(b.validitySeconds)*time.Second)).
		Claim("vct", b.vct)
	if b.subject != "" {
		builder = builder.Subject(b.subject)
	}
	if len(sdDigests) > 0 {
		builder = builder.Claim("_sd", sdDigests).Claim("_sd_alg", "sha-256")
	}
	for _, c := range b.plainClaims {
		builder = builder.Claim(c.name, c.value)
	}
	if b.holderKey != nil {
		holderPublicJWK, err := b.holderKey.PublicKey()
		if err != nil {
			return "", fmt.Errorf("sdjwt: deriving holder public JWK: %w", err)
		}
		holderJWKMap, err := jwkToMap(holderPublicJWK)
		if err != nil {
			return "", fmt.Errorf("sdjwt: encoding holder JWK: %w", err)
		}
		builder = builder.Claim("cnf", map[string]any{"jwk": holderJWKMap})
	}

	token, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("sdjwt: building claims: %w", err)
	}

	headers := jws.NewHeaders()
	if err := headers.Set(jws.TypeKey, "dc+sd-jwt"); err != nil {
		return "", err
	}
	if err := headers.Set(jws.KeyIDKey, b.issuerKey.KID()); err != nil {
		return "", err
	}
	if len(b.x5cChain) > 0 {
		chain, err := fikuacrypto.BuildX5CChain(b.x5cChain)
		if err != nil {
			return "", err
		}
		if err := headers.Set(jws.X509CertChainKey, chain); err != nil {
			return "", err
		}
	}

	signed, err := jwt.Sign(token, jwt.WithKey(fikuacrypto.Algorithm, b.issuerKey.Signer(), jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", fmt.Errorf("sdjwt: signing: %w", err)
	}

	var sb strings.Builder
	sb.Write(signed)
	for _, d := range disclosures {
		sb.WriteByte('~')
		sb.WriteString(d.Encoded)
	}
	sb.WriteByte('~')
	return sb.String(), nil
}

// jwkToMap round-trips a jwk.Key through JSON to get a plain map — this is
// exactly what ends up embedded as the SD-JWT's cnf.jwk claim (the wallet's
// raw public JWK JSON object), matching the Java issuer's
// holderKey.toPublicJWK().toJSONObject().
func jwkToMap(key jwk.Key) (map[string]any, error) {
	buf, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(buf, &m); err != nil {
		return nil, err
	}
	return m, nil
}
