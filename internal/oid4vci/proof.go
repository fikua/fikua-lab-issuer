package oid4vci

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/fikua/fikua-lab-issuer/internal/oauth2"
)

// proofIATWindow is the allowed clock skew for a proof JWT's iat claim
// (OID4VCI 1.0 Final §8.2.1.1), symmetric — past and future.
const proofIATWindow = 5 * time.Minute

// ValidateProofJWT validates a wallet's key-proof JWT per OID4VCI 1.0 Final
// §8.2.1.1 and returns the wallet's public key extracted from its `jwk`
// header parameter. expectedIssuer is this issuer's base URL (aud).
//
// Only the `jwk` header key-reference method is supported — a proof using
// `x5c` or `kid` is rejected with the same error message the Java issuer
// uses, even though the exact wording differs by which reference was
// present.
func ValidateProofJWT(proofJWT string, expectedIssuer string) (jwk.Key, error) {
	msg, err := jws.Parse([]byte(proofJWT))
	if err != nil {
		return nil, oauth2.BadRequest(oauth2.InvalidProof, "Invalid proof: "+err.Error())
	}
	if len(msg.Signatures()) != 1 {
		return nil, oauth2.BadRequest(oauth2.InvalidProof, "Proof must have exactly one signature")
	}
	headers := msg.Signatures()[0].ProtectedHeaders()

	typ, _ := headers.Type()
	if typ != "openid4vci-proof+jwt" {
		return nil, oauth2.BadRequest(oauth2.InvalidProof, "Proof typ must be openid4vci-proof+jwt")
	}

	alg, _ := headers.Algorithm()
	if alg != jwa.ES256() {
		return nil, oauth2.BadRequest(oauth2.InvalidProof, "Proof must use ES256")
	}

	walletJWK, hasJWK := headers.JWK()
	_, hasX5C := headers.X509CertChain()
	_, hasKID := headers.KeyID()
	keyRefs := 0
	if hasJWK {
		keyRefs++
	}
	if hasX5C {
		keyRefs++
	}
	if hasKID {
		keyRefs++
	}
	switch {
	case keyRefs == 0:
		return nil, oauth2.BadRequest(oauth2.InvalidProof, "Proof must contain exactly one of jwk, x5c, or kid header parameters")
	case keyRefs > 1:
		return nil, oauth2.BadRequest(oauth2.InvalidProof, "Proof must contain exactly one of jwk, x5c, or kid — multiple key references found")
	case !hasJWK:
		return nil, oauth2.BadRequest(oauth2.InvalidProof, "Only jwk key binding method is supported")
	}

	token, err := jwt.Parse([]byte(proofJWT), jwt.WithKey(jwa.ES256(), walletJWK), jwt.WithValidate(false))
	if err != nil {
		return nil, oauth2.BadRequest(oauth2.InvalidProof, "Proof signature invalid")
	}

	aud, _ := token.Audience()
	if !contains(aud, expectedIssuer) {
		return nil, oauth2.BadRequest(oauth2.InvalidProof, "Proof aud must be the credential issuer")
	}

	iat, hasIAT := token.IssuedAt()
	if !hasIAT {
		return nil, oauth2.BadRequest(oauth2.InvalidProof, "Proof must contain iat claim")
	}
	if skew := time.Since(iat); skew > proofIATWindow || skew < -proofIATWindow {
		return nil, oauth2.BadRequest(oauth2.InvalidProof, "Proof expired")
	}

	return walletJWK, nil
}

// ProofNonce extracts the "nonce" claim from a proof JWT without
// re-validating its signature — used by the credential endpoint to check
// the proof's nonce against the session/global nonce stores, mirroring the
// Java issuer's extractProofNonce.
func ProofNonce(proofJWT string) (string, error) {
	token, err := jwt.Parse([]byte(proofJWT), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return "", fmt.Errorf("oid4vci: parsing proof for nonce: %w", err)
	}
	var nonce string
	if err := token.Get("nonce", &nonce); err != nil {
		return "", nil
	}
	return nonce, nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
