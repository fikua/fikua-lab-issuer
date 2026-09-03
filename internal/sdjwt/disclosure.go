// Package sdjwt builds SD-JWT VC credentials (dc+sd-jwt), matching the Java
// issuer's SdJwtBuilder byte-for-byte where it matters for wallet
// interoperability (disclosure digest computation, salt/encoding).
package sdjwt

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

// Disclosure is one SD-JWT selective-disclosure claim: salt, claim name,
// and value, encoded per SD-JWT §5.1.
type Disclosure struct {
	Salt      string
	ClaimName string
	Value     any
	Encoded   string
}

// NewDisclosure builds a Disclosure for the given claim name/value.
//
// Byte-level detail that must match the Java issuer for wallet
// interoperability: a 16-byte random salt (base64url, no padding); the
// disclosure array [salt, claimName, value] JSON-encoded compactly (no
// extra whitespace, matching Jackson's default writer); that JSON encoded
// as base64url, no padding.
func NewDisclosure(claimName string, value any) (Disclosure, error) {
	saltBytes := make([]byte, 16)
	if _, err := rand.Read(saltBytes); err != nil {
		return Disclosure{}, err
	}
	salt := base64.RawURLEncoding.EncodeToString(saltBytes)

	arr, err := json.Marshal([]any{salt, claimName, value})
	if err != nil {
		return Disclosure{}, err
	}
	encoded := base64.RawURLEncoding.EncodeToString(arr)

	return Disclosure{Salt: salt, ClaimName: claimName, Value: value, Encoded: encoded}, nil
}

// Digest computes the SD-JWT §5.1.1.3 digest of this disclosure: SHA-256
// over the ASCII bytes of the base64url-encoded disclosure string itself
// (not the raw JSON), base64url-no-padding encoded.
func (d Disclosure) Digest() string {
	hash := sha256.Sum256([]byte(d.Encoded))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
