package mdoc

import (
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// mobileSecurityObject is the ISO 18013-5 MSO. Field order matches the
// Java issuer's insertion order: version, digestAlgorithm, valueDigests,
// deviceKeyInfo, docType, validityInfo.
type mobileSecurityObject struct {
	Version         string                    `cbor:"version"`
	DigestAlgorithm string                    `cbor:"digestAlgorithm"`
	ValueDigests    map[string]map[int][]byte `cbor:"valueDigests"`
	DeviceKeyInfo   *deviceKeyInfo            `cbor:"deviceKeyInfo,omitempty"`
	DocType         string                    `cbor:"docType"`
	ValidityInfo    validityInfo              `cbor:"validityInfo"`
}

type deviceKeyInfo struct {
	DeviceKey coseKey `cbor:"deviceKey"`
}

// coseKey is a bare EC2 COSE_Key (RFC 9053 §7.1) — integer labels for
// kty/crv/x/y, no kid/alg/key_ops.
type coseKey struct {
	Kty int    `cbor:"1,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

const (
	coseKeyTypeEC2 = 2
	coseCurveP256  = 1
)

type validityInfo struct {
	Signed     cbor.Tag `cbor:"signed"`
	ValidFrom  cbor.Tag `cbor:"validFrom"`
	ValidUntil cbor.Tag `cbor:"validUntil"`
}

// tdate wraps t as a CBOR tag-0 (RFC 8949 §3.4.1) date/time string, per
// ISO 18013-5's tdate type — RFC 3339/ISO-8601 UTC, matching the Java
// issuer's DateTimeFormatter.ISO_INSTANT output shape.
func tdate(t time.Time) cbor.Tag {
	return cbor.Tag{Number: 0, Content: t.UTC().Format("2006-01-02T15:04:05Z")}
}

// deviceKeyFromJWK converts a wallet's public EC P-256 JWK (as extracted
// from a validated proof JWT) into a COSE_Key, for MSO deviceKeyInfo.
func deviceKeyFromJWK(key jwk.Key) (coseKey, error) {
	ecKey, ok := key.(jwk.ECDSAPublicKey)
	if !ok {
		return coseKey{}, fmt.Errorf("mdoc: device key is not an EC public key (%T)", key)
	}
	xb, ok := ecKey.X()
	if !ok {
		return coseKey{}, fmt.Errorf("mdoc: device key missing x coordinate")
	}
	yb, ok := ecKey.Y()
	if !ok {
		return coseKey{}, fmt.Errorf("mdoc: device key missing y coordinate")
	}
	return coseKey{Kty: coseKeyTypeEC2, Crv: coseCurveP256, X: xb, Y: yb}, nil
}
