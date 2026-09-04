package mdoc

import (
	"encoding/base64"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/lestrrat-go/jwx/v3/jwk"

	fikuacrypto "github.com/fikua/fikua-lab-issuer/internal/crypto"
)

// defaultValidityDays is 1 year, matching the Java issuer's MdocBuilder
// default (never overridden by the current issuance wiring).
const defaultValidityDays = 365

// Builder builds an mdoc IssuerSigned credential, mirroring the Java
// issuer's MdocBuilder fluent API and exact structural layout.
type Builder struct {
	issuerKey    *fikuacrypto.SigningKey
	docType      string
	namespace    string
	elements     []element
	deviceKey    jwk.Key
	x5cChain     [][]byte
	validityDays int
}

// NewBuilder starts a Builder that signs with issuerKey.
func NewBuilder(issuerKey *fikuacrypto.SigningKey) *Builder {
	return &Builder{issuerKey: issuerKey, validityDays: defaultValidityDays}
}

// DocType sets the mdoc docType (embedded in the MSO).
func (b *Builder) DocType(docType string) *Builder { b.docType = docType; return b }

// Namespace sets the single namespace every subsequent Element call
// attaches to — the Java issuer's PID mdoc wiring always uses one
// namespace, equal to docType.
func (b *Builder) Namespace(namespace string) *Builder { b.namespace = namespace; return b }

// DeviceKey sets the wallet's public key, embedded in the MSO's
// deviceKeyInfo as a COSE_Key.
func (b *Builder) DeviceKey(key jwk.Key) *Builder { b.deviceKey = key; return b }

// X5CChain sets the leaf-first DER certificate chain for the COSE_Sign1
// unprotected header's x5chain (label 33).
func (b *Builder) X5CChain(chain [][]byte) *Builder { b.x5cChain = chain; return b }

// Element adds a claim to the current namespace. Its CBOR encoding
// (tstr vs full-date) is picked automatically by claim name — see
// NewElement.
func (b *Builder) Element(identifier, value string) *Builder {
	b.elements = append(b.elements, NewElement(identifier, value))
	return b
}

// MapElement adds a claim whose value is a CBOR map rather than a tstr —
// used for the "status" element (IETF Token Status List).
func (b *Builder) MapElement(identifier string, value map[string]any) *Builder {
	b.elements = append(b.elements, MapElement(identifier, value))
	return b
}

// Build assembles and signs the mdoc, returning the IssuerSigned CBOR
// bytes: {issuerAuth, nameSpaces}.
func (b *Builder) Build() ([]byte, error) {
	nd, err := buildNamespaceItems(b.elements)
	if err != nil {
		return nil, err
	}

	mso := mobileSecurityObject{
		Version:         "1.0",
		DigestAlgorithm: "SHA-256",
		ValueDigests:    map[string]map[int][]byte{b.namespace: nd.digests},
		DocType:         b.docType,
		ValidityInfo:    b.buildValidityInfo(),
	}
	if b.deviceKey != nil {
		deviceKey, err := deviceKeyFromJWK(b.deviceKey)
		if err != nil {
			return nil, err
		}
		mso.DeviceKeyInfo = &deviceKeyInfo{DeviceKey: deviceKey}
	}

	msoBytes, err := cbor.Marshal(mso)
	if err != nil {
		return nil, err
	}
	msoPayload, err := cbor.Marshal(cbor.Tag{Number: 24, Content: msoBytes})
	if err != nil {
		return nil, err
	}

	issuerAuth, err := signCoseSign1(msoPayload, b.issuerKey.Signer(), b.x5cChain)
	if err != nil {
		return nil, err
	}

	// issuerAuth is embedded as a native CBOR array value (decoded back
	// from its own encoding), untagged — no COSE tag 18 — matching the
	// Java issuer. rawIssuerAuth carries the pre-encoded bytes through
	// as-is via cbor.RawMessage so no re-encoding changes its byte
	// layout.
	issuerSigned := struct {
		IssuerAuth cbor.RawMessage              `cbor:"issuerAuth"`
		NameSpaces map[string][]cbor.RawMessage `cbor:"nameSpaces"`
	}{
		IssuerAuth: issuerAuth,
		NameSpaces: map[string][]cbor.RawMessage{b.namespace: taggedItemsAsRaw(nd.taggedItems)},
	}
	return cbor.Marshal(issuerSigned)
}

// BuildBase64URL builds the credential and encodes it as base64url
// (no padding) of the raw CBOR bytes — the exact string OID4VCI's
// credential response field carries for mso_mdoc.
func (b *Builder) BuildBase64URL() (string, error) {
	bytes, err := b.Build()
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func (b *Builder) buildValidityInfo() validityInfo {
	now := time.Now()
	return validityInfo{
		Signed:     tdate(now),
		ValidFrom:  tdate(now),
		ValidUntil: tdate(now.AddDate(0, 0, b.validityDays)),
	}
}

func taggedItemsAsRaw(items [][]byte) []cbor.RawMessage {
	out := make([]cbor.RawMessage, len(items))
	for i, item := range items {
		out[i] = cbor.RawMessage(item)
	}
	return out
}
