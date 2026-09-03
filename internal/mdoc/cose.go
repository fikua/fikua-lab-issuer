// Package mdoc builds ISO 18013-5 mdoc (mso_mdoc) credentials: the
// IssuerSigned CBOR structure (nameSpaces + issuerAuth), matching the Java
// issuer's MdocBuilder/CoseSign1 byte-for-byte where it matters for
// wallet interoperability — except birth_date, deliberately fixed here to
// use full-date (CBOR tag 1004) instead of the Java implementation's plain
// tstr, which is a spec-compliance gap in the source being ported (see the
// migration notes).
package mdoc

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

const (
	coseAlgES256      = -7
	coseHeaderAlg     = 1
	coseHeaderX5Chain = 33
)

// coseSign1 is the COSE_Sign1 structure (RFC 9052 §4.2), as embedded
// untagged (no COSE tag 18) inside IssuerSigned.issuerAuth.
type coseSign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[int]any
	Payload     []byte
	Signature   []byte
}

// signCoseSign1 builds and signs a COSE_Sign1 over payload, with a
// protected header of {1: -7} (alg: ES256) and an unprotected header
// carrying x5cChain under label 33 (x5chain) — a single bstr for one
// certificate, an array of bstr for more than one, matching real-world
// COSE x5chain convention.
func signCoseSign1(payload []byte, signer crypto.Signer, x5cChain [][]byte) ([]byte, error) {
	protectedMap := map[int]any{coseHeaderAlg: coseAlgES256}
	protectedBytes, err := cbor.Marshal(protectedMap)
	if err != nil {
		return nil, err
	}

	unprotected := map[int]any{}
	if len(x5cChain) == 1 {
		unprotected[coseHeaderX5Chain] = x5cChain[0]
	} else if len(x5cChain) > 1 {
		unprotected[coseHeaderX5Chain] = x5cChain
	}

	sigStructure := struct {
		_           struct{} `cbor:",toarray"`
		Context     string
		Protected   []byte
		ExternalAAD []byte
		Payload     []byte
	}{Context: "Signature1", Protected: protectedBytes, ExternalAAD: []byte{}, Payload: payload}
	toBeSigned, err := cbor.Marshal(sigStructure)
	if err != nil {
		return nil, err
	}

	signature, err := signRawP1363(signer, toBeSigned)
	if err != nil {
		return nil, err
	}

	return cbor.Marshal(coseSign1{
		Protected:   protectedBytes,
		Unprotected: unprotected,
		Payload:     payload,
		Signature:   signature,
	})
}

// signRawP1363 signs sha256(data) with signer, returning the fixed 64-byte
// raw r||s signature COSE requires (not DER/ASN.1) — the equivalent of the
// Java issuer's "SHA256withECDSAinP1363Format". crypto.Signer.Sign returns
// an ASN.1 DER-encoded ECDSA signature (standard Go convention, followed by
// both *ecdsa.PrivateKey and remote signers such as cscclient.Signer), so
// it's decoded and re-packed as fixed-width r||s here.
func signRawP1363(signer crypto.Signer, data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	der, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	r, s, err := parseECDSADER(der)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// parseECDSADER decodes an ASN.1 DER-encoded ECDSA signature (SEQUENCE { r
// INTEGER, s INTEGER }) into its r and s components.
func parseECDSADER(der []byte) (r, s *big.Int, err error) {
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, nil, fmt.Errorf("parsing ECDSA signature: %w", err)
	}
	return sig.R, sig.S, nil
}
