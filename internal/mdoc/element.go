package mdoc

import "github.com/fxamacker/cbor/v2"

// element is one claim to embed in an mdoc namespace: an identifier and a
// value, plus how that value should be CBOR-encoded.
type element struct {
	identifier string
	value      string
	kind       elementKind
}

// elementKind selects the CBOR encoding for an element's value. The Java
// issuer this is ported from encodes every value as a plain CBOR text
// string (tstr) regardless of the field's actual data type — including
// birth_date, which ISO 18013-5 and the EUDI PID rulebook require as
// full-date (CBOR tag 1004). This port fixes that gap for birth_date;
// every other field stays tstr, matching the Java behavior (and matching
// what the current attestation-registry PID mdoc schema documents for
// them: tstr, or vendor-specific types like nationalities/place_of_birth
// that this issuer doesn't yet expose on its issuance form — see
// credentialconfig's scalar-only claim filter).
type elementKind int

const (
	elementText elementKind = iota
	elementFullDate
)

// TextElement builds a plain tstr-valued element.
func TextElement(identifier, value string) element {
	return element{identifier: identifier, value: value, kind: elementText}
}

// FullDateElement builds a full-date-valued element (CBOR tag 1004),
// value formatted as "YYYY-MM-DD".
func FullDateElement(identifier, value string) element {
	return element{identifier: identifier, value: value, kind: elementFullDate}
}

// birthDateIdentifier is the one field this issuer knows to encode as
// full-date rather than tstr — see resolveElementKind.
const birthDateIdentifier = "birth_date"

// resolveElementKind picks TextElement vs FullDateElement for a claim by
// name, matching this issuer's own PID mdoc claim set (see
// internal/issuance's mdoc credential building).
func resolveElementKind(identifier string) elementKind {
	if identifier == birthDateIdentifier {
		return elementFullDate
	}
	return elementText
}

// NewElement builds an element, picking its CBOR encoding by claim name.
func NewElement(identifier, value string) element {
	if resolveElementKind(identifier) == elementFullDate {
		return FullDateElement(identifier, value)
	}
	return TextElement(identifier, value)
}

func (e element) cborValue() any {
	switch e.kind {
	case elementFullDate:
		return cbor.Tag{Number: 1004, Content: e.value}
	default:
		return e.value
	}
}
