package mdoc

import (
	"crypto/rand"
	"crypto/sha256"

	"github.com/fxamacker/cbor/v2"
)

// issuerSignedItem is one ISO 18013-5 IssuerSignedItem. Field order is the
// wire order (digestID, random, elementIdentifier, elementValue) — the
// Java issuer relies on insertion order rather than any canonical-CBOR
// sort, so this struct's declaration order must match exactly for
// byte-compatible output.
type issuerSignedItem struct {
	DigestID          int    `cbor:"digestID"`
	Random            []byte `cbor:"random"`
	ElementIdentifier string `cbor:"elementIdentifier"`
	ElementValue      any    `cbor:"elementValue"`
}

// namespaceDigest is one namespace's built items (as tag-24-wrapped CBOR,
// ready to embed in nameSpaces) plus the SHA-256 digest of each item's
// tagged bytes (as required for the MSO's valueDigests — ISO 18013-5
// §9.1.2.5: the digest is computed over the tag-24 encoding, not the bare
// item bytes).
type namespaceDigest struct {
	taggedItems [][]byte       // each already-encoded #6.24(bstr .cbor IssuerSignedItem)
	digests     map[int][]byte // digestID -> sha256(taggedItem bytes)
}

// buildNamespaceItems builds every element's IssuerSignedItem for one
// namespace, in the given (already insertion-ordered) element list.
// digestID is the 0-based index within this namespace, matching the Java
// issuer.
func buildNamespaceItems(elements []element) (namespaceDigest, error) {
	nd := namespaceDigest{digests: make(map[int][]byte)}
	for i, elem := range elements {
		itemBytes, err := buildIssuerSignedItem(i, elem)
		if err != nil {
			return namespaceDigest{}, err
		}
		tagged, err := cbor.Marshal(cbor.Tag{Number: 24, Content: itemBytes})
		if err != nil {
			return namespaceDigest{}, err
		}
		digest := sha256.Sum256(tagged)
		nd.taggedItems = append(nd.taggedItems, tagged)
		nd.digests[i] = digest[:]
	}
	return nd, nil
}

func buildIssuerSignedItem(digestID int, elem element) ([]byte, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, err
	}
	item := issuerSignedItem{
		DigestID:          digestID,
		Random:            randomBytes,
		ElementIdentifier: elem.identifier,
		ElementValue:      elem.cborValue(),
	}
	return cbor.Marshal(item)
}
