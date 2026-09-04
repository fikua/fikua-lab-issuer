// Package statuslist builds and signs IETF Token Status List tokens
// (draft-ietf-oauth-status-list-21): the bitstring encoding, DEFLATE/ZLIB
// compression, and JWT assembly/signing, reusing the issuer's own signing
// key (same-entity key reuse, per the spec's §11.3 guidance).
package statuslist

// Bits is the status list's bit width — 2 bits per entry, enough for
// VALID(0)/INVALID(1)/SUSPENDED(2) with one value spare, per this
// issuer's status model.
const Bits = 2

// packBitstring builds the raw (uncompressed) status list byte array for
// entries, per §4.1: index i's status occupies bits [i*Bits, i*Bits+Bits)
// of the array, packed LSB-first within each byte, bytes filled left to
// right. size is the number of entries the array must cover (highest
// allocated idx + 1) — any idx in [0,size) absent from entries defaults
// to VALID(0), matching a freshly allocated-but-not-yet-fetched entry.
func packBitstring(entries map[int64]uint8, size int64) []byte {
	if size < 0 {
		size = 0
	}
	numBytes := (size*Bits + 7) / 8
	out := make([]byte, numBytes)
	for idx, status := range entries {
		if idx < 0 || idx >= size {
			continue
		}
		byteIndex := (idx * Bits) / 8
		bitOffset := uint((idx * Bits) % 8)
		out[byteIndex] |= (status & ((1 << Bits) - 1)) << bitOffset
	}
	return out
}
