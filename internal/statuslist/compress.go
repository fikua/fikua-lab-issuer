package statuslist

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
)

// compressAndEncode DEFLATE-compresses raw (wrapped in a ZLIB/RFC1950
// header, per §4.1 — Go's compress/zlib is exactly that, not bare
// compress/flate) at the highest compression level, then base64url
// (no padding) encodes the result — the wire format for a Status List
// JSON object's "lst" field.
func compressAndEncode(raw []byte) (string, error) {
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(raw); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}
