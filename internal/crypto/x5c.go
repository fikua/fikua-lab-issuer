package crypto

import (
	"encoding/base64"

	joseCert "github.com/lestrrat-go/jwx/v3/cert"
)

// BuildX5CChain builds a jwx cert.Chain from a leaf-first list of raw DER
// certificate bytes. cert.Chain.Add expects either a PEM block or a
// base64-encoded DER string (the JOSE x5c wire format) — raw DER bytes
// must be base64-encoded first, which this helper does.
func BuildX5CChain(certChainDER [][]byte) (*joseCert.Chain, error) {
	var chain joseCert.Chain
	for _, der := range certChainDER {
		encoded := base64.StdEncoding.EncodeToString(der)
		if err := chain.AddString(encoded); err != nil {
			return nil, err
		}
	}
	return &chain, nil
}
