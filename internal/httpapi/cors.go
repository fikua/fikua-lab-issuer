package httpapi

import "net/http"

// WithCORS wraps next with permissive CORS headers — this issuer is an
// OID4VCI Credential Issuer meant to be interoperable with any
// conformant wallet, and its endpoints are already protocol-secured
// independently of the calling origin (DPoP-bound access tokens on
// /oid4vci/v1/credential, proof-of-possession on the nonce/credential
// exchange). CORS is not an access-control mechanism — it only gates
// whether a browser's own fetch()/XHR may read the response, and any
// non-browser caller bypasses it entirely — so restricting Origin adds
// no real security here, only the risk of blocking legitimate
// third-party wallets running as web apps from a different origin. See
// fikua-lab-idp's identical cors.go — not shared as a module across
// these two young, independently-deployed repos (same rationale as
// other small cross-repo duplication in this ecosystem, e.g. DPoP
// verification).
func WithCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, DPoP, OAuth-Client-Attestation, OAuth-Client-Attestation-PoP")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
