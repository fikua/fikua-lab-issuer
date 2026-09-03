package oauth2

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// dpopIATWindow is the allowed clock skew for a DPoP proof's iat claim
// (RFC 9449), symmetric — past and future both count as "expired" beyond
// this window.
const dpopIATWindow = 5 * time.Minute

// JTIStore tracks DPoP proof jti values to reject replay (RFC 9449 §11.1).
// A plain in-memory, size-bounded set — no persistence, matching the Java
// issuer's bounded ConcurrentHashMap.newKeySet() (10k cap, evicts 1k on
// overflow).
type JTIStore struct {
	mu  sync.Mutex
	set map[string]struct{}
}

const (
	jtiStoreMaxSize    = 10_000
	jtiStoreEvictCount = 1_000
)

// NewJTIStore builds an empty JTIStore.
func NewJTIStore() *JTIStore {
	return &JTIStore{set: make(map[string]struct{})}
}

// Accept reports whether jti is new (true) or a replay (false),
// registering it on success.
func (s *JTIStore) Accept(jti string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, seen := s.set[jti]; seen {
		return false
	}
	if len(s.set) >= jtiStoreMaxSize {
		evicted := 0
		for k := range s.set {
			delete(s.set, k)
			evicted++
			if evicted >= jtiStoreEvictCount {
				break
			}
		}
	}
	s.set[jti] = struct{}{}
	return true
}

// ValidateDPoPProof validates a DPoP proof JWT per RFC 9449 §4.3, and
// returns the wallet's public key from its `jwk` header. htm/htu are the
// expected HTTP method/URL this proof must be bound to. ath, if non-empty,
// is the expected `ath` claim value (BASE64URL(SHA-256(access_token))) —
// pass "" when validating a proof that carries no access token (e.g. at
// the token endpoint, before an access token exists).
func ValidateDPoPProof(dpopHeader, htm, htu, ath string, jtis *JTIStore) (jwk.Key, error) {
	if dpopHeader == "" {
		return nil, BadRequest(InvalidRequest, "Missing DPoP proof")
	}

	msg, err := jws.Parse([]byte(dpopHeader))
	if err != nil {
		return nil, BadRequest(InvalidRequest, "Invalid DPoP proof: "+err.Error())
	}
	if len(msg.Signatures()) != 1 {
		return nil, BadRequest(InvalidRequest, "Invalid DPoP proof: expected exactly one signature")
	}
	headers := msg.Signatures()[0].ProtectedHeaders()

	typ, _ := headers.Type()
	if typ != "dpop+jwt" {
		return nil, BadRequest(InvalidRequest, "DPoP typ must be dpop+jwt")
	}
	walletJWK, hasJWK := headers.JWK()
	if !hasJWK {
		return nil, BadRequest(InvalidRequest, "DPoP must contain jwk header")
	}
	alg, _ := headers.Algorithm()
	if alg != jwa.ES256() {
		return nil, BadRequest(InvalidRequest, "DPoP must use ES256")
	}

	token, err := jwt.Parse([]byte(dpopHeader), jwt.WithKey(jwa.ES256(), walletJWK), jwt.WithValidate(false))
	if err != nil {
		return nil, BadRequest(InvalidRequest, "DPoP signature invalid")
	}

	var claimedHTM string
	_ = token.Get("htm", &claimedHTM)
	if !equalFoldASCII(claimedHTM, htm) {
		return nil, BadRequest(InvalidRequest, "DPoP htm mismatch")
	}
	var claimedHTU string
	_ = token.Get("htu", &claimedHTU)
	if claimedHTU != htu {
		return nil, BadRequest(InvalidRequest, "DPoP htu mismatch")
	}

	iat, hasIAT := token.IssuedAt()
	if !hasIAT {
		return nil, BadRequest(InvalidRequest, "DPoP proof expired")
	}
	if skew := time.Since(iat); skew > dpopIATWindow || skew < -dpopIATWindow {
		return nil, BadRequest(InvalidRequest, "DPoP proof expired")
	}

	var jti string
	_ = token.Get("jti", &jti)
	if jti == "" || !jtis.Accept(jti) {
		return nil, BadRequest(InvalidRequest, "DPoP jti replay detected")
	}

	if ath != "" {
		var claimedATH string
		_ = token.Get("ath", &claimedATH)
		if claimedATH != ath {
			return nil, BadRequest(InvalidRequest, "DPoP ath mismatch")
		}
	}

	return walletJWK, nil
}

// ComputeATH computes the DPoP `ath` claim value for accessToken, per RFC
// 9449 §4.2: BASE64URL(SHA-256(accessToken)).
func ComputeATH(accessToken string) string {
	hash := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// DPoPThumbprint returns the RFC 7638 SHA-256 JWK thumbprint of key, for
// pinning/comparing a DPoP key across requests within a session.
func DPoPThumbprint(key jwk.Key) (string, error) {
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("oauth2: computing DPoP key thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
