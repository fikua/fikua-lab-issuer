// Package accesstoken verifies the RFC 9068 JWT access tokens minted by
// fikua-lab-idp, the authorization server this issuer delegates
// authentication to.
//
// Before that split, /token and /credential shared one process and one
// in-memory session map, so "validating" an access token meant looking it
// up. Now the token is a self-contained signed JWT: everything the
// credential endpoint needs (the issuance record id, the c_nonce, the
// DPoP key thumbprint it is bound to) travels inside it, and this package
// checks the signature against the AS's published JWK Set instead.
package accesstoken

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/fikua/fikua-lab-issuer/internal/oauth2"
)

// tokenType is the RFC 9068 §2.1 `typ` header every access token must
// carry. Checking it is what stops some other ES256 JWT the AS signs
// (were it ever to sign one) being replayed here as an access token.
const tokenType = "at+jwt"

// Claims is everything this issuer reads out of a verified access token —
// the fields that used to live in session.Data when both services shared
// a process.
type Claims struct {
	// IssuanceRecordID names the record IssueCredential builds the
	// credential from.
	IssuanceRecordID string
	// CNonce is the c_nonce bound at the token endpoint, which a
	// wallet's first proof JWT may use without calling the Nonce
	// Endpoint first.
	CNonce string
	// JKT is the RFC 7638 thumbprint of the DPoP key this token is
	// sender-constrained to (RFC 9449 §6.1's cnf.jkt) — the presented
	// DPoP proof's key must match it.
	JKT string
	// JTI identifies this token, for the revocation denylist.
	JTI string
}

// Verifier validates access tokens against the authorization server's
// published JWK Set, caching both that key set and the AS's revoked-token
// denylist so the common path costs no network round trip.
type Verifier struct {
	issuer     string // expected `iss`: the AS's own identifier
	audience   string // expected `aud`: this issuer's base URL
	jwksURL    string
	revokedURL string
	http       *http.Client

	mu         sync.Mutex
	keys       jwk.Set
	keysExp    time.Time
	revoked    map[string]struct{}
	revokedExp time.Time
}

// cacheTTL bounds how stale the cached JWK Set and revocation denylist
// may get. Short enough that a revoked token stops working promptly (the
// AS keeps a jti published well past this, so no revocation is missed),
// long enough that /credential doesn't turn into a proxy for two extra
// HTTP calls per request.
const cacheTTL = 60 * time.Second

// New builds a Verifier. issuer is the authorization server's identifier
// (the expected `iss`), audience is this credential issuer's own base URL
// (the expected `aud`), and asBaseURL is where the AS's JWK Set and
// revocation list are served.
func New(issuer, audience, asBaseURL string) *Verifier {
	return &Verifier{
		issuer:     issuer,
		audience:   audience,
		jwksURL:    asBaseURL + "/oid4vci/v1/jwks",
		revokedURL: asBaseURL + "/oid4vci/v1/revoked-tokens",
		http:       &http.Client{Timeout: 10 * time.Second},
		revoked:    make(map[string]struct{}),
	}
}

// Verify parses and validates token, returning the claims this issuer
// needs. Every failure is reported as invalid_token: a client has no
// business learning which of the signature, audience, expiry or
// revocation checks rejected it.
func (v *Verifier) Verify(ctx context.Context, token string) (Claims, error) {
	keys, err := v.keySet(ctx)
	if err != nil {
		return Claims{}, oauth2.ServiceUnavailable(oauth2.InvalidToken, "Cannot verify access token: authorization server unreachable")
	}

	// RFC 9068 §4 step 1: reject anything not typed as an access token
	// before spending a signature verification on it.
	if err := requireAccessTokenType(token); err != nil {
		return Claims{}, err
	}

	parsed, err := jwt.Parse([]byte(token),
		jwt.WithKeySet(keys),
		jwt.WithValidate(true),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
	)
	if err != nil {
		return Claims{}, oauth2.Unauthorized(oauth2.InvalidToken, "Invalid access token")
	}

	claims := Claims{}
	if jti, ok := parsed.JwtID(); ok {
		claims.JTI = jti
	}
	if claims.JTI == "" {
		// The denylist is keyed by jti; a token without one could never
		// be revoked, so accepting it would quietly void RFC 6749
		// §4.1.2's revocation requirement.
		return Claims{}, oauth2.Unauthorized(oauth2.InvalidToken, "Invalid access token")
	}

	revoked, err := v.isRevoked(ctx, claims.JTI)
	if err != nil {
		return Claims{}, oauth2.ServiceUnavailable(oauth2.InvalidToken, "Cannot verify access token: authorization server unreachable")
	}
	if revoked {
		return Claims{}, oauth2.Unauthorized(oauth2.InvalidToken, "Access token has been revoked")
	}

	_ = parsed.Get("issuance_record_id", &claims.IssuanceRecordID)
	_ = parsed.Get("c_nonce", &claims.CNonce)

	var cnf map[string]any
	if err := parsed.Get("cnf", &cnf); err != nil {
		return Claims{}, oauth2.Unauthorized(oauth2.InvalidToken, "Access token is not DPoP-bound")
	}
	claims.JKT, _ = cnf["jkt"].(string)
	if claims.JKT == "" {
		// This issuer is HAIP-only: every access token is
		// sender-constrained, so one arriving without a cnf.jkt is not a
		// bearer token to fall back on — it's a token that lost its
		// binding somewhere, and must be refused.
		return Claims{}, oauth2.Unauthorized(oauth2.InvalidToken, "Access token is not DPoP-bound")
	}

	return claims, nil
}

// requireAccessTokenType checks the JWS `typ` header without verifying
// the signature — cheap, and it lets an id_token or a proof JWT replayed
// here be rejected on shape alone.
func requireAccessTokenType(token string) error {
	msg, err := jws.Parse([]byte(token))
	if err != nil || len(msg.Signatures()) != 1 {
		return oauth2.Unauthorized(oauth2.InvalidToken, "Invalid access token")
	}
	typ, _ := msg.Signatures()[0].ProtectedHeaders().Type()
	// RFC 9068 §2.1 allows the media type with or without its
	// "application/" prefix.
	if typ != tokenType && typ != "application/"+tokenType {
		return oauth2.Unauthorized(oauth2.InvalidToken, "Access token typ must be at+jwt")
	}
	return nil
}

// keySet returns the AS's JWK Set, refetching it when the cache has
// expired. A fetch failure with a still-populated cache returns the stale
// keys rather than failing the request: the AS rotating its key is rare,
// the AS being briefly unreachable is not, and refusing every credential
// request during a blip would be the worse failure.
func (v *Verifier) keySet(ctx context.Context) (jwk.Set, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.keys != nil && time.Now().Before(v.keysExp) {
		return v.keys, nil
	}

	keys, err := v.fetchKeys(ctx)
	if err != nil {
		if v.keys != nil {
			return v.keys, nil
		}
		return nil, err
	}
	v.keys, v.keysExp = keys, time.Now().Add(cacheTTL)
	return keys, nil
}

func (v *Verifier) fetchKeys(ctx context.Context) (jwk.Set, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("accesstoken: fetching %s: %w", v.jwksURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("accesstoken: fetching %s: unexpected status %d", v.jwksURL, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("accesstoken: reading %s: %w", v.jwksURL, err)
	}
	return jwk.Parse(body)
}

// isRevoked reports whether jti appears on the AS's denylist, refreshing
// the cached copy when it has expired.
//
// Unlike the JWK Set, a stale denylist is not silently tolerated: serving
// a credential against a token the AS has revoked is exactly the outcome
// RFC 6749 §4.1.2 asks this check to prevent, so an unreachable AS fails
// the request instead.
func (v *Verifier) isRevoked(ctx context.Context, jti string) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if time.Now().After(v.revokedExp) {
		revoked, err := v.fetchRevoked(ctx)
		if err != nil {
			return false, err
		}
		v.revoked, v.revokedExp = revoked, time.Now().Add(cacheTTL)
	}
	_, found := v.revoked[jti]
	return found, nil
}

func (v *Verifier) fetchRevoked(ctx context.Context) (map[string]struct{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.revokedURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("accesstoken: fetching %s: %w", v.revokedURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("accesstoken: fetching %s: unexpected status %d", v.revokedURL, resp.StatusCode)
	}

	var body struct {
		RevokedJTI []string `json:"revoked_jti"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("accesstoken: decoding revocation list: %w", err)
	}
	out := make(map[string]struct{}, len(body.RevokedJTI))
	for _, jti := range body.RevokedJTI {
		out[jti] = struct{}{}
	}
	return out, nil
}
