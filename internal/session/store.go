// Package session holds ephemeral OID4VCI/OAuth2 protocol state: PAR
// requests, authorization codes, access tokens, and nonces. In-memory
// only, matching the Java issuer's InMemorySessionStore — no TTL/expiry,
// relies on single-use consumption for codes/nonces.
package session

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Data is the session state bound to an authorization code or access
// token.
type Data struct {
	SessionID string
	CNonce    string
	DPoPKey   jwk.Key // the DPoP proof key bound at /token; nil until then
	CreatedAt time.Time
	Metadata  map[string]any
}

// Store is the in-memory session store.
type Store struct {
	mu               sync.Mutex
	parRequests      map[string]map[string]string
	authCodes        map[string]Data
	accessTokens     map[string]Data
	nonces           map[string]struct{}
	credentialOffers map[string]string
}

// NewStore builds an empty Store.
func NewStore() *Store {
	return &Store{
		parRequests:      make(map[string]map[string]string),
		authCodes:        make(map[string]Data),
		accessTokens:     make(map[string]Data),
		nonces:           make(map[string]struct{}),
		credentialOffers: make(map[string]string),
	}
}

// RandomToken returns a base64url, no-padding random token of n bytes —
// matching the Java issuer's randomToken.
func RandomToken(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// GenerateNonce returns a fresh 32-byte random nonce candidate. It is not
// registered until passed to RegisterNonce.
func GenerateNonce() string {
	return RandomToken(32)
}

// StoreParRequest stores a Pushed Authorization Request's form params
// under requestUri.
func (s *Store) StoreParRequest(requestURI string, params map[string]string) {
	s.mu.Lock()
	s.parRequests[requestURI] = params
	s.mu.Unlock()
}

// ConsumeParRequest atomically removes and returns the params stored
// under requestURI. ok is false if unknown (already consumed, or never
// stored).
func (s *Store) ConsumeParRequest(requestURI string) (params map[string]string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	params, ok = s.parRequests[requestURI]
	if ok {
		delete(s.parRequests, requestURI)
	}
	return params, ok
}

// CreateAuthCode stores session under a fresh authorization code.
func (s *Store) CreateAuthCode(data Data) string {
	code := RandomToken(32)
	s.mu.Lock()
	s.authCodes[code] = data
	s.mu.Unlock()
	return code
}

// ConsumeAuthCode atomically removes and returns the session bound to
// code. ok is false if the code is unknown (already consumed, or never
// issued).
func (s *Store) ConsumeAuthCode(code string) (data Data, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok = s.authCodes[code]
	if ok {
		delete(s.authCodes, code)
	}
	return data, ok
}

// CreateAccessToken stores session under a fresh access token.
func (s *Store) CreateAccessToken(data Data) string {
	token := RandomToken(32)
	s.mu.Lock()
	s.accessTokens[token] = data
	s.mu.Unlock()
	return token
}

// GetAccessTokenSession is a non-destructive lookup of the session bound to
// an access token.
func (s *Store) GetAccessTokenSession(token string) (Data, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.accessTokens[token]
	return data, ok
}

// UpdateAccessTokenSession overwrites the session bound to an existing
// access token in place (e.g. to bind a fresh cNonce) — unlike
// CreateAccessToken, this does not mint a new token.
func (s *Store) UpdateAccessTokenSession(token string, data Data) {
	s.mu.Lock()
	s.accessTokens[token] = data
	s.mu.Unlock()
}

// RegisterNonce adds nonce to the global single-use nonce store (used by
// both the token endpoint and the nonce endpoint).
func (s *Store) RegisterNonce(nonce string) {
	s.mu.Lock()
	s.nonces[nonce] = struct{}{}
	s.mu.Unlock()
}

// ValidateNonce reports whether nonce is registered, consuming it
// (single-use) on success.
func (s *Store) ValidateNonce(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.nonces[nonce]
	if ok {
		delete(s.nonces, nonce)
	}
	return ok
}

// InvalidateNonce removes nonce from the global store, if present. A no-op
// if it's already absent.
func (s *Store) InvalidateNonce(nonce string) {
	s.mu.Lock()
	delete(s.nonces, nonce)
	s.mu.Unlock()
}

// StoreCredentialOffer stores offerJSON under a fresh offer id, for
// by-reference credential offers (credential_offer_uri).
func (s *Store) StoreCredentialOffer(offerJSON string) string {
	id := RandomToken(16)
	s.mu.Lock()
	s.credentialOffers[id] = offerJSON
	s.mu.Unlock()
	return id
}

// GetCredentialOffer is a non-destructive lookup of a stored offer's JSON
// — non-destructive because a wallet may legitimately retry the GET
// (e.g. after a network hiccup) before ever using the offer.
func (s *Store) GetCredentialOffer(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	offerJSON, ok := s.credentialOffers[id]
	return offerJSON, ok
}
