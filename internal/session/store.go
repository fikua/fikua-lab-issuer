// Package session holds ephemeral OID4VCI protocol state: pre-authorized
// codes, access tokens, nonces, and stored credential offers. In-memory
// only, matching the Java issuer's InMemorySessionStore — no TTL/expiry,
// relies on single-use consumption for codes/nonces.
package session

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// Data is the session state bound to an access token or pre-auth code.
type Data struct {
	SessionID string
	CNonce    string
	CreatedAt time.Time
	Metadata  map[string]any
}

// Store is the in-memory session store.
type Store struct {
	mu               sync.Mutex
	preAuthCodes     map[string]Data
	accessTokens     map[string]Data
	nonces           map[string]struct{}
	credentialOffers map[string]string
}

// NewStore builds an empty Store.
func NewStore() *Store {
	return &Store{
		preAuthCodes:     make(map[string]Data),
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

// CreatePreAuthCode stores session under a fresh pre-authorized_code.
func (s *Store) CreatePreAuthCode(data Data) string {
	code := RandomToken(32)
	s.mu.Lock()
	s.preAuthCodes[code] = data
	s.mu.Unlock()
	return code
}

// ConsumePreAuthCode atomically removes and returns the session bound to
// code. ok is false if the code is unknown (already consumed, or never
// issued).
func (s *Store) ConsumePreAuthCode(code string) (data Data, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok = s.preAuthCodes[code]
	if ok {
		delete(s.preAuthCodes, code)
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
// by-reference credential offers.
func (s *Store) StoreCredentialOffer(offerJSON string) string {
	id := RandomToken(16)
	s.mu.Lock()
	s.credentialOffers[id] = offerJSON
	s.mu.Unlock()
	return id
}

// GetCredentialOffer is a non-destructive lookup of a stored offer's JSON.
func (s *Store) GetCredentialOffer(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	offerJSON, ok := s.credentialOffers[id]
	return offerJSON, ok
}
