// Package session holds this issuer's ephemeral protocol state: the
// single-use nonces its Nonce Endpoint hands out, and credential offers
// stored for by-reference retrieval. In-memory only.
//
// The OAuth2 state that used to live here — PAR requests, authorization
// codes, access tokens, deferred authorizations awaiting end-user
// identification — moved to fikua-lab-idp along with the authorization
// server itself. Access tokens in particular are no longer stored
// anywhere: they are self-contained RFC 9068 JWTs this issuer verifies
// offline (see internal/accesstoken).
package session

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
)

// Store is the in-memory session store.
type Store struct {
	mu               sync.Mutex
	nonces           map[string]struct{}
	credentialOffers map[string]string
}

// NewStore builds an empty Store.
func NewStore() *Store {
	return &Store{
		nonces:           make(map[string]struct{}),
		credentialOffers: make(map[string]string),
	}
}

// RandomToken returns a base64url, no-padding random token of n bytes.
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

// RegisterNonce adds nonce to the single-use nonce store.
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

// InvalidateNonce removes nonce from the store, if present. A no-op if
// it's already absent — which is the normal case for a c_nonce that came
// in on an access token rather than from the Nonce Endpoint, since this
// issuer never registered that one.
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
