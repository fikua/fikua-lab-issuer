// Package issuance implements this issuer's OID4VCI flow (HAIP:
// authorization_code + PAR + DPoP + client attestation) and SD-JWT/mdoc
// credential building, plus the issuance-record store it's backed by.
package issuance

import (
	"sync"
	"time"

	"github.com/fikua/fikua-lab-issuer/internal/session"
)

// Record is one issuance attempt. credentialData is a JSON-object string,
// e.g. {"given_name":"...", ...} — matching the Java issuer's
// IssuanceStore.IssuanceRecord.credentialData.
type Record struct {
	ID             string
	CredentialType string
	CredentialData string
	SourceType     string
	SourceRef      string
	Status         string
	IssuerState    string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Store is an in-memory stand-in for the Java issuer's Postgres-backed
// IssuanceStore — Postgres wiring lands in a later slice.
type Store struct {
	mu            sync.Mutex
	records       map[string]Record
	byIssuerState map[string]string // issuer_state -> record id
}

// NewStore builds an empty Store.
func NewStore() *Store {
	return &Store{records: make(map[string]Record), byIssuerState: make(map[string]string)}
}

// Create inserts a new Record, defaulting credentialData to "{}" if empty.
func (s *Store) Create(credentialType, credentialData, sourceType, sourceRef string) Record {
	if credentialData == "" {
		credentialData = "{}"
	}
	now := time.Now()
	rec := Record{
		ID:             session.RandomToken(16),
		CredentialType: credentialType,
		CredentialData: credentialData,
		SourceType:     sourceType,
		SourceRef:      sourceRef,
		Status:         "pending",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	s.mu.Lock()
	s.records[rec.ID] = rec
	s.mu.Unlock()
	return rec
}

// FindByID is a non-destructive lookup, returning ok=false if absent.
func (s *Store) FindByID(id string) (Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[id]
	return rec, ok
}

// FindByIssuerState is a non-destructive lookup by issuer_state, used to
// link a wallet's /authorize (via PAR) back to the issuance record that
// triggered its credential offer.
func (s *Store) FindByIssuerState(issuerState string) (Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byIssuerState[issuerState]
	if !ok {
		return Record{}, false
	}
	rec, ok := s.records[id]
	return rec, ok
}

// UpdateStatus sets a record's status.
func (s *Store) UpdateStatus(id, status string) {
	s.mutate(id, func(r *Record) { r.Status = status })
}

// UpdateIssuerState sets a record's linked issuer_state and indexes it
// for FindByIssuerState.
func (s *Store) UpdateIssuerState(id, issuerState string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[id]
	if !ok {
		return
	}
	rec.IssuerState = issuerState
	rec.UpdatedAt = time.Now()
	s.records[id] = rec
	s.byIssuerState[issuerState] = id
}

func (s *Store) mutate(id string, fn func(*Record)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[id]
	if !ok {
		return
	}
	fn(&rec)
	rec.UpdatedAt = time.Now()
	s.records[id] = rec
}
