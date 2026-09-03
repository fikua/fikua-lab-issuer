// Package issuance implements the pre-authorized_code OID4VCI flow and
// SD-JWT credential building, plus the issuance-record store this slice
// backs it with.
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
	PreAuthCode    string
	OfferID        string
	RecipientEmail string
	TxCode         string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Store is an in-memory stand-in for the Java issuer's Postgres-backed
// IssuanceStore — this slice doesn't wire up Postgres yet (see the
// migration plan's phase breakdown); persistence lands in a later slice.
type Store struct {
	mu      sync.Mutex
	records map[string]Record
}

// NewStore builds an empty Store.
func NewStore() *Store {
	return &Store{records: make(map[string]Record)}
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

// UpdateStatus sets a record's status.
func (s *Store) UpdateStatus(id, status string) {
	s.mutate(id, func(r *Record) { r.Status = status })
}

// UpdatePreAuthCode sets a record's linked pre-authorized_code.
func (s *Store) UpdatePreAuthCode(id, code string) {
	s.mutate(id, func(r *Record) { r.PreAuthCode = code })
}

// UpdateOfferID sets a record's linked stored-offer id.
func (s *Store) UpdateOfferID(id, offerID string) {
	s.mutate(id, func(r *Record) { r.OfferID = offerID })
}

// UpdateRecipientEmail sets a record's recipient email (for tx_code/email
// delivery).
func (s *Store) UpdateRecipientEmail(id, email string) {
	s.mutate(id, func(r *Record) { r.RecipientEmail = email })
}

// UpdateTxCode sets a record's tx_code.
func (s *Store) UpdateTxCode(id, txCode string) {
	s.mutate(id, func(r *Record) { r.TxCode = txCode })
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
