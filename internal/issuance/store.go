// Package issuance implements this issuer's OID4VCI flow (HAIP:
// authorization_code + PAR + DPoP + client attestation) and SD-JWT/mdoc
// credential building, plus the issuance-record store it's backed by.
package issuance

import (
	"sort"
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

// allowedSortFields/allowedSortOrders restrict FindAll's sort/order
// params to a safe allowlist, matching the Java issuer's
// JdbcIssuanceStore guard (there, against SQL injection; here, just
// against an unrecognized field silently no-op'ing wrong).
var allowedSortFields = map[string]bool{
	"created_at": true, "updated_at": true, "status": true, "credential_type": true,
}

// FindAll returns a page of records ordered by sortField/sortOrder
// (falling back to created_at/desc if either is not in the allowlist),
// plus the total record count.
func (s *Store) FindAll(offset, limit int, sortField, sortOrder string) ([]Record, int) {
	if !allowedSortFields[sortField] {
		sortField = "created_at"
	}
	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "desc"
	}

	s.mu.Lock()
	all := make([]Record, 0, len(s.records))
	for _, rec := range s.records {
		all = append(all, rec)
	}
	s.mu.Unlock()

	sort.Slice(all, func(i, j int) bool {
		less := sortLess(all[i], all[j], sortField)
		if sortOrder == "desc" {
			return !less
		}
		return less
	})

	total := len(all)
	if offset >= total {
		return nil, total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return all[offset:end], total
}

// Count returns the total number of records.
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

func sortLess(a, b Record, field string) bool {
	switch field {
	case "updated_at":
		return a.UpdatedAt.Before(b.UpdatedAt)
	case "status":
		return a.Status < b.Status
	case "credential_type":
		return a.CredentialType < b.CredentialType
	default:
		return a.CreatedAt.Before(b.CreatedAt)
	}
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
