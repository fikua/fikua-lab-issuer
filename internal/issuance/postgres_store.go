package issuance

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/fikua/fikua-lab-issuer/internal/session"
)

// PostgresStore is a Postgres-backed RecordStore. See db/schema.sql for
// the table it expects — applied idempotently at boot by the caller
// (cmd/issuer/main.go), not by this type.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore builds a PostgresStore around an already-open,
// already-pinged *sql.DB.
func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

const recordColumns = "id, credential_type, credential_data, source_type, source_ref, status, issuer_state, created_at, updated_at"

// Create inserts a new Record, defaulting credentialData to "{}" if
// empty — matching the in-memory Store's behavior.
func (s *PostgresStore) Create(credentialType, credentialData, sourceType, sourceRef string) Record {
	if credentialData == "" {
		credentialData = "{}"
	}
	id := session.RandomToken(16)
	row := s.db.QueryRowContext(context.Background(), `
		INSERT INTO issuance_records (id, credential_type, credential_data, source_type, source_ref, status)
		VALUES ($1, $2, $3::jsonb, $4, $5, 'pending')
		RETURNING `+recordColumns,
		id, credentialType, credentialData, sourceType, sourceRef,
	)
	rec, err := scanRecord(row)
	if err != nil {
		// Create has no error return in RecordStore (matching the
		// in-memory Store's signature) — a failure here means the
		// caller gets a zero-value Record, which will fail its
		// subsequent FindByID/nonce checks downstream rather than
		// silently succeeding.
		return Record{}
	}
	return rec
}

// FindByID is a non-destructive lookup, returning ok=false if absent.
func (s *PostgresStore) FindByID(id string) (Record, bool) {
	row := s.db.QueryRowContext(context.Background(), `SELECT `+recordColumns+` FROM issuance_records WHERE id = $1`, id)
	rec, err := scanRecord(row)
	if err != nil {
		return Record{}, false
	}
	return rec, true
}

// FindByIssuerState is a non-destructive lookup by issuer_state.
func (s *PostgresStore) FindByIssuerState(issuerState string) (Record, bool) {
	row := s.db.QueryRowContext(context.Background(), `SELECT `+recordColumns+` FROM issuance_records WHERE issuer_state = $1`, issuerState)
	rec, err := scanRecord(row)
	if err != nil {
		return Record{}, false
	}
	return rec, true
}

// UpdateStatus sets a record's status.
func (s *PostgresStore) UpdateStatus(id, status string) {
	_, _ = s.db.ExecContext(context.Background(),
		`UPDATE issuance_records SET status = $1, updated_at = now() WHERE id = $2`, status, id)
}

// UpdateIssuerState sets a record's linked issuer_state.
func (s *PostgresStore) UpdateIssuerState(id, issuerState string) {
	_, _ = s.db.ExecContext(context.Background(),
		`UPDATE issuance_records SET issuer_state = $1, updated_at = now() WHERE id = $2`, issuerState, id)
}

// FindAll returns a page of records ordered by sortField/sortOrder
// (falling back to created_at/desc if either is not in allowedSortFields
// — the same allowlist the in-memory Store uses), plus the total record
// count. sortField/sortOrder are validated against that allowlist before
// being interpolated into the query, since they can't be passed as bind
// parameters for an ORDER BY clause.
func (s *PostgresStore) FindAll(offset, limit int, sortField, sortOrder string) ([]Record, int) {
	if !allowedSortFields[sortField] {
		sortField = "created_at"
	}
	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "desc"
	}

	var total int
	if err := s.db.QueryRowContext(context.Background(), `SELECT count(*) FROM issuance_records`).Scan(&total); err != nil {
		return nil, 0
	}

	query := fmt.Sprintf(`SELECT %s FROM issuance_records ORDER BY %s %s LIMIT $1 OFFSET $2`, recordColumns, sortField, sortOrder)
	rows, err := s.db.QueryContext(context.Background(), query, limit, offset)
	if err != nil {
		return nil, total
	}
	defer rows.Close()

	var records []Record
	for rows.Next() {
		rec, err := scanRecordRows(rows)
		if err != nil {
			return nil, total
		}
		records = append(records, rec)
	}
	return records, total
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanRecord(row rowScanner) (Record, error) {
	return scanRecordRows(row)
}

func scanRecordRows(row rowScanner) (Record, error) {
	var rec Record
	var createdAt, updatedAt time.Time
	err := row.Scan(&rec.ID, &rec.CredentialType, &rec.CredentialData, &rec.SourceType, &rec.SourceRef, &rec.Status, &rec.IssuerState, &createdAt, &updatedAt)
	rec.CreatedAt, rec.UpdatedAt = createdAt, updatedAt
	return rec, err
}

// AllocateIdx implements StatusListStore: get-or-create inside a single
// transaction, so a concurrent allocation for a different record can't
// observe or clobber this one, and a retried call for the same record
// always reuses its existing idx (enforced by
// idx_status_list_entries_record, not just this lookup).
func (s *PostgresStore) AllocateIdx(issuanceRecordID string) (int64, error) {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var existing int64
	err = tx.QueryRowContext(ctx, `SELECT idx FROM status_list_entries WHERE issuance_record_id = $1`, issuanceRecordID).Scan(&existing)
	if err == nil {
		return existing, tx.Commit()
	}
	if err != sql.ErrNoRows {
		return 0, err
	}

	var idx int64
	if err := tx.QueryRowContext(ctx, `UPDATE status_list_seq SET next_idx = next_idx + 1 WHERE id = 1 RETURNING next_idx - 1`).Scan(&idx); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO status_list_entries (idx, issuance_record_id, status) VALUES ($1, $2, $3)`,
		idx, issuanceRecordID, StatusValid,
	); err != nil {
		return 0, err
	}
	return idx, tx.Commit()
}

// SetStatus implements StatusListStore.
func (s *PostgresStore) SetStatus(issuanceRecordID string, value uint8) (int64, bool) {
	row := s.db.QueryRowContext(context.Background(),
		`UPDATE status_list_entries SET status = $1, updated_at = now() WHERE issuance_record_id = $2 RETURNING idx`,
		value, issuanceRecordID,
	)
	var idx int64
	if err := row.Scan(&idx); err != nil {
		return 0, false
	}
	return idx, true
}

// FindByRecordID implements StatusListStore.
func (s *PostgresStore) FindByRecordID(issuanceRecordID string) (int64, uint8, bool) {
	row := s.db.QueryRowContext(context.Background(),
		`SELECT idx, status FROM status_list_entries WHERE issuance_record_id = $1`, issuanceRecordID)
	var idx int64
	var status uint8
	if err := row.Scan(&idx, &status); err != nil {
		return 0, 0, false
	}
	return idx, status, true
}

// AllEntries implements StatusListStore.
func (s *PostgresStore) AllEntries() (map[int64]uint8, error) {
	rows, err := s.db.QueryContext(context.Background(), `SELECT idx, status FROM status_list_entries`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[int64]uint8)
	for rows.Next() {
		var idx int64
		var status uint8
		if err := rows.Scan(&idx, &status); err != nil {
			return nil, err
		}
		out[idx] = status
	}
	return out, rows.Err()
}
