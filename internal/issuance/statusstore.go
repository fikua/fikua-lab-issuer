package issuance

// Status list values, per draft-ietf-oauth-status-list-21 §7.1's registry
// — only VALID and INVALID are ever set by this issuer today; SUSPENDED is
// defined for completeness but no revoke-adjacent action sets it (EUDI ARF
// VCR_01 recommends revoking rather than suspending).
const (
	StatusValid     uint8 = 0x00
	StatusInvalid   uint8 = 0x01
	StatusSuspended uint8 = 0x02
)

// StatusListStore persists the IETF Token Status List's bit allocation:
// which issuance record owns which idx, and that idx's current status
// value. Implemented by both the in-memory Store and PostgresStore,
// mirroring RecordStore's split.
type StatusListStore interface {
	// AllocateIdx returns the idx already assigned to issuanceRecordID, or
	// allocates and persists a fresh one (status VALID) if none exists yet
	// — get-or-create, so re-issuing a credential for the same record
	// never leaks a second idx.
	AllocateIdx(issuanceRecordID string) (idx int64, err error)
	// SetStatus updates the status value for issuanceRecordID's entry.
	// ok is false if the record has no status-list entry yet.
	SetStatus(issuanceRecordID string, value uint8) (idx int64, ok bool)
	// FindByRecordID looks up issuanceRecordID's idx and current status
	// value. ok is false if no entry exists (e.g. the credential was
	// issued before this feature shipped, or is still in draft).
	FindByRecordID(issuanceRecordID string) (idx int64, value uint8, ok bool)
	// AllEntries returns every allocated idx and its current status
	// value, for building the status list bitstring.
	AllEntries() (map[int64]uint8, error)
}
