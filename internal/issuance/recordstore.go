package issuance

// RecordStore persists issuance records — either the in-memory Store
// (dev/no-Postgres fallback) or PostgresStore (production). Service only
// depends on this interface, never a concrete store type.
type RecordStore interface {
	Create(credentialType, credentialData, sourceType, sourceRef string) Record
	FindByID(id string) (Record, bool)
	FindByIssuerState(issuerState string) (Record, bool)
	UpdateStatus(id, status string)
	UpdateIssuerState(id, issuerState string)
	FindAll(offset, limit int, sortField, sortOrder string) ([]Record, int)
}
