-- issuance_records: a fresh table, not shared with fikua-lab's Java
-- issuer/Postgres. The Java schema (Flyway V3-V5) carries pre_auth_code,
-- tx_code, and recipient_email columns for the pre-authorized_code and
-- Student ID/email flows this HAIP-only, PID-only issuer doesn't
-- implement — those are intentionally not replicated here. issuer_state
-- is new: it links a PAR-backed /authorize back to the issuance record
-- that triggered its credential offer, and has no Java counterpart.
--
-- Applied idempotently at boot (see cmd/issuer/main.go) — no migration
-- tool, just CREATE TABLE/INDEX IF NOT EXISTS, appropriate for a single
-- table with no schema evolution yet.
CREATE TABLE IF NOT EXISTS issuance_records (
    id              TEXT PRIMARY KEY,
    credential_type TEXT NOT NULL,
    credential_data JSONB NOT NULL DEFAULT '{}',
    source_type     TEXT NOT NULL DEFAULT '',
    source_ref      TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'pending',
    issuer_state    TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_issuance_records_status ON issuance_records(status);

-- Only one non-empty issuer_state should ever map to a given record —
-- enforced here rather than just in application code.
CREATE UNIQUE INDEX IF NOT EXISTS idx_issuance_records_issuer_state
    ON issuance_records(issuer_state) WHERE issuer_state != '';
