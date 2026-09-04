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

-- status_list_entries: bit allocation for the IETF Token Status List
-- (draft-ietf-oauth-status-list-21). One global, monotonically-growing
-- list (bits=2: 0=VALID, 1=INVALID/revoked, 2=SUSPENDED — unused for now)
-- shared by both SD-JWT and mdoc PID credentials issued by this issuer —
-- a single list is enough at this scale, no per-format/per-expiry
-- splitting, no aggregation_uri. An idx is assigned only at actual
-- credential issuance (issuance_records.status = 'credential_issued'),
-- never at 'pending'/'offer_created' — those "draft" states have no
-- status-list bit at all, and credentials issued before this feature
-- shipped have no entry and can never be revoked (a known, accepted
-- limitation for this lab issuer — no backfill).
CREATE TABLE IF NOT EXISTS status_list_entries (
    idx                 BIGINT PRIMARY KEY,
    issuance_record_id  TEXT NOT NULL REFERENCES issuance_records(id),
    status              SMALLINT NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- At most one status-list entry per issuance record — AllocateIdx is
-- get-or-create against this, so a credential re-issued for the same
-- record (e.g. both formats requested, or a retried /credential call)
-- reuses its existing idx rather than leaking a fresh one.
CREATE UNIQUE INDEX IF NOT EXISTS idx_status_list_entries_record
    ON status_list_entries(issuance_record_id);

-- status_list_seq: the monotonically-growing idx allocator — a
-- single-row counter table rather than a SEQUENCE, so the in-memory and
-- Postgres stores share the same "next idx" mental model.
CREATE TABLE IF NOT EXISTS status_list_seq (
    id       SMALLINT PRIMARY KEY DEFAULT 1,
    next_idx BIGINT NOT NULL DEFAULT 0,
    CHECK (id = 1)
);
INSERT INTO status_list_seq (id, next_idx) VALUES (1, 0) ON CONFLICT (id) DO NOTHING;
