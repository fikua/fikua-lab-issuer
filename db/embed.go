// Package db embeds this issuer's Postgres schema so it ships inside the
// compiled binary and can be applied idempotently at boot — no external
// migration tool, see schema.sql.
package db

import _ "embed"

//go:embed schema.sql
var Schema string
