# fikua-lab-issuer

OID4VCI credential issuer for the Fikua Lab EUDI Wallet ecosystem.

Standalone Go service (single binary, no dependency on `fikua-lab`'s Java
backend) that serves both the JSON/OID4VCI API and the issuance UI — same
shape as [`fikua-lab-attestation-registry`](https://github.com/fikua/fikua-lab-attestation-registry),
from which it fetches credential-scheme definitions (claims, display
metadata, format info) over HTTP instead of hardcoding them.

This is a rewrite of `fikua-lab`'s Java/Javalin `fikua-issuer` module
(`suite/backend/fikua-issuer`). Currently issues EUDI PID (SD-JWT VC +
mdoc); Student ID is not carried over from the Java service.

**HAIP-only**: this issuer implements a single protocol profile —
authorization_code via Pushed Authorization Requests (RFC 9126), DPoP
sender-constraining (RFC 9449), ATCA draft-07 client attestation, and
PKCE S256 are all mandatory on every request. There is no profile
selection and no pre-authorized_code/plain flow.

**The authorization server is a separate service.** PAR, `/authorize` and
`/token` live in
[`fikua-lab-idp`](https://github.com/fikua/fikua-lab-idp), advertised via
this issuer's `authorization_servers` metadata. This service verifies the
RFC 9068 JWT access tokens that AS mints, against its published JWK Set —
set `FIKUA_AUTH_SERVER_URL` to point at it.

## Run

```sh
make run          # http://localhost:8080
```

## API

- `GET /.well-known/openid-credential-issuer` — OID4VCI metadata (its `authorization_servers` points at `fikua-lab-idp`).
- `GET /oid4vci/v1/jwks` — issuer's public JWK Set.
- `POST /oid4vci/v1/issuance` — trigger an issuance, returns a `credential_offer_uri` (by-reference authorization_code credential offer).
- `GET /oid4vci/v1/credential-offer/{id}` — resolves a `credential_offer_uri` to its Credential Offer JSON.
- `GET /oid4vci/v1/issuance` — paginated, sortable issuance record listing.
- `GET /oid4vci/v1/issuance/by-issuer-state/{issuerState}` — resolves an offer's `issuer_state` to its record; called by `fikua-lab-idp` during `/authorize`.
- `POST /oid4vci/v1/nonce` — c_nonce issuance (OID4VCI §7), DPoP-validated when an access token is presented.
- `POST /oid4vci/v1/credential` — credential issuance (SD-JWT VC or mdoc).
- `POST /oid4vci/v1/notification` — no-op per OID4VCI §10.1 (this issuer doesn't yet track notification_id).
- `GET /health` — health check (reports `degraded` if the attestation-registry catalogue refresh is stale).
- `GET /openapi.yaml` — OpenAPI spec.
- `GET /swagger` — Swagger UI for the JSON API.

## UI

`/` serves the issuance UI (credential picker, issuance form, records
browser) — plain HTML/CSS/JS, no build step, ported as-is from the
previous Cloudflare Worker frontend.

## Persistence

Issuance records persist to Postgres when `FIKUA_DB_URL` is set (a
Go-native DSN, e.g. `postgresql://user:pass@host:5432/dbname` — not the
`jdbc:postgresql://` format `fikua-lab`'s Java services use). The schema
(`db/schema.sql`) is embedded in the binary and applied idempotently at
boot — no external migration tool. Without `FIKUA_DB_URL`, issuance
records fall back to an in-memory store (data lost on restart) — fine for
local development, not for a real deployment. Sessions (PAR requests,
authorization codes, access tokens, nonces) always stay in-memory,
matching the Java issuer.

## Build

```sh
make build        # bin/issuer, static binary, no CGO
```

Docker image is built `FROM scratch` — no runtime dependencies, single
static binary.

## Deployment

CI/CD mirrors `fikua-lab-attestation-registry`'s pipeline:

1. `build.yml` — vet/build/test on every push and PR.
2. `release.yml` — on push to `main` or a published release, builds a
   multi-arch image and pushes `docker.io/fikua/fikua-lab-issuer` to
   Docker Hub.
3. `deploy.yml` — manually dispatched, or auto-triggered by a published
   release (gated behind the `prd` GitHub Environment's required
   reviewers). SSHes into the VPS through a Cloudflare Access tunnel,
   syncs `compose.yaml` to `/opt/vps/projects/fikua-lab-issuer/`, runs
   `docker compose pull && up -d`, then polls `/health`.

Public at `https://issuer.fikua.com` — a plain Cloudflare-proxied A
record straight to Traefik, same pattern as `fikua-lab-attestation-registry`.
No Cloudflare Access, no Tunnel, no Worker in front.

Required repo secrets (same as `fikua-lab-attestation-registry`):
`DOCKER_USERNAME`, `DOCKER_TOKEN`, `VPS_SSH_PRIVATE_KEY`,
`CF_ACCESS_CLIENT_ID`, `CF_ACCESS_CLIENT_SECRET`.

## License

Apache-2.0. See [LICENSE](LICENSE).
